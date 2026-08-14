"""PostgreSQL-backed integrity checkpoint provider."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Iterator

from .database import ConnectionFactory
from .integrity import (
    GENESIS_HASH,
    IntegrityCheckpoint,
    IntegrityCheckpointError,
    JournalKind,
    _as_utc,
    _checkpoint_body,
    _current_recovery_epoch,
    _latest,
    _validate_actor_id,
    _validate_checkpoint_records,
    _validate_expected_recovery_epoch,
    _validate_head,
    _validate_installation_id,
    _validate_operation_id,
    sign_integrity_checkpoint,
)
from .postgresql import CORE_SCHEMA, _execute, _fetchall, _qualified, _safe_close

_CHECKPOINT_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"plaik-v2:postgresql-integrity-checkpoint:v1").digest()[:8],
    byteorder="big",
    signed=True,
)

_SELECT_COLUMNS = """
    sequence,
    format_version,
    installation_id,
    journal,
    event_count,
    head_hash,
    recorded_at,
    previous_hash,
    checkpoint_hash,
    recovery_epoch,
    recovery_operation_id,
    recovery_actor_id,
    recovery_manifest_sha256
"""


class PostgreSQLCheckpointStore:
    """Append-only checkpoint chain stored outside audit/operation journal tables."""

    def __init__(self, connect: ConnectionFactory, *, integrity_key: bytes) -> None:
        if len(integrity_key) < 32:
            raise ValueError("checkpoint integrity key must contain at least 32 bytes")
        self.connect = connect
        self._integrity_key = integrity_key
        self._thread_lock = threading.RLock()
        self._table = _qualified(CORE_SCHEMA, "plaik_integrity_checkpoints")

    def checkpoint(
        self,
        installation_id: str,
        journal: JournalKind,
        *,
        event_count: int,
        head_hash: str,
        now: datetime | None = None,
        expected_recovery_epoch: int | None = None,
    ) -> IntegrityCheckpoint:
        installation_id = _validate_installation_id(installation_id)
        journal = JournalKind(journal)
        event_count, head_hash = _validate_head(event_count, head_hash)
        expected_recovery_epoch = _validate_expected_recovery_epoch(
            expected_recovery_epoch
        )
        timestamp = _as_utc(now or datetime.now(UTC))

        with self._exclusive():
            records = self._read_and_verify()
            recovery_epoch = _current_recovery_epoch(records, installation_id)
            if (
                expected_recovery_epoch is not None
                and recovery_epoch != expected_recovery_epoch
            ):
                raise IntegrityCheckpointError(
                    "recovery epoch changed while checkpointing"
                )
            existing = _latest(records, installation_id, journal)
            if existing is not None:
                if (
                    existing.event_count == event_count
                    and hmac.compare_digest(existing.head_hash, head_hash)
                ):
                    return existing
                if event_count <= existing.event_count:
                    raise IntegrityCheckpointError(
                        "integrity checkpoint cannot move backward"
                    )
            previous_hash = records[-1].checkpoint_hash if records else GENESIS_HASH
            body = {
                "format_version": 2,
                "sequence": len(records) + 1,
                "installation_id": installation_id,
                "journal": journal.value,
                "event_count": event_count,
                "head_hash": head_hash,
                "recorded_at": timestamp.isoformat(),
                "previous_hash": previous_hash,
                "recovery_epoch": recovery_epoch,
                "recovery_operation_id": None,
                "recovery_actor_id": None,
                "recovery_manifest_sha256": None,
            }
            record = IntegrityCheckpoint.model_validate(
                {
                    **body,
                    "checkpoint_hash": sign_integrity_checkpoint(
                        self._integrity_key, body
                    ),
                }
            )
            self._append_many((record,))
            return record

    def current_recovery_epoch(self, installation_id: str) -> int:
        installation_id = _validate_installation_id(installation_id)
        with self._exclusive():
            return _current_recovery_epoch(
                self._read_and_verify(),
                installation_id,
            )

    def recover(
        self,
        installation_id: str,
        heads: Mapping[JournalKind, tuple[int, str]],
        *,
        operation_id: str,
        actor_id: str,
        manifest_sha256: str,
        now: datetime | None = None,
    ) -> tuple[IntegrityCheckpoint, IntegrityCheckpoint]:
        installation_id = _validate_installation_id(installation_id)
        operation_id = _validate_operation_id(operation_id)
        actor_id = _validate_actor_id(actor_id)
        if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
            raise ValueError("invalid recovery manifest digest")
        normalized: dict[JournalKind, tuple[int, str]] = {}
        for journal in JournalKind:
            try:
                event_count, head_hash = heads[journal]
            except (KeyError, TypeError):
                raise ValueError("recovery requires both journal heads") from None
            normalized[journal] = _validate_head(event_count, head_hash)
        if len(heads) != len(JournalKind):
            raise ValueError("recovery contains an unknown journal head")
        timestamp = _as_utc(now or datetime.now(UTC))

        with self._exclusive():
            records = self._read_and_verify()
            prior = [
                record
                for record in records
                if record.installation_id == installation_id
                and record.recovery_operation_id == operation_id
            ]
            if prior:
                if len(prior) != len(JournalKind):
                    raise IntegrityCheckpointError(
                        "recovery checkpoint set is incomplete"
                    )
                by_journal = {record.journal: record for record in prior}
                if set(by_journal) != set(JournalKind):
                    raise IntegrityCheckpointError(
                        "recovery checkpoint set is invalid"
                    )
                for journal, record in by_journal.items():
                    latest = _latest(records, installation_id, journal)
                    if latest is None or latest.sequence != record.sequence:
                        raise IntegrityCheckpointError(
                            "recovery operation is no longer current"
                        )
                for journal, (event_count, head_hash) in normalized.items():
                    record = by_journal[journal]
                    if (
                        record.event_count != event_count
                        or not hmac.compare_digest(record.head_hash, head_hash)
                        or record.recovery_actor_id != actor_id
                        or record.recovery_manifest_sha256 != manifest_sha256
                    ):
                        raise IntegrityCheckpointError(
                            "recovery operation ID is bound to different evidence"
                        )
                return by_journal[JournalKind.AUDIT], by_journal[JournalKind.OPERATIONS]

            recovery_epoch = _current_recovery_epoch(records, installation_id) + 1
            previous_hash = records[-1].checkpoint_hash if records else GENESIS_HASH
            created: list[IntegrityCheckpoint] = []
            for journal in JournalKind:
                event_count, head_hash = normalized[journal]
                body = {
                    "format_version": 2,
                    "sequence": len(records) + len(created) + 1,
                    "installation_id": installation_id,
                    "journal": journal.value,
                    "event_count": event_count,
                    "head_hash": head_hash,
                    "recorded_at": timestamp.isoformat(),
                    "previous_hash": previous_hash,
                    "recovery_epoch": recovery_epoch,
                    "recovery_operation_id": operation_id,
                    "recovery_actor_id": actor_id,
                    "recovery_manifest_sha256": manifest_sha256,
                }
                record = IntegrityCheckpoint.model_validate(
                    {
                        **body,
                        "checkpoint_hash": sign_integrity_checkpoint(
                            self._integrity_key, body
                        ),
                    }
                )
                created.append(record)
                previous_hash = record.checkpoint_hash
            self._append_many(created)
            return created[0], created[1]

    def latest(
        self, installation_id: str, journal: JournalKind
    ) -> IntegrityCheckpoint | None:
        installation_id = _validate_installation_id(installation_id)
        journal = JournalKind(journal)
        with self._exclusive():
            return _latest(self._read_and_verify(), installation_id, journal)

    def verify_current(
        self,
        installation_id: str,
        journal: JournalKind,
        *,
        event_count: int,
        head_hash: str,
    ) -> IntegrityCheckpoint:
        installation_id = _validate_installation_id(installation_id)
        journal = JournalKind(journal)
        event_count, head_hash = _validate_head(event_count, head_hash)
        with self._exclusive():
            record = _latest(
                self._read_and_verify(),
                installation_id,
                journal,
            )
            if record is None:
                raise IntegrityCheckpointError(
                    "trusted integrity checkpoint is missing"
                )
            if record.event_count != event_count or not hmac.compare_digest(
                record.head_hash, head_hash
            ):
                raise IntegrityCheckpointError(
                    "journal head does not match the trusted integrity checkpoint"
                )
            return record

    def verify(self) -> tuple[IntegrityCheckpoint, ...]:
        with self._exclusive():
            return tuple(self._read_and_verify())

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        with self._thread_lock:
            connection = self.connect()
            self._connection = connection
            try:
                _execute(
                    connection,
                    "SELECT pg_advisory_lock(%s)",
                    (_CHECKPOINT_LOCK_KEY,),
                )
                yield
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                try:
                    _execute(
                        connection,
                        "SELECT pg_advisory_unlock(%s)",
                        (_CHECKPOINT_LOCK_KEY,),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                _safe_close(connection)

    _connection: Any

    def _read_and_verify(self) -> list[IntegrityCheckpoint]:
        rows = _fetchall(
            self._connection,
            f"""
            SELECT {_SELECT_COLUMNS}
            FROM {self._table}
            ORDER BY sequence
            """,
        )
        records: list[IntegrityCheckpoint] = []
        previous_hash = GENESIS_HASH
        try:
            for line_number, row in enumerate(rows, start=1):
                record = _row_to_checkpoint(row)
                if record.sequence != line_number:
                    raise IntegrityCheckpointError(
                        "integrity checkpoint sequence is invalid"
                    )
                if not hmac.compare_digest(record.previous_hash, previous_hash):
                    raise IntegrityCheckpointError(
                        "integrity checkpoint chain is broken"
                    )
                body = _checkpoint_body(record)
                if not hmac.compare_digest(
                    record.checkpoint_hash,
                    sign_integrity_checkpoint(self._integrity_key, body),
                ):
                    raise IntegrityCheckpointError(
                        "integrity checkpoint signature is invalid"
                    )
                previous_hash = record.checkpoint_hash
                records.append(record)
            _validate_checkpoint_records(records)
        except IntegrityCheckpointError:
            raise
        except Exception:
            raise IntegrityCheckpointError(
                "integrity checkpoint could not be verified"
            ) from None
        return records

    def _append_many(
        self,
        records: tuple[IntegrityCheckpoint, ...] | list[IntegrityCheckpoint],
    ) -> None:
        for record in records:
            _execute(
                self._connection,
                f"""
                INSERT INTO {self._table} (
                    sequence,
                    format_version,
                    installation_id,
                    journal,
                    event_count,
                    head_hash,
                    recorded_at,
                    previous_hash,
                    checkpoint_hash,
                    recovery_epoch,
                    recovery_operation_id,
                    recovery_actor_id,
                    recovery_manifest_sha256
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    record.sequence,
                    record.format_version,
                    record.installation_id,
                    record.journal.value,
                    record.event_count,
                    record.head_hash,
                    record.recorded_at,
                    record.previous_hash,
                    record.checkpoint_hash,
                    record.recovery_epoch,
                    record.recovery_operation_id,
                    record.recovery_actor_id,
                    record.recovery_manifest_sha256,
                ),
            )


def _row_to_checkpoint(row: tuple[Any, ...]) -> IntegrityCheckpoint:
    return IntegrityCheckpoint(
        format_version=int(row[1]),
        sequence=int(row[0]),
        installation_id=row[2],
        journal=JournalKind(row[3]),
        event_count=int(row[4]),
        head_hash=row[5],
        recorded_at=_as_utc(row[6]),
        previous_hash=row[7],
        checkpoint_hash=row[8],
        recovery_epoch=int(row[9]),
        recovery_operation_id=row[10],
        recovery_actor_id=row[11],
        recovery_manifest_sha256=row[12],
    )
