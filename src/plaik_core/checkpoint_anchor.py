"""Concurrency-safe anchoring for verified journal heads."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from .integrity import (
    CheckpointProvider,
    IntegrityCheckpoint,
    IntegrityCheckpointError,
    JournalKind,
)


_MAX_ANCHOR_ATTEMPTS = 3


class VerifiedJournalHead(Protocol):
    event_count: int
    head_hash: str


def checkpoint_verified_journal(
    checkpoints: CheckpointProvider,
    installation_id: str,
    journal: JournalKind,
    *,
    verify: Callable[[], VerifiedJournalHead],
    expected_recovery_epoch: int,
) -> IntegrityCheckpoint:
    """Verify and anchor a journal head with bounded same-epoch race recovery.

    If another worker checkpoints a newer verified head between this worker's
    verification and checkpoint write, the journal itself is verified again
    before retrying. A real rollback therefore keeps failing instead of being
    hidden by the newer trusted checkpoint. Recovery-epoch changes never retry.
    """

    last_error: IntegrityCheckpointError | None = None
    for _attempt in range(_MAX_ANCHOR_ATTEMPTS):
        head = verify()
        try:
            return checkpoints.checkpoint(
                installation_id,
                journal,
                event_count=head.event_count,
                head_hash=head.head_hash,
                expected_recovery_epoch=expected_recovery_epoch,
            )
        except IntegrityCheckpointError as error:
            latest = checkpoints.latest(installation_id, journal)
            if (
                latest is None
                or latest.recovery_epoch != expected_recovery_epoch
                or latest.event_count <= head.event_count
            ):
                raise
            last_error = error

    assert last_error is not None
    raise last_error
