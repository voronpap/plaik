"""Pure recovery decisions for crash-atomic package SQL participation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .package_prepared_transactions import (
    PackagePreparedTransaction,
    package_prepared_transaction,
)


_CHECKSUM = re.compile(r"^[0-9a-f]{64}$")


class PackageSQLRecoveryError(RuntimeError):
    """Persisted package SQL participant evidence is inconsistent."""


class PackageSQLParticipantPhase(StrEnum):
    PREPARING = "preparing"
    PREPARED = "prepared"
    FINISHED = "finished"


class PackageSQLRecoveryAction(StrEnum):
    NONE = "none"
    ROLLBACK_PREPARED = "rollback_prepared"
    COMMIT_PREPARED = "commit_prepared"
    VERIFY_ROLLED_BACK = "verify_rolled_back"
    VERIFY_FINISHED = "verify_finished"


@dataclass(frozen=True, slots=True)
class PackageMigrationEvidence:
    owner: str
    version: str
    checksum: str

    def __post_init__(self) -> None:
        if not self.owner or not self.version or _CHECKSUM.fullmatch(self.checksum) is None:
            raise ValueError("invalid package migration evidence")


@dataclass(frozen=True, slots=True)
class PackageSQLParticipantEvidence:
    participant: PackagePreparedTransaction
    migrations: tuple[PackageMigrationEvidence, ...]
    phase: PackageSQLParticipantPhase

    def __post_init__(self) -> None:
        if not self.migrations:
            raise ValueError("package SQL participant must bind at least one migration")
        keys = [(item.owner, item.version) for item in self.migrations]
        if len(keys) != len(set(keys)):
            raise ValueError("package SQL participant contains duplicate migration keys")
        if any(item.owner != self.participant.package_id for item in self.migrations):
            raise ValueError("package SQL participant migration owner does not match package")


class PackageMigrationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    owner: str
    version: str
    checksum: str


class PackageSQLParticipantRecord(BaseModel):
    """JSON-safe durable representation stored inside a package lifecycle intent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    operation_id: str
    package_id: str
    artifact_sha256: str
    gid: str
    owner_role: str
    migrations: tuple[PackageMigrationRecord, ...]
    phase: PackageSQLParticipantPhase

    @classmethod
    def from_evidence(
        cls,
        evidence: PackageSQLParticipantEvidence,
    ) -> "PackageSQLParticipantRecord":
        return cls(
            operation_id=evidence.participant.operation_id,
            package_id=evidence.participant.package_id,
            artifact_sha256=evidence.participant.artifact_sha256,
            gid=evidence.participant.gid,
            owner_role=evidence.participant.owner_role,
            migrations=tuple(
                PackageMigrationRecord(
                    owner=item.owner,
                    version=item.version,
                    checksum=item.checksum,
                )
                for item in evidence.migrations
            ),
            phase=evidence.phase,
        )

    def to_evidence(self) -> PackageSQLParticipantEvidence:
        participant = package_prepared_transaction(
            self.operation_id,
            self.package_id,
            self.artifact_sha256,
        )
        if participant.gid != self.gid or participant.owner_role != self.owner_role:
            raise PackageSQLRecoveryError(
                "durable package SQL participant identity does not match Core derivation"
            )
        return PackageSQLParticipantEvidence(
            participant=participant,
            migrations=tuple(
                PackageMigrationEvidence(
                    owner=item.owner,
                    version=item.version,
                    checksum=item.checksum,
                )
                for item in self.migrations
            ),
            phase=self.phase,
        )


def package_sql_recovery_action(
    *,
    local_committed: bool,
    evidence: PackageSQLParticipantEvidence | None,
    prepared_exists: bool,
) -> PackageSQLRecoveryAction:
    """Choose the only safe database action from durable local/DB evidence."""

    if evidence is None:
        if prepared_exists:
            raise PackageSQLRecoveryError(
                "prepared package transaction exists without bound participant evidence"
            )
        return PackageSQLRecoveryAction.NONE

    if evidence.phase == PackageSQLParticipantPhase.PREPARING:
        if local_committed:
            raise PackageSQLRecoveryError(
                "local package commit cannot precede durable database prepare evidence"
            )
        return (
            PackageSQLRecoveryAction.ROLLBACK_PREPARED
            if prepared_exists
            else PackageSQLRecoveryAction.VERIFY_ROLLED_BACK
        )

    if evidence.phase == PackageSQLParticipantPhase.PREPARED:
        if prepared_exists:
            return (
                PackageSQLRecoveryAction.COMMIT_PREPARED
                if local_committed
                else PackageSQLRecoveryAction.ROLLBACK_PREPARED
            )
        return (
            PackageSQLRecoveryAction.VERIFY_FINISHED
            if local_committed
            else PackageSQLRecoveryAction.VERIFY_ROLLED_BACK
        )

    if evidence.phase == PackageSQLParticipantPhase.FINISHED:
        if prepared_exists:
            raise PackageSQLRecoveryError(
                "finished package SQL participant still exists as prepared"
            )
        if not local_committed:
            raise PackageSQLRecoveryError(
                "database participant finished before local package commit decision"
            )
        return PackageSQLRecoveryAction.VERIFY_FINISHED

    raise PackageSQLRecoveryError("unknown package SQL participant phase")
