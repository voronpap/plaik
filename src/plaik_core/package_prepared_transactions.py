"""PostgreSQL prepared-transaction participant for package lifecycle recovery."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .database import DatabaseConnection
from .postgresql import PostgreSQLOwnerScope, _execute, _fetchone, _safe_close


_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_ARTIFACT_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GID_PREFIX = "plaik:pkg:"
_GID = re.compile(r"^plaik:pkg:[0-9a-f]{64}$")


class PackagePreparedTransactionError(RuntimeError):
    """A package prepared transaction could not be proven or completed safely."""


@dataclass(frozen=True, slots=True)
class PackagePreparedTransaction:
    operation_id: str
    package_id: str
    artifact_sha256: str
    gid: str
    owner_role: str


def package_prepared_transaction(
    operation_id: str,
    package_id: str,
    artifact_sha256: str,
) -> PackagePreparedTransaction:
    """Derive the stable PostgreSQL participant identity from Core-owned inputs."""

    if not isinstance(operation_id, str) or _OPERATION_ID.fullmatch(operation_id) is None:
        raise ValueError("invalid package operation id")
    if (
        not isinstance(artifact_sha256, str)
        or _ARTIFACT_SHA256.fullmatch(artifact_sha256) is None
    ):
        raise ValueError("invalid package artifact digest")
    scope = PostgreSQLOwnerScope.for_package(package_id)
    digest = hashlib.sha256(
        f"{operation_id}\0{package_id}\0{artifact_sha256}".encode("utf-8")
    ).hexdigest()
    return PackagePreparedTransaction(
        operation_id=operation_id,
        package_id=package_id,
        artifact_sha256=artifact_sha256,
        gid=f"{_GID_PREFIX}{digest}",
        owner_role=scope.role,
    )


def prepare_package_transaction(
    connection: DatabaseConnection,
    participant: PackagePreparedTransaction,
) -> None:
    """Prepare the caller's active owner transaction under the Core-derived GID."""

    _require_owner_identity(connection, participant.owner_role)
    existing = _fetchone(
        connection,
        "SELECT gid, owner FROM pg_prepared_xacts WHERE gid = %s",
        (participant.gid,),
    )
    if existing is not None:
        raise PackagePreparedTransactionError(
            "package prepared transaction identifier is already in use"
        )
    try:
        _execute(
            connection,
            f"PREPARE TRANSACTION {_prepared_gid_literal(participant.gid)}",
        )
    except Exception:
        raise PackagePreparedTransactionError(
            "package transaction could not be prepared"
        ) from None


def inspect_package_transaction(
    connection: DatabaseConnection,
    participant: PackagePreparedTransaction,
) -> bool:
    """Return whether the expected prepared participant exists with the right owner."""

    row = _fetchone(
        connection,
        "SELECT gid, owner FROM pg_prepared_xacts WHERE gid = %s",
        (participant.gid,),
    )
    if row is None:
        return False
    gid, owner = row
    if gid != participant.gid or owner != participant.owner_role:
        raise PackagePreparedTransactionError(
            "package prepared transaction ownership is inconsistent"
        )
    return True


def finish_package_transaction(
    connection: DatabaseConnection,
    participant: PackagePreparedTransaction,
    *,
    commit: bool,
) -> None:
    """Commit or roll back one proven participant on an owner-authenticated session."""

    _require_autocommit(connection)
    _require_owner_identity(connection, participant.owner_role)
    row = _fetchone(
        connection,
        "SELECT gid, owner FROM pg_prepared_xacts WHERE gid = %s",
        (participant.gid,),
    )
    if row is None:
        raise PackagePreparedTransactionError(
            "expected package prepared transaction is missing"
        )
    gid, owner = row
    if gid != participant.gid or owner != participant.owner_role:
        raise PackagePreparedTransactionError(
            "package prepared transaction ownership is inconsistent"
        )
    command = "COMMIT PREPARED" if commit else "ROLLBACK PREPARED"
    try:
        _execute(
            connection,
            f"{command} {_prepared_gid_literal(participant.gid)}",
        )
    except Exception:
        raise PackagePreparedTransactionError(
            "package prepared transaction could not be completed"
        ) from None


def _prepared_gid_literal(gid: str) -> str:
    """Render only a Core-derived fixed-alphabet GID for PostgreSQL utility SQL."""

    if not isinstance(gid, str) or _GID.fullmatch(gid) is None:
        raise PackagePreparedTransactionError(
            "package prepared transaction identifier is invalid"
        )
    return f"'{gid}'"


def _require_owner_identity(connection: DatabaseConnection, owner_role: str) -> None:
    row = _fetchone(connection, "SELECT current_user, session_user")
    if row is None or tuple(row) != (owner_role, owner_role):
        raise PackagePreparedTransactionError(
            "package prepared transaction session is not the expected owner"
        )


def _require_autocommit(connection: DatabaseConnection) -> None:
    if not hasattr(connection, "autocommit"):
        raise PackagePreparedTransactionError(
            "package prepared transaction completion requires autocommit support"
        )
    try:
        setattr(connection, "autocommit", True)
    except Exception:
        raise PackagePreparedTransactionError(
            "package prepared transaction completion requires autocommit"
        ) from None
    if getattr(connection, "autocommit", None) is not True:
        raise PackagePreparedTransactionError(
            "package prepared transaction completion requires autocommit"
        )


def close_package_transaction_connection(connection: DatabaseConnection) -> None:
    """Best-effort close helper for coordinator recovery composition."""

    _safe_close(connection)
