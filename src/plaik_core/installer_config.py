"""Validated, atomic installer configuration contract.

Database credentials are represented only by external secret references.  The
store remains independent from HTTP and from the runtime configuration module.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

from .installer import InstallState, InstallStateStore
from .settings_store import SecretReference
from .storage import exclusive_file_lock, read_json, write_json_atomic


_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_LOCALE_PATTERN = re.compile(
    r"^[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-(?:[A-Z]{2}|[0-9]{3}))?$"
)
class InstallerConfigurationError(RuntimeError):
    """Installer configuration persistence or lifecycle invariant failed."""


class InstallationProfile(StrEnum):
    PLATFORM = "platform"
    STANDARD = "standard"


class DeploymentMode(StrEnum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    REFERENCE = "reference"


class DatabaseBackend(StrEnum):
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"


class PostgreSQLDatabase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    backend: Literal[DatabaseBackend.POSTGRESQL] = DatabaseBackend.POSTGRESQL
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")
    username: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}$")
    credential: SecretReference
    runtime_username: str | None = Field(
        default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}$"
    )
    runtime_credential: SecretReference | None = None
    checkpoint_username: str | None = Field(
        default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}$"
    )
    checkpoint_credential: SecretReference | None = None
    ssl_mode: Literal["disable", "prefer", "require", "verify-ca", "verify-full"] = (
        "require"
    )
    connect_timeout_seconds: int = Field(default=10, ge=1, le=60)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        value = value.strip()
        if not value or any(character.isspace() or ord(character) < 32 for character in value):
            raise ValueError("invalid PostgreSQL host")
        if "/" in value or "@" in value:
            raise ValueError("PostgreSQL host must not contain credentials or a path")
        return value

    @model_validator(mode="after")
    def validate_runtime_identity_pair(self) -> "PostgreSQLDatabase":
        pairs = (
            (self.runtime_username, self.runtime_credential, "runtime"),
            (self.checkpoint_username, self.checkpoint_credential, "checkpoint"),
        )
        for username, credential, label in pairs:
            if (username is None) != (credential is None):
                raise ValueError(f"PostgreSQL {label} identity must be complete")
        identities = [
            value
            for value in (self.username, self.runtime_username, self.checkpoint_username)
            if value is not None
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("PostgreSQL migrator, runtime and checkpoint identities must differ")
        return self


class SQLiteDatabase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    backend: Literal[DatabaseBackend.SQLITE] = DatabaseBackend.SQLITE
    path: str = Field(min_length=1, max_length=1024)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if "\x00" in value or value.strip() != value:
            raise ValueError("invalid SQLite path")
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("SQLite path must remain relative to the Platform data directory")
        return value


DatabaseConfiguration = Annotated[
    PostgreSQLDatabase | SQLiteDatabase,
    Field(discriminator="backend"),
]


class InstallerConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    profile: InstallationProfile = InstallationProfile.STANDARD
    mode: DeploymentMode = DeploymentMode.PRODUCTION
    installation_id: str
    group_id: str
    store_id: str
    locale: str
    timezone: str
    public_url: HttpUrl
    database: DatabaseConfiguration
    sealed: bool = False
    sealed_at: datetime | None = None

    @field_validator("installation_id", "group_id", "store_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError(
                "identifier must be 2-64 lowercase letters, digits, or hyphens"
            )
        return value

    @field_validator("locale")
    @classmethod
    def validate_locale(cls, value: str) -> str:
        if not _LOCALE_PATTERN.fullmatch(value):
            raise ValueError("locale must be a canonical BCP 47 language tag")
        return value

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise ValueError("unknown IANA timezone") from error
        return value

    @model_validator(mode="after")
    def validate_environment_contract(self) -> "InstallerConfiguration":
        if isinstance(self.database, PostgreSQLDatabase):
            if self.mode == DeploymentMode.PRODUCTION and (
                self.database.runtime_username is None
                or self.database.runtime_credential is None
                or self.database.checkpoint_username is None
                or self.database.checkpoint_credential is None
            ):
                raise ValueError(
                    "production PostgreSQL requires distinct runtime and checkpoint identities"
                )
        if isinstance(self.database, SQLiteDatabase):
            if self.mode not in {DeploymentMode.DEVELOPMENT, DeploymentMode.REFERENCE}:
                raise ValueError(
                    "SQLite requires explicit development or reference mode"
                )
        elif self.mode == DeploymentMode.PRODUCTION and self.database.ssl_mode not in {
            "require",
            "verify-ca",
            "verify-full",
        }:
            raise ValueError("production PostgreSQL requires encrypted transport")

        if self.mode == DeploymentMode.PRODUCTION and self.public_url.scheme != "https":
            raise ValueError("production public URL must use HTTPS")
        if self.public_url.username or self.public_url.password:
            raise ValueError("public URL must not contain credentials")
        if self.public_url.query or self.public_url.fragment:
            raise ValueError("public URL must not contain query parameters or a fragment")

        if self.sealed != (self.sealed_at is not None):
            raise ValueError("sealed and sealed_at must change together")
        return self

    def redacted(self) -> dict[str, Any]:
        output = self.model_dump(mode="json")
        if isinstance(self.database, PostgreSQLDatabase):
            output["database"]["credential"] = self.database.credential.redacted()
        return output

    def fingerprint(self) -> str:
        payload = self.model_dump(
            mode="json",
            exclude={"sealed", "sealed_at"},
        )
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def __repr__(self) -> str:
        return f"InstallerConfiguration({json.dumps(self.redacted(), sort_keys=True)})"

    __str__ = __repr__


class InstallerConfigurationStore:
    """Atomic configuration store that can be sealed after installer completion."""

    _IMMUTABLE_IDS = ("installation_id", "group_id", "store_id")

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> InstallerConfiguration | None:
        if not self.path.is_file():
            return None
        return InstallerConfiguration.model_validate(read_json(self.path, {}))

    def require(self) -> InstallerConfiguration:
        configuration = self.read()
        if configuration is None:
            raise InstallerConfigurationError("installer configuration does not exist")
        return configuration

    def write(self, configuration: InstallerConfiguration) -> InstallerConfiguration:
        # Do not trust model_copy/model_construct callers: validate again at the
        # persistence boundary before evaluating lifecycle invariants.
        configuration = InstallerConfiguration.model_validate(
            configuration.model_dump(mode="json")
        )
        if configuration.sealed:
            raise InstallerConfigurationError("only the store can seal configuration")
        with exclusive_file_lock(self.path):
            current = self.read()
            if current is not None:
                if current.sealed:
                    raise InstallerConfigurationError("installer configuration is sealed")
                changed_ids = [
                    name
                    for name in self._IMMUTABLE_IDS
                    if getattr(current, name) != getattr(configuration, name)
                ]
                if changed_ids:
                    raise InstallerConfigurationError(
                        f"installation identity fields are immutable: {changed_ids}"
                    )
            self._write(configuration)
            return configuration

    def seal(
        self,
        install_state_store: InstallStateStore,
        *,
        now: datetime | None = None,
    ) -> InstallerConfiguration:
        with exclusive_file_lock(self.path):
            configuration = self.require()
            if configuration.sealed:
                return configuration
            if install_state_store.read() != InstallState.COMPLETED:
                raise InstallerConfigurationError(
                    "installer configuration can be sealed only after completion"
                )
            sealed_at = _as_utc(now or datetime.now(UTC))
            sealed = configuration.model_copy(
                update={"sealed": True, "sealed_at": sealed_at}
            )
            # Revalidate the copy because model_copy intentionally skips validation.
            sealed = InstallerConfiguration.model_validate(sealed.model_dump(mode="json"))
            self._write(sealed)
            return sealed

    def redacted(self) -> dict[str, Any] | None:
        configuration = self.read()
        return configuration.redacted() if configuration is not None else None

    def _write(self, configuration: InstallerConfiguration) -> None:
        write_json_atomic(self.path, configuration.model_dump(mode="json"))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("seal timestamp must be timezone-aware")
    return value.astimezone(UTC)
