"""Secret provider registry and safe bootstrap providers.

Settings persist :class:`SecretReference` objects.  This module resolves those
references at the last responsible moment and returns Pydantic ``SecretStr``
values, whose string and repr representations are redacted.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import SecretStr
from plaik_contracts import SecretReference


_PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_LOCAL_KEY = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$"
)
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SecretStoreError(RuntimeError):
    """A secret reference cannot be safely processed."""


class SecretNotFoundError(SecretStoreError):
    """A provider has no value for the requested reference."""


class SecretProviderReadOnlyError(SecretStoreError):
    """A write was requested from a read-only provider."""


@runtime_checkable
class SecretProvider(Protocol):
    name: str

    def read(self, key: str, *, version: str | None = None) -> SecretStr: ...

    def write(
        self,
        key: str,
        value: str | SecretStr,
        *,
        version: str | None = None,
    ) -> SecretStr: ...

    def generate_if_missing(
        self,
        key: str,
        *,
        version: str | None = None,
        entropy_bytes: int = 32,
    ) -> SecretStr: ...


class SecretProviderRegistry:
    """Resolve secret references through explicitly registered providers."""

    def __init__(self, providers: tuple[SecretProvider, ...] = ()) -> None:
        self._providers: dict[str, SecretProvider] = {}
        for provider in providers:
            self.register(provider)

    @property
    def provider_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    def register(self, provider: SecretProvider) -> None:
        if not isinstance(provider, SecretProvider):
            raise TypeError("secret provider does not implement the provider contract")
        if not _PROVIDER_NAME.fullmatch(provider.name):
            raise ValueError("invalid secret provider name")
        if provider.name in self._providers:
            raise SecretStoreError(f"secret provider already registered: {provider.name}")
        self._providers[provider.name] = provider

    def resolve(self, reference: SecretReference) -> SecretStr:
        provider = self._provider(reference.provider)
        return provider.read(reference.key, version=reference.version)

    def write(self, reference: SecretReference, value: str | SecretStr) -> SecretStr:
        provider = self._provider(reference.provider)
        return provider.write(reference.key, value, version=reference.version)

    def generate_if_missing(
        self,
        reference: SecretReference,
        *,
        entropy_bytes: int = 32,
    ) -> SecretStr:
        provider = self._provider(reference.provider)
        return provider.generate_if_missing(
            reference.key,
            version=reference.version,
            entropy_bytes=entropy_bytes,
        )

    def _provider(self, name: str) -> SecretProvider:
        try:
            return self._providers[name]
        except KeyError as error:
            raise SecretStoreError(f"secret provider is not registered: {name}") from error


class EnvironmentSecretProvider:
    """Resolve deployment-managed environment variables without mutating them."""

    name = "env"

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = os.environ if environ is None else environ

    def read(self, key: str, *, version: str | None = None) -> SecretStr:
        self._validate_key(key)
        reference = _reference_label(self.name, key, version)
        if version is not None:
            raise SecretStoreError(
                f"environment secrets do not support versions ({reference})"
            )
        value = self._environ.get(key)
        if value is None:
            raise SecretNotFoundError(f"secret is not set ({reference})")
        if not value:
            raise SecretStoreError(f"secret is empty ({reference})")
        return SecretStr(value)

    def write(
        self,
        key: str,
        value: str | SecretStr,
        *,
        version: str | None = None,
    ) -> SecretStr:
        self._validate_key(key)
        raise SecretProviderReadOnlyError("environment secret provider is read-only")

    def generate_if_missing(
        self,
        key: str,
        *,
        version: str | None = None,
        entropy_bytes: int = 32,
    ) -> SecretStr:
        self._validate_key(key)
        try:
            return self.read(key, version=version)
        except SecretNotFoundError as error:
            raise SecretProviderReadOnlyError(
                "environment secret provider cannot generate secrets"
            ) from error

    @staticmethod
    def _validate_key(key: str) -> None:
        if not _ENV_KEY.fullmatch(key):
            raise SecretStoreError(
                f"invalid secret key ({_reference_label('env', key, None)})"
            )


class LocalFileSecretProvider:
    """Local text-secret provider for bootstrap and single-node deployments."""

    name = "local"
    MAX_SECRET_BYTES = 1024 * 1024

    def __init__(self, root: Path) -> None:
        self.root = Path(root).absolute()
        self._secure_directory(self.root)

    def read(self, key: str, *, version: str | None = None) -> SecretStr:
        path = self._path(key, version)
        reference = _reference_label(self.name, key, version)
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            raise SecretNotFoundError(
                f"secret does not exist ({reference})"
            ) from None
        except OSError:
            raise SecretStoreError(
                f"secret cannot be opened ({reference})"
            ) from None

        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise SecretStoreError(f"secret is not a regular file ({reference})")
            get_effective_uid = getattr(os, "geteuid", None)
            if get_effective_uid is not None and file_stat.st_uid != get_effective_uid():
                raise SecretStoreError(f"secret has an unexpected owner ({reference})")
            if file_stat.st_nlink != 1:
                raise SecretStoreError(
                    f"secret has an unsafe hard-link count ({reference})"
                )
            if stat.S_IMODE(file_stat.st_mode) & 0o077:
                raise SecretStoreError(f"secret has unsafe file permissions ({reference})")
            if file_stat.st_size > self.MAX_SECRET_BYTES:
                raise SecretStoreError(f"secret exceeds the maximum size ({reference})")
            with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
                value = stream.read(self.MAX_SECRET_BYTES + 1)
            try:
                after = os.fstat(descriptor)
                path_after = os.stat(path, follow_symlinks=False)
            except OSError:
                raise SecretStoreError(
                    f"secret changed while it was read ({reference})"
                ) from None
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if (
                not stat.S_ISREG(path_after.st_mode)
                or any(getattr(after, field) != getattr(file_stat, field) for field in fields)
                or any(getattr(path_after, field) != getattr(after, field) for field in fields)
            ):
                raise SecretStoreError(
                    f"secret changed while it was read ({reference})"
                )
        except UnicodeDecodeError:
            raise SecretStoreError(
                f"secret must be valid UTF-8 text ({reference})"
            ) from None
        finally:
            os.close(descriptor)

        if len(value.encode("utf-8")) > self.MAX_SECRET_BYTES:
            raise SecretStoreError(f"secret exceeds the maximum size ({reference})")
        if not value:
            raise SecretStoreError(f"secret is empty ({reference})")
        return SecretStr(value)

    def write(
        self,
        key: str,
        value: str | SecretStr,
        *,
        version: str | None = None,
    ) -> SecretStr:
        path = self._path(key, version)
        reference = _reference_label(self.name, key, version)
        raw_value = self._raw_value(value, reference=reference)
        self._secure_directory(path.parent)
        self._write_atomic(path, raw_value, reference=reference)
        return SecretStr(raw_value)

    def write_group(
        self,
        items: list[tuple[str, str | SecretStr, str]],
    ) -> None:
        """Write several secrets and roll back this batch on partial failure."""

        if not items:
            raise SecretStoreError("secret group is empty")
        snapshots: list[tuple[Path, str | None]] = []
        prepared: list[tuple[Path, str, str]] = []
        for key, value, version in items:
            path = self._path(key, version)
            reference = _reference_label(self.name, key, version)
            raw_value = self._raw_value(value, reference=reference)
            previous: str | None = None
            if path.is_file():
                previous = path.read_text(encoding="utf-8")
            snapshots.append((path, previous))
            prepared.append((path, raw_value, reference))
        published = 0
        try:
            for path, raw_value, reference in prepared:
                self._secure_directory(path.parent)
                self._write_atomic(path, raw_value, reference=reference)
                published += 1
        except Exception:
            for path, previous in snapshots[:published]:
                if previous is None:
                    path.unlink(missing_ok=True)
                else:
                    self._write_atomic(
                        path,
                        previous,
                        reference=_reference_label(self.name, path.name, None),
                    )
            raise

    def generate_if_missing(
        self,
        key: str,
        *,
        version: str | None = None,
        entropy_bytes: int = 32,
    ) -> SecretStr:
        if not 16 <= entropy_bytes <= 4096:
            raise ValueError("entropy_bytes must be between 16 and 4096")
        path = self._path(key, version)
        reference = _reference_label(self.name, key, version)
        self._secure_directory(path.parent)
        try:
            return self.read(key, version=version)
        except SecretNotFoundError:
            pass

        generated = secrets.token_urlsafe(entropy_bytes)
        temporary_path = self._write_temporary(path, generated)
        try:
            try:
                expected = temporary_path.lstat()
                os.link(temporary_path, path)
                temporary_path.unlink()
                self._verify_published_secret(path, expected, reference=reference)
                self._fsync_directory(path.parent)
                return SecretStr(generated)
            except FileExistsError:
                return self.read(key, version=version)
        finally:
            temporary_path.unlink(missing_ok=True)

    def path_for(self, key: str, *, version: str | None = None) -> Path:
        """Return the validated path for diagnostics without reading the secret."""

        return self._path(key, version)

    def _path(self, key: str, version: str | None) -> Path:
        self._validate_key(key)
        self._validate_version(key, version)
        segments = key.split("/")
        suffix = f"@{version}" if version is not None else ""
        filename = f"{segments[-1]}{suffix}.secret"
        candidate = self.root.joinpath(*segments[:-1], filename)
        if self.root != candidate.parent and self.root not in candidate.parents:
            raise SecretStoreError("local secret path escapes provider root")
        return candidate

    @staticmethod
    def _validate_key(key: str) -> None:
        if not key or len(key) > 255 or not _LOCAL_KEY.fullmatch(key):
            raise SecretStoreError(
                f"invalid secret key ({_reference_label('local', key, None)})"
            )
        if any(part in {".", ".."} for part in key.split("/")):
            raise SecretStoreError(
                f"invalid secret key ({_reference_label('local', key, None)})"
            )

    @staticmethod
    def _validate_version(key: str, version: str | None) -> None:
        if version is not None and not _VERSION.fullmatch(version):
            raise SecretStoreError(
                "invalid secret version "
                f"({_reference_label('local', key, version)})"
            )

    @classmethod
    def _raw_value(cls, value: str | SecretStr, *, reference: str) -> str:
        if isinstance(value, SecretStr):
            raw_value = value.get_secret_value()
        elif isinstance(value, str):
            raw_value = value
        else:
            raise TypeError(f"secret value must be text or SecretStr ({reference})")
        if not raw_value:
            raise SecretStoreError(f"secret value must not be empty ({reference})")
        try:
            encoded_size = len(raw_value.encode("utf-8"))
        except UnicodeEncodeError:
            raise SecretStoreError(
                f"secret value must be valid UTF-8 text ({reference})"
            ) from None
        if encoded_size > cls.MAX_SECRET_BYTES:
            raise SecretStoreError(
                f"secret value exceeds the maximum size ({reference})"
            )
        return raw_value

    def _secure_directory(self, directory: Path) -> None:
        try:
            relative = directory.relative_to(self.root)
        except ValueError as error:
            raise SecretStoreError("local secret directory escapes provider root")

        current = self.root
        self._secure_directory_component(current, allow_parents=True)
        for part in relative.parts:
            current = current / part
            self._secure_directory_component(current, allow_parents=False)

    @staticmethod
    def _secure_directory_component(path: Path, *, allow_parents: bool) -> None:
        descriptor = -1
        try:
            path.mkdir(mode=0o700, parents=allow_parents, exist_ok=True)
            path_hint = path.lstat()
            if not stat.S_ISDIR(path_hint.st_mode):
                raise SecretStoreError("local secret path contains a non-directory")
            if not hasattr(os, "O_NOFOLLOW") and path.is_symlink():
                raise SecretStoreError("local secret path contains a non-directory")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(path, flags)
            path_stat = os.fstat(descriptor)
            if not stat.S_ISDIR(path_stat.st_mode):
                raise SecretStoreError("local secret path contains a non-directory")
            get_effective_uid = getattr(os, "geteuid", None)
            if (
                get_effective_uid is not None
                and path_stat.st_uid != get_effective_uid()
            ):
                raise SecretStoreError("local secret directory has an unexpected owner")
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(descriptor, 0o700)
            else:
                try:
                    os.chmod(path, 0o700, follow_symlinks=False)
                except (NotImplementedError, TypeError):
                    os.chmod(path, 0o700)
                current = os.stat(path, follow_symlinks=False)
                if current.st_dev != path_stat.st_dev or current.st_ino != path_stat.st_ino:
                    raise SecretStoreError("local secret directory changed while secured")
        except SecretStoreError:
            raise
        except OSError:
            raise SecretStoreError("local secret directory cannot be secured") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _write_atomic(self, path: Path, value: str, *, reference: str) -> None:
        try:
            temporary_path = self._write_temporary(path, value)
        except (OSError, UnicodeError):
            raise SecretStoreError(
                f"secret cannot be written atomically ({reference})"
            ) from None
        try:
            expected = temporary_path.lstat()
            os.replace(temporary_path, path)
            self._verify_published_secret(path, expected, reference=reference)
            self._fsync_directory(path.parent)
        except SecretStoreError:
            raise
        except OSError:
            raise SecretStoreError(
                f"secret cannot be written atomically ({reference})"
            ) from None
        finally:
            temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _write_temporary(path: Path, value: str) -> Path:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}-",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            return temporary_path
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _verify_published_secret(
        path: Path,
        expected: os.stat_result,
        *,
        reference: str,
    ) -> None:
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            published = os.fstat(descriptor)
            get_effective_uid = getattr(os, "geteuid", None)
            if (
                not stat.S_ISREG(published.st_mode)
                or published.st_dev != expected.st_dev
                or published.st_ino != expected.st_ino
                or published.st_size != expected.st_size
                or published.st_nlink != 1
                or stat.S_IMODE(published.st_mode) & 0o077
                or (
                    get_effective_uid is not None
                    and published.st_uid != get_effective_uid()
                )
            ):
                raise SecretStoreError(
                    f"secret changed while it was published ({reference})"
                )
        except SecretStoreError:
            raise
        except OSError:
            raise SecretStoreError(
                f"secret changed while it was published ({reference})"
            ) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)



def _reference_label(provider: str, key: str, version: str | None) -> str:
    """Return useful diagnostics without revealing the provider key."""

    material = f"{provider}\0{key}\0{version or ''}".encode("utf-8", errors="replace")
    fingerprint = hashlib.sha256(material).hexdigest()[:16]
    return f"provider={provider}, reference={fingerprint}"
