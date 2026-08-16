"""Public-only runtime secret publication.

The generic :class:`LocalFileSecretProvider` contract is unchanged. Root
finalization copies the runtime credential into a separate directory that
``plaik-public`` can read but cannot modify.
"""

from __future__ import annotations

import os
import pwd
import stat
import tempfile
from pathlib import Path

from pydantic import SecretStr

from .secret_store import (
    LocalFileSecretProvider,
    SecretNotFoundError,
    SecretProviderReadOnlyError,
    SecretStoreError,
    _LOCAL_KEY,
    _VERSION,
    _reference_label,
)


class PublishedRuntimeSecretProvider:
    """Read-only provider for a root-published public runtime credential."""

    name = "local"
    MAX_SECRET_BYTES = LocalFileSecretProvider.MAX_SECRET_BYTES

    def __init__(self, root: Path) -> None:
        self.root = Path(root).absolute()
        self._validate_root()

    def read(self, key: str, *, version: str | None = None) -> SecretStr:
        path = _secret_path(self.root, key, version)
        reference = _reference_label(self.name, key, version)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            raise SecretNotFoundError(f"secret does not exist ({reference})") from None
        except OSError:
            raise SecretStoreError(f"secret cannot be opened ({reference})") from None
        try:
            file_stat = os.fstat(descriptor)
            geteuid = getattr(os, "geteuid", lambda: None)
            current_uid = geteuid()
            if not stat.S_ISREG(file_stat.st_mode):
                raise SecretStoreError(f"secret is not a regular file ({reference})")
            if file_stat.st_uid != 0:
                raise SecretStoreError(f"secret must be owned by root ({reference})")
            if current_uid is not None:
                identity_gid = pwd.getpwuid(current_uid).pw_gid
                if file_stat.st_gid != identity_gid:
                    raise SecretStoreError(
                        f"secret group does not match the public identity ({reference})"
                    )
            if stat.S_IMODE(file_stat.st_mode) != 0o440:
                raise SecretStoreError(f"secret has unsafe file permissions ({reference})")
            if file_stat.st_nlink != 1:
                raise SecretStoreError(
                    f"secret has an unsafe hard-link count ({reference})"
                )
            if file_stat.st_size > self.MAX_SECRET_BYTES:
                raise SecretStoreError(f"secret exceeds the maximum size ({reference})")
            with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
                value = stream.read(self.MAX_SECRET_BYTES + 1)
        except UnicodeDecodeError:
            raise SecretStoreError(
                f"secret must be valid UTF-8 text ({reference})"
            ) from None
        finally:
            os.close(descriptor)
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
        raise SecretProviderReadOnlyError("published runtime secrets are read-only")

    def generate_if_missing(
        self,
        key: str,
        *,
        version: str | None = None,
        entropy_bytes: int = 32,
    ) -> SecretStr:
        try:
            return self.read(key, version=version)
        except SecretNotFoundError as error:
            raise SecretProviderReadOnlyError(
                "published runtime secrets cannot generate secrets"
            ) from error

    def _validate_root(self) -> None:
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(self.root, flags)
        except FileNotFoundError:
            raise SecretStoreError("published secret directory is missing") from None
        except OSError:
            raise SecretStoreError("published secret directory cannot be opened") from None
        try:
            path_stat = os.fstat(descriptor)
            if not stat.S_ISDIR(path_stat.st_mode):
                raise SecretStoreError("published secret path is not a directory")
            if stat.S_IMODE(path_stat.st_mode) & 0o022:
                raise SecretStoreError("published secret directory is writable by others")
            if path_stat.st_uid != 0:
                raise SecretStoreError(
                    "published secret directory must be owned by root"
                )
        finally:
            os.close(descriptor)


def publish_runtime_secret(
    destination: Path,
    value: str | SecretStr,
    *,
    key: str = "database/runtime",
    version: str = "v1",
    public_user: str | None = None,
) -> None:
    """Publish a read-only runtime credential for the public Unix identity."""

    raw = value.get_secret_value() if isinstance(value, SecretStr) else value
    if not raw:
        raise SecretStoreError("published runtime secret must not be empty")
    destination = Path(destination).absolute()
    destination.mkdir(parents=True, exist_ok=True)
    path = _secret_path(destination, key, version)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_readonly_secret(path, raw, mode=0o440)
    geteuid = getattr(os, "geteuid", lambda: None)
    if geteuid() != 0:
        os.chmod(destination, 0o750)
        os.chmod(path.parent, 0o750)
        os.chmod(path, 0o440)
        return
    account = public_user or os.environ.get("PLAIK_PUBLIC_USER", "plaik-public")
    try:
        identity = pwd.getpwnam(account)
    except KeyError:
        raise SecretStoreError("public service identity is missing") from None
    _lock_published_tree(destination, identity.pw_gid)


def read_private_secret_for_publication(
    root: Path,
    key: str,
    *,
    version: str,
) -> SecretStr:
    """Read a private local secret, including as root across identity handoff."""

    geteuid = getattr(os, "geteuid", lambda: None)
    if geteuid() != 0:
        return LocalFileSecretProvider(root).read(key, version=version)
    path = _secret_path(Path(root).absolute(), key, version)
    reference = _reference_label("local", key, version)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise SecretNotFoundError(f"secret does not exist ({reference})") from None
    except OSError:
        raise SecretStoreError(f"secret cannot be opened ({reference})") from None
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise SecretStoreError(f"secret is not a regular file ({reference})")
        if file_stat.st_uid == 0:
            raise SecretStoreError(f"secret must not be owned by root ({reference})")
        allowed_uids: set[int] = set()
        for env_name, default_name, missing in (
            ("PLAIK_INSTALLER_USER", "plaik-installer", "installer identity is missing"),
            ("PLAIK_ADMIN_USER", "plaik-admin", "admin identity is missing"),
        ):
            try:
                allowed_uids.add(pwd.getpwnam(os.environ.get(env_name, default_name)).pw_uid)
            except KeyError:
                raise SecretStoreError(missing) from None
        if file_stat.st_uid not in allowed_uids:
            raise SecretStoreError(f"secret has an unexpected owner ({reference})")
        if stat.S_IMODE(file_stat.st_mode) & 0o077:
            raise SecretStoreError(f"secret has unsafe file permissions ({reference})")
        if file_stat.st_nlink != 1:
            raise SecretStoreError(
                f"secret has an unsafe hard-link count ({reference})"
            )
        if file_stat.st_size > LocalFileSecretProvider.MAX_SECRET_BYTES:
            raise SecretStoreError(f"secret exceeds the maximum size ({reference})")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
            value = stream.read(LocalFileSecretProvider.MAX_SECRET_BYTES + 1)
    except UnicodeDecodeError:
        raise SecretStoreError(f"secret must be valid UTF-8 text ({reference})") from None
    finally:
        os.close(descriptor)
    if not value:
        raise SecretStoreError(f"secret is empty ({reference})")
    return SecretStr(value)


def _secret_path(root: Path, key: str, version: str | None) -> Path:
    if not _LOCAL_KEY.fullmatch(key):
        raise SecretStoreError(
            f"invalid secret key ({_reference_label('local', key, version)})"
        )
    if version is not None and not _VERSION.fullmatch(version):
        raise SecretStoreError(
            f"invalid secret version ({_reference_label('local', key, version)})"
        )
    segments = key.split("/")
    suffix = f"@{version}" if version is not None else ""
    filename = f"{segments[-1]}{suffix}.secret"
    candidate = root.joinpath(*segments[:-1], filename)
    if root != candidate.parent and root not in candidate.parents:
        raise SecretStoreError("local secret path escapes provider root")
    return candidate


def _write_readonly_secret(path: Path, value: str, *, mode: int = 0o440) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}-",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, mode)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def _lock_published_tree(root: Path, gid: int) -> None:
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        path = Path(current)
        os.chown(path, 0, gid)
        os.chmod(path, 0o750)
        for name in filenames:
            file_path = path / name
            if file_path.is_symlink():
                raise SecretStoreError("published secret tree must not contain symlinks")
            os.chown(file_path, 0, gid)
            os.chmod(file_path, 0o440)
        if any(Path(current, name).is_symlink() for name in dirnames):
            raise SecretStoreError("published secret tree must not contain symlinks")
