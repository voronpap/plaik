"""Strict local trust store for public Ed25519 package/release keys."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from plaik_contracts import PackageManifest, PackageType


_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_MAX_TRUST_STORE_BYTES = 256 * 1024
_MAX_TRUSTED_KEYS = 128
_PACKAGE_PATTERN = re.compile(
    r"^(?:\*|[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:-\*)?)$"
)


class SigningKeyStoreError(RuntimeError):
    """The operator-managed public key trust store is unavailable or invalid."""


@dataclass(frozen=True, slots=True)
class PackageSigningGrant:
    """One publisher key's deliberately narrow package authority."""

    public_key: bytes
    packages: tuple[str, ...]
    types: frozenset[PackageType]
    revoked: bool
    transfers_from: frozenset[str]

    def authorizes(self, manifest: PackageManifest) -> bool:
        return (
            not self.revoked
            and manifest.type in self.types
            and any(_package_pattern_matches(pattern, manifest.id) for pattern in self.packages)
        )


@dataclass(frozen=True, slots=True)
class PackageTrustPolicy:
    """Versioned package-purpose trust snapshot loaded for each mutation."""

    grants: dict[str, PackageSigningGrant]

    @property
    def public_keys(self) -> dict[str, bytes]:
        return {
            key_id: grant.public_key
            for key_id, grant in sorted(self.grants.items())
        }

    def authorizes(self, key_id: str, manifest: PackageManifest) -> bool:
        grant = self.grants.get(key_id)
        return grant is not None and grant.authorizes(manifest)

    def authorizes_transfer(
        self,
        *,
        package_id: str,
        package_type: PackageType,
        previous_key_id: str,
        next_key_id: str,
    ) -> bool:
        if previous_key_id == next_key_id:
            return True
        grant = self.grants.get(next_key_id)
        if grant is None:
            return False
        return (
            not grant.revoked
            and package_type in grant.types
            and any(
                _package_pattern_matches(pattern, package_id)
                for pattern in grant.packages
            )
            and previous_key_id in grant.transfers_from
        )


def load_ed25519_public_keys(path: Path) -> dict[str, bytes]:
    """Read a versioned public-key map without accepting links or loose data."""

    try:
        payload = json.loads(_read_regular_file(Path(path)).decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != {"version", "keys"}:
            raise ValueError
        if payload["version"] != 1 or not isinstance(payload["keys"], dict):
            raise ValueError
        if len(payload["keys"]) > _MAX_TRUSTED_KEYS:
            raise ValueError
        parsed: dict[str, bytes] = {}
        for key_id, encoded in payload["keys"].items():
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
                raise ValueError
            if not isinstance(encoded, str) or len(encoded) > 64:
                raise ValueError
            padding = "=" * (-len(encoded) % 4)
            raw = base64.b64decode(
                encoded + padding,
                altchars=b"-_",
                validate=True,
            )
            if len(raw) != 32:
                raise ValueError
            parsed[key_id] = raw
        if not parsed:
            raise ValueError
        return dict(sorted(parsed.items()))
    except SigningKeyStoreError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, binascii.Error):
        raise SigningKeyStoreError("trusted signing key store is invalid") from None


def load_package_trust_policy(path: Path) -> PackageTrustPolicy:
    """Load the package-only v2 policy with namespace/type/revocation grants."""

    try:
        payload = json.loads(_read_regular_file(Path(path)).decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != {"version", "keys"}:
            raise ValueError
        keys = payload["keys"]
        if payload["version"] != 2 or not isinstance(keys, dict):
            raise ValueError
        if not keys or len(keys) > _MAX_TRUSTED_KEYS:
            raise ValueError
        grants: dict[str, PackageSigningGrant] = {}
        for key_id, raw_grant in keys.items():
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
                raise ValueError
            if not isinstance(raw_grant, dict) or set(raw_grant) != {
                "public_key",
                "packages",
                "types",
                "revoked",
                "transfers_from",
            }:
                raise ValueError
            encoded = raw_grant["public_key"]
            package_patterns = raw_grant["packages"]
            raw_types = raw_grant["types"]
            revoked = raw_grant["revoked"]
            transfers = raw_grant["transfers_from"]
            if not isinstance(encoded, str) or len(encoded) > 64:
                raise ValueError
            if (
                not isinstance(package_patterns, list)
                or not package_patterns
                or len(package_patterns) > 128
                or not all(
                    isinstance(item, str) and _PACKAGE_PATTERN.fullmatch(item)
                    for item in package_patterns
                )
            ):
                raise ValueError
            if (
                not isinstance(raw_types, list)
                or not raw_types
                or len(raw_types) > len(PackageType)
            ):
                raise ValueError
            package_types = frozenset(PackageType(value) for value in raw_types)
            if len(package_types) != len(raw_types) or not isinstance(revoked, bool):
                raise ValueError
            if (
                not isinstance(transfers, list)
                or len(transfers) > _MAX_TRUSTED_KEYS
                or not all(
                    isinstance(item, str) and _KEY_ID.fullmatch(item)
                    for item in transfers
                )
                or len(set(transfers)) != len(transfers)
            ):
                raise ValueError
            padding = "=" * (-len(encoded) % 4)
            public_key = base64.b64decode(
                encoded + padding,
                altchars=b"-_",
                validate=True,
            )
            if len(public_key) != 32:
                raise ValueError
            grants[key_id] = PackageSigningGrant(
                public_key=public_key,
                packages=tuple(sorted(set(package_patterns))),
                types=package_types,
                revoked=revoked,
                transfers_from=frozenset(transfers),
            )
        return PackageTrustPolicy(dict(sorted(grants.items())))
    except SigningKeyStoreError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        binascii.Error,
    ):
        raise SigningKeyStoreError("package trust policy is invalid") from None


def _package_pattern_matches(pattern: str, package_id: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("-*"):
        return package_id.startswith(pattern[:-1])
    return package_id == pattern


def _read_regular_file(path: Path) -> bytes:
    """Read one bounded file descriptor without following a link swap."""

    try:
        before = path.lstat()
    except OSError as error:
        raise SigningKeyStoreError("trusted signing key store is unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SigningKeyStoreError("trusted signing key store is unavailable")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SigningKeyStoreError("trusted signing key store is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SigningKeyStoreError("trusted signing key store is unavailable")
        if (
            getattr(before, "st_ino", 0)
            and getattr(metadata, "st_ino", 0)
            and (
                before.st_ino != metadata.st_ino
                or before.st_dev != metadata.st_dev
            )
        ):
            raise SigningKeyStoreError("trusted signing key store changed before read")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_TRUST_STORE_BYTES:
            raise SigningKeyStoreError("trusted signing key store is too large")
        chunks: list[bytes] = []
        remaining = _MAX_TRUST_STORE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        try:
            after = os.fstat(descriptor)
        except OSError:
            raise SigningKeyStoreError("trusted signing key store changed while read") from None
        if (
            len(content) != metadata.st_size
            or len(content) > _MAX_TRUST_STORE_BYTES
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or after.st_mtime_ns != metadata.st_mtime_ns
            or after.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise SigningKeyStoreError("trusted signing key store changed while read")
        return content
    finally:
        os.close(descriptor)