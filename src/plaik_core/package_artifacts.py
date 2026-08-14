"""Verification and safe staging for detached-signed package artifacts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import re
import shutil
import stat
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from plaik_contracts import PackageManifest


MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 4096
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SIGNATURE_ENVELOPE_BYTES = 16 * 1024
INTEGRITY_MARKER_FILENAME = ".plaik-artifact.json"

_KEY_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_CONTEXT = b"plaik-package-signature-v1\0"
_ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_WINDOWS_RESERVED_BASENAMES = {
    "aux",
    "con",
    "conin$",
    "conout$",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


class PackageArtifactError(RuntimeError):
    """A package artifact is malformed, unsafe, or incompatible with its envelope."""


class PackageSignatureError(PackageArtifactError):
    """A detached signature is absent, untrusted, or invalid."""


class MissingSignatureDependency(PackageSignatureError):
    """The approved asymmetric crypto provider is not installed."""


class _RegularSnapshotError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class SignatureEnvelope(BaseModel):
    """Detached signature metadata; the signature itself is URL-safe base64."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str = Field(min_length=3, max_length=128)
    artifact_sha256: str = Field(min_length=64, max_length=64)
    signature: str = Field(min_length=1, max_length=128)

    @field_validator("key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        if not _KEY_ID_PATTERN.fullmatch(value):
            raise ValueError("invalid signature key id")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("artifact digest must be lowercase SHA-256")
        return value

    def signature_bytes(self) -> bytes:
        try:
            padding = "=" * (-len(self.signature) % 4)
            decoded = base64.b64decode(
                self.signature + padding,
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, binascii.Error) as error:
            raise PackageSignatureError("package signature encoding is invalid") from error
        if len(decoded) != 64:
            raise PackageSignatureError("package signature has an invalid length")
        return decoded

    def signed_payload(self) -> bytes:
        body = self.model_dump(mode="json", exclude={"signature"})
        canonical = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return _SIGNATURE_CONTEXT + canonical


class SignatureVerifier(Protocol):
    """Trusted asymmetric verification boundary supplied by the composition root."""

    def verify(self, *, key_id: str, payload: bytes, signature: bytes) -> None:
        """Raise ``PackageSignatureError`` unless the trusted key verifies payload."""


class Ed25519SignatureVerifier:
    """PyCA-backed Ed25519 verifier with an explicit optional dependency boundary."""

    dependency = "cryptography==50.0.0"

    def __init__(self, trusted_public_keys: Mapping[str, bytes]) -> None:
        if not trusted_public_keys:
            raise ValueError("at least one trusted package signing key is required")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError as error:
            raise MissingSignatureDependency(
                f"Ed25519 package verification requires {self.dependency}"
            ) from error

        public_keys = {}
        for key_id, raw_key in trusted_public_keys.items():
            if not _KEY_ID_PATTERN.fullmatch(key_id):
                raise ValueError("invalid trusted package signing key id")
            if not isinstance(raw_key, bytes) or len(raw_key) != 32:
                raise ValueError("Ed25519 public keys must contain exactly 32 bytes")
            public_keys[key_id] = Ed25519PublicKey.from_public_bytes(raw_key)
        self._public_keys = public_keys

    def verify(self, *, key_id: str, payload: bytes, signature: bytes) -> None:
        try:
            public_key = self._public_keys[key_id]
        except KeyError as error:
            raise PackageSignatureError("package signing key is not trusted") from error
        if len(signature) != 64:
            raise PackageSignatureError("package signature has an invalid length")
        try:
            public_key.verify(signature, payload)
        except Exception as error:
            # PyCA raises InvalidSignature. Keep the public error stable and avoid
            # exposing backend details or attacker-controlled material.
            raise PackageSignatureError("package signature verification failed") from error


@dataclass(frozen=True, slots=True)
class VerifiedPackageArtifact:
    manifest: PackageManifest
    artifact_sha256: str
    artifact_size: int
    signature_key_id: str
    files: tuple[str, ...]
    archive_bytes: bytes = field(repr=False)


class PackageArtifactVerifier:
    """Verify a detached signature, validate ZIP structure, and stage safe files."""

    def __init__(
        self,
        signature_verifier: SignatureVerifier,
        authorization: Callable[[str, PackageManifest], bool] | None = None,
    ) -> None:
        if signature_verifier is None:
            raise TypeError("a trusted package signature verifier is required")
        if authorization is not None and not callable(authorization):
            raise TypeError("package signing authorization must be callable")
        self.signature_verifier = signature_verifier
        self.authorization = authorization

    def verify(self, artifact_path: Path, signature_path: Path) -> VerifiedPackageArtifact:
        envelope = self._read_envelope(signature_path)
        archive_bytes = self._read_artifact(artifact_path)
        digest = hashlib.sha256(archive_bytes).hexdigest()
        if digest != envelope.artifact_sha256:
            raise PackageSignatureError("package artifact digest does not match its signature")
        self.signature_verifier.verify(
            key_id=envelope.key_id,
            payload=envelope.signed_payload(),
            signature=envelope.signature_bytes(),
        )

        manifest, files = self._inspect_archive(archive_bytes)
        if self.authorization is not None:
            try:
                authorized = self.authorization(envelope.key_id, manifest)
            except PackageSignatureError:
                raise
            except Exception as error:
                raise PackageSignatureError(
                    "package signing key authorization failed"
                ) from error
            if authorized is not True:
                raise PackageSignatureError(
                    "package signing key is not authorized for this package"
                )
        return VerifiedPackageArtifact(
            manifest=manifest,
            artifact_sha256=digest,
            artifact_size=len(archive_bytes),
            signature_key_id=envelope.key_id,
            files=files,
            archive_bytes=archive_bytes,
        )

    def extract(self, artifact: VerifiedPackageArtifact, destination: Path) -> None:
        destination = Path(destination)
        if destination.exists() or destination.is_symlink():
            raise PackageArtifactError("package staging destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.mkdir(mode=0o700)
        try:
            manifest, files = self._inspect_archive(artifact.archive_bytes)
            if manifest != artifact.manifest or files != artifact.files:
                raise PackageArtifactError("verified package snapshot is inconsistent")
            with zipfile.ZipFile(io.BytesIO(artifact.archive_bytes), "r") as archive:
                for entry in archive.infolist():
                    relative = _safe_archive_path(entry.filename)
                    target = destination.joinpath(*relative.parts)
                    if entry.is_dir():
                        target.mkdir(parents=True, exist_ok=True, mode=0o755)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                    with archive.open(entry, "r") as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                        output.flush()
                        os.fsync(output.fileno())
                    target.chmod(0o644)
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise

    @staticmethod
    def _read_artifact(path: Path) -> bytes:
        try:
            return _read_regular_snapshot(Path(path), maximum_bytes=MAX_ARTIFACT_BYTES)
        except _RegularSnapshotError as error:
            if error.reason == "not_regular":
                raise PackageArtifactError("package artifact must be a regular file") from None
            if error.reason == "size":
                raise PackageArtifactError(
                    "package artifact size exceeds the allowed boundary"
                ) from None
            if error.reason == "changed":
                raise PackageArtifactError("package artifact changed while it was read") from None
            raise PackageArtifactError("package artifact cannot be read") from None

    @staticmethod
    def _read_envelope(path: Path) -> SignatureEnvelope:
        try:
            content = _read_regular_snapshot(
                Path(path),
                maximum_bytes=MAX_SIGNATURE_ENVELOPE_BYTES,
            )
        except _RegularSnapshotError as error:
            if error.reason == "size":
                raise PackageSignatureError("package signature envelope is too large") from None
            if error.reason == "not_regular":
                raise PackageSignatureError("package signature envelope is missing") from None
            raise PackageSignatureError("package signature envelope is invalid") from None
        try:
            return SignatureEnvelope.model_validate_json(content)
        except (UnicodeError, ValidationError, ValueError, TypeError):
            raise PackageSignatureError("package signature envelope is invalid") from None

    @staticmethod
    def _inspect_archive(content: bytes) -> tuple[PackageManifest, tuple[str, ...]]:
        try:
            with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
                entries = archive.infolist()
                if not entries or len(entries) > MAX_ARCHIVE_ENTRIES:
                    raise PackageArtifactError("package archive entry count is invalid")
                names: set[str] = set()
                folded_names: set[str] = set()
                expanded_size = 0
                manifest_entry = None
                files: list[str] = []
                for entry in entries:
                    relative = _safe_archive_path(entry.filename)
                    normalized = relative.as_posix()
                    if normalized == INTEGRITY_MARKER_FILENAME:
                        raise PackageArtifactError(
                            "package archive uses a reserved lifecycle path"
                        )
                    folded = normalized.casefold()
                    if normalized in names or folded in folded_names:
                        raise PackageArtifactError("package archive contains duplicate paths")
                    names.add(normalized)
                    folded_names.add(folded)
                    _validate_archive_entry(entry)
                    if entry.is_dir():
                        continue
                    expanded_size += entry.file_size
                    if expanded_size > MAX_EXPANDED_BYTES:
                        raise PackageArtifactError("package archive expands beyond its limit")
                    files.append(normalized)
                    if normalized == "manifest.json":
                        manifest_entry = entry
                if manifest_entry is None:
                    raise PackageArtifactError("package archive is missing manifest.json")
                if manifest_entry.file_size > MAX_MANIFEST_BYTES:
                    raise PackageArtifactError("package manifest is too large")
                try:
                    manifest_bytes = archive.read(manifest_entry)
                    manifest = PackageManifest.model_validate_json(manifest_bytes)
                except (KeyError, UnicodeError, ValidationError, ValueError) as error:
                    raise PackageArtifactError("package manifest is invalid") from error
                if manifest.type == "theme":
                    _validate_theme_archive_files(files)
                return manifest, tuple(sorted(files))
        except PackageArtifactError:
            raise
        except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
            raise PackageArtifactError("package archive is invalid") from error


def _validate_theme_archive_files(files: list[str]) -> None:
    """Keep signed themes inside the presentation-only package boundary."""

    allowed_files = {"manifest.json", "theme.json"}
    allowed_roots = {"templates", "modules", "assets", "translations", "previews"}
    forbidden_suffixes = {".py", ".pyc", ".pyo", ".so", ".dll", ".dylib", ".sql"}
    if "theme.json" not in files:
        raise PackageArtifactError("theme package is missing theme.json")
    for value in files:
        path = PurePosixPath(value)
        if value not in allowed_files and path.parts[0] not in allowed_roots:
            raise PackageArtifactError(
                "theme package contains a non-presentation path"
            )
        if path.suffix.casefold() in forbidden_suffixes:
            raise PackageArtifactError(
                "theme package contains executable or database content"
            )


def _read_regular_snapshot(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one bounded regular-file snapshot without a path-reopen race."""

    try:
        before = path.lstat()
    except OSError:
        raise _RegularSnapshotError("unavailable") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise _RegularSnapshotError("not_regular")
    if before.st_size <= 0 or before.st_size > maximum_bytes:
        raise _RegularSnapshotError("size")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise _RegularSnapshotError("unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _RegularSnapshotError("not_regular")
        if (
            getattr(before, "st_ino", 0)
            and getattr(metadata, "st_ino", 0)
            and (
                before.st_ino != metadata.st_ino
                or before.st_dev != metadata.st_dev
            )
        ):
            raise _RegularSnapshotError("changed")
        if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
            raise _RegularSnapshotError("size")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            try:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
            except OSError:
                raise _RegularSnapshotError("unavailable") from None
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > maximum_bytes:
            raise _RegularSnapshotError("size")
        if len(content) != metadata.st_size:
            raise _RegularSnapshotError("changed")
        return content
    finally:
        os.close(descriptor)


def _safe_archive_path(value: str) -> PurePosixPath:
    if not value or len(value) > 1024 or "\\" in value or "\x00" in value:
        raise PackageArtifactError("package archive contains an unsafe path")
    path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if (
        path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or not path.parts
    ):
        raise PackageArtifactError("package archive contains an unsafe path")
    canonical_input = value[:-1] if value.endswith("/") else value
    if canonical_input != path.as_posix():
        raise PackageArtifactError("package archive contains a non-canonical path")
    for part in path.parts:
        if part in {"", ".", ".."} or len(part) > 255:
            raise PackageArtifactError("package archive contains an unsafe path")
        if (
            part.rstrip(" .") != part
            or ":" in part
            or any(ord(char) < 32 or ord(char) == 127 for char in part)
        ):
            raise PackageArtifactError("package archive contains an unsafe path")
        device_basename = part.split(".", 1)[0].rstrip(" .").casefold()
        if device_basename in _WINDOWS_RESERVED_BASENAMES:
            raise PackageArtifactError("package archive contains an unsafe path")
    return path


def _validate_archive_entry(entry: zipfile.ZipInfo) -> None:
    if entry.flag_bits & 0x1:
        raise PackageArtifactError("encrypted package archive entries are forbidden")
    if entry.compress_type not in _ALLOWED_COMPRESSION:
        raise PackageArtifactError("package archive compression method is forbidden")
    unix_mode = (entry.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode)
    allowed_type = stat.S_IFDIR if entry.is_dir() else stat.S_IFREG
    if file_type not in {0, allowed_type}:
        raise PackageArtifactError("package archive contains a special file")
    if entry.file_size < 0 or entry.file_size > MAX_FILE_BYTES:
        raise PackageArtifactError("package archive entry exceeds its size limit")
    if entry.file_size:
        if entry.compress_size <= 0:
            raise PackageArtifactError("package archive entry has an invalid size")
        if entry.file_size > entry.compress_size * MAX_COMPRESSION_RATIO:
            raise PackageArtifactError("package archive entry compression ratio is unsafe")
