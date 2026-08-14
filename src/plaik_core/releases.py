"""Verified release staging, activation and rollback state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Protocol

from packaging.specifiers import SpecifierSet
from packaging.version import Version
from pydantic import BaseModel, ConfigDict, Field

from .storage import exclusive_file_lock, fsync_directory_best_effort, write_json_atomic


_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_MAX_RELEASE_BYTES = 512 * 1024 * 1024
_MAX_DESCRIPTOR_BYTES = 256 * 1024
_MAX_SIGNATURE_BYTES = 1024
_MAX_STATE_BYTES = 256 * 1024
_MAX_VERSION_CHARS = 128
_MAX_COMPATIBILITY_CHARS = 2048
_MAX_HISTORY_ENTRIES = 4096


class ReleaseError(RuntimeError):
    """A release artifact or state transition failed verification."""


class DetachedSignatureVerifier(Protocol):
    def verify(self, key_id: str, message: bytes, signature: bytes) -> None: ...


class ReleaseDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=5, max_length=_MAX_VERSION_CHARS)
    core_compatibility: str = Field(min_length=1, max_length=_MAX_COMPATIBILITY_CHARS)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_size: int = Field(gt=0, le=_MAX_RELEASE_BYTES)
    data_schema: int = Field(ge=0)
    key_id: str = Field(min_length=3, max_length=128)


class ReleaseState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = 1
    active: str | None = None
    previous: str | None = None
    history: tuple[str, ...] = Field(default=(), max_length=_MAX_HISTORY_ENTRIES)


class ReleaseManager:
    """Manage immutable verified artifacts and an atomic active marker.

    Process supervision and binary replacement remain an operations concern;
    this class owns the safe release decision and rollback compatibility gate.
    """

    def __init__(
        self,
        root: Path,
        *,
        running_core_version: str,
        verifier: DetachedSignatureVerifier,
    ) -> None:
        self.root = Path(root)
        self.running_core_version = running_core_version
        self.verifier = verifier
        self.state_path = self.root / "release-state.json"

    def stage(
        self,
        artifact: Path,
        descriptor: ReleaseDescriptor,
        signature: bytes,
    ) -> ReleaseDescriptor:
        descriptor = ReleaseDescriptor.model_validate(descriptor)
        _validate_descriptor(descriptor, self.running_core_version)
        try:
            signature_bytes = bytes(signature)
        except (TypeError, ValueError):
            raise ReleaseError("release signature size is invalid") from None
        if not signature_bytes or len(signature_bytes) > _MAX_SIGNATURE_BYTES:
            raise ReleaseError("release signature size is invalid")
        message = _descriptor_bytes(descriptor)
        if len(message) > _MAX_DESCRIPTOR_BYTES:
            raise ReleaseError("release descriptor exceeds its size limit")
        try:
            self.verifier.verify(descriptor.key_id, message, signature_bytes)
        except Exception:
            raise ReleaseError("release signature verification failed") from None
        source = Path(artifact)
        target_dir = self._release_dir(descriptor.version)
        with exclusive_file_lock(self.state_path):
            if target_dir.exists():
                if target_dir.is_symlink() or not target_dir.is_dir():
                    raise ReleaseError("staged release path is unsafe")
                existing = self._verify_staged(descriptor.version)
                if existing != descriptor:
                    raise ReleaseError("immutable staged release already differs")
                return existing
            target_dir.parent.mkdir(parents=True, exist_ok=True)
            staging = Path(
                tempfile.mkdtemp(prefix=f".{descriptor.version}-", dir=target_dir.parent)
            )
            try:
                digest, size = _copy_regular_and_hash(
                    source,
                    staging / "artifact.whl",
                    maximum_bytes=_MAX_RELEASE_BYTES,
                )
                if (
                    digest != descriptor.artifact_sha256
                    or size != descriptor.artifact_size
                ):
                    raise ReleaseError(
                        "release artifact checksum or size does not match descriptor"
                    )
                os.chmod(staging / "artifact.whl", 0o600)
                (staging / "descriptor.json").write_bytes(message + b"\n")
                os.chmod(staging / "descriptor.json", 0o600)
                (staging / "signature.bin").write_bytes(signature_bytes)
                os.chmod(staging / "signature.bin", 0o600)
                for path in staging.iterdir():
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
                os.replace(staging, target_dir)
                fsync_directory_best_effort(target_dir.parent)
            except ReleaseError:
                raise
            except Exception:
                raise ReleaseError("release staging failed") from None
            finally:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)
        return descriptor

    def activate(self, version: str) -> ReleaseState:
        version = _validate_version(version)
        with exclusive_file_lock(self.state_path):
            descriptor = self._verify_staged(version)
            state = self._read_state()
            if state.active == version:
                return state
            if state.active is not None:
                if Version(version) <= Version(state.active):
                    raise ReleaseError(
                        "activate accepts only a newer release; use explicit rollback"
                    )
                active_descriptor = self._verify_staged(state.active)
                if descriptor.data_schema < active_descriptor.data_schema:
                    raise ReleaseError("release would downgrade the active data schema")
            history = tuple(item for item in state.history if item != version) + (version,)
            if len(history) > _MAX_HISTORY_ENTRIES:
                history = history[-_MAX_HISTORY_ENTRIES:]
            updated = ReleaseState(
                active=version,
                previous=state.active,
                history=history,
            )
            write_json_atomic(self.state_path, updated.model_dump(mode="json"))
            return updated

    def rollback(self) -> ReleaseState:
        with exclusive_file_lock(self.state_path):
            state = self._read_state()
            if state.active is None or state.previous is None:
                raise ReleaseError("no previous release is available")
            active = self._verify_staged(state.active)
            previous = self._verify_staged(state.previous)
            if previous.data_schema != active.data_schema:
                raise ReleaseError(
                    "release rollback is blocked by incompatible data schema"
                )
            history = tuple(item for item in state.history if item != state.previous)
            history += (state.previous,)
            if len(history) > _MAX_HISTORY_ENTRIES:
                history = history[-_MAX_HISTORY_ENTRIES:]
            updated = ReleaseState(
                active=state.previous,
                previous=state.active,
                history=history,
            )
            write_json_atomic(self.state_path, updated.model_dump(mode="json"))
            return updated

    def state(self) -> ReleaseState:
        with exclusive_file_lock(self.state_path):
            return self._read_state()

    def _verify_staged(self, version: str) -> ReleaseDescriptor:
        descriptor = self._read_descriptor(version)
        _validate_descriptor(descriptor, self.running_core_version)
        target_dir = self._release_dir(version)
        if target_dir.is_symlink() or not target_dir.is_dir():
            raise ReleaseError("staged release directory is unsafe")
        signature_path = target_dir / "signature.bin"
        artifact_path = target_dir / "artifact.whl"
        digest, size = _sha256_regular_file(artifact_path)
        if digest != descriptor.artifact_sha256 or size != descriptor.artifact_size:
            raise ReleaseError("staged release artifact was modified")
        try:
            self.verifier.verify(
                descriptor.key_id,
                _descriptor_bytes(descriptor),
                _read_regular_bytes(
                    signature_path,
                    maximum_bytes=_MAX_SIGNATURE_BYTES,
                ),
            )
        except Exception:
            raise ReleaseError("staged release signature is invalid") from None
        return descriptor

    def _read_descriptor(self, version: str) -> ReleaseDescriptor:
        path = self._release_dir(_validate_version(version)) / "descriptor.json"
        try:
            return ReleaseDescriptor.model_validate_json(
                _read_regular_bytes(path, maximum_bytes=_MAX_DESCRIPTOR_BYTES)
            )
        except Exception:
            raise ReleaseError("staged release descriptor is missing or invalid") from None

    def _read_state(self) -> ReleaseState:
        if self.state_path.is_symlink():
            raise ReleaseError("release state path is unsafe")
        if not self.state_path.exists():
            return ReleaseState()
        try:
            state = ReleaseState.model_validate_json(
                _read_regular_bytes(
                    self.state_path,
                    maximum_bytes=_MAX_STATE_BYTES,
                )
            )
            for version in (
                state.active,
                state.previous,
                *state.history,
            ):
                if version is not None:
                    _validate_version(version)
            if state.active is None:
                if state.previous is not None or state.history:
                    raise ValueError("inactive release state contains history")
            elif not state.history or state.history[-1] != state.active:
                raise ValueError("active release is not the latest history entry")
            return state
        except ReleaseError:
            raise
        except Exception:
            raise ReleaseError("release state is invalid") from None

    def _release_dir(self, version: str) -> Path:
        return self.root / "versions" / _validate_version(version)


def _descriptor_bytes(descriptor: ReleaseDescriptor) -> bytes:
    return json.dumps(
        descriptor.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _validate_descriptor(descriptor: ReleaseDescriptor, core_version: str) -> None:
    _validate_version(descriptor.version)
    if not _KEY_ID.fullmatch(descriptor.key_id):
        raise ValueError("invalid release signing key id")
    try:
        compatible = core_version in SpecifierSet(descriptor.core_compatibility)
    except Exception:
        raise ValueError("invalid release Core compatibility range") from None
    if not compatible:
        raise ReleaseError("release is incompatible with the running Core")


def _validate_version(version: str) -> str:
    if (
        not isinstance(version, str)
        or len(version) > _MAX_VERSION_CHARS
        or not _VERSION.fullmatch(version)
    ):
        raise ValueError("invalid release version")
    return version


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReleaseError("release artifact cannot be read") from None
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        raise ReleaseError("release artifact cannot be read") from None
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ReleaseError("release artifact must be a regular file")
    return descriptor, metadata


def _require_stable_regular_read(
    path: Path,
    descriptor: int,
    initial: os.stat_result,
    *,
    error_message: str,
) -> None:
    try:
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        raise ReleaseError(error_message) from None
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        not stat.S_ISREG(current.st_mode)
        or any(getattr(after, field) != getattr(initial, field) for field in fields)
        or any(getattr(current, field) != getattr(after, field) for field in fields)
    ):
        raise ReleaseError(error_message)


def _sha256_regular_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    descriptor, metadata = _open_regular(path)
    copied = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                copied += len(chunk)
                if copied > _MAX_RELEASE_BYTES:
                    raise ReleaseError("release artifact exceeds its size limit")
        if copied != metadata.st_size:
            raise ReleaseError("release artifact changed while it was read")
        _require_stable_regular_read(
            path,
            descriptor,
            metadata,
            error_message="release artifact changed while it was read",
        )
    except ReleaseError:
        raise
    except OSError:
        raise ReleaseError("release artifact cannot be read") from None
    finally:
        os.close(descriptor)
    return digest.hexdigest(), copied


def _copy_regular_and_hash(
    source_path: Path,
    destination_path: Path,
    *,
    maximum_bytes: int,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    source_descriptor, metadata = _open_regular(source_path)
    copied = 0
    try:
        with os.fdopen(source_descriptor, "rb", closefd=False) as source:
            with destination_path.open("xb") as destination:
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > maximum_bytes:
                        raise ReleaseError("release artifact exceeds its size limit")
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
        if copied != metadata.st_size:
            raise ReleaseError("release artifact changed while it was staged")
        _require_stable_regular_read(
            source_path,
            source_descriptor,
            metadata,
            error_message="release artifact changed while it was staged",
        )
    except ReleaseError:
        raise
    except OSError:
        raise ReleaseError("release artifact cannot be staged") from None
    finally:
        os.close(source_descriptor)
    return digest.hexdigest(), copied


def _read_regular_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    descriptor, metadata = _open_regular(path)
    try:
        if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
            raise ReleaseError("release metadata size is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(maximum_bytes + 1)
        if len(content) != metadata.st_size or len(content) > maximum_bytes:
            raise ReleaseError("release metadata changed while it was read")
        _require_stable_regular_read(
            path,
            descriptor,
            metadata,
            error_message="release metadata changed while it was read",
        )
        return content
    finally:
        os.close(descriptor)
