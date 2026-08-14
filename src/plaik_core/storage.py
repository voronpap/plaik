"""Atomic JSON storage used before the database is available."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.Lock] = {}
MAX_JSON_STATE_BYTES = 64 * 1024 * 1024


def read_json(path: Path, default: Any) -> Any:
    """Read one bounded stable regular UTF-8 JSON file without following symlinks."""

    target = Path(path)
    if not hasattr(os, "O_NOFOLLOW") and target.is_symlink():
        raise OSError("JSON state path is a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except FileNotFoundError:
        return default
    except OSError:
        raise OSError("JSON state path cannot be opened safely") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("JSON state path is not a regular file")
        if metadata.st_size > MAX_JSON_STATE_BYTES:
            raise OSError("JSON state exceeds the size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_JSON_STATE_BYTES + 1)
        try:
            after = os.fstat(descriptor)
            current = os.stat(target, follow_symlinks=False)
        except OSError:
            raise OSError("JSON state changed while it was read") from None
        if (
            len(payload) > MAX_JSON_STATE_BYTES
            or len(payload) != metadata.st_size
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or after.st_mtime_ns != metadata.st_mtime_ns
            or after.st_ctime_ns != metadata.st_ctime_ns
            or not stat.S_ISREG(current.st_mode)
            or current.st_dev != after.st_dev
            or current.st_ino != after.st_ino
            or current.st_size != after.st_size
            or current.st_mtime_ns != after.st_mtime_ns
            or current.st_ctime_ns != after.st_ctime_ns
        ):
            raise OSError("JSON state changed while it was read")
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError("JSON state is invalid") from None
    finally:
        os.close(descriptor)


def write_json_atomic(path: Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}-", dir=target.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            if os.fstat(stream.fileno()).st_size > MAX_JSON_STATE_BYTES:
                raise OSError("JSON state exceeds the size limit")
            os.fsync(stream.fileno())
        expected = temporary_path.lstat()
        os.replace(temporary_path, target)
        try:
            current = os.stat(target, follow_symlinks=False)
        except OSError:
            raise OSError("JSON state changed while it was published") from None
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != expected.st_dev
            or current.st_ino != expected.st_ino
            or current.st_size != expected.st_size
            or current.st_mtime_ns != expected.st_mtime_ns
        ):
            raise OSError("JSON state changed while it was published")
        fsync_directory_best_effort(target.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def fsync_directory_best_effort(directory: Path) -> None:
    """Persist a directory entry when the host filesystem supports it.

    POSIX filesystems require syncing the containing directory after an atomic
    rename for power-loss durability. Some supported platforms reject opening
    or syncing directories, so this helper deliberately degrades to the atomic
    replace guarantee available there.
    """

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(Path(directory), flags)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            return
    finally:
        try:
            os.close(descriptor)
        except OSError:
            # Cleanup cannot replace the successfully persisted write.
            pass


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    """Serialize a file-backed read-modify-write operation.

    The process-local mutex is required because advisory file-lock semantics for
    separate descriptors in one process vary by platform.  The persistent lock
    file adds process-level exclusion.  Callers must acquire this lock before
    reading state that they intend to modify and hold it through the atomic
    replacement.
    """

    target = Path(path)
    lock_path = target.with_name(f".{target.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    thread_lock = _thread_lock_for(lock_path)
    with thread_lock:
        if not hasattr(os, "O_NOFOLLOW") and lock_path.is_symlink():
            raise OSError("lock path is a symbolic link")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        release = None
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("lock path is not a regular file")
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(descriptor, 0o600)
            else:
                try:
                    os.chmod(lock_path, 0o600)
                except OSError:
                    # Windows may not expose POSIX permission bits. The platform
                    # ACL remains authoritative there.
                    pass
            release = _lock_descriptor(descriptor)
            yield
        finally:
            try:
                if release is not None:
                    release()
            finally:
                os.close(descriptor)


def _thread_lock_for(path: Path) -> threading.Lock:
    key = os.path.normcase(str(path.resolve(strict=False)))
    with _LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.Lock())


def _lock_descriptor(descriptor: int):
    try:
        import fcntl
    except ImportError:
        import msvcrt

        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)

        def release() -> None:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)

        return release

    fcntl.flock(descriptor, fcntl.LOCK_EX)

    def release() -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)

    return release
