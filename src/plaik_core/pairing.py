"""One-time Remote Control pairing for ENROLLMENT_PENDING /activate.

This module issues and consumes the WAN bootstrap credential. It does not
register WebAuthn credentials, open Control Center, or change
``RemoteControlStatus``. Successful pairing stays ENROLLMENT_PENDING and only
creates a short-lived enrollment session for a later passkey PR.

The pairing code is hashed at rest with scrypt. The plaintext is returned once
from ``issue()`` and is never written to disk. After a successful consume the
code verifier is destroyed. The enrollment session token is stored only as
SHA-256.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .installer import InstallState
from .remote_control import (
    RemoteControlRecord,
    RemoteControlStatus,
    RemoteControlStore,
    validate_dns_hostname,
)
from .storage import exclusive_file_lock, read_json, write_json_atomic


PAIRING_TTL = timedelta(minutes=10)
ENROLLMENT_SESSION_TTL = timedelta(minutes=15)
IN_FLIGHT_LEASE = timedelta(seconds=30)
MAX_FAILED_ATTEMPTS = 8
PAIRING_CODE_LENGTH = 8
PAIRING_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
PAIRING_SESSION_COOKIE = "__Host-plaik_pairing_session"
ACTIVATE_PATH = "/activate"

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_CODE_GROUP = 4
_NON_CODE = re.compile(r"[^0-9A-Z]")


class PairingError(RuntimeError):
    """Pairing credential contract failed without opening Control Center."""


class PairingDenied(PairingError):
    """The /activate surface is not available for this request."""


class PairingRejected(PairingError):
    """The presented pairing code or enrollment session is invalid."""


class PairingIssueUnavailable(PairingError):
    """A pairing code cannot be issued in the current observed state."""


class IssuedPairing(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    activate_url: str
    control_hostname: str
    expires_at: datetime


class ConsumedPairing(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enrollment_session_token: str
    enrollment_expires_at: datetime
    control_hostname: str


class StoredPairing(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    installation_id: str
    control_hostname: str
    code_salt_hex: str | None = None
    code_hash_hex: str | None = None
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    failed_attempts: int = Field(default=0, ge=0)
    in_flight: int = Field(default=0, ge=0)
    in_flight_until: datetime | None = None
    locked: bool = False
    enrollment_session_hash_hex: str | None = None
    enrollment_expires_at: datetime | None = None

    @field_validator("control_hostname")
    @classmethod
    def validate_control_hostname(cls, value: str) -> str:
        return validate_dns_hostname(value, label="control_hostname")


def utc_now() -> datetime:
    return datetime.now(UTC)


def activate_url(control_hostname: str) -> str:
    host = validate_dns_hostname(control_hostname, label="control_hostname")
    return f"https://{host}{ACTIVATE_PATH}"


def format_pairing_code(raw: str) -> str:
    normalized = normalize_pairing_code(raw)
    return f"{normalized[:_CODE_GROUP]}-{normalized[_CODE_GROUP:]}"


def normalize_pairing_code(value: str) -> str:
    compact = _NON_CODE.sub("", value.strip().upper())
    if len(compact) != PAIRING_CODE_LENGTH or any(
        character not in PAIRING_ALPHABET for character in compact
    ):
        raise PairingRejected("invalid pairing")
    return compact


def generate_pairing_code() -> str:
    raw = "".join(secrets.choice(PAIRING_ALPHABET) for _ in range(PAIRING_CODE_LENGTH))
    return format_pairing_code(raw)


def host_from_header(value: str | None) -> str:
    if value is None:
        raise PairingDenied("activate is unavailable")
    candidate = value.strip().casefold()
    if (
        not candidate
        or "/" in candidate
        or "@" in candidate
        or " " in candidate
        or candidate.startswith("[")
        or candidate.endswith(".")
    ):
        raise PairingDenied("activate is unavailable")
    host, separator, port = candidate.partition(":")
    if separator and port != "443":
        raise PairingDenied("activate is unavailable")
    try:
        canonical = validate_dns_hostname(host, label="host")
    except ValueError:
        raise PairingDenied("activate is unavailable") from None
    if canonical != host:
        raise PairingDenied("activate is unavailable")
    return canonical


def origin_from_header(
    value: str | None,
    control_hostname: str,
    *,
    required: bool,
) -> None:
    if value is None or value == "":
        if required:
            raise PairingDenied("activate is unavailable")
        return
    expected = f"https://{control_hostname}"
    if value != expected and value.casefold() != expected:
        raise PairingDenied("activate is unavailable")


def _require_completed(install_state: InstallState) -> None:
    if install_state is not InstallState.COMPLETED:
        raise PairingDenied("activate is unavailable")


def _enrollment_control_hostname(
    record: RemoteControlRecord,
    *,
    unavailable: type[PairingError],
) -> str:
    if (
        record.status is not RemoteControlStatus.ENROLLMENT_PENDING
        or record.intent is None
        or not record.intent.remote_access_requested
    ):
        raise unavailable("activate is unavailable")
    return record.intent.control_hostname


def _scrypt(password: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password,
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )


def _code_password(installation_id: str, control_hostname: str, code: str) -> bytes:
    return f"{installation_id}\0{control_hostname}\0{code}".encode("utf-8")


def _hash_session(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _replace_pairing(record: StoredPairing, **updates: object) -> StoredPairing:
    payload = record.model_dump()
    payload.update(updates)
    return StoredPairing.model_validate(payload)


def _chmod_private(path: Path) -> None:
    if path.is_file():
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _effective_in_flight(record: StoredPairing, now: datetime) -> int:
    if record.in_flight <= 0:
        return 0
    if record.in_flight_until is None or now >= record.in_flight_until:
        return 0
    return record.in_flight


def _live_code_verifier(
    record: StoredPairing | None,
    *,
    installation_id: str,
    control_hostname: str,
    now: datetime,
) -> bool:
    return (
        record is not None
        and record.installation_id == installation_id
        and record.control_hostname == control_hostname
        and record.consumed_at is None
        and not record.locked
        and now < record.expires_at
        and record.code_salt_hex is not None
        and record.code_hash_hex is not None
    )


def _same_live_code_verifier(
    record: StoredPairing | None,
    *,
    salt_hex: str,
    hash_hex: str,
    installation_id: str,
    control_hostname: str,
    now: datetime,
) -> bool:
    return _live_code_verifier(
        record,
        installation_id=installation_id,
        control_hostname=control_hostname,
        now=now,
    ) and record is not None and record.code_salt_hex == salt_hex and record.code_hash_hex == hash_hex


class PairingStore:
    """Atomic hashed pairing credential. Never writes installer or nginx state."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> StoredPairing | None:
        if not self.path.is_file():
            return None
        payload = read_json(self.path, None)
        if not payload:
            return None
        return StoredPairing.model_validate(payload)

    def issue(
        self,
        *,
        remote: RemoteControlRecord,
        installation_id: str,
        install_state: InstallState,
        now: datetime | None = None,
    ) -> IssuedPairing:
        if install_state is not InstallState.COMPLETED:
            raise PairingIssueUnavailable(
                "pairing can be issued only after installation is COMPLETED"
            )
        try:
            control_hostname = _enrollment_control_hostname(
                remote,
                unavailable=PairingIssueUnavailable,
            )
        except PairingIssueUnavailable:
            raise PairingIssueUnavailable(
                "pairing can be issued only while remote control is ENROLLMENT_PENDING"
            ) from None
        if not installation_id:
            raise PairingIssueUnavailable("installation identity is unavailable")
        issued_at = now or utc_now()
        code = generate_pairing_code()
        normalized = normalize_pairing_code(code)
        salt = secrets.token_bytes(16)
        digest = _scrypt(
            _code_password(installation_id, control_hostname, normalized),
            salt,
        )
        record = StoredPairing(
            installation_id=installation_id,
            control_hostname=control_hostname,
            code_salt_hex=salt.hex(),
            code_hash_hex=digest.hex(),
            issued_at=issued_at,
            expires_at=issued_at + PAIRING_TTL,
        )
        with exclusive_file_lock(self.path):
            self._write_unlocked(record)
        return IssuedPairing(
            code=code,
            activate_url=activate_url(control_hostname),
            control_hostname=control_hostname,
            expires_at=record.expires_at,
        )

    def consume(
        self,
        code: str,
        *,
        remote_store: RemoteControlStore,
        installation_id: str,
        install_state: InstallState,
        host: str,
        origin: str | None = None,
        now: datetime | None = None,
    ) -> ConsumedPairing:
        _require_completed(install_state)
        presented_host = host_from_header(host)
        moment = now or utc_now()
        with exclusive_file_lock(self.path):
            remote = remote_store.read()
            control_hostname = _enrollment_control_hostname(
                remote,
                unavailable=PairingDenied,
            )
            if presented_host != control_hostname:
                raise PairingDenied("activate is unavailable")
            origin_from_header(origin, control_hostname, required=True)
            if not installation_id:
                raise PairingRejected("invalid pairing")
            record = self.read()
            if record is not None and _effective_in_flight(record, moment) == 0 and record.in_flight:
                record = _replace_pairing(record, in_flight=0, in_flight_until=None)
                self._write_unlocked(record)
            if not _live_code_verifier(
                record,
                installation_id=installation_id,
                control_hostname=control_hostname,
                now=moment,
            ):
                raise PairingRejected("invalid pairing")
            assert record is not None
            if record.failed_attempts + _effective_in_flight(record, moment) >= MAX_FAILED_ATTEMPTS:
                raise PairingRejected("invalid pairing")
            salt_hex = record.code_salt_hex
            hash_hex = record.code_hash_hex
            assert salt_hex is not None and hash_hex is not None
            self._write_unlocked(
                _replace_pairing(
                    record,
                    in_flight=record.in_flight + 1,
                    in_flight_until=moment + IN_FLIGHT_LEASE,
                )
            )
        settled = False
        try:
            try:
                normalized = normalize_pairing_code(code)
            except PairingRejected:
                self._fail_if_same_verifier(
                    salt_hex=salt_hex,
                    hash_hex=hash_hex,
                    installation_id=installation_id,
                    control_hostname=control_hostname,
                    now=moment,
                )
                settled = True
                raise
            digest = _scrypt(
                _code_password(installation_id, control_hostname, normalized),
                bytes.fromhex(salt_hex),
            )
            commit_now = now if now is not None else utc_now()
            with exclusive_file_lock(self.path):
                current = self.read()
                try:
                    commit_control = _enrollment_control_hostname(
                        remote_store.read(),
                        unavailable=PairingDenied,
                    )
                    if presented_host != commit_control:
                        raise PairingDenied("activate is unavailable")
                except PairingDenied:
                    self._release_inflight_unlocked(
                        current,
                        salt_hex=salt_hex,
                        hash_hex=hash_hex,
                    )
                    raise
                if not _same_live_code_verifier(
                    current,
                    salt_hex=salt_hex,
                    hash_hex=hash_hex,
                    installation_id=installation_id,
                    control_hostname=commit_control,
                    now=commit_now,
                ):
                    self._release_inflight_unlocked(
                        current,
                        salt_hex=salt_hex,
                        hash_hex=hash_hex,
                    )
                    raise PairingRejected("invalid pairing")
                if not hmac.compare_digest(digest.hex(), hash_hex):
                    self._register_failure_unlocked(current)
                    raise PairingRejected("invalid pairing")
                session_token = secrets.token_urlsafe(32)
                consumed = StoredPairing(
                    installation_id=current.installation_id,
                    control_hostname=current.control_hostname,
                    issued_at=current.issued_at,
                    expires_at=current.expires_at,
                    consumed_at=commit_now,
                    failed_attempts=current.failed_attempts,
                    locked=False,
                    enrollment_session_hash_hex=_hash_session(session_token),
                    enrollment_expires_at=commit_now + ENROLLMENT_SESSION_TTL,
                )
                self._write_unlocked(consumed)
                settled = True
                return ConsumedPairing(
                    enrollment_session_token=session_token,
                    enrollment_expires_at=consumed.enrollment_expires_at,
                    control_hostname=commit_control,
                )
        except (PairingDenied, PairingRejected):
            settled = True
            raise
        finally:
            if not settled:
                with exclusive_file_lock(self.path):
                    self._release_inflight_unlocked(
                        self.read(),
                        salt_hex=salt_hex,
                        hash_hex=hash_hex,
                    )

    def enrollment_session_valid(
        self,
        token: str,
        *,
        remote: RemoteControlRecord,
        installation_id: str,
        now: datetime | None = None,
    ) -> bool:
        if (
            remote.status is not RemoteControlStatus.ENROLLMENT_PENDING
            or remote.intent is None
            or not token
        ):
            return False
        record = self.read()
        moment = now or utc_now()
        if (
            record is None
            or record.consumed_at is None
            or record.enrollment_session_hash_hex is None
            or record.enrollment_expires_at is None
            or record.installation_id != installation_id
            or record.control_hostname != remote.intent.control_hostname
            or moment >= record.enrollment_expires_at
        ):
            return False
        return hmac.compare_digest(
            _hash_session(token),
            record.enrollment_session_hash_hex,
        )

    def destroy_after_passkey(
        self,
        *,
        installation_id: str,
        control_hostname: str,
        enrollment_session_token: str,
    ) -> None:
        token_hash = _hash_session(enrollment_session_token)
        with exclusive_file_lock(self.path):
            record = self.read()
            if record is None or record.enrollment_session_hash_hex is None:
                return
            if (
                record.installation_id != installation_id
                or record.control_hostname != control_hostname
                or not hmac.compare_digest(
                    record.enrollment_session_hash_hex,
                    token_hash,
                )
            ):
                return
            if self.path.is_file():
                self.path.unlink()

    def _fail_if_same_verifier(
        self,
        *,
        salt_hex: str,
        hash_hex: str,
        installation_id: str,
        control_hostname: str,
        now: datetime,
    ) -> None:
        with exclusive_file_lock(self.path):
            current = self.read()
            if _same_live_code_verifier(
                current,
                salt_hex=salt_hex,
                hash_hex=hash_hex,
                installation_id=installation_id,
                control_hostname=control_hostname,
                now=now,
            ):
                self._register_failure_unlocked(current)
            else:
                self._release_inflight_unlocked(
                    current,
                    salt_hex=salt_hex,
                    hash_hex=hash_hex,
                )

    def _release_inflight_unlocked(
        self,
        record: StoredPairing | None,
        *,
        salt_hex: str,
        hash_hex: str,
    ) -> None:
        if (
            record is None
            or record.code_salt_hex != salt_hex
            or record.code_hash_hex != hash_hex
            or record.in_flight <= 0
        ):
            return
        next_in_flight = record.in_flight - 1
        self._write_unlocked(
            _replace_pairing(
                record,
                in_flight=next_in_flight,
                in_flight_until=None if next_in_flight <= 0 else record.in_flight_until,
            )
        )

    def _register_failure_unlocked(self, record: StoredPairing) -> None:
        attempts = record.failed_attempts + 1
        locked = attempts >= MAX_FAILED_ATTEMPTS
        next_in_flight = 0 if locked else max(0, record.in_flight - 1)
        updated = _replace_pairing(
            record,
            code_salt_hex=None if locked else record.code_salt_hex,
            code_hash_hex=None if locked else record.code_hash_hex,
            failed_attempts=attempts,
            in_flight=next_in_flight,
            in_flight_until=None if next_in_flight <= 0 else record.in_flight_until,
            locked=locked,
        )
        self._write_unlocked(updated)

    def _write_unlocked(self, record: StoredPairing) -> None:
        write_json_atomic(self.path, record.model_dump(mode="json"))
        _chmod_private(self.path)


def mount_pairing_activate(
    application: FastAPI,
    *,
    remote_store: RemoteControlStore,
    pairing_store: PairingStore,
    installation_id_provider: Callable[[], str | None],
    install_state_provider: Callable[[], InstallState],
) -> None:
    """Expose GET/POST /activate without mounting Control Center APIs."""

    def _denied() -> HTTPException:
        return HTTPException(
            status_code=404,
            detail="not found",
            headers={"Cache-Control": "no-store"},
        )

    def _rejected() -> HTTPException:
        return HTTPException(
            status_code=401,
            detail="invalid pairing",
            headers={"Cache-Control": "no-store"},
        )

    def _surface() -> str:
        _require_completed(install_state_provider())
        remote = remote_store.read()
        return _enrollment_control_hostname(remote, unavailable=PairingDenied)

    @application.get(ACTIVATE_PATH, response_class=HTMLResponse)
    def activate_form(request: Request) -> HTMLResponse:
        try:
            control_hostname = _surface()
            presented = host_from_header(request.headers.get("host"))
            if presented != control_hostname:
                raise PairingDenied("activate is unavailable")
            origin_from_header(
                request.headers.get("origin"),
                control_hostname,
                required=False,
            )
        except PairingDenied:
            raise _denied() from None
        return HTMLResponse(_ACTIVATE_HTML, headers=_ACTIVATE_HEADERS)

    @application.post(ACTIVATE_PATH)
    async def activate_submit(request: Request) -> Response:
        try:
            control_hostname = _surface()
            presented = host_from_header(request.headers.get("host"))
            if presented != control_hostname:
                raise PairingDenied("activate is unavailable")
            origin_from_header(
                request.headers.get("origin"),
                control_hostname,
                required=True,
            )
            code = await _read_code(request)
            consumed = pairing_store.consume(
                code,
                remote_store=remote_store,
                installation_id=installation_id_provider() or "",
                install_state=install_state_provider(),
                host=request.headers.get("host") or "",
                origin=request.headers.get("origin"),
            )
        except PairingDenied:
            raise _denied() from None
        except PairingRejected:
            raise _rejected() from None
        wants_json = _wants_json(request)
        if wants_json:
            response: Response = JSONResponse(
                {
                    "status": "paired",
                    "next": "passkey",
                    "control_hostname": consumed.control_hostname,
                },
                headers={"Cache-Control": "no-store"},
            )
        else:
            response = HTMLResponse(_PAIRED_HTML, headers=_ACTIVATE_HEADERS)
        response.set_cookie(
            key=PAIRING_SESSION_COOKIE,
            value=consumed.enrollment_session_token,
            max_age=int(ENROLLMENT_SESSION_TTL.total_seconds()),
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return response


async def _read_code(request: Request) -> str:
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        try:
            payload = await request.json()
        except Exception:
            raise PairingRejected("invalid pairing") from None
        if not isinstance(payload, dict):
            raise PairingRejected("invalid pairing")
        code = payload.get("code")
        if not isinstance(code, str):
            raise PairingRejected("invalid pairing")
        return code
    form = await request.form()
    code = form.get("code")
    if not isinstance(code, str):
        raise PairingRejected("invalid pairing")
    return code


def _wants_json(request: Request) -> bool:
    content_type = request.headers.get("content-type", "")
    accept = request.headers.get("accept", "")
    return content_type.startswith("application/json") or "application/json" in accept


_ACTIVATE_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

_ACTIVATE_HTML = """<!doctype html>
<html lang="uk" data-plaik-activate><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PLAIK Activate</title><style>
[data-plaik-activate]{color-scheme:dark;font-family:system-ui,sans-serif;background:#111318;color:#f4f6fb}
[data-plaik-activate] body{margin:0}[data-plaik-activate] main{max-width:28rem;margin:12vh auto;padding:2rem}
[data-plaik-activate] .card{background:#1a1e26;border:1px solid #303745;border-radius:1rem;padding:1.5rem}
[data-plaik-activate] label{display:block;margin:0 0 .5rem;font-size:.9rem}
[data-plaik-activate] input{width:100%;box-sizing:border-box;padding:.7rem .8rem;border-radius:.5rem;border:1px solid #303745;background:#111318;color:#f4f6fb}
[data-plaik-activate] button{margin-top:1rem;padding:.7rem 1rem;border:0;border-radius:.5rem;background:#e8c547;color:#111318;font-weight:600}
</style></head><body><main><section class="card">
<h1>Активація</h1>
<p>Введіть одноразовий код pairing. Control Center тут недоступний.</p>
<form method="post" action="/activate" autocomplete="off">
<label for="code">Код</label>
<input id="code" name="code" inputmode="text" autocapitalize="characters" spellcheck="false" required>
<button type="submit">Продовжити</button>
</form>
</section></main></body></html>"""

_PAIRED_HTML = """<!doctype html>
<html lang="uk" data-plaik-activate><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PLAIK Activate</title><style>
[data-plaik-activate]{color-scheme:dark;font-family:system-ui,sans-serif;background:#111318;color:#f4f6fb}
[data-plaik-activate] body{margin:0}[data-plaik-activate] main{max-width:28rem;margin:12vh auto;padding:2rem}
[data-plaik-activate] .card{background:#1a1e26;border:1px solid #303745;border-radius:1rem;padding:1.5rem}
</style></head><body><main><section class="card">
<h1>Код прийнято</h1>
<p>Далі потрібен passkey на цьому control origin. Control Center ще закритий.</p>
</section></main></body></html>"""
