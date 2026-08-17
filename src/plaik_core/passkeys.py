"""First admin passkey on the exact control origin.

RP ID is the current ``control_hostname``. Origin is ``https://{rp_id}``.
Enrollment requires a live pairing session and does not accept a password.
The pairing code is destroyed only after a verified credential is stored.
Generic JSON storage is unchanged. nginx never talks to this module.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .identity import SUPER_ADMIN_ROLE, IdentityStore, SessionError, SessionStore, UserRecord
from .installer import InstallState
from .pairing import (
    PAIRING_SESSION_COOKIE,
    PairingDenied,
    PairingRejected,
    PairingStore,
    PairingStoreUnavailable,
    host_from_header,
    origin_from_header,
)
from .remote_control import (
    CONTROL_SESSION_COOKIE,
    InvalidRemoteControlTransition,
    RemoteControlRecord,
    RemoteControlStatus,
    RemoteControlStore,
    WanSurface,
)
from .storage import exclusive_file_lock, read_json, write_json_atomic


PASSKEY_PATH = "/activate/passkey"
PASSKEY_OPTIONS_PATH = "/activate/passkey/options"
PASSKEY_AUTH_PATH = "/api/auth/passkey"
PASSKEY_AUTH_OPTIONS_PATH = "/api/auth/passkey/options"
CHALLENGE_TTL = timedelta(minutes=5)
MAX_PENDING_CHALLENGES = 16
RP_NAME = "PLAIK Control Center"


class PasskeyError(RuntimeError):
    """Passkey ceremony failed without disclosing storage details."""


class PasskeyDenied(PasskeyError):
    """The passkey surface is not available for this request."""


class PasskeyRejected(PasskeyError):
    """The presented passkey response or session is invalid."""


class PasskeyStoreUnavailable(PasskeyError):
    """Passkey state could not be opened without exposing storage details."""


class StoredCredential(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_id_hex: str
    public_key_hex: str
    sign_count: int = Field(ge=0)
    user_id: str


class PendingChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_hex: str
    expires_at: datetime
    purpose: Literal["register", "authenticate"]

    @field_validator("expires_at")
    @classmethod
    def _timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("pending challenge expiry must be timezone-aware")
        return value


class StoredPasskeys(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    installation_id: str
    rp_id: str
    credentials: tuple[StoredCredential, ...] = ()
    pending: tuple[PendingChallenge, ...] = ()


def utc_now() -> datetime:
    return datetime.now(UTC)


class PasskeyStore:
    """Admin-private WebAuthn credentials. One first-admin passkey per RP ID."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> StoredPasskeys | None:
        try:
            if not self.path.is_file():
                return None
            payload = read_json(self.path, None)
            if payload is None:
                raise PasskeyStoreUnavailable("passkey store is unavailable")
            if not isinstance(payload, dict):
                raise PasskeyStoreUnavailable("passkey store is unavailable")
            return StoredPasskeys.model_validate(payload)
        except (OSError, ValueError) as error:
            raise PasskeyStoreUnavailable("passkey store is unavailable") from error

    def begin_registration(
        self,
        *,
        installation_id: str,
        rp_id: str,
        user: UserRecord,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not installation_id:
            raise PasskeyDenied("passkey is unavailable")
        moment = now or utc_now()
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=RP_NAME,
            user_name=user.email,
            user_id=user.id.encode("ascii"),
            user_display_name=user.email,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                require_resident_key=True,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        with exclusive_file_lock(self.path):
            current = self.read()
            if current is not None and (
                current.installation_id != installation_id or current.rp_id != rp_id
            ):
                current = None
            record = _with_pending(
                StoredPasskeys(
                    installation_id=installation_id,
                    rp_id=rp_id,
                    credentials=() if current is None else current.credentials,
                    pending=() if current is None else current.pending,
                ),
                challenge_hex=options.challenge.hex(),
                purpose="register",
                now=moment,
            )
            self._write_unlocked(record)
        return json.loads(options_to_json(options))

    def complete_registration(
        self,
        credential: dict[str, Any],
        *,
        installation_id: str,
        rp_id: str,
        origin: str,
        user: UserRecord,
        now: datetime | None = None,
    ) -> StoredCredential:
        moment = now or utc_now()
        with exclusive_file_lock(self.path):
            current = self.read()
            existing = _matching_credential(
                current,
                installation_id=installation_id,
                rp_id=rp_id,
                user_id=user.id,
            )
            if existing is not None and current is not None:
                self._write_unlocked(
                    current.model_copy(
                        update={"pending": _prune_pending(current.pending, moment)}
                    )
                )
                return existing
            verified = None
            last_error: Exception | None = None
            for challenge in _live_challenges(
                current,
                installation_id=installation_id,
                rp_id=rp_id,
                purpose="register",
                now=moment,
            ):
                try:
                    verified = verify_registration_response(
                        credential=credential,
                        expected_challenge=challenge,
                        expected_rp_id=rp_id,
                        expected_origin=origin,
                        require_user_verification=True,
                    )
                    break
                except InvalidRegistrationResponse as error:
                    last_error = error
            if verified is None:
                raise PasskeyRejected("invalid passkey") from last_error
            stored = StoredCredential(
                credential_id_hex=verified.credential_id.hex(),
                public_key_hex=verified.credential_public_key.hex(),
                sign_count=verified.sign_count,
                user_id=user.id,
            )
            record = StoredPasskeys(
                installation_id=installation_id,
                rp_id=rp_id,
                credentials=(stored,),
                pending=_prune_pending(
                    () if current is None else current.pending,
                    moment,
                    used_challenge_hex=challenge.hex(),
                ),
            )
            self._write_unlocked(record)
            return stored

    def begin_authentication(
        self,
        *,
        installation_id: str,
        rp_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = now or utc_now()
        with exclusive_file_lock(self.path):
            current = self.read()
            if (
                current is None
                or current.installation_id != installation_id
                or current.rp_id != rp_id
                or not current.credentials
            ):
                raise PasskeyRejected("invalid passkey")
            allow = [
                PublicKeyCredentialDescriptor(id=bytes.fromhex(item.credential_id_hex))
                for item in current.credentials
            ]
            options = generate_authentication_options(
                rp_id=rp_id,
                allow_credentials=allow,
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            record = _with_pending(
                current,
                challenge_hex=options.challenge.hex(),
                purpose="authenticate",
                now=moment,
            )
            self._write_unlocked(record)
        return json.loads(options_to_json(options))

    def complete_authentication(
        self,
        credential: dict[str, Any],
        *,
        installation_id: str,
        rp_id: str,
        origin: str,
        now: datetime | None = None,
    ) -> StoredCredential:
        moment = now or utc_now()
        with exclusive_file_lock(self.path):
            current = self.read()
            if (
                current is None
                or current.installation_id != installation_id
                or current.rp_id != rp_id
            ):
                raise PasskeyRejected("invalid passkey")
            credential_id = _credential_id_hex(credential)
            stored = next(
                (
                    item
                    for item in current.credentials
                    if item.credential_id_hex == credential_id
                ),
                None,
            )
            if stored is None:
                raise PasskeyRejected("invalid passkey")
            verified = None
            last_error: Exception | None = None
            used_hex: str | None = None
            for challenge in _live_challenges(
                current,
                installation_id=installation_id,
                rp_id=rp_id,
                purpose="authenticate",
                now=moment,
            ):
                try:
                    verified = verify_authentication_response(
                        credential=credential,
                        expected_challenge=challenge,
                        expected_rp_id=rp_id,
                        expected_origin=origin,
                        credential_public_key=bytes.fromhex(stored.public_key_hex),
                        credential_current_sign_count=stored.sign_count,
                        require_user_verification=True,
                    )
                    used_hex = challenge.hex()
                    break
                except InvalidAuthenticationResponse as error:
                    last_error = error
            if verified is None:
                raise PasskeyRejected("invalid passkey") from last_error
            updated = stored.model_copy(update={"sign_count": verified.new_sign_count})
            credentials = tuple(
                updated if item.credential_id_hex == stored.credential_id_hex else item
                for item in current.credentials
            )
            record = current.model_copy(
                update={
                    "credentials": credentials,
                    "pending": _prune_pending(
                        current.pending, moment, used_challenge_hex=used_hex
                    ),
                }
            )
            self._write_unlocked(record)
            return updated

    def _write_unlocked(self, record: StoredPasskeys) -> None:
        write_json_atomic(self.path, record.model_dump(mode="json"))


def _prune_pending(
    pending: tuple[PendingChallenge, ...],
    now: datetime,
    *,
    used_challenge_hex: str | None = None,
) -> tuple[PendingChallenge, ...]:
    live = []
    for item in pending:
        if now >= item.expires_at:
            continue
        if used_challenge_hex is not None and item.challenge_hex == used_challenge_hex:
            continue
        live.append(item)
    return tuple(live)


def _with_pending(
    record: StoredPasskeys,
    *,
    challenge_hex: str,
    purpose: Literal["register", "authenticate"],
    now: datetime,
) -> StoredPasskeys:
    live = _prune_pending(record.pending, now)
    if len(live) >= MAX_PENDING_CHALLENGES:
        raise PasskeyRejected("invalid passkey")
    return record.model_copy(
        update={
            "pending": live
            + (
                PendingChallenge(
                    challenge_hex=challenge_hex,
                    expires_at=now + CHALLENGE_TTL,
                    purpose=purpose,
                ),
            )
        }
    )


def _live_challenges(
    record: StoredPasskeys | None,
    *,
    installation_id: str,
    rp_id: str,
    purpose: str,
    now: datetime,
) -> tuple[bytes, ...]:
    if (
        record is None
        or record.installation_id != installation_id
        or record.rp_id != rp_id
    ):
        raise PasskeyRejected("invalid passkey")
    challenges = tuple(
        bytes.fromhex(item.challenge_hex)
        for item in record.pending
        if item.purpose == purpose and now < item.expires_at
    )
    if not challenges:
        raise PasskeyRejected("invalid passkey")
    return challenges


def _matching_credential(
    record: StoredPasskeys | None,
    *,
    installation_id: str,
    rp_id: str,
    user_id: str,
) -> StoredCredential | None:
    if (
        record is None
        or record.installation_id != installation_id
        or record.rp_id != rp_id
        or not record.credentials
    ):
        return None
    for item in record.credentials:
        if item.user_id == user_id:
            return item
    return None


def _credential_id_hex(credential: dict[str, Any]) -> str:
    raw = credential.get("rawId") or credential.get("id")
    if not isinstance(raw, str) or not raw:
        raise PasskeyRejected("invalid passkey")
    try:
        return base64url_to_bytes(raw).hex()
    except Exception as error:
        raise PasskeyRejected("invalid passkey") from error


def _super_admin(identity_store: IdentityStore) -> UserRecord:
    admins = [
        user
        for user in identity_store.users().values()
        if user.active and SUPER_ADMIN_ROLE in user.roles
    ]
    if not admins:
        raise PasskeyDenied("passkey is unavailable")
    return sorted(admins, key=lambda user: user.id)[0]


def _control_hostname(record: RemoteControlRecord) -> str:
    if record.intent is None or not record.intent.remote_access_requested:
        raise PasskeyDenied("passkey is unavailable")
    return record.intent.control_hostname


def mount_passkey_activate(
    application: FastAPI,
    *,
    remote_store: RemoteControlStore,
    pairing_store: PairingStore,
    passkey_store: PasskeyStore,
    identity_store: IdentityStore,
    session_store: SessionStore | None,
    installation_id_provider: Callable[[], str | None],
    install_state_provider: Callable[[], InstallState],
) -> None:
    """Expose /activate/passkey without opening Control Center APIs."""

    def _denied() -> HTTPException:
        return HTTPException(
            status_code=404,
            detail="not found",
            headers={"Cache-Control": "no-store"},
        )

    def _rejected() -> HTTPException:
        return HTTPException(
            status_code=401,
            detail="invalid passkey",
            headers={"Cache-Control": "no-store"},
        )

    def _unavailable() -> HTTPException:
        return HTTPException(
            status_code=503,
            detail="unavailable",
            headers={"Cache-Control": "no-store"},
        )

    def _require_enrollment_surface(request: Request, *, origin_required: bool) -> str:
        if install_state_provider() is not InstallState.COMPLETED:
            raise PasskeyDenied("passkey is unavailable")
        remote = remote_store.read()
        if (
            remote.status is not RemoteControlStatus.ENROLLMENT_PENDING
            or remote.wan_surface is not WanSurface.ACTIVATE_ONLY
        ):
            raise PasskeyDenied("passkey is unavailable")
        control_hostname = _control_hostname(remote)
        presented = host_from_header(request.headers.get("host"))
        if presented != control_hostname:
            raise PasskeyDenied("passkey is unavailable")
        origin_from_header(
            request.headers.get("origin"),
            control_hostname,
            required=origin_required,
        )
        return control_hostname

    def _require_pairing_session(request: Request, control_hostname: str) -> str:
        token = request.cookies.get(PAIRING_SESSION_COOKIE) or ""
        installation_id = installation_id_provider() or ""
        if not pairing_store.enrollment_session_valid(
            token,
            remote=remote_store.read(),
            installation_id=installation_id,
        ):
            raise PasskeyRejected("invalid passkey")
        return token

    @application.get(PASSKEY_PATH, response_class=HTMLResponse)
    def passkey_form(request: Request) -> HTMLResponse:
        try:
            control_hostname = _require_enrollment_surface(
                request, origin_required=False
            )
            _require_pairing_session(request, control_hostname)
        except (PasskeyDenied, PairingDenied):
            raise _denied() from None
        except PasskeyRejected:
            raise _rejected() from None
        except (PasskeyStoreUnavailable, PairingStoreUnavailable, OSError, ValueError):
            raise _unavailable() from None
        return HTMLResponse(_PASSKEY_HTML, headers=_PASSKEY_HEADERS)

    @application.post(PASSKEY_OPTIONS_PATH)
    def passkey_options(request: Request) -> JSONResponse:
        try:
            control_hostname = _require_enrollment_surface(
                request, origin_required=True
            )
            _require_pairing_session(request, control_hostname)
            user = _super_admin(identity_store)
            options = passkey_store.begin_registration(
                installation_id=installation_id_provider() or "",
                rp_id=control_hostname,
                user=user,
            )
        except (PasskeyDenied, PairingDenied):
            raise _denied() from None
        except (PasskeyRejected, PairingRejected):
            raise _rejected() from None
        except (PasskeyStoreUnavailable, PairingStoreUnavailable, OSError, ValueError):
            raise _unavailable() from None
        return JSONResponse(options, headers={"Cache-Control": "no-store"})

    @application.post(PASSKEY_PATH)
    async def passkey_register(request: Request) -> JSONResponse:
        try:
            control_hostname = _require_enrollment_surface(
                request, origin_required=True
            )
            token = _require_pairing_session(request, control_hostname)
            user = _super_admin(identity_store)
            try:
                payload = await request.json()
            except Exception:
                raise PasskeyRejected("invalid passkey") from None
            if not isinstance(payload, dict):
                raise PasskeyRejected("invalid passkey")
            origin = f"https://{control_hostname}"
            stored = passkey_store.complete_registration(
                payload,
                installation_id=installation_id_provider() or "",
                rp_id=control_hostname,
                origin=origin,
                user=user,
            )
            try:
                remote_store.record_admin_passkey_enrolled(
                    rp_id=control_hostname,
                    install_state=install_state_provider(),
                )
            except InvalidRemoteControlTransition:
                remote = remote_store.read()
                if (
                    remote.status is not RemoteControlStatus.ENABLED
                    or remote.enrolled_admin_passkey_rp_id != control_hostname
                ):
                    raise
            pairing_store.destroy_after_passkey(
                installation_id=installation_id_provider() or "",
                control_hostname=control_hostname,
                enrollment_session_token=token,
            )
            issued = (
                session_store.create(stored.user_id)
                if session_store is not None
                else None
            )
        except (PasskeyDenied, PairingDenied, InvalidRemoteControlTransition):
            raise _denied() from None
        except (PasskeyRejected, PairingRejected):
            raise _rejected() from None
        except (
            PasskeyStoreUnavailable,
            PairingStoreUnavailable,
            SessionError,
            OSError,
            ValueError,
        ):
            raise _unavailable() from None
        response = JSONResponse(
            {
                "status": "enrolled",
                "next": "control-center",
                "control_hostname": control_hostname,
            },
            headers={"Cache-Control": "no-store"},
        )
        if issued is not None:
            max_age = max(1, int((issued.expires_at - utc_now()).total_seconds()))
            response.set_cookie(
                key=CONTROL_SESSION_COOKIE,
                value=issued.value.get_secret_value(),
                max_age=max_age,
                path="/",
                secure=True,
                httponly=True,
                samesite="strict",
            )
        response.delete_cookie(
            PAIRING_SESSION_COOKIE,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return response


def mount_passkey_login(
    application: FastAPI,
    *,
    remote_store: RemoteControlStore,
    passkey_store: PasskeyStore,
    identity_store: IdentityStore,
    session_store: SessionStore,
    installation_id_provider: Callable[[], str | None],
    install_state_provider: Callable[[], InstallState],
) -> None:
    """WAN passkey assertion. Password login stays loopback-only."""

    def _denied() -> HTTPException:
        return HTTPException(
            status_code=404,
            detail="not found",
            headers={"Cache-Control": "no-store"},
        )

    def _rejected() -> HTTPException:
        return HTTPException(
            status_code=401,
            detail="invalid passkey",
            headers={"Cache-Control": "no-store"},
        )

    def _unavailable() -> HTTPException:
        return HTTPException(
            status_code=503,
            detail="unavailable",
            headers={"Cache-Control": "no-store"},
        )

    def _require_enabled_surface(request: Request) -> str:
        if install_state_provider() is not InstallState.COMPLETED:
            raise PasskeyDenied("passkey is unavailable")
        remote = remote_store.read()
        if remote.status is not RemoteControlStatus.ENABLED or not remote.enrolled_admin_passkey:
            raise PasskeyDenied("passkey is unavailable")
        control_hostname = _control_hostname(remote)
        presented = host_from_header(request.headers.get("host"))
        if presented != control_hostname:
            raise PasskeyDenied("passkey is unavailable")
        origin_from_header(
            request.headers.get("origin"),
            control_hostname,
            required=True,
        )
        return control_hostname

    @application.post(PASSKEY_AUTH_OPTIONS_PATH)
    def passkey_auth_options(request: Request) -> JSONResponse:
        try:
            control_hostname = _require_enabled_surface(request)
            options = passkey_store.begin_authentication(
                installation_id=installation_id_provider() or "",
                rp_id=control_hostname,
            )
        except (PasskeyDenied, PairingDenied):
            raise _denied() from None
        except PasskeyRejected:
            raise _rejected() from None
        except (PasskeyStoreUnavailable, OSError, ValueError):
            raise _unavailable() from None
        return JSONResponse(options, headers={"Cache-Control": "no-store"})

    @application.post(PASSKEY_AUTH_PATH)
    async def passkey_auth(request: Request) -> JSONResponse:
        try:
            control_hostname = _require_enabled_surface(request)
            try:
                payload = await request.json()
            except Exception:
                raise PasskeyRejected("invalid passkey") from None
            if not isinstance(payload, dict):
                raise PasskeyRejected("invalid passkey")
            stored = passkey_store.complete_authentication(
                payload,
                installation_id=installation_id_provider() or "",
                rp_id=control_hostname,
                origin=f"https://{control_hostname}",
            )
            user = identity_store.get_user(stored.user_id)
            if user is None or not user.active:
                raise PasskeyRejected("invalid passkey")
            issued = session_store.create(user.id)
        except (PasskeyDenied, PairingDenied):
            raise _denied() from None
        except PasskeyRejected:
            raise _rejected() from None
        except (PasskeyStoreUnavailable, SessionError, OSError, ValueError):
            raise _unavailable() from None
        response = JSONResponse(
            {"status": "authenticated", "next": "control-center"},
            headers={"Cache-Control": "no-store"},
        )
        response.set_cookie(
            key=CONTROL_SESSION_COOKIE,
            value=issued.value.get_secret_value(),
            max_age=max(1, int((issued.expires_at - utc_now()).total_seconds())),
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return response


_PASSKEY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

_PASSKEY_HTML = """<!doctype html>
<html lang="uk" data-plaik-activate><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PLAIK Passkey</title><style>
[data-plaik-activate]{color-scheme:dark;font-family:system-ui,sans-serif;background:#111318;color:#f4f6fb}
[data-plaik-activate] body{margin:0}[data-plaik-activate] main{max-width:28rem;margin:12vh auto;padding:2rem}
[data-plaik-activate] .card{background:#1a1e26;border:1px solid #303745;border-radius:1rem;padding:1.5rem}
[data-plaik-activate] button{margin-top:1rem;padding:.7rem 1rem;border:0;border-radius:.5rem;background:#e8c547;color:#111318;font-weight:600}
[data-plaik-activate] .err{color:#f3b4b4}
</style></head><body><main><section class="card">
<h1>Passkey</h1>
<p>Зареєструйте passkey на цьому control origin. Control Center відкриється після цього.</p>
<button id="enroll" type="button">Зареєструвати passkey</button>
<p id="status" class="err" hidden></p>
</section></main>
<script>
function b64urlToBuf(v){v=v.replace(/-/g,'+').replace(/_/g,'/');while(v.length%4)v+='=';const b=atob(v);const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer}
function bufToB64url(buf){const u=new Uint8Array(buf);let s='';for(const n of u)s+=String.fromCharCode(n);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}
function revive(o){if(!o||typeof o!=='object')return o;if(o.challenge)o.challenge=b64urlToBuf(o.challenge);if(o.user&&o.user.id)o.user.id=b64urlToBuf(o.user.id);if(o.excludeCredentials)o.excludeCredentials=o.excludeCredentials.map(c=>({...c,id:b64urlToBuf(c.id)}));return o}
document.getElementById('enroll').onclick=async()=>{
  const status=document.getElementById('status');
  status.hidden=true;
  try{
    const optRes=await fetch('/activate/passkey/options',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json',origin:location.origin}});
    if(!optRes.ok) throw new Error('options');
    const cred=await navigator.credentials.create({publicKey:revive(await optRes.json())});
    const body={id:cred.id,rawId:bufToB64url(cred.rawId),type:cred.type,response:{clientDataJSON:bufToB64url(cred.response.clientDataJSON),attestationObject:bufToB64url(cred.response.attestationObject)}};
    const done=await fetch('/activate/passkey',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json',origin:location.origin},body:JSON.stringify(body)});
    if(!done.ok) throw new Error('register');
    const payload=await done.json();
    status.hidden=false;status.className='';status.textContent='Passkey прийнято. Control Center: '+payload.control_hostname;
  }catch(e){status.hidden=false;status.textContent='Не вдалося зареєструвати passkey.';}
};
</script></body></html>"""
