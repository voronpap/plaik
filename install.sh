#!/bin/sh
set -eu

PLAIK_RUNTIME_DIR="${PLAIK_RUNTIME_DIR:-/opt/plaik}"
PLAIK_DATA_DIR="${PLAIK_DATA_DIR:-/var/lib/plaik}"
PLAIK_CONFIG_DIR="${PLAIK_CONFIG_DIR:-/etc/plaik}"
PLAIK_LOG_DIR="${PLAIK_LOG_DIR:-/var/log/plaik}"
PLAIK_INSTALLER_USER="${PLAIK_INSTALLER_USER:-plaik-installer}"
PLAIK_ADMIN_USER="${PLAIK_ADMIN_USER:-plaik-admin}"
PLAIK_PUBLIC_USER="${PLAIK_PUBLIC_USER:-plaik-public}"
PLAIK_UV_VERSION="${PLAIK_UV_VERSION:-0.12.3}"
PLAIK_RELEASE_REPOSITORY="${PLAIK_RELEASE_REPOSITORY:-voronpap/plaik}"
PLAIK_RELEASE_TAG="${PLAIK_RELEASE_TAG:-}"
PLAIK_WHEEL_FILE="${PLAIK_WHEEL_FILE:-}"
PLAIK_WHEEL_SHA256="${PLAIK_WHEEL_SHA256:-}"
PLAIK_SDK_WHEEL_FILE="${PLAIK_SDK_WHEEL_FILE:-}"
PLAIK_SDK_WHEEL_SHA256="${PLAIK_SDK_WHEEL_SHA256:-}"
PLAIK_MAX_WHEEL_BYTES="${PLAIK_MAX_WHEEL_BYTES:-83886080}"
PLAIK_MAX_CHECKSUM_BYTES="${PLAIK_MAX_CHECKSUM_BYTES:-8192}"
PLAIK_MAX_UV_BYTES="${PLAIK_MAX_UV_BYTES:-41943040}"
FORCE=0

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh [--force] [--wheel /path/to/plaik.whl --sdk-wheel /path/to/plaik_sdk.whl]

System bootstrap only. It installs the PLAIK runtime and systemd services.
Stage 2 uses the local web installer at http://127.0.0.1:8765/
The installer binds loopback only. Remote access is an SSH tunnel from
your local computer, not a LAN or public listener.

CLI remains available as headless fallback:

    sudo plaik setup

Environment overrides:
  PLAIK_RELEASE_TAG       release tag to install instead of latest
  PLAIK_WHEEL_FILE        local runtime wheel for development/testing
  PLAIK_WHEEL_SHA256      expected SHA-256 for the local runtime wheel
  PLAIK_SDK_WHEEL_FILE    local SDK wheel for development/testing
  PLAIK_SDK_WHEEL_SHA256  expected SHA-256 for the local SDK wheel
  PLAIK_UV_VERSION        pinned uv bootstrap version
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --force)
            FORCE=1
            shift
            ;;
        --wheel)
            [ "$#" -ge 2 ] || { echo "install.sh: --wheel requires a path" >&2; exit 2; }
            PLAIK_WHEEL_FILE=$2
            shift 2
            ;;
        --sdk-wheel)
            [ "$#" -ge 2 ] || { echo "install.sh: --sdk-wheel requires a path" >&2; exit 2; }
            PLAIK_SDK_WHEEL_FILE=$2
            shift 2
            ;;
        --validate-paths)
            PLAIK_INSTALL_ACTION=validate-paths
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "install.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

is_plaik_prefix() {
    case "$1" in
        /opt/plaik|/opt/plaik/*|/var/lib/plaik|/var/lib/plaik/*|/etc/plaik|/etc/plaik/*|/var/log/plaik|/var/log/plaik/*)
            return 0
            ;;
    esac
    return 1
}

is_forbidden_path() {
    if is_plaik_prefix "$1"; then
        return 1
    fi
    return 0
}

paths_overlap() {
    left=$1
    right=$2
    case "$left" in
        "$right"|"$right"/*) return 0 ;;
    esac
    case "$right" in
        "$left"|"$left"/*) return 0 ;;
    esac
    return 1
}

reject_foreign_existing_path() {
    path=$1
    label=$2
    if [ ! -e "$path" ]; then
        return 0
    fi
    if [ -L "$path" ]; then
        echo "install.sh: refusing symlink $label: $path" >&2
        exit 1
    fi
    owner=$(stat -c %u "$path" 2>/dev/null || true)
    case "$owner" in
        ''|*[!0-9]*)
            echo "install.sh: cannot inspect $label owner: $path" >&2
            exit 1
            ;;
    esac
    if [ "$owner" -ne 0 ]; then
        echo "install.sh: refusing foreign-owned $label: $path" >&2
        exit 1
    fi
}

reject_symlink_components() {
    path=$1
    prefix=""
    old_ifs=$IFS
    IFS=/
    # shellcheck disable=SC2086
    set -- $path
    IFS=$old_ifs
    for part in "$@"; do
        [ -n "$part" ] || continue
        prefix="$prefix/$part"
        if [ -L "$prefix" ]; then
            echo "install.sh: refusing symlink path component: $prefix" >&2
            exit 1
        fi
    done
}

canonicalize_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *)
            echo "install.sh: $label must be an absolute path" >&2
            exit 1
            ;;
    esac
    case "$path" in
        *..*)
            echo "install.sh: $label must not contain .." >&2
            exit 1
            ;;
    esac
    reject_symlink_components "$path"
    if command -v realpath >/dev/null 2>&1; then
        path=$(realpath -m "$path")
    fi
    if is_forbidden_path "$path"; then
        echo "install.sh: refusing dangerous $label: $path" >&2
        exit 1
    fi
    reject_foreign_existing_path "$path" "$label"
    printf '%s\n' "$path"
}

validate_configured_paths() {
    PLAIK_RUNTIME_DIR=$(canonicalize_path "$PLAIK_RUNTIME_DIR" "PLAIK_RUNTIME_DIR")
    PLAIK_DATA_DIR=$(canonicalize_path "$PLAIK_DATA_DIR" "PLAIK_DATA_DIR")
    PLAIK_CONFIG_DIR=$(canonicalize_path "$PLAIK_CONFIG_DIR" "PLAIK_CONFIG_DIR")
    PLAIK_LOG_DIR=$(canonicalize_path "$PLAIK_LOG_DIR" "PLAIK_LOG_DIR")
    if [ "$PLAIK_RUNTIME_DIR" = "$PLAIK_DATA_DIR" ] \
        || [ "$PLAIK_RUNTIME_DIR" = "$PLAIK_CONFIG_DIR" ] \
        || [ "$PLAIK_RUNTIME_DIR" = "$PLAIK_LOG_DIR" ] \
        || [ "$PLAIK_DATA_DIR" = "$PLAIK_CONFIG_DIR" ] \
        || [ "$PLAIK_DATA_DIR" = "$PLAIK_LOG_DIR" ] \
        || [ "$PLAIK_CONFIG_DIR" = "$PLAIK_LOG_DIR" ] \
        || paths_overlap "$PLAIK_RUNTIME_DIR" "$PLAIK_DATA_DIR" \
        || paths_overlap "$PLAIK_RUNTIME_DIR" "$PLAIK_CONFIG_DIR" \
        || paths_overlap "$PLAIK_RUNTIME_DIR" "$PLAIK_LOG_DIR" \
        || paths_overlap "$PLAIK_DATA_DIR" "$PLAIK_CONFIG_DIR" \
        || paths_overlap "$PLAIK_DATA_DIR" "$PLAIK_LOG_DIR" \
        || paths_overlap "$PLAIK_CONFIG_DIR" "$PLAIK_LOG_DIR"; then
        echo "install.sh: runtime, data, config and log paths must be distinct" >&2
        exit 1
    fi
}

atomic_switch_release() {
    new_release=$1
    current_link=$2
    [ -d "$new_release" ] || { echo "install.sh: new release is missing" >&2; exit 1; }
    [ -x "$new_release/venv/bin/plaik" ] || { echo "install.sh: new release is not executable" >&2; exit 1; }
    tmp_link="${current_link}.new"
    ln -sfn "$new_release" "$tmp_link"
    mv -Tf "$tmp_link" "$current_link"
}

commit_staged_release() {
    new_release=$1
    ready_release=$2
    [ -d "$new_release" ] || { echo "install.sh: staged release is missing" >&2; exit 1; }
    [ ! -e "$ready_release" ] || { echo "install.sh: ready release already exists" >&2; exit 1; }
    mv "$new_release" "$ready_release"
    if [ -d "$ready_release/venv/bin" ]; then
        find "$ready_release/venv/bin" -type f | while IFS= read -r file; do
            if grep -Fq "$new_release" "$file" 2>/dev/null; then
                sed -i "s|$new_release|$ready_release|g" "$file"
            fi
        done
    fi
    if [ -f "$ready_release/venv/pyvenv.cfg" ] && grep -Fq "$new_release" "$ready_release/venv/pyvenv.cfg" 2>/dev/null; then
        sed -i "s|$new_release|$ready_release|g" "$ready_release/venv/pyvenv.cfg"
    fi
}

install_plaik_command() {
    command_path="${PLAIK_COMMAND_PATH:-/usr/local/bin/plaik}"
    mkdir -p "$(dirname "$command_path")"
    ln -sfn "$CURRENT_LINK/venv/bin/plaik" "$command_path"
}

service_main_pid() {
    systemctl show -p MainPID --value "$1" 2>/dev/null || printf '%s\n' "0"
}

service_runs_from_release() {
    unit=$1
    release=$2
    pid=$(service_main_pid "$unit")
    case "$pid" in
        ''|0|1|*[!0-9]*) return 1 ;;
    esac
    cmdline_file="${PLAIK_PROC_DIR:-/proc}/$pid/cmdline"
    [ -r "$cmdline_file" ] || return 1
    cmdline=$(tr '\0' ' ' < "$cmdline_file")
    case "$cmdline" in
        *"$release"*) ;;
        *) return 1 ;;
    esac
    case "$cmdline" in
        *.new/*) return 1 ;;
    esac
    return 0
}

installer_port_closed() {
    port=${1:-8765}
    python3 - "$port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
try:
    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
        raise SystemExit(1)
except ConnectionRefusedError:
    raise SystemExit(0)
except Exception:
    raise SystemExit(1)
PY
}

completed_endpoint_ok() {
    url=$1
    kind=$2
    expected_version=$3
    python3 - "$url" "$kind" "$expected_version" <<'PY'
import json
import sys
import urllib.error
import urllib.request

url, kind, expected = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with urllib.request.urlopen(url, timeout=3) as response:
        status = response.getcode()
        body = response.read().decode("utf-8", "replace")
except urllib.error.HTTPError as error:
    status = error.code
    body = error.read().decode("utf-8", "replace")
except Exception:
    raise SystemExit(1)
if status != 200:
    raise SystemExit(1)
try:
    payload = json.loads(body)
except Exception:
    raise SystemExit(1)
if payload.get("status") != "ok":
    raise SystemExit(1)
core_version = str(payload.get("core_version") or "")
if expected and core_version != expected:
    raise SystemExit(1)
raise SystemExit(0)
PY
}

completed_runtime_ready() {
    new_release=$1
    expected_version=$2
    web_url="${PLAIK_WEB_READY_URL:-http://127.0.0.1:8080/health}"
    admin_url="${PLAIK_ADMIN_HEALTH_URL:-http://127.0.0.1:8081/health}"
    installer_port="${PLAIK_INSTALLER_PORT:-8765}"
    systemctl is-active --quiet plaik-web.service || return 1
    systemctl is-active --quiet plaik-admin.service || return 1
    if systemctl is-active --quiet plaik-installer.service; then
        return 1
    fi
    if [ -e "$PLAIK_CONFIG_DIR/installer.env" ]; then
        return 1
    fi
    service_runs_from_release plaik-web.service "$new_release" || return 1
    service_runs_from_release plaik-admin.service "$new_release" || return 1
    installer_port_closed "$installer_port" || return 1
    completed_endpoint_ok "$web_url" web "$expected_version" || return 1
    completed_endpoint_ok "$admin_url" admin "$expected_version" || return 1
    return 0
}

wait_for_completed_readiness() {
    new_release=$1
    expected_version=$2
    attempts=${PLAIK_READINESS_ATTEMPTS:-30}
    sleep_s=${PLAIK_READINESS_SLEEP:-1}
    i=0
    while [ "$i" -lt "$attempts" ]; do
        if completed_runtime_ready "$new_release" "$expected_version"; then
            return 0
        fi
        i=$((i + 1))
        sleep "$sleep_s"
    done
    return 1
}

restart_completed_services() {
    if systemctl restart plaik-web.service plaik-admin.service; then
        return 0
    fi
    echo "install.sh: failed to restart plaik-web.service plaik-admin.service" >&2
    return 1
}

restore_previous_completed_release() {
    previous_release=$1
    attempted_release=$2
    echo "install.sh: restoring previous release $previous_release" >&2
    atomic_switch_release "$previous_release" "$CURRENT_LINK"
    install_plaik_command
    systemctl daemon-reload
    systemctl disable --now plaik-installer.service >/dev/null 2>&1 || true
    if ! restart_completed_services; then
        echo "install.sh: rollback restart of previous release failed" >&2
        exit 1
    fi
    previous_version=$3
    if [ -z "$previous_version" ] && [ -x "$previous_release/venv/bin/python" ]; then
        previous_version=$("$previous_release/venv/bin/python" -c 'from plaik_core import __version__; print(__version__)' 2>/dev/null || true)
    fi
    if wait_for_completed_readiness "$previous_release" "$previous_version"; then
        echo "install.sh: previous release restored after failed upgrade of $attempted_release" >&2
        exit 1
    fi
    echo "install.sh: rollback to previous release also failed readiness" >&2
    exit 1
}

promote_completed_release() {
    new_release=$1
    previous_release=$2
    expected_version=$3
    systemctl disable --now plaik-installer.service >/dev/null 2>&1 || true
    if [ -e "$PLAIK_CONFIG_DIR/installer.env" ]; then
        echo "install.sh: installer token must remain revoked after completed upgrade" >&2
        if [ -n "$previous_release" ] && [ "$previous_release" != "$new_release" ] && [ -d "$previous_release" ]; then
            restore_previous_completed_release "$previous_release" "$new_release" ""
        fi
        echo "install.sh: completed upgrade failed closed" >&2
        exit 1
    fi
    if ! restart_completed_services; then
        echo "install.sh: new release failed to restart" >&2
        if [ -n "$previous_release" ] && [ "$previous_release" != "$new_release" ] && [ -d "$previous_release" ]; then
            restore_previous_completed_release "$previous_release" "$new_release" ""
        fi
        echo "install.sh: completed upgrade failed closed; current points at $new_release but services are unhealthy" >&2
        exit 1
    fi
    if wait_for_completed_readiness "$new_release" "$expected_version"; then
        echo "install.sh: web and admin are running from $new_release"
        return 0
    fi
    echo "install.sh: new release failed readiness" >&2
    if [ -n "$previous_release" ] && [ "$previous_release" != "$new_release" ] && [ -d "$previous_release" ]; then
        restore_previous_completed_release "$previous_release" "$new_release" ""
    fi
    echo "install.sh: completed upgrade failed closed; current points at $new_release but services are unhealthy" >&2
    exit 1
}

ensure_system_user() {
    account=$1
    home=$2
    if getent passwd "$account" >/dev/null 2>&1; then
        validate_existing_system_user "$account" "$home"
        return
    fi
    useradd --system --user-group --home-dir "$home" --shell /usr/sbin/nologin "$account"
}

validate_existing_system_user() {
    account=$1
    expected_home=$2
    entry=$(getent passwd "$account") || {
        echo "install.sh: missing system user: $account" >&2
        exit 1
    }
    uid=$(printf '%s\n' "$entry" | cut -d: -f3)
    gid=$(printf '%s\n' "$entry" | cut -d: -f4)
    home=$(printf '%s\n' "$entry" | cut -d: -f6)
    shell=$(printf '%s\n' "$entry" | cut -d: -f7)
    case "$uid" in
        ''|*[!0-9]*)
            echo "install.sh: invalid uid for $account" >&2
            exit 1
            ;;
    esac
    if [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; then
        echo "install.sh: refusing to reuse a non-system account: $account" >&2
        exit 1
    fi
    group_entry=$(getent group "$account") || {
        echo "install.sh: missing dedicated group: $account" >&2
        exit 1
    }
    group_gid=$(printf '%s\n' "$group_entry" | cut -d: -f3)
    if [ "$gid" != "$group_gid" ]; then
        echo "install.sh: $account must use a dedicated primary group" >&2
        exit 1
    fi
    case "$shell" in
        /usr/sbin/nologin|/sbin/nologin|/usr/bin/nologin|/bin/nologin|/bin/false|/usr/bin/false) ;;
        *)
            echo "install.sh: $account must use a noninteractive shell" >&2
            exit 1
            ;;
    esac
    if [ "$home" != "$expected_home" ]; then
        echo "install.sh: $account home directory is not the PLAIK identity home" >&2
        exit 1
    fi
}

validate_plaik_identities() {
    if [ "$PLAIK_INSTALLER_USER" = "$PLAIK_ADMIN_USER" ] \
        || [ "$PLAIK_INSTALLER_USER" = "$PLAIK_PUBLIC_USER" ] \
        || [ "$PLAIK_ADMIN_USER" = "$PLAIK_PUBLIC_USER" ]; then
        echo "install.sh: PLAIK service identities must be distinct" >&2
        exit 1
    fi
    installer_uid=$(getent passwd "$PLAIK_INSTALLER_USER" | cut -d: -f3)
    admin_uid=$(getent passwd "$PLAIK_ADMIN_USER" | cut -d: -f3)
    public_uid=$(getent passwd "$PLAIK_PUBLIC_USER" | cut -d: -f3)
    installer_gid=$(getent passwd "$PLAIK_INSTALLER_USER" | cut -d: -f4)
    admin_gid=$(getent passwd "$PLAIK_ADMIN_USER" | cut -d: -f4)
    public_gid=$(getent passwd "$PLAIK_PUBLIC_USER" | cut -d: -f4)
    if [ "$installer_uid" = "$admin_uid" ] \
        || [ "$installer_uid" = "$public_uid" ] \
        || [ "$admin_uid" = "$public_uid" ] \
        || [ "$installer_gid" = "$admin_gid" ] \
        || [ "$installer_gid" = "$public_gid" ] \
        || [ "$admin_gid" = "$public_gid" ]; then
        echo "install.sh: PLAIK service identities must be distinct" >&2
        exit 1
    fi
}

verify_wheel_bundle() {
    "${BOOTSTRAP_PYTHON:-python3}" - "$1" "$2" "$3" "$4" <<'PY'
import re
import sys
import zipfile
from email.parser import Parser

runtime_path, sdk_path, expected_tag, expected_runtime_name = sys.argv[1:]

def metadata(path):
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise SystemExit(f"wheel METADATA is missing: {path}")
        return Parser().parsestr(archive.read(names[0]).decode("utf-8"))

def parse_version(value):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise SystemExit("SDK version is not a release version")
    return tuple(int(part) for part in match.groups())

def parse_spec(value):
    clauses = []
    for raw in value.split(","):
        item = raw.strip()
        for operator in (">=", "<=", "!=", "==", "~=", ">", "<"):
            if item.startswith(operator):
                clauses.append((operator, parse_version(item[len(operator):].strip())))
                break
        else:
            raise SystemExit("unsupported SDK compatibility specifier")
    return clauses

def matches(version, clauses):
    for operator, target in clauses:
        if operator == ">=" and version < target:
            return False
        if operator == "<=" and version > target:
            return False
        if operator == ">" and version <= target:
            return False
        if operator == "<" and version >= target:
            return False
        if operator == "==" and version != target:
            return False
        if operator == "!=" and version == target:
            return False
        if operator == "~=":
            if version < target or version >= (target[0], target[1] + 1, 0):
                return False
    return True

runtime = metadata(runtime_path)
sdk = metadata(sdk_path)
runtime_version = runtime.get("Version", "")
sdk_version = sdk.get("Version", "")
runtime_name = f"plaik-{runtime_version}-py3-none-any.whl"
if runtime.get("Name") != "plaik" or not runtime_version:
    raise SystemExit("runtime wheel METADATA version is invalid")
if expected_runtime_name and expected_runtime_name != runtime_name:
    raise SystemExit("wheel filename version does not match METADATA")
tag = expected_tag.lstrip("v")
if expected_tag and expected_tag not in {"local", "dev"} and tag != runtime_version:
    raise SystemExit("release tag/version mismatch")
if sdk.get("Name") not in {"plaik-sdk", "plaik_sdk"} or not sdk_version:
    raise SystemExit("SDK wheel METADATA version is invalid")
sdk_requirement = None
for item in runtime.get_all("Requires-Dist") or []:
    requirement = item.split(";", 1)[0].strip()
    name = re.split(r"[ \t(<>=!~\[]", requirement, maxsplit=1)[0]
    if name.replace("_", "-").casefold() == "plaik-sdk":
        sdk_requirement = requirement
        break
if sdk_requirement is None:
    raise SystemExit("runtime wheel does not declare plaik-sdk compatibility")
paren = re.search(r"\(([^)]+)\)", sdk_requirement)
if paren is not None:
    range_text = paren.group(1).strip()
else:
    range_text = re.sub(
        r"^plaik[-_]sdk(?:\[[^\]]+\])?\s*",
        "",
        sdk_requirement,
        flags=re.I,
    ).strip()
if not range_text:
    raise SystemExit("runtime SDK compatibility range is missing")
if not matches(parse_version(sdk_version), parse_spec(range_text)):
    raise SystemExit("bundled SDK version is outside the runtime compatibility range")
print(runtime_version)
PY
}

is_safe_ssh_user() {
    value=$1
    case "$value" in
        ''|*[!a-zA-Z0-9_-]*|-*) return 1 ;;
    esac
    case "$value" in
        [A-Za-z_]*) ;;
        *) return 1 ;;
    esac
    [ "${#value}" -le 32 ]
}

is_safe_tcp_port() {
    value=$1
    case "$value" in
        ''|*[!0-9]*|0|0*) return 1 ;;
    esac
    [ "$value" -ge 1 ] && [ "$value" -le 65535 ]
}

is_safe_ipv4() {
    value=$1
    case "$value" in
        ''|*[!0-9.]*|.*|*..*|*.) return 1 ;;
    esac
    old_ifs=$IFS
    IFS=.
    # shellcheck disable=SC2086
    set -- $value
    IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    for octet in "$@"; do
        case "$octet" in
            ''|*[!0-9]*) return 1 ;;
            0) ;;
            0*) return 1 ;;
        esac
        [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || return 1
    done
    [ "$value" != "0.0.0.0" ] && [ "$value" != "127.0.0.1" ]
}

is_safe_ipv6() {
    value=$1
    case "$value" in
        ''|*[!0-9a-fA-F:]*|*:::*|[Ff][Ee]80:*) return 1 ;;
    esac
    [ "${#value}" -ge 2 ] && [ "${#value}" -le 39 ] || return 1
    case "$value" in
        *:*) ;;
        *) return 1 ;;
    esac
    rest=${value#*::}
    case "$value" in
        *::*)
            case "$rest" in
                *::*) return 1 ;;
            esac
            ;;
    esac
    [ "$value" != "::1" ] && [ "$value" != "::" ]
}

ssh_host_token() {
    value=$1
    if is_safe_ipv4 "$value"; then
        printf '%s\n' "$value"
        return 0
    fi
    if is_safe_ipv6 "$value"; then
        printf '[%s]\n' "$value"
        return 0
    fi
    return 1
}

format_ssh_tunnel_command() {
    user="<user>"
    host="<server>"
    port=""
    if is_safe_ssh_user "${SUDO_USER:-}"; then
        user=$SUDO_USER
    fi
    set -f
    # shellcheck disable=SC2086
    set -- ${SSH_CONNECTION:-}
    set +f
    if [ "$#" -eq 4 ] && is_safe_tcp_port "$2" && is_safe_tcp_port "$4"; then
        if token=$(ssh_host_token "$3"); then
            host=$token
        fi
        if [ "$4" != 22 ]; then
            port=$4
        fi
    else
        set -f
        # shellcheck disable=SC2086
        set -- ${SSH_CLIENT:-}
        set +f
        if [ "$#" -eq 3 ] && is_safe_tcp_port "$2" && is_safe_tcp_port "$3" && [ "$3" != 22 ]; then
            port=$3
        fi
    fi
    if [ -n "$port" ]; then
        printf 'ssh -p %s -N -L 8765:127.0.0.1:8765 %s@%s\n' "$port" "$user" "$host"
    else
        printf 'ssh -N -L 8765:127.0.0.1:8765 %s@%s\n' "$user" "$host"
    fi
}

print_stage2_access() {
    tunnel_command=$(format_ssh_tunnel_command)
    cat <<EOF
PLAIK Stage 1 installation complete.

Secure Web Installer:
  http://127.0.0.1:8765/

The installer listens on 127.0.0.1:8765 only. It is not opened on LAN or a public interface.

If this server is local:
  Open http://127.0.0.1:8765/ in a browser.

If you installed PLAIK over SSH:
  Run this command ON YOUR LOCAL COMPUTER, in a second terminal.
  Do not run it inside this SSH session on the server.

  ${tunnel_command}

  Use the same SSH login as this session: key or password.
  If you sign in with a password, OpenSSH will prompt for it locally.
  Do not put the password in the command.

  Then open:
  http://127.0.0.1:8765/

Keep the SSH tunnel open while completing installation.
After Stage 2 finishes (installer off, Web/Admin on), you can close the tunnel.

Installer token:
  On THIS server run:
    sudo plaik installer-token
  Paste that value into the Web Installer. Do not put the token in the SSH command.

CLI fallback:
  sudo plaik setup
EOF
}

if [ "${PLAIK_INSTALL_ACTION:-}" = "validate-paths" ]; then
    validate_configured_paths
    echo "paths ok"
    exit 0
fi

if [ "${PLAIK_INSTALL_ACTION:-}" = "print-stage2-access" ]; then
    print_stage2_access
    exit 0
fi

migrate_shared_installer_token() {
    shared=$1
    installer=$2
    [ -f "$shared" ] || return 0
    if ! grep -q '^PLAIK_INSTALLER_TOKEN=' "$shared" 2>/dev/null; then
        return 0
    fi
    if [ ! -f "$installer" ]; then
        (umask 027; grep '^PLAIK_INSTALLER_TOKEN=' "$shared" > "$installer")
    fi
    tmp_env="${shared}.tmp"
    grep -v '^PLAIK_INSTALLER_TOKEN=' "$shared" > "$tmp_env"
    mv -f "$tmp_env" "$shared"
}

if [ "${PLAIK_INSTALL_ACTION:-}" = "migrate-installer-token" ]; then
    shared="${PLAIK_SHARED_ENV:-$PLAIK_CONFIG_DIR/plaik.env}"
    installer="${PLAIK_INSTALLER_ENV:-$PLAIK_CONFIG_DIR/installer.env}"
    migrate_shared_installer_token "$shared" "$installer"
    echo "token migrated"
    exit 0
fi

if [ "${PLAIK_INSTALL_ACTION:-}" = "validate-identities" ]; then
    ensure_system_user "$PLAIK_INSTALLER_USER" "$PLAIK_DATA_DIR"
    ensure_system_user "$PLAIK_ADMIN_USER" "$PLAIK_DATA_DIR"
    ensure_system_user "$PLAIK_PUBLIC_USER" "$PLAIK_DATA_DIR/public"
    validate_plaik_identities
    echo "identities ok"
    exit 0
fi

if [ "${PLAIK_INSTALL_ACTION:-}" = "verify-wheels" ]; then
    [ -n "${PLAIK_WHEEL_FILE:-}" ] && [ -n "${PLAIK_SDK_WHEEL_FILE:-}" ] || {
        echo "install.sh: verify-wheels requires PLAIK_WHEEL_FILE and PLAIK_SDK_WHEEL_FILE" >&2
        exit 2
    }
    verify_wheel_bundle "$PLAIK_WHEEL_FILE" "$PLAIK_SDK_WHEEL_FILE" "${PLAIK_RELEASE_TAG:-}" "$(basename "$PLAIK_WHEEL_FILE")"
    exit 0
fi

if [ "${PLAIK_INSTALL_ACTION:-}" = "switch-release" ]; then
    atomic_switch_release "$PLAIK_INSTALL_NEW_RELEASE" "$PLAIK_INSTALL_CURRENT_LINK"
    exit 0
fi

if [ "${PLAIK_INSTALL_ACTION:-}" = "commit-staged-release" ]; then
    commit_staged_release "$PLAIK_INSTALL_NEW_RELEASE" "$PLAIK_INSTALL_READY_RELEASE"
    echo "release committed"
    exit 0
fi

if [ "${PLAIK_INSTALL_ACTION:-}" = "promote-completed-release" ]; then
    CURRENT_LINK="${PLAIK_INSTALL_CURRENT_LINK:?}"
    PLAIK_CONFIG_DIR="${PLAIK_CONFIG_DIR:-/etc/plaik}"
    promote_completed_release \
        "${PLAIK_INSTALL_NEW_RELEASE:?}" \
        "${PLAIK_INSTALL_PREVIOUS_RELEASE:-}" \
        "${PLAIK_INSTALL_EXPECTED_VERSION:-}"
    echo "completed release promoted"
    exit 0
fi

validate_configured_paths

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root (sudo ./install.sh)" >&2
    exit 1
fi

if [ ! -r /etc/os-release ]; then
    echo "install.sh: /etc/os-release is required" >&2
    exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu) ;;
    *)
        echo "install.sh: supported bootstrap hosts are Debian and Ubuntu; found ${ID:-unknown}" >&2
        exit 1
        ;;
esac

if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
    echo "install.sh: systemd is required" >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "install.sh: apt-get is required on the supported bootstrap hosts" >&2
    exit 1
fi

CURRENT_LINK="$PLAIK_RUNTIME_DIR/current"
if [ -x "$CURRENT_LINK/venv/bin/plaik" ] && [ "$FORCE" -ne 1 ]; then
    echo "PLAIK runtime is already installed. Use --force to reinstall runtime files." >&2
    echo "Existing PLAIK data is not modified." >&2
    exit 1
fi
if [ ! -e "$CURRENT_LINK" ] && [ -x "$PLAIK_RUNTIME_DIR/venv/bin/plaik" ] && [ "$FORCE" -ne 1 ]; then
    echo "PLAIK runtime is already installed. Use --force to reinstall runtime files." >&2
    echo "Existing PLAIK data is not modified." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl git >/dev/null

ensure_system_user "$PLAIK_INSTALLER_USER" "$PLAIK_DATA_DIR"
ensure_system_user "$PLAIK_ADMIN_USER" "$PLAIK_DATA_DIR"
ensure_system_user "$PLAIK_PUBLIC_USER" "$PLAIK_DATA_DIR/public"
validate_plaik_identities
install -d -m 0755 -o root -g root "$PLAIK_RUNTIME_DIR/releases"
# Data root is traversable; only installer may create platform files during setup.
# After handoff, finalize reowns the root to root:plaik-admin 0771. Public never
# gets write on the whole tree — only $PLAIK_DATA_DIR/public.
install -d -m 0771 -o root -g "$PLAIK_INSTALLER_USER" "$PLAIK_DATA_DIR"
install -d -m 0770 -o root -g "$PLAIK_INSTALLER_USER" "$PLAIK_DATA_DIR/run"
install -d -m 0750 -o "$PLAIK_PUBLIC_USER" -g "$PLAIK_PUBLIC_USER" "$PLAIK_DATA_DIR/public"
install -d -m 0751 -o root -g "$PLAIK_ADMIN_USER" "$PLAIK_CONFIG_DIR"
install -d -m 0751 -o root -g root "$PLAIK_LOG_DIR"
install -d -m 0750 -o "$PLAIK_INSTALLER_USER" -g "$PLAIK_INSTALLER_USER" "$PLAIK_LOG_DIR/installer"
install -d -m 0750 -o "$PLAIK_ADMIN_USER" -g "$PLAIK_ADMIN_USER" "$PLAIK_LOG_DIR/admin"
install -d -m 0750 -o "$PLAIK_PUBLIC_USER" -g "$PLAIK_PUBLIC_USER" "$PLAIK_LOG_DIR/public"
# Trusted journal heads live beside the data directory, not inside it.
PLAIK_INTEGRITY_DIR="$(dirname "$PLAIK_DATA_DIR")/.$(basename "$PLAIK_DATA_DIR")-integrity"
if [ -L "$PLAIK_INTEGRITY_DIR" ]; then
    echo "install.sh: refusing symlink integrity directory: $PLAIK_INTEGRITY_DIR" >&2
    exit 1
fi
install -d -m 0700 -o "$PLAIK_INSTALLER_USER" -g "$PLAIK_INSTALLER_USER" "$PLAIK_INTEGRITY_DIR"
install -d -m 0755 -o root -g root "$PLAIK_RUNTIME_DIR/bootstrap/bin"
install -d -m 0755 -o root -g root "$PLAIK_RUNTIME_DIR/bootstrap/python"

TMP_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

UV_BIN="$PLAIK_RUNTIME_DIR/bootstrap/bin/uv"
if [ ! -x "$UV_BIN" ]; then
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) UV_TARGET=x86_64-unknown-linux-gnu ;;
        aarch64|arm64) UV_TARGET=aarch64-unknown-linux-gnu ;;
        *)
            echo "install.sh: unsupported architecture for uv: $ARCH" >&2
            exit 1
            ;;
    esac
    UV_TAR="uv-${UV_TARGET}.tar.gz"
    UV_URL="https://github.com/astral-sh/uv/releases/download/${PLAIK_UV_VERSION}/${UV_TAR}"
    UV_SHA_URL="${UV_URL}.sha256"
    curl -fsSL --max-filesize "$PLAIK_MAX_UV_BYTES" "$UV_URL" -o "$TMP_DIR/$UV_TAR"
    curl -fsSL --max-filesize "$PLAIK_MAX_CHECKSUM_BYTES" "$UV_SHA_URL" -o "$TMP_DIR/$UV_TAR.sha256"
    expected=$(awk 'NF {print $1; exit}' "$TMP_DIR/$UV_TAR.sha256")
    if ! printf '%s\n' "$expected" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
        echo "install.sh: uv checksum is invalid" >&2
        exit 1
    fi
    actual=$(sha256sum "$TMP_DIR/$UV_TAR" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        echo "install.sh: uv SHA-256 mismatch" >&2
        exit 1
    fi
    tar -xzf "$TMP_DIR/$UV_TAR" -C "$TMP_DIR"
    UV_EXTRACTED=$(find "$TMP_DIR" -type f -name uv | head -n 1)
    [ -n "$UV_EXTRACTED" ] || { echo "install.sh: uv binary missing from release archive" >&2; exit 1; }
    install -m 0755 "$UV_EXTRACTED" "$UV_BIN"
fi

export UV_PYTHON_INSTALL_DIR="$PLAIK_RUNTIME_DIR/bootstrap/python"
"$UV_BIN" python install 3.12 >/dev/null
BOOTSTRAP_PYTHON=$("$UV_BIN" python find 3.12)

resolve_release_assets() {
    "$BOOTSTRAP_PYTHON" - "$PLAIK_RELEASE_REPOSITORY" "$PLAIK_RELEASE_TAG" <<'PY'
import json
import re
import sys
import urllib.request

repository, tag = sys.argv[1:]
if tag:
    endpoint = f"https://api.github.com/repos/{repository}/releases/tags/{tag}"
else:
    endpoint = f"https://api.github.com/repos/{repository}/releases/latest"
request = urllib.request.Request(
    endpoint,
    headers={"Accept": "application/vnd.github+json", "User-Agent": "plaik-install"},
)
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.load(response)
except Exception as error:
    raise SystemExit(f"cannot resolve PLAIK release: {type(error).__name__}")
if release.get("draft"):
    raise SystemExit("PLAIK release is still a draft")
tag_name = str(release.get("tag_name") or "")
assets = [item for item in (release.get("assets") or []) if isinstance(item, dict)]
runtime_pattern = re.compile(r"^plaik-[0-9][A-Za-z0-9._+!-]*-py3-none-any\.whl$")
sdk_pattern = re.compile(r"^plaik_sdk-[0-9][A-Za-z0-9._+!-]*-py3-none-any\.whl$")
runtime_wheels = [item for item in assets if runtime_pattern.fullmatch(str(item.get("name", "")))]
sdk_wheels = [item for item in assets if sdk_pattern.fullmatch(str(item.get("name", "")))]
if len(runtime_wheels) != 1:
    raise SystemExit("release must contain exactly one PLAIK runtime wheel")
if len(sdk_wheels) != 1:
    raise SystemExit("release must contain exactly one PLAIK SDK wheel")

def pair(wheel):
    wheel_name = str(wheel["name"])
    checksum_name = wheel_name + ".sha256"
    checksums = [item for item in assets if item.get("name") == checksum_name]
    if len(checksums) != 1:
        raise SystemExit(f"release is missing checksum asset: {checksum_name}")
    size = int(wheel.get("size") or 0)
    if size <= 0 or size > 83886080:
        raise SystemExit(f"release asset is oversized: {wheel_name}")
    wheel_url = str(wheel.get("browser_download_url", ""))
    checksum_url = str(checksums[0].get("browser_download_url", ""))
    prefix = f"https://github.com/{repository}/releases/download/"
    if not wheel_url.startswith(prefix) or not checksum_url.startswith(prefix):
        raise SystemExit("release asset URL is outside the configured PLAIK repository")
    return wheel_url, checksum_url, wheel_name

runtime = pair(runtime_wheels[0])
sdk = pair(sdk_wheels[0])
print(tag_name)
print(runtime[0])
print(runtime[1])
print(runtime[2])
print(sdk[0])
print(sdk[1])
print(sdk[2])
PY
}

verify_local_wheel() {
    path=$1
    expected=$2
    label=$3
    if [ ! -f "$path" ]; then
        echo "install.sh: local $label wheel does not exist: $path" >&2
        exit 1
    fi
    size=$(wc -c < "$path")
    if [ "$size" -gt "$PLAIK_MAX_WHEEL_BYTES" ]; then
        echo "install.sh: local $label wheel is oversized" >&2
        exit 1
    fi
    if [ -n "$expected" ]; then
        if ! printf '%s\n' "$expected" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
            echo "install.sh: local $label SHA-256 is invalid" >&2
            exit 1
        fi
        actual=$(sha256sum "$path" | awk '{print $1}')
        if [ "$actual" != "$expected" ]; then
            echo "install.sh: local $label wheel SHA-256 mismatch" >&2
            exit 1
        fi
    else
        echo "install.sh: warning: local development $label wheel has no explicit SHA-256" >&2
    fi
}

download_verified_wheel() {
    wheel_url=$1
    checksum_url=$2
    destination=$3
    label=$4
    checksum_path="$destination.sha256"
    curl -fsSL --max-filesize "$PLAIK_MAX_WHEEL_BYTES" "$wheel_url" -o "$destination"
    curl -fsSL --max-filesize "$PLAIK_MAX_CHECKSUM_BYTES" "$checksum_url" -o "$checksum_path"
    expected=$(awk 'NF {print $1; exit}' "$checksum_path")
    if ! printf '%s\n' "$expected" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
        echo "install.sh: release $label checksum is invalid" >&2
        exit 1
    fi
    actual=$(sha256sum "$destination" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        echo "install.sh: release $label wheel SHA-256 mismatch" >&2
        exit 1
    fi
}

if [ -n "$PLAIK_WHEEL_FILE" ] || [ -n "$PLAIK_SDK_WHEEL_FILE" ]; then
    if [ -z "$PLAIK_WHEEL_FILE" ] || [ -z "$PLAIK_SDK_WHEEL_FILE" ]; then
        echo "install.sh: local development mode requires both --wheel and --sdk-wheel" >&2
        exit 1
    fi
    verify_local_wheel "$PLAIK_WHEEL_FILE" "$PLAIK_WHEEL_SHA256" "runtime"
    verify_local_wheel "$PLAIK_SDK_WHEEL_FILE" "$PLAIK_SDK_WHEEL_SHA256" "SDK"
    WHEEL_PATH=$PLAIK_WHEEL_FILE
    SDK_WHEEL_PATH=$PLAIK_SDK_WHEEL_FILE
    RELEASE_TAG=${PLAIK_RELEASE_TAG:-local}
    WHEEL_NAME=$(basename "$WHEEL_PATH")
else
    ASSET_INFO="$TMP_DIR/assets.txt"
    resolve_release_assets > "$ASSET_INFO"
    RELEASE_TAG=$(sed -n '1p' "$ASSET_INFO")
    WHEEL_URL=$(sed -n '2p' "$ASSET_INFO")
    CHECKSUM_URL=$(sed -n '3p' "$ASSET_INFO")
    WHEEL_NAME=$(sed -n '4p' "$ASSET_INFO")
    SDK_WHEEL_URL=$(sed -n '5p' "$ASSET_INFO")
    SDK_CHECKSUM_URL=$(sed -n '6p' "$ASSET_INFO")
    [ -n "$WHEEL_URL" ] && [ -n "$CHECKSUM_URL" ] \
        && [ -n "$SDK_WHEEL_URL" ] && [ -n "$SDK_CHECKSUM_URL" ] || {
        echo "install.sh: release asset resolution failed" >&2
        exit 1
    }
    WHEEL_PATH="$TMP_DIR/$(basename "$WHEEL_URL")"
    SDK_WHEEL_PATH="$TMP_DIR/$(basename "$SDK_WHEEL_URL")"
    download_verified_wheel "$WHEEL_URL" "$CHECKSUM_URL" "$WHEEL_PATH" "runtime"
    download_verified_wheel "$SDK_WHEEL_URL" "$SDK_CHECKSUM_URL" "$SDK_WHEEL_PATH" "SDK"
fi

RELEASE_VERSION=$(verify_wheel_bundle "$WHEEL_PATH" "$SDK_WHEEL_PATH" "$RELEASE_TAG" "$WHEEL_NAME")
RELEASE_ID="${RELEASE_VERSION}-$(date -u +%Y%m%d%H%M%S)"
NEW_RELEASE="$PLAIK_RUNTIME_DIR/releases/${RELEASE_ID}.new"
rm -rf "$NEW_RELEASE"
"$UV_BIN" venv --python 3.12 --relocatable "$NEW_RELEASE/venv" >/dev/null
PYTHON_BIN="$NEW_RELEASE/venv/bin/python"
"$UV_BIN" pip install --python "$PYTHON_BIN" "$SDK_WHEEL_PATH" "$WHEEL_PATH" >/dev/null
"$PYTHON_BIN" -c 'import plaik_core, plaik_installer, plaik_web, plaik_admin' >/dev/null
READY_RELEASE="$PLAIK_RUNTIME_DIR/releases/$RELEASE_ID"
PREVIOUS_RELEASE=""
if [ -L "$CURRENT_LINK" ] || [ -d "$CURRENT_LINK" ]; then
    PREVIOUS_RELEASE=$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)
fi
commit_staged_release "$NEW_RELEASE" "$READY_RELEASE"
atomic_switch_release "$READY_RELEASE" "$CURRENT_LINK"
PYTHON_BIN="$CURRENT_LINK/venv/bin/python"

SHARED_ENV="$PLAIK_CONFIG_DIR/plaik.env"
INSTALLER_ENV="$PLAIK_CONFIG_DIR/installer.env"
WEB_ENV="$PLAIK_CONFIG_DIR/web.env"
ADMIN_ENV="$PLAIK_CONFIG_DIR/admin.env"
if [ ! -f "$SHARED_ENV" ]; then
    umask 027
    cat > "$SHARED_ENV" <<EOF
PLAIK_DATA_DIR=$PLAIK_DATA_DIR
PLAIK_ADMIN_PATH=/control-center
EOF
fi
migrate_shared_installer_token "$SHARED_ENV" "$INSTALLER_ENV"
if [ ! -f "$INSTALLER_ENV" ]; then
    INSTALLER_TOKEN=$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(48))')
    umask 027
    printf 'PLAIK_INSTALLER_TOKEN=%s\n' "$INSTALLER_TOKEN" > "$INSTALLER_ENV"
fi
if [ ! -f "$WEB_ENV" ]; then
    umask 027
    cat > "$WEB_ENV" <<EOF
PLAIK_DATA_DIR=$PLAIK_DATA_DIR
PLAIK_ADMIN_PATH=/control-center
PLAIK_SECRETS_DIR=$PLAIK_CONFIG_DIR/web-secrets
PLAIK_PUBLIC_SECRETS=1
EOF
fi
if [ ! -f "$ADMIN_ENV" ]; then
    umask 027
    cat > "$ADMIN_ENV" <<EOF
PLAIK_DATA_DIR=$PLAIK_DATA_DIR
PLAIK_ADMIN_PATH=/control-center
EOF
fi
chown root:"$PLAIK_ADMIN_USER" "$SHARED_ENV"
chmod 0640 "$SHARED_ENV"
chown root:"$PLAIK_INSTALLER_USER" "$INSTALLER_ENV"
chmod 0640 "$INSTALLER_ENV"
chown root:"$PLAIK_PUBLIC_USER" "$WEB_ENV"
chmod 0640 "$WEB_ENV"
chown root:"$PLAIK_ADMIN_USER" "$ADMIN_ENV"
chmod 0640 "$ADMIN_ENV"
install -d -m 0750 -o root -g "$PLAIK_PUBLIC_USER" "$PLAIK_CONFIG_DIR/web-secrets"
if ! grep -q '^PLAIK_PUBLIC_SECRETS=' "$WEB_ENV" 2>/dev/null; then
    printf 'PLAIK_PUBLIC_SECRETS=1\n' >> "$WEB_ENV"
    chown root:"$PLAIK_PUBLIC_USER" "$WEB_ENV"
    chmod 0640 "$WEB_ENV"
fi

COMMON_HARDENING=$(cat <<'EOF'
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
CapabilityBoundingSet=
AmbientCapabilities=
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RemoveIPC=yes
MemoryDenyWriteExecute=yes
DevicePolicy=closed
TasksMax=128
LimitNOFILE=4096
EOF
)

# Units are generated with separate identities:
#   User=$PLAIK_INSTALLER_USER
#   User=$PLAIK_ADMIN_USER
#   User=$PLAIK_PUBLIC_USER
write_app_unit() {
    UNIT_PATH=$1
    USER_NAME=$2
    GROUP_NAME=$3
    ENV_FILES=$4
    ENTRYPOINT=$5
    PORT=$6
    DESCRIPTION=$7
    EXTRA=$8
    MEMORY=$9
    {
        cat <<EOF
[Unit]
Description=$DESCRIPTION
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME
$ENV_FILES
WorkingDirectory=$WORKDIR
ExecStart=$CURRENT_LINK/venv/bin/uvicorn $ENTRYPOINT --host 127.0.0.1 --port $PORT --workers 1
$COMMON_HARDENING
MemoryMax=$MEMORY
ReadOnlyPaths=$PLAIK_RUNTIME_DIR $PLAIK_CONFIG_DIR
ReadWritePaths=$RWPATHS
$EXTRA
[Install]
WantedBy=multi-user.target
EOF
    } > "$UNIT_PATH"
    chmod 0644 "$UNIT_PATH"
}

WORKDIR=$PLAIK_DATA_DIR
RWPATHS="$PLAIK_DATA_DIR $PLAIK_LOG_DIR/installer $PLAIK_DATA_DIR/run $PLAIK_INTEGRITY_DIR"
write_app_unit /etc/systemd/system/plaik-installer.service \
    "$PLAIK_INSTALLER_USER" "$PLAIK_INSTALLER_USER" \
    "EnvironmentFile=$SHARED_ENV
EnvironmentFile=$INSTALLER_ENV" \
    plaik_installer.app:app 8765 "PLAIK setup service" "" "512M"

WORKDIR=$PLAIK_DATA_DIR
RWPATHS="$PLAIK_DATA_DIR $PLAIK_LOG_DIR/admin"
write_app_unit /etc/systemd/system/plaik-admin.service \
    "$PLAIK_ADMIN_USER" "$PLAIK_ADMIN_USER" \
    "EnvironmentFile=$SHARED_ENV
EnvironmentFile=$ADMIN_ENV" \
    plaik_admin.app:app 8081 "PLAIK Admin" "UMask=0027
" "512M"

PUBLIC_EXTRA=$(cat <<EOF
UMask=0077
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
InaccessiblePaths=-$INSTALLER_ENV -$PLAIK_DATA_DIR/run -$PLAIK_DATA_DIR/secrets -$PLAIK_DATA_DIR/identities.json -$PLAIK_DATA_DIR/sessions.json -$PLAIK_DATA_DIR/admin-passkeys.json -$PLAIK_DATA_DIR/audit.jsonl -$PLAIK_DATA_DIR/installer-operations.jsonl -$PLAIK_DATA_DIR/package-inbox -$PLAIK_DATA_DIR/package-transactions
EOF
)
WORKDIR=$PLAIK_DATA_DIR/public
RWPATHS="$PLAIK_DATA_DIR/public $PLAIK_LOG_DIR/public"
write_app_unit /etc/systemd/system/plaik-web.service \
    "$PLAIK_PUBLIC_USER" "$PLAIK_PUBLIC_USER" \
    "EnvironmentFile=$WEB_ENV" \
    plaik_web.app:app 8080 "PLAIK Web" "$PUBLIC_EXTRA" "256M"

write_oneshot() {
    cat > "$1" <<EOF
[Unit]
Description=$2

[Service]
Type=oneshot
EnvironmentFile=$SHARED_ENV
ExecStart=$CURRENT_LINK/venv/bin/plaik privileged $3
EOF
    chmod 0644 "$1"
}

write_oneshot /etc/systemd/system/plaik-finalize.service "PLAIK installer service finalization" finalize-services
write_oneshot /etc/systemd/system/plaik-provision.service "PLAIK installer database provisioning" provision-database

cat > /etc/systemd/system/plaik-installer-stop.service <<'EOF'
[Unit]
Description=PLAIK installer stop after confirmed handoff
After=plaik-finalize.service

[Service]
Type=oneshot
ExecStart=/bin/systemctl disable --now plaik-installer.service
EOF
cat > /etc/systemd/system/plaik-installer-stop.timer <<'EOF'
[Unit]
Description=PLAIK delayed installer stop after handoff

[Timer]
OnActiveSec=3
AccuracySec=1s
Unit=plaik-installer-stop.service
RemainAfterElapse=no
EOF
chmod 0644 /etc/systemd/system/plaik-installer-stop.service /etc/systemd/system/plaik-installer-stop.timer

cat > /etc/systemd/system/plaik-finalize.path <<EOF
[Unit]
Description=PLAIK installer finalization trigger

[Path]
PathExists=$PLAIK_DATA_DIR/run/finalize.request
Unit=plaik-finalize.service

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/plaik-provision.path <<EOF
[Unit]
Description=PLAIK installer provisioning trigger

[Path]
PathExists=$PLAIK_DATA_DIR/run/provision.request
Unit=plaik-provision.service

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/plaik-finalize.path /etc/systemd/system/plaik-provision.path

install_plaik_command
systemctl daemon-reload
systemctl enable --now plaik-finalize.path plaik-provision.path >/dev/null

if [ -f "$PLAIK_DATA_DIR/install-state.json" ] \
    && grep -Eq '"state"[[:space:]]*:[[:space:]]*"completed"' "$PLAIK_DATA_DIR/install-state.json"; then
    export PLAIK_DATA_DIR PLAIK_CONFIG_DIR
    export PLAIK_INSTALLER_USER PLAIK_ADMIN_USER PLAIK_PUBLIC_USER
    if ! "$CURRENT_LINK/venv/bin/plaik" privileged finalize-services; then
        echo "install.sh: completed installation could not be finalized" >&2
        if [ -n "$PREVIOUS_RELEASE" ] && [ "$PREVIOUS_RELEASE" != "$READY_RELEASE" ] && [ -d "$PREVIOUS_RELEASE" ]; then
            restore_previous_completed_release "$PREVIOUS_RELEASE" "$READY_RELEASE" ""
        fi
        exit 1
    fi
    promote_completed_release "$READY_RELEASE" "$PREVIOUS_RELEASE" "$RELEASE_VERSION"
    echo "PLAIK runtime reinstalled; existing completed installation was preserved."
else
    systemctl disable --now plaik-web.service plaik-admin.service >/dev/null 2>&1 || true
    systemctl enable plaik-installer.service >/dev/null
    systemctl restart plaik-installer.service >/dev/null
    print_stage2_access
fi
