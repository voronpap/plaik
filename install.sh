#!/bin/sh
set -eu

PLAIK_RUNTIME_DIR="${PLAIK_RUNTIME_DIR:-/opt/plaik}"
PLAIK_DATA_DIR="${PLAIK_DATA_DIR:-/var/lib/plaik}"
PLAIK_CONFIG_DIR="${PLAIK_CONFIG_DIR:-/etc/plaik}"
PLAIK_LOG_DIR="${PLAIK_LOG_DIR:-/var/log/plaik}"
PLAIK_SERVICE_USER="${PLAIK_SERVICE_USER:-plaik}"
PLAIK_UV_VERSION="${PLAIK_UV_VERSION:-0.12.3}"
PLAIK_RELEASE_REPOSITORY="${PLAIK_RELEASE_REPOSITORY:-voronpap/plaik}"
PLAIK_RELEASE_TAG="${PLAIK_RELEASE_TAG:-}"
PLAIK_WHEEL_FILE="${PLAIK_WHEEL_FILE:-}"
PLAIK_WHEEL_SHA256="${PLAIK_WHEEL_SHA256:-}"
PLAIK_SDK_WHEEL_FILE="${PLAIK_SDK_WHEEL_FILE:-}"
PLAIK_SDK_WHEEL_SHA256="${PLAIK_SDK_WHEEL_SHA256:-}"
FORCE=0

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh [--force] [--wheel /path/to/plaik.whl --sdk-wheel /path/to/plaik_sdk.whl]

System bootstrap only. It installs the PLAIK runtime and systemd services.
Domain, database and administrator configuration happens later with:

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

if [ -x "$PLAIK_RUNTIME_DIR/venv/bin/plaik" ] && [ "$FORCE" -ne 1 ]; then
    echo "PLAIK runtime is already installed. Use --force to reinstall runtime files." >&2
    echo "Existing PLAIK data is not modified." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl git >/dev/null

if ! getent passwd "$PLAIK_SERVICE_USER" >/dev/null 2>&1; then
    useradd \
        --system \
        --user-group \
        --home-dir "$PLAIK_DATA_DIR" \
        --shell /usr/sbin/nologin \
        "$PLAIK_SERVICE_USER"
fi

PLAIK_GROUP=$(id -gn "$PLAIK_SERVICE_USER")
install -d -m 0755 -o root -g root "$PLAIK_RUNTIME_DIR"
install -d -m 0700 -o "$PLAIK_SERVICE_USER" -g "$PLAIK_GROUP" "$PLAIK_DATA_DIR"
install -d -m 0750 -o root -g "$PLAIK_GROUP" "$PLAIK_CONFIG_DIR"
install -d -m 0750 -o "$PLAIK_SERVICE_USER" -g "$PLAIK_GROUP" "$PLAIK_LOG_DIR"
install -d -m 0755 -o root -g root "$PLAIK_RUNTIME_DIR/bootstrap/bin"
install -d -m 0755 -o root -g root "$PLAIK_RUNTIME_DIR/bootstrap/python"

TMP_DIR=$(mktemp -d)
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

UV_BIN="$PLAIK_RUNTIME_DIR/bootstrap/bin/uv"
if [ ! -x "$UV_BIN" ]; then
    UV_INSTALLER="$TMP_DIR/uv-install.sh"
    curl -fsSL \
        "https://astral.sh/uv/${PLAIK_UV_VERSION}/install.sh" \
        -o "$UV_INSTALLER"
    env \
        UV_UNMANAGED_INSTALL="$PLAIK_RUNTIME_DIR/bootstrap/bin" \
        UV_NO_MODIFY_PATH=1 \
        sh "$UV_INSTALLER"
fi

export UV_PYTHON_INSTALL_DIR="$PLAIK_RUNTIME_DIR/bootstrap/python"
"$UV_BIN" python install 3.12 >/dev/null
rm -rf "$PLAIK_RUNTIME_DIR/venv"
"$UV_BIN" venv --python 3.12 "$PLAIK_RUNTIME_DIR/venv" >/dev/null
PYTHON_BIN="$PLAIK_RUNTIME_DIR/venv/bin/python"

resolve_release_assets() {
    "$PYTHON_BIN" - "$PLAIK_RELEASE_REPOSITORY" "$PLAIK_RELEASE_TAG" <<'PY'
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
    wheel_url = str(wheel.get("browser_download_url", ""))
    checksum_url = str(checksums[0].get("browser_download_url", ""))
    prefix = f"https://github.com/{repository}/releases/download/"
    if not wheel_url.startswith(prefix) or not checksum_url.startswith(prefix):
        raise SystemExit("release asset URL is outside the configured PLAIK repository")
    return wheel_url, checksum_url

runtime = pair(runtime_wheels[0])
sdk = pair(sdk_wheels[0])
print(runtime[0])
print(runtime[1])
print(sdk[0])
print(sdk[1])
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
    curl -fsSL "$wheel_url" -o "$destination"
    curl -fsSL --max-filesize 4096 "$checksum_url" -o "$checksum_path"
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
else
    ASSET_INFO="$TMP_DIR/assets.txt"
    resolve_release_assets > "$ASSET_INFO"
    WHEEL_URL=$(sed -n '1p' "$ASSET_INFO")
    CHECKSUM_URL=$(sed -n '2p' "$ASSET_INFO")
    SDK_WHEEL_URL=$(sed -n '3p' "$ASSET_INFO")
    SDK_CHECKSUM_URL=$(sed -n '4p' "$ASSET_INFO")
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

"$UV_BIN" pip install --python "$PYTHON_BIN" "$SDK_WHEEL_PATH" "$WHEEL_PATH" >/dev/null

ENV_FILE="$PLAIK_CONFIG_DIR/plaik.env"
if [ ! -f "$ENV_FILE" ]; then
    INSTALLER_TOKEN=$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(48))')
    umask 027
    cat > "$ENV_FILE" <<EOF
PLAIK_DATA_DIR=$PLAIK_DATA_DIR
PLAIK_INSTALLER_TOKEN=$INSTALLER_TOKEN
PLAIK_ADMIN_PATH=/control-center
EOF
fi
chown root:"$PLAIK_GROUP" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

write_unit() {
    UNIT_PATH=$1
    ENTRYPOINT=$2
    PORT=$3
    DESCRIPTION=$4
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=$DESCRIPTION
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$PLAIK_SERVICE_USER
Group=$PLAIK_GROUP
EnvironmentFile=$ENV_FILE
WorkingDirectory=$PLAIK_DATA_DIR
ExecStart=$PLAIK_RUNTIME_DIR/venv/bin/uvicorn $ENTRYPOINT --host 127.0.0.1 --port $PORT --workers 1
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
ReadOnlyPaths=$PLAIK_RUNTIME_DIR $PLAIK_CONFIG_DIR
ReadWritePaths=$PLAIK_DATA_DIR $PLAIK_LOG_DIR

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$UNIT_PATH"
}

write_unit /etc/systemd/system/plaik-installer.service plaik_installer.app:app 8765 "PLAIK setup service"
write_unit /etc/systemd/system/plaik-web.service plaik_web.app:app 8080 "PLAIK Web"
write_unit /etc/systemd/system/plaik-admin.service plaik_admin.app:app 8081 "PLAIK Admin"

ln -sfn "$PLAIK_RUNTIME_DIR/venv/bin/plaik" /usr/local/bin/plaik
systemctl daemon-reload

if [ -f "$PLAIK_DATA_DIR/install-state.json" ] \
    && grep -Eq '"state"[[:space:]]*:[[:space:]]*"completed"' "$PLAIK_DATA_DIR/install-state.json"; then
    systemctl disable --now plaik-installer.service >/dev/null 2>&1 || true
    systemctl enable --now plaik-web.service plaik-admin.service >/dev/null
    echo "PLAIK runtime reinstalled; existing completed installation was preserved."
else
    systemctl disable --now plaik-web.service plaik-admin.service >/dev/null 2>&1 || true
    systemctl enable --now plaik-installer.service >/dev/null
    echo "PLAIK system bootstrap completed."
    echo
    echo "Next step:"
    echo "  sudo plaik setup"
fi
