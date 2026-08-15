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
FORCE=0

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh [--force] [--wheel /path/to/plaik.whl]

System bootstrap only. It installs the PLAIK runtime and systemd services.
Domain, database and administrator configuration happens later with:

    sudo plaik setup

Environment overrides:
  PLAIK_RELEASE_TAG       release tag to install instead of latest
  PLAIK_WHEEL_FILE        local wheel for development/testing
  PLAIK_WHEEL_SHA256      expected SHA-256 for a local wheel
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
assets = release.get("assets") or []
wheels = [
    item for item in assets
    if isinstance(item, dict)
    and str(item.get("name", "")).startswith("plaik-")
    and str(item.get("name", "")).endswith(".whl")
]
if len(wheels) != 1:
    raise SystemExit("release must contain exactly one PLAIK runtime wheel")
wheel = wheels[0]
checksum_name = str(wheel["name"]) + ".sha256"
checksums = [item for item in assets if item.get("name") == checksum_name]
if len(checksums) != 1:
    raise SystemExit(f"release is missing checksum asset: {checksum_name}")
print(wheel["browser_download_url"])
print(checksums[0]["browser_download_url"])
PY
}

if [ -n "$PLAIK_WHEEL_FILE" ]; then
    if [ ! -f "$PLAIK_WHEEL_FILE" ]; then
        echo "install.sh: local wheel does not exist: $PLAIK_WHEEL_FILE" >&2
        exit 1
    fi
    WHEEL_PATH=$PLAIK_WHEEL_FILE
    if [ -n "$PLAIK_WHEEL_SHA256" ]; then
        ACTUAL=$(sha256sum "$WHEEL_PATH" | awk '{print $1}')
        if [ "$ACTUAL" != "$PLAIK_WHEEL_SHA256" ]; then
            echo "install.sh: local wheel SHA-256 mismatch" >&2
            exit 1
        fi
    else
        echo "install.sh: warning: local development wheel has no explicit SHA-256" >&2
    fi
else
    ASSET_INFO="$TMP_DIR/assets.txt"
    resolve_release_assets > "$ASSET_INFO"
    WHEEL_URL=$(sed -n '1p' "$ASSET_INFO")
    CHECKSUM_URL=$(sed -n '2p' "$ASSET_INFO")
    [ -n "$WHEEL_URL" ] && [ -n "$CHECKSUM_URL" ] || {
        echo "install.sh: release asset resolution failed" >&2
        exit 1
    }
    WHEEL_PATH="$TMP_DIR/$(basename "$WHEEL_URL")"
    CHECKSUM_PATH="$TMP_DIR/$(basename "$CHECKSUM_URL")"
    curl -fsSL "$WHEEL_URL" -o "$WHEEL_PATH"
    curl -fsSL "$CHECKSUM_URL" -o "$CHECKSUM_PATH"
    EXPECTED=$(awk 'NF {print $1; exit}' "$CHECKSUM_PATH")
    ACTUAL=$(sha256sum "$WHEEL_PATH" | awk '{print $1}')
    if [ -z "$EXPECTED" ] || [ "$ACTUAL" != "$EXPECTED" ]; then
        echo "install.sh: release wheel SHA-256 mismatch" >&2
        exit 1
    fi
fi

"$UV_BIN" pip install --python "$PYTHON_BIN" "$WHEEL_PATH" >/dev/null

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
