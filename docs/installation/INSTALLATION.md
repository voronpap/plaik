# PLAIK installation

PLAIK uses a two-stage installation model. Stage 2 for a normal operator is
the local web installer. `sudo plaik setup` remains as headless automation
and recovery fallback.

## Stage 1 — system bootstrap

The system bootstrap prepares the host and installs the PLAIK runtime. It does
not ask for a domain, database identity, administrator account or theme.

Supported bootstrap hosts in the first release:

- Debian or Ubuntu;
- systemd as PID 1;
- `apt-get`;
- root access;
- outbound HTTPS access to the PLAIK release repository and dependency sources.

The host does **not** need Python 3.12 preinstalled. The bootstrap installs a
private `uv` bootstrap under `/opt/plaik/bootstrap`, installs a managed Python
3.12 there and creates `/opt/plaik/venv`.

Recommended invocation:

```bash
curl -fsSL https://github.com/voronpap/plaik/releases/latest/download/install.sh -o install.sh
sudo sh install.sh
```

The bootstrap creates:

```text
/opt/plaik/current     atomic runtime symlink
/opt/plaik/releases    verified runtime versions
/etc/plaik/            host configuration; installer token only in installer.env
/var/lib/plaik/        persistent PLAIK data
/var/log/plaik/        service logs/runtime log target
```

and installs loopback-only systemd services with separate Unix identities:

```text
plaik-installer.service  127.0.0.1:8765  User=plaik-installer
plaik-web.service        127.0.0.1:8080  User=plaik-public
plaik-admin.service      127.0.0.1:8081  User=plaik-admin
```

Before setup is complete only the installer service is enabled. After setup is
sealed the installer service is disabled and Web/Admin are enabled.

Release installation is fail-closed: the GitHub Release must contain exactly one
PLAIK runtime wheel, exactly one PLAIK SDK wheel, and a matching `<wheel>.sha256`
asset for each. For development only, local wheels can be supplied together with
`--wheel` and `--sdk-wheel`, optionally with `PLAIK_WHEEL_SHA256` and
`PLAIK_SDK_WHEEL_SHA256`.

## Stage 2 — PLAIK setup

This is the product configuration stage. The domain belongs here, not in the
system bootstrap. The Web Installer listens only on `127.0.0.1:8765`. It does
not bind a LAN or public address, does not add a firewall exception, and does
not sit behind a reverse proxy. Remote access is an SSH local forward from a
computer that already has SSH access to the server.

The CLI is an adapter over the existing installer API and Core state machine;
it does not implement a second set of database/theme/admin lifecycle rules.
The web wizard uses the same API. Both remain resumable from persisted Core
state. After COMPLETED they request the same privileged service finalization.
The canonical sequence remains:

```text
NOT_STARTED
→ REQUIREMENTS_CHECKED
→ CONFIGURED
→ DATABASE_READY
→ ADMIN_READY
→ THEME_READY
→ COMPLETED
```

The setup is resumable. Re-running `sudo plaik setup` continues from the
persisted installer state.

### Local installation

If the browser runs on the same machine as PLAIK, open:

```text
http://127.0.0.1:8765/
```

### Remote installation over SSH

If Stage 1 was installed over SSH, keep that session on the server and run
the tunnel command **on your local computer**, in a second terminal. Do not
run it inside the SSH session on the server.

Linux, macOS, and Windows PowerShell use the same OpenSSH command:

```powershell
ssh -N -L 8765:127.0.0.1:8765 user@server
```

For a non-standard SSH port:

```powershell
ssh -p 2222 -N -L 8765:127.0.0.1:8765 user@server
```

The command is the same for SSH key and SSH password logins. If this server
asks for a password, OpenSSH prompts for it in that local terminal. Do not
put the password on the command line.

Then open:

```text
http://127.0.0.1:8765/
```

The browser runs on your local computer. The SSH tunnel forwards local port
`8765` to the server's loopback port `8765`. Keep the tunnel open until Stage
2 finishes. After confirmed handoff (`installer` off, Web/Admin on, installer
token revoked) port `8765` is no longer needed and the tunnel can be closed.

### CLI fallback

Headless automation and recovery remain:

```bash
sudo plaik setup
```

### Interactive setup

Production setup first shows detected host state (PostgreSQL listeners,
inspectable local databases and PLAIK backup artifacts). It then asks for:

- domain (stored as the production HTTPS public URL);
- locale and timezone;
- PostgreSQL source: `use-detected`, `create`, `manual` or `restore`;
- PostgreSQL endpoint/database, including the port;
- distinct migration, runtime and checkpoint PostgreSQL identities;
- database passwords, written to the PLAIK local secret provider without being
  stored in installer configuration;
- first administrator email and password;
- default theme activation.

`use-detected` selects an empty local `plaik` database when one is visible.
`create` provisions an empty local loopback database plus the three production
roles through the host `postgres` peer identity. It refuses occupied databases,
Docker listeners without local peer access, and foreign SQL dumps. `restore` is
rejected: dump restore is a separate operational procedure, not Stage 2 setup.
`manual` lets you enter host, port and database yourself. The host must still
be loopback in this release.

SQLite is accepted only in development/reference modes, matching the Core
installer configuration contract.

### Non-interactive setup

For automation:

```bash
sudo plaik setup --non-interactive --config /root/plaik-install.toml
```

Example:

```toml
[site]
mode = "production"
domain = "example.com"
locale = "uk-UA"
timezone = "Europe/Kyiv"
group_id = "default-group"
store_id = "default-store"

[database]
backend = "postgresql"
host = "127.0.0.1"
port = 5432
database = "plaik"
username = "plaik_migrator"
runtime_username = "plaik_runtime"
checkpoint_username = "plaik_checkpoint"
ssl_mode = "require"
# source = "create"   # provision empty local DB+roles when none exists
# provision = true    # same as source = "create"
password_env = "PLAIK_DB_MIGRATOR_PASSWORD"
runtime_password_env = "PLAIK_DB_RUNTIME_PASSWORD"
checkpoint_password_env = "PLAIK_DB_CHECKPOINT_PASSWORD"

[admin]
email = "admin@example.com"
password_env = "PLAIK_ADMIN_PASSWORD"
```

Secrets are supplied through environment variables, not plaintext TOML.

## Operational installation commands

```bash
plaik status
plaik status --json
plaik doctor
```

### Reset for development/testing

```bash
sudo plaik reset
sudo plaik reset --yes
```

`reset` removes installation state/local application data but keeps the runtime
installed and re-enables the setup service. A completed production installation
requires the explicit `--force-production` guard. Backups are preserved unless
`--purge-backups` is supplied.

### Uninstall

Normal uninstall removes runtime and systemd units but preserves configuration
and application data:

```bash
sudo plaik uninstall
```

Preview:

```bash
sudo plaik uninstall --dry-run
```

Full local purge for disposable test hosts:

```bash
sudo plaik uninstall --purge --yes
```

PLAIK never drops an external PostgreSQL database or external PostgreSQL roles
from the uninstall command. Database destruction must remain a separate,
explicit operator action.

## Security boundaries

- Installer API binds to loopback only (`127.0.0.1:8765`). Remote Stage 2
  access is an SSH local forward, not a LAN/public listener or firewall
  opening.
- The installer token is generated during system bootstrap and stored under
  `/etc/plaik` with restricted permissions.
- PLAIK services run as three dedicated identities: `plaik-installer`,
  `plaik-admin` and `plaik-public`.
- Stage 2 PostgreSQL in this release is loopback-only (`127.0.0.1` /
  `localhost` / `::1`), matching the public Web unit which may reach
  localhost only.
- Runtime files are read-only to the service account; persistent writes are
  restricted to PLAIK data/log paths.
- Database passwords are persisted through the existing local secret provider,
  not inside `installer-config.json`.
- Completing setup seals the installer configuration, disables the installer
  systemd service, and revokes the installer token. The SSH tunnel to port
  `8765` can be closed after that confirmed handoff.

## Not part of Stage 1

Reverse proxy and public TLS termination are intentionally not part of the
system bootstrap. The domain is selected during Stage 2. Public HTTPS gateway
configuration is a separate deployment adapter so Core installation does not
become coupled to a specific proxy implementation.
