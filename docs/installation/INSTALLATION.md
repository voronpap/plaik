# PLAIK installation

PLAIK uses a two-stage, terminal-first installation model.

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
/opt/plaik/        runtime, bootstrap tooling and virtual environment
/etc/plaik/        host configuration and installer token
/var/lib/plaik/    persistent PLAIK data
/var/log/plaik/    service logs/runtime log target
```

and installs three loopback-only systemd services:

```text
plaik-installer.service  127.0.0.1:8765
plaik-web.service        127.0.0.1:8080
plaik-admin.service      127.0.0.1:8081
```

Before setup is complete only the installer service is enabled. After setup is
sealed the installer service is disabled and Web/Admin are enabled.

Release installation is fail-closed: the GitHub Release must contain exactly one
PLAIK runtime wheel, exactly one PLAIK SDK wheel, and a matching `<wheel>.sha256`
asset for each. For development only, local wheels can be supplied together with
`--wheel` and `--sdk-wheel`, optionally with `PLAIK_WHEEL_SHA256` and
`PLAIK_SDK_WHEEL_SHA256`.

## Stage 2 — PLAIK setup

Run:

```bash
sudo plaik setup
```

This is the product configuration stage. The domain belongs here, not in the
system bootstrap.

The CLI is an adapter over the existing installer API and Core state machine;
it does not implement a second set of database/theme/admin lifecycle rules.
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

### Interactive setup

Production setup asks for:

- domain (stored as the production HTTPS public URL);
- locale and timezone;
- PostgreSQL endpoint/database;
- distinct migration, runtime and checkpoint PostgreSQL identities;
- database passwords, written to the PLAIK local secret provider without being
  stored in installer configuration;
- first administrator email and password;
- default theme activation.

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

- Installer API binds to loopback by default.
- The installer token is generated during system bootstrap and stored under
  `/etc/plaik` with restricted permissions.
- PLAIK services run as the dedicated `plaik` system user.
- Runtime files are read-only to the service account; persistent writes are
  restricted to PLAIK data/log paths.
- Database passwords are persisted through the existing local secret provider,
  not inside `installer-config.json`.
- Completing setup seals the installer configuration and disables the installer
  systemd service.

## Not part of Stage 1

Reverse proxy and public TLS termination are intentionally not part of the
system bootstrap. The domain is selected during Stage 2. Public HTTPS gateway
configuration is a separate deployment adapter so Core installation does not
become coupled to a specific proxy implementation.
