# PLAIK

**PLAIK — Platform for Local Automation, Integration & Knowledge**

PLAIK is a modular application platform built around a small domain-neutral core and explicit extension contracts, with local automation, integration and knowledge as its product focus.

The name also echoes the Ukrainian Carpathian word **плаїк** — a small mountain path or trail.

> Status: 0.2.0 is the first published production runtime. Installer hardening after that review ships as 0.2.1 and does not overwrite the published v0.2.0 assets. The public repository contains product source and public documentation only. Internal tests, agent instructions, CI gates, deployment infrastructure and operational evidence are kept in a separate private repository.

## Project layout

PLAIK is intentionally split into three public repositories:

- **`plaik`** — runtime, Core, Installer, Admin, Web app (`plaik_web`), CLI, default theme and distribution assembly;
- **`plaik-sdk`** — public contracts, SDK, schemas, validators, scaffolding and developer documentation;
- **`plaik-packages`** — official modules, integrations, themes and packs, including commerce modules.

Private engineering and operations live in **`plaik-internal`** and are not part of the public product repositories. This includes internal test suites, agent instructions, CI/release gates, host-specific deployment, infrastructure configuration and operational evidence.

## Installation

PLAIK uses a two-stage, terminal-first installation flow on supported Linux hosts:

```bash
curl -fsSL https://github.com/voronpap/plaik/releases/latest/download/install.sh -o install.sh
sudo sh install.sh
sudo plaik setup
```

The first command bootstraps the Linux runtime, private Python environment and systemd services. Domain, database, administrator and theme configuration belongs to the local web wizard at `http://127.0.0.1:8765/` while the installer service is open. The wizard binds loopback only; from another computer use an SSH tunnel as documented in [`docs/installation/INSTALLATION.md`](docs/installation/INSTALLATION.md). `sudo plaik setup` remains as the headless automation and recovery fallback.

Operational lifecycle commands include:

```bash
sudo plaik installer-token
plaik status
plaik doctor
sudo plaik reset
sudo plaik uninstall
sudo plaik uninstall --purge --yes
```

See [`docs/installation/INSTALLATION.md`](docs/installation/INSTALLATION.md) for the installation contract, non-interactive TOML setup and reset/uninstall safety rules.

## Core acceptance boundary

**Core 0.2 platform-kernel acceptance** covers the domain-neutral runtime mechanisms, package lifecycle, migrations, identity/session boundaries, audit/integrity, backup/restore contracts, extension runtime, Installer/Admin/Web compositions and the public SDK boundary. Business-domain packages, including commerce modules, and host-specific production operations remain separate scopes and do not redefine Core completion.

Installer, Admin and Web are isolated application compositions. Each application is an independent
  failure domain with its own process/runtime boundary; one application failing must not make another application's health or lifecycle authoritative.

The public completion contract is recorded in [`docs/specs/CORE_DEFINITION_OF_DONE.md`](docs/specs/CORE_DEFINITION_OF_DONE.md). The private acceptance suite is the authoritative regression/security gate for this boundary. Public release readiness additionally requires the public repositories to remain free of legacy product namespaces and deployment-specific private evidence.

## Architecture

```text
Core         = domain-neutral platform mechanisms and gatekeeper
Contracts    = stable public types and extension boundaries
SDK          = supported public integration surface
Modules      = business data and rules
Themes       = web presentation only
Integrations = external providers behind explicit ports
Packs        = compatible extension selections, no implementation
Apps         = isolated Installer, Admin and Web compositions
```

Core does not own catalog, inventory, carts, checkout, orders, payments, shipping, pricing, promotions or other business-domain implementations. Those belong to packages built against the public SDK.

## Repository boundaries

See [`docs/architecture/REPOSITORY_BOUNDARIES.md`](docs/architecture/REPOSITORY_BOUNDARIES.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
