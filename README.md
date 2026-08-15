# PLAIK

**PLAIK** is a modular application platform built around a small domain-neutral core and explicit extension contracts.

The name comes from the Ukrainian Carpathian word **плаїк** — a small mountain path or trail.

> Status: pre-release. The public repository contains product source and public documentation only. Internal tests, agent instructions, CI gates, deployment infrastructure and operational evidence are kept in a separate private repository.

## Project layout

PLAIK is intentionally split into three public repositories:

- **`plaik`** — runtime, Core, Installer, Admin, Web app (`plaik_web`), CLI, default theme and distribution assembly;
- **`plaik-sdk`** — public contracts, SDK, schemas, validators, scaffolding and developer documentation;
- **`plaik-packages`** — official modules, integrations, themes and packs, including commerce modules.

Private engineering and operations live in **`plaik-internal`** and are not part of the public product repositories. This includes internal test suites, agent instructions, CI/release gates, host-specific deployment, infrastructure configuration and operational evidence.

## Core acceptance boundary

**Core 0.2 platform-kernel acceptance** covers the domain-neutral runtime mechanisms, package lifecycle, migrations, identity/session boundaries, audit/integrity, backup/restore contracts, extension runtime, Installer/Admin/Web compositions and the public SDK boundary. Business-domain packages, including commerce modules, and host-specific production operations remain separate scopes and do not redefine Core completion.

The private acceptance suite is the authoritative regression/security gate for this boundary. Public release readiness additionally requires the public repositories to remain free of legacy product namespaces and deployment-specific private evidence.

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
