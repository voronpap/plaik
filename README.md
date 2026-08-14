# PLAIK

**PLAIK** is a modular application platform built around a small domain-neutral core and explicit extension contracts.

The name comes from the Ukrainian Carpathian word **плаїк** — a small mountain path or trail.

> Status: pre-release. The public repository contains product source and public documentation only. Internal tests, agent instructions, CI gates, deployment infrastructure and operational evidence are kept in a separate private repository.

## Project layout

PLAIK is intentionally split into three public repositories:

- **`plaik`** — runtime, Core, Installer, Admin, Storefront shell, CLI, default theme and distribution assembly;
- **`plaik-sdk`** — public contracts, SDK, schemas, validators, scaffolding and developer documentation;
- **`plaik-packages`** — official modules, integrations, themes and packs, including commerce packages.

Private engineering and operations live in **`plaik-internal`** and are not part of the public product repositories. This includes internal test suites, agent instructions, CI/release gates, host-specific deployment, infrastructure configuration and operational evidence.

## Architecture

```text
Core         = domain-neutral platform mechanisms and gatekeeper
Contracts    = stable public types and extension boundaries
SDK          = supported public integration surface
Modules      = business data and rules
Themes       = storefront presentation only
Integrations = external providers behind explicit ports
Packs        = compatible extension selections, no implementation
Apps         = isolated Installer, Admin and Storefront compositions
```

Core does not own catalog, inventory, carts, checkout, orders, payments, shipping, pricing, promotions or other business-domain implementations. Those belong to packages built against the public SDK.

## Repository boundaries

See [`docs/architecture/REPOSITORY_BOUNDARIES.md`](docs/architecture/REPOSITORY_BOUNDARIES.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
