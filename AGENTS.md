# AGENTS.md — PLAIK

Canonical engineering rules for this repository.

## Priorities

Optimize in this order:

1. correctness;
2. security and data integrity;
3. maintainability and explicit contracts;
4. testable behavior;
5. delivery speed.

## Work loop

```text
Inspect -> understand -> search existing code -> specify -> plan
-> implement -> test -> review -> verify -> document
```

For non-trivial capabilities, update the relevant contract/specification together with the implementation. Do not weaken tests or security gates to obtain a green build.

## Repository boundary

This repository owns the PLAIK runtime and distribution:

- Core platform mechanisms;
- Installer, Admin and Storefront application compositions;
- CLI and distribution assembly;
- the protected default fallback theme;
- runtime migrations, persistence adapters and operational primitives required by Core.

The companion repositories own:

- **`plaik-sdk`** — public contracts, SDK, schemas, extension test harness and developer tooling;
- **`plaik-packages`** — official modules, integrations, themes and packs.

Private host deployment, credentials and production operational evidence do not belong in public product repositories.

## Architecture — non-negotiable

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

Core must not own products, catalog, inventory, carts, customers, checkout, orders, payments, shipping, pricing, promotions, tax policy, reviews or other commerce-domain implementation.

Extensions depend only on supported public contracts/SDK. They must not import another extension's private code or access another extension's tables directly. Cross-extension behavior uses declared services, events, hooks, slots or public APIs.

## Security

Every change must consider authentication, authorization, IDOR, SQL injection, XSS, CSRF, SSRF, path traversal, unsafe archive/upload handling, command execution, package signatures, secret handling, logging/redaction, concurrency, rollback and partial failure where applicable.

Never commit production credentials, private keys, `.env`, customer data or host-specific secret material.

## Testing

Use narrow regression tests while developing and full repository gates before claiming completion. Do not report a pass from memory or another repository/session.

Completion reports must distinguish:

- verified now;
- not run;
- blocked/pending;
- assumptions.

## Git safety

Preserve unrelated changes. Do not rewrite shared history or perform destructive cleanup without explicit approval. Keep commits scoped and reviewable.
