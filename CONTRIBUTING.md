# Contributing to PLAIK

PLAIK is a modular platform with strict boundaries between the domain-neutral runtime and extension code.

## Before changing code

1. Read the relevant public architecture and specification documents.
2. Search for an existing contract before adding a new interface.
3. Add or update public acceptance criteria for non-trivial behavior where appropriate.
4. Keep product-domain logic out of Core.
5. Preserve backwards compatibility unless the change is explicitly versioned as breaking.

## Repository responsibilities

- `plaik`: runtime, Core, Installer, Admin, Web app, CLI and distribution assembly.
- `plaik-sdk`: public contracts, SDK, schemas, validators, scaffolding and developer tooling.
- `plaik-packages`: official modules, integrations, themes and packs.

Extensions must depend on supported public contracts/SDK rather than private Core implementation details.

Internal PLAIK test suites, agent instructions, CI/release gates and operational infrastructure are maintained privately and are not part of the public contribution surface.

## Security

Never commit credentials, private keys, production `.env` files, customer data or host-specific secret material. See `SECURITY.md` for vulnerability reporting.

## Build wheels

From `plaik-sdk`, then from `plaik`:

```bash
python -m pip install build
python -m build
```

A release installation expects exactly one runtime wheel, exactly one SDK
wheel, and a matching `<wheel>.sha256` file for each. Do not publish those
assets by retagging a frozen GitHub Release.

## Quality

Public changes should include clear behavior, compatibility impact and documentation. Final release validation is performed through private internal gates before publication.
