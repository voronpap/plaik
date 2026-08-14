# Contributing to PLAIK

PLAIK is a modular platform with strict boundaries between the domain-neutral runtime and extension code.

## Before changing code

1. Read `AGENTS.md` and the relevant architecture/specification documents.
2. Search for an existing contract before adding a new interface.
3. Add or update acceptance criteria for non-trivial behavior.
4. Keep product-domain logic out of Core.
5. Add regression tests for behavior changes.

## Repository responsibilities

- `plaik`: runtime, Core, Installer, Admin, Storefront shell, CLI and distribution assembly.
- `plaik-sdk`: public contracts, SDK, schemas and developer tooling.
- `plaik-packages`: official modules, integrations, themes and packs.

Extensions must depend on supported public contracts/SDK rather than private Core implementation details.

## Security

Never commit credentials, private keys, production `.env` files, customer data or host-specific secret material. See `SECURITY.md` for vulnerability reporting.

## Quality

A change is not complete until applicable tests, documentation, compatibility, rollback/recovery and security implications are addressed.
