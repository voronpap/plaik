# Public snapshot migration

The PLAIK public repository is initialized as a clean snapshot rather than by publishing the private development repository history.

## Included

- domain-neutral Core runtime;
- Installer, Admin and Storefront application compositions;
- public-safe tests and specifications required to verify the runtime;
- protected fallback theme;
- generic build and CI tooling.

## Excluded

- production-host configuration;
- hostnames, local users, database role names and backup destinations tied to a live environment;
- `docs/evidence` records containing environment-specific operational topology;
- private operations automation;
- credentials, keys and `.env` data;
- business packages that belong in `plaik-packages`.

The snapshot must remain buildable and testable. Public contracts/SDK may temporarily remain in-tree during bootstrap only until the companion `plaik-sdk` release exists; extraction must preserve compatibility and executable tests.
