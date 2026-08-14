# Public snapshot migration

The PLAIK public repository is initialized as a clean snapshot rather than by publishing the private development repository history.

## Included

- domain-neutral Core runtime;
- Installer, Admin and Storefront application compositions;
- public specifications required to use and integrate the runtime;
- protected fallback theme;
- generic build and packaging tooling required by users.

## Excluded

- internal test suites and fixtures;
- agent instructions and private engineering workflow;
- internal CI, release gates and acceptance evidence;
- production-host configuration;
- hostnames, local users, database role names and backup destinations tied to a live environment;
- environment-specific operational evidence;
- private operations automation;
- credentials, keys and `.env` data;
- business packages that belong in `plaik-packages`.

Internal validation remains mandatory before release, but its implementation lives in private `plaik-internal` rather than in the public source repositories.

Public contracts/SDK may temporarily remain in-tree during bootstrap only until the companion `plaik-sdk` release exists; extraction must preserve compatibility.
