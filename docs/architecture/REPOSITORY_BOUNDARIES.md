# PLAIK repository boundaries

Status: accepted bootstrap architecture

PLAIK is split by release responsibility and dependency direction, not by arbitrary directory size.

## 1. `plaik`

Owns the executable platform distribution:

- Core runtime and domain-neutral mechanisms;
- Installer, Admin and Storefront process compositions;
- CLI and distribution assembly;
- Core migrations and persistence adapters;
- package lifecycle/runtime orchestration;
- the protected default fallback theme;
- generic reference configuration required to install and run the platform.

It may depend on released public interfaces from `plaik-sdk`.

It must not contain customer-specific production configuration, production credentials or host-specific operational evidence.

## 2. `plaik-sdk`

Owns the supported extension-development surface:

- stable public contracts and types;
- SDK helpers and protocol surfaces;
- package manifest/schema definitions;
- extension compatibility and validation tooling;
- extension test harness and scaffolding;
- public examples for module/theme/integration authors.

`plaik-sdk` must remain usable without importing private PLAIK Core implementation details.

## 3. `plaik-packages`

Owns official installable packages:

- business modules;
- external integrations;
- installable themes other than the protected Core fallback;
- packs that select compatible package sets.

Commerce is one package family, not the architecture boundary of this repository.

Examples include catalog, inventory, cart, checkout, orders, payments, shipping and `commerce-standard`.

## Dependency direction

```text
              plaik-sdk
              /      \
             v        v
          plaik    plaik-packages
```

`plaik` and `plaik-packages` depend on released SDK/contracts. `plaik-packages` does not import private Core code. `plaik` does not depend on business packages to remain operational as a platform.

No Git submodules are used for normal product composition. Cross-repository dependencies are released/versioned artifacts with explicit compatibility ranges.

## Private operations

Host-specific deployment automation, nginx/systemd configuration containing environment topology, backup destinations, recovery authority and production evidence belong in a separate private operations repository or private infrastructure system.

## Release consequence

The platform runtime can release independently of official packages. SDK compatibility is versioned explicitly. Official packages declare the SDK/platform versions they support.
