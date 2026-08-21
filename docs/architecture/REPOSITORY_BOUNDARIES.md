# PLAIK repository boundaries

Status: accepted bootstrap architecture

PLAIK is split by release responsibility and dependency direction, not by arbitrary directory size.

## 1. `plaik`

Owns the executable platform distribution:

- Core runtime and domain-neutral mechanisms;
- Installer, Admin and Web process compositions;
- public Web application namespace `plaik_web`;
- CLI and distribution assembly;
- Core migrations and persistence adapters;
- package lifecycle/runtime orchestration;
- the protected default fallback theme;
- generic reference configuration required to install and run the platform.

It may depend on released public interfaces from `plaik-sdk`.

It must not contain internal tests, agent instructions, private CI/release gates, customer-specific production configuration, credentials or host-specific operational evidence.

## 2. `plaik-sdk`

Owns the supported extension-development surface:

- stable public contracts and types;
- SDK helpers and protocol surfaces;
- package manifest/schema definitions;
- public compatibility validators;
- scaffolding and developer tooling;
- public examples for module/theme/integration authors.

`plaik-sdk` must remain usable without importing private PLAIK Core implementation details. Internal PLAIK acceptance/regression/security test suites do not belong here.

## 3. `plaik-packages`

Owns official installable packages:

- business modules;
- external integrations;
- installable themes other than the protected Core fallback;
- packs that select compatible package sets.

Commerce is one package family, not the architecture boundary of this repository.

Examples include catalog, inventory, cart, checkout, orders, payments, shipping and `commerce-standard`.

## 4. `plaik-internal` — private

Owns non-public engineering and operational control-plane material:

- `AGENTS.md` and agent/workflow instructions;
- internal unit, integration, regression, migration, security and acceptance tests;
- private fixtures and test infrastructure;
- CI/release gates and release evidence;
- deployment automation and host-specific infrastructure;
- nginx/systemd/database/backup configuration tied to real environments;
- operational evidence, recovery procedures and internal runbooks.

No production credential, private key or plaintext secret should be committed even to `plaik-internal`; those belong in an external secret store or GitHub encrypted secrets.

## Dependency direction

```text
              plaik-sdk
              /      \
             v        v
          plaik    plaik-packages
             \        /
              \      /
            plaik-internal
           (private validation)
```

`plaik` and `plaik-packages` depend on released SDK/contracts. `plaik-packages` does not import private Core code. `plaik` does not depend on business packages to remain operational as a platform.

`plaik-internal` may consume all three public repositories for validation and release orchestration, but public repositories must never depend on private code in order to install, build or run.

No Git submodules are used for normal product composition. Cross-repository product dependencies are released/versioned artifacts with explicit compatibility ranges.

## Compatibility

See [`COMPATIBILITY.md`](COMPATIBILITY.md) for the 0.4 runtime, SDK and
official-package version ranges.

## Release consequence

The platform runtime can release independently of official packages. SDK compatibility is versioned explicitly. Official packages declare the SDK/platform versions they support. Releases are validated privately before publication; the public repositories contain product source and reproducible build/use documentation rather than the internal validation implementation.
