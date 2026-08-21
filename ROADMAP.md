# PLAIK bootstrap roadmap

## Public repository bootstrap

- [x] Create public `plaik` repository.
- [x] Add Apache-2.0 license and public security/contribution policy.
- [x] Define the three-public-repository architecture plus private internal control-plane.
- [ ] Complete the clean runtime snapshot without private deployment, tests or evidence history.
- [x] Use PLAIK-native user-facing product identifiers.
- [x] Publish reproducible build and release instructions without exposing internal CI/test implementation.

## Companion repositories

- [x] Publish `plaik-sdk` and extract public contracts/SDK.
- [x] Publish `plaik-packages` for official modules, integrations, themes and packs.
- [x] Create private `plaik-internal` for tests, agent instructions, CI/release gates, operations and evidence.
- [x] Release a compatibility matrix between runtime, SDK and official packages.

## Before first tagged release

- [ ] Complete runtime import closure and private regression migration.
- [x] Verify official-module PostgreSQL install/upgrade/uninstall through private acceptance suites.
- [ ] Verify host clean install from a published 0.4 GitHub Release (separate owner publication).
- [ ] Add extension author documentation and a minimal public example package.
- [ ] Define semantic versioning and deprecation policy.
