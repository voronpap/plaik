# PLAIK bootstrap roadmap

## Public repository bootstrap

- [x] Create public `plaik` repository.
- [x] Add Apache-2.0 license and public security/contribution policy.
- [x] Define the three-public-repository architecture plus private internal control-plane.
- [ ] Import a clean runtime snapshot without private deployment, tests or evidence history.
- [ ] Rename user-facing product identifiers from Modularis to PLAIK.
- [ ] Publish reproducible build and release instructions without exposing internal CI/test implementation.

## Companion repositories

- [ ] Publish `plaik-sdk` and extract public contracts/SDK without breaking the runtime.
- [ ] Publish `plaik-packages` for official modules, integrations, themes and packs.
- [ ] Create private `plaik-internal` for tests, agent instructions, CI/release gates, operations and evidence.
- [ ] Release a compatibility matrix between runtime, SDK and official packages.

## Before first tagged release

- [ ] Replace compatibility package/CLI identifiers where migration is safe.
- [ ] Verify clean install and upgrade through private acceptance suites.
- [ ] Add extension author documentation and a minimal public example package.
- [ ] Define semantic versioning and deprecation policy.
