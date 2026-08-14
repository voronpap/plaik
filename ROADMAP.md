# PLAIK bootstrap roadmap

## Public repository bootstrap

- [x] Create public `plaik` repository.
- [x] Add Apache-2.0 license and public security/contribution policy.
- [x] Define the three-repository architecture.
- [ ] Import a clean runtime snapshot without private deployment/evidence history.
- [ ] Rename user-facing product identifiers from Modularis to PLAIK.
- [ ] Add CI and run the complete public validation gate.

## Companion repositories

- [ ] Publish `plaik-sdk` and extract public contracts/SDK without breaking the runtime.
- [ ] Publish `plaik-packages` for official modules, integrations, themes and packs.
- [ ] Release a compatibility matrix between runtime, SDK and official packages.

## Before first tagged release

- [ ] Replace compatibility package/CLI identifiers where migration is safe.
- [ ] Add clean-install and upgrade evidence generated only from public-safe test fixtures.
- [ ] Add extension author documentation and a minimal example package.
- [ ] Define semantic versioning and deprecation policy.
