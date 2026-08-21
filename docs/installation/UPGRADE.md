# Upgrade

Use this document with [`INSTALLATION.md`](INSTALLATION.md) and
[`../architecture/COMPATIBILITY.md`](../architecture/COMPATIBILITY.md).

## 0.3 to 0.4

0.4 is Official Modules Foundation. The 0.3 kernel remains the domain-neutral
platform base. 0.4 runtime and SDK are versioned `0.4.x` and host official
business modules from `plaik-packages` through released `plaik-sdk`.

The published GitHub Release tag `v0.2.2` is a frozen snapshot. Do not retag
it. Publishing a 0.4 GitHub Release is a separate owner decision; until that
publication, install 0.4 from matching local wheels as documented in
`INSTALLATION.md`.

## Clean install

Follow the two-stage bootstrap in `INSTALLATION.md`. Until a 0.4 GitHub
Release exists, supply matching local 0.4 runtime and SDK wheels with
`--wheel` and `--sdk-wheel`. After setup is sealed, install official modules
from `plaik-packages` — `catalog`, then `inventory` and `pricing`, then
`search` and `seo`. The `auto-parts-pack` pack selects that compatible set.

Package SQL migrations run through package lifecycle. Do not apply module SQL
by hand.

## Upgrade an existing 0.3 installation

1. Take a PLAIK backup and confirm that restore works on a non-production host.
2. Install the 0.4 runtime wheel and a matching `plaik-sdk` 0.4.x wheel. Keep
   the same two-stage host layout; for a controlled host supply `--wheel` and
   `--sdk-wheel` with matching `.sha256` files.
3. After the 0.4 runtime is running, install the official 1.0.x modules in the
   order above (or install `auto-parts-pack`).
4. Re-run `plaik doctor` and confirm package status in Admin.
5. Leave the bundled Default theme as the protected fallback. Storefront
   catalog/cart routes are not part of 0.4.

## Rollback

Restore the pre-upgrade backup. Official 0.4 modules require runtime 0.4.x;
they are not compatible with a 0.3-only runtime. Do not mix 1.0.x official
modules onto a 0.3-only Core.

## Module uninstall

Uninstalling a package drops that package's PostgreSQL LOGIN role and schema.
Other packages and Core data remain. `plaik uninstall` never drops an external
PostgreSQL database or external PostgreSQL roles; that remains a separate
operator action.

## Recovery

`sudo plaik reset` and `sudo plaik uninstall` keep the same safety rules as
`INSTALLATION.md`. A completed production installation still requires
`--force-production` for reset. Backups are preserved unless `--purge-backups`
is supplied.
