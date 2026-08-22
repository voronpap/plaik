# Upgrade

Use this document with [`INSTALLATION.md`](INSTALLATION.md) and
[`../architecture/COMPATIBILITY.md`](../architecture/COMPATIBILITY.md).

## 0.3 to 0.4

0.4 is Official Modules Foundation. The 0.3 kernel remains the domain-neutral
platform base. 0.4 runtime and SDK are versioned `0.4.x` and host official
business modules from `plaik-packages` through released `plaik-sdk`.

The published GitHub Release tag `v0.2.2` is a frozen snapshot. Do not retag
it. 0.4.0 is published as tag `v0.4.0` and is `releases/latest`. Pin
`PLAIK_RELEASE_TAG=v0.4.0` if you must not follow `latest`.

## 0.4 to 0.5

0.5 is Commerce Runtime. It does **not** bump Core. Install the 0.5 official
modules from `plaik-packages` on frozen runtime `0.4.x`: `cart`, `orders`,
`shipping`, `payments`, `promotions`, then `checkout`. `auto-parts-pack` 0.2.x
selects the 0.4 proof stack plus that commerce set. Package SQL migrations
run through package lifecycle. Do not apply module SQL by hand. Do not retag
`v0.2.2`. Do not unfreeze the bundled Default theme.

## 0.5 to 0.6

0.6 is Integrations & Data. It does **not** bump Core. Install the 0.6 official
integrations from `plaik-packages` on frozen runtime `0.4.x`: `data-exchange`
then `psp-outbound` (payments 1.0.x dispatch is required for recorded capture).
`auto-parts-pack` 0.3.x selects the 0.4 proof stack, 0.5 commerce modules, and
that integration set. Package SQL migrations run through package lifecycle.
Do not apply integration SQL by hand. Do not retag `v0.2.2`. Do not unfreeze
the bundled Default theme. Do not enable live production PSP charges.

## 0.6 to 0.7

0.7 is Multi-store / Scale isolation. It does **not** bump Core. Official
modules already key package SQL by `store_id`. Two `store_id` runtimes on the
same database do not read each other's catalog or payments rows. Payload
`store_id` is ignored. A production installation still has one store; this is
not a multi-store installer. Do not retag `v0.2.2`. Do not unfreeze the bundled
Default theme.

## Clean install

Follow the two-stage bootstrap in `INSTALLATION.md`. `releases/latest` installs
0.4.0. After setup is sealed, install official modules from `plaik-packages` —
`catalog`, then `inventory` and `pricing`, then `search` and `seo`. For 0.5
commerce, also install `cart`, `orders`, `shipping`, `payments`, `promotions`,
and `checkout`. For 0.6 integrations, also install `data-exchange` and
`psp-outbound`. `auto-parts-pack` 0.3.x selects the 0.4 proof stack, 0.5
commerce modules, and that integration set. Local `--wheel` /
`--sdk-wheel` remains valid for controlled hosts.

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
