# PLAIK compatibility

This is the public compatibility contract. Version ranges are inclusive on
the lower bound and exclusive on the upper bound.

| Component | Version | Requires |
|---|---|---|
| PLAIK runtime (`plaik`) | 0.4.x | `plaik-sdk>=0.4.0,<0.5.0` |
| PLAIK SDK (`plaik-sdk`) | 0.4.x | Python >= 3.12 |
| Official modules `catalog`, `inventory`, `pricing`, `search`, `seo` | 1.0.x | Core `>=0.4.0,<0.5.0`; depend only on released `plaik-sdk` |
| Official modules `cart`, `orders`, `shipping`, `payments`, `promotions`, `checkout` | 1.0.x | Core `>=0.4.0,<0.5.0`; depend only on released `plaik-sdk` |
| Pack `auto-parts-pack` | 0.2.x | 0.4 proof stack and 0.5 commerce modules `>=1.0.0,<2.0.0`; Core `>=0.4.0,<0.5.0` |

Official packages must not import `plaik_core`. Cross-package behavior uses
declared services, events, hooks, slots or public SDK contracts. Package SQL
is namespaced per package; one package must not read another package's tables.

0.5 commerce modules ship as packages on frozen Core 0.4.0. They do not move
business logic into Core and do not unfreeze the bundled Default theme.

GitHub Release `v0.4.0` is the published 0.4 runtime/SDK tag. Frozen tag
`v0.2.2` remains published and must not be retagged. A 0.5 GitHub Release is
not implied by this matrix.
