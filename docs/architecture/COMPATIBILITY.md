# PLAIK compatibility

This is the public 0.4 compatibility contract. Version ranges are inclusive on
the lower bound and exclusive on the upper bound.

| Component | Version | Requires |
|---|---|---|
| PLAIK runtime (`plaik`) | 0.4.x | `plaik-sdk>=0.4.0,<0.5.0` |
| PLAIK SDK (`plaik-sdk`) | 0.4.x | Python >= 3.12 |
| Official modules `catalog`, `inventory`, `pricing`, `search`, `seo` | 1.0.x | Core `>=0.4.0,<0.5.0`; depend only on released `plaik-sdk` |
| Pack `auto-parts-pack` | 0.1.x | those modules `>=1.0.0,<2.0.0`; Core `>=0.4.0,<0.5.0` |

Official packages must not import `plaik_core`. Cross-package behavior uses
declared services, events, hooks, slots or public SDK contracts. Package SQL
is namespaced per package; one package must not read another package's tables.

Cart, checkout, orders, payments, shipping and promotions are not part of 0.4.
The bundled Default theme remains the protected fallback presentation; it is
not a commerce storefront.

A published GitHub Release is a separate operator/publication step. This matrix
describes source and wheel compatibility, not a specific GitHub tag.
