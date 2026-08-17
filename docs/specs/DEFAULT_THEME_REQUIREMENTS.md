# PLAIK Default Theme — Requirements

## 1. Purpose

`PLAIK Default` is the primary official production-ready theme for PLAIK.

It must be:

- suitable for a real storefront immediately after installation;
- universal across different store types;
- highly configurable without editing theme code;
- fast and performance-first;
- responsive;
- accessible;
- SEO-friendly;
- compatible with official PLAIK modules;
- the reference implementation of the public PLAIK Theme API.

`PLAIK Default` is not the emergency renderer. Core must provide a separate minimal protected system fallback that does not depend on installed theme packages.

## 2. Architecture

The presentation model is:

```text
Template
  -> Sections
    -> Blocks
      -> Slots
        -> Modules / extensions
```

The theme owns presentation only.

The theme must not implement catalog, products, categories, inventory, pricing, carts, wishlist, checkout, orders, payments, shipping, reviews, search, filtering, recommendations, promotions, tax or other business-domain logic.

Those capabilities belong to modules/packages. The theme defines where module UI may render, how supported public components are presented, how pages are composed, and which presentation settings are available.

## 3. Base theme structure

Recommended base structure:

```text
default/
├── manifest.json
├── config/
│   ├── settings.schema.json
│   ├── settings.json
│   └── presets.json
├── templates/
│   ├── home.json
│   ├── product.json
│   ├── category.json
│   ├── search.json
│   ├── cart.json
│   ├── checkout.json
│   ├── account.json
│   ├── page.json
│   ├── error.json
│   └── maintenance.json
├── sections/
├── blocks/
├── snippets/
├── assets/
│   ├── css/
│   ├── js/
│   ├── icons/
│   └── images/
└── locales/
```

## 4. Templates

A template describes page composition instead of containing the complete HTML implementation.

Templates must support:

- ordered sections;
- settings for each section;
- blocks inside sections;
- visibility rules;
- responsive presentation configuration;
- module slots;
- deterministic serialization in a structured format such as JSON.

Example:

```json
{
  "sections": {
    "hero": {
      "type": "hero",
      "settings": {}
    },
    "featured": {
      "type": "product-grid",
      "settings": {}
    }
  },
  "order": ["hero", "featured"]
}
```

## 5. Required page types

The default theme must provide production-ready layouts for:

- home;
- category;
- search results;
- product;
- cart;
- checkout shell;
- account shell;
- static page;
- contact page shell;
- 403;
- 404;
- 500;
- maintenance;
- empty states;
- storefront state when a catalog module is not installed.

## 6. Sections

Sections are the main page-builder units.

Sections must be addable, removable, reorderable, duplicable, enableable/disableable, configurable through schema, block-capable and slot-capable without editing template HTML.

Minimum section set:

### Global

- announcement bar;
- header;
- navigation;
- breadcrumbs;
- footer.

### Home

- hero;
- slideshow;
- image banner;
- video banner;
- text;
- rich text;
- image + text;
- multi-column;
- featured categories;
- featured products;
- product carousel;
- category grid;
- promotional banners;
- brands;
- benefits;
- testimonials slot;
- newsletter slot;
- custom content;
- generic module area.

### Product

- product main;
- media gallery;
- product information;
- price area;
- purchase actions slot;
- attributes/options slot;
- stock information slot;
- description;
- specifications;
- tabs;
- accordion;
- reviews slot;
- related products slot;
- recommendations slot;
- recently viewed slot.

### Category / Search

- heading;
- description;
- category navigation;
- filters slot;
- sorting slot;
- product grid;
- product list;
- pagination;
- infinite-load-compatible container;
- active filters area;
- empty results.

## 7. Blocks

Blocks are reusable fine-grained presentation units.

Minimum block set:

- heading;
- text;
- rich text;
- image;
- icon;
- button;
- link;
- badge;
- divider;
- spacer;
- price;
- product title;
- product image;
- product metadata;
- module slot;
- sanitized custom content;
- navigation item.

Nested blocks may be supported where explicitly allowed by a public schema.

## 8. Slots and module integration

Slots are the stable presentation contract between themes and functional modules.

Example slot names:

```text
header.before
header.logo.after
header.search
header.account
header.cart

home.hero.after
home.featured

category.filters
category.sort
category.product_grid.before
category.product_grid.after

product.media.after
product.info.before
product.price.after
product.purchase
product.tabs
product.reviews
product.recommendations

cart.summary
cart.actions

footer.before
footer.columns
footer.after
```

The theme must not import private module implementation.

Modules may inject UI only through released public Theme/SDK contracts.

An absent optional module must not break page rendering.

## 9. Header builder readiness

Header presentation must support:

- logo;
- text brand;
- desktop navigation;
- mega-menu slot;
- search;
- account;
- wishlist slot;
- comparison slot;
- cart;
- language selector;
- currency selector;
- contact data;
- announcement bar;
- sticky mode;
- transparent mode;
- boxed/full-width layout.

Desktop, tablet and mobile header compositions must be independently configurable. Mobile must not be treated as a merely shrunken desktop header.

## 10. Footer builder readiness

Footer presentation must support:

- configurable columns within schema limits;
- menus;
- text;
- logo;
- contact data;
- social links;
- newsletter slot;
- payment icons;
- delivery icons;
- module slots;
- copyright;
- custom blocks.

## 11. Product card

Product card is a key public presentation contract.

Configurable presentation should include:

- image ratio;
- contain/cover behavior;
- secondary image;
- title position;
- category/vendor visibility;
- price;
- old price;
- discount badge;
- stock badge;
- custom badges;
- rating slot;
- wishlist slot;
- compare slot;
- quick-view slot;
- add-to-cart slot;
- available attribute presentation;
- hover behavior.

Required variants:

- compact;
- standard;
- detailed;
- horizontal.

## 12. Product grid

Required responsive column ranges:

```text
Desktop: 2-6 columns
Tablet:  2-4 columns
Mobile:  1-2 columns
```

The theme must be ready for:

- grid;
- list;
- responsive gaps;
- pagination;
- load more;
- infinite-scroll integration;
- sidebar;
- no-sidebar;
- sticky filters;
- mobile filter drawer.

## 13. Product page layouts

Provide at least three reference compositions:

### Classic

```text
Gallery | Product Info
```

### Wide Gallery

```text
Large Gallery
Product Info
```

### Sticky

```text
Gallery | Sticky Product Info
```

Users must be able to change the order of supported top-level sections through configuration rather than editing template code.

## 14. Category layouts

At minimum:

- full width;
- left sidebar;
- right sidebar;
- top filters;
- mobile filter drawer.

Layout choices must be structured settings, not CSS hacks.

## 15. Global theme settings

### Colors

- background;
- surface;
- text;
- muted text;
- primary;
- secondary;
- accent;
- success;
- warning;
- error;
- borders.

### Typography

- body font;
- heading font;
- base size;
- heading scale;
- weights;
- line height;
- letter spacing.

### Layout

- max content width;
- wide content width;
- page gutters;
- section spacing;
- grid gaps.

### UI

- button radius;
- input radius;
- card radius;
- border width;
- shadows;
- focus style.

### Images

- product aspect ratio;
- category aspect ratio;
- object-fit;
- lazy-loading behavior.

## 16. Design tokens

Theme CSS must use public PLAIK design tokens.

Example:

```css
--plaik-color-primary;
--plaik-color-background;
--plaik-color-surface;
--plaik-color-text;
--plaik-color-muted;
--plaik-radius-sm;
--plaik-radius-md;
--plaik-radius-lg;
--plaik-space-sm;
--plaik-space-md;
--plaik-content-width;
```

Public classes, variables and APIs must use PLAIK-only namespaces.

## 17. Presets

One codebase must support multiple ready-made designs without duplicating theme implementation.

Initial presets:

- Default;
- Minimal;
- Fashion;
- Electronics;
- Auto Parts;
- Large Catalog.

A preset may change typography, colors, section composition, card style, header, footer, spacing and product layouts.

## 18. Auto Parts preset

The Auto Parts preset must provide presentation space suitable for large technical catalogs and integrations such as:

- VIN/OEM search module;
- vehicle selector;
- manufacturer;
- brand;
- OEM number;
- compatibility;
- specifications;
- warehouse availability;
- alternative parts;
- analogues;
- related products;
- large filter trees.

The theme only provides presentation contracts and slots. It does not implement those domain capabilities.

## 19. Responsive behavior

Desktop, tablet and mobile are required.

Sections may expose presentation overrides for:

- visibility;
- alignment;
- columns;
- spacing;
- ordering;
- image behavior.

Responsive behavior must not require duplicating business content solely for different breakpoints.

## 20. Performance

The default theme is performance-first.

Requirements:

- server-rendered HTML by default;
- JavaScript only where required;
- no mandatory SPA runtime;
- minimal global JavaScript;
- lazy loading for non-critical media;
- responsive images;
- explicit width/height where applicable;
- minimized layout shift;
- critical storefront UI functional without JavaScript where technically reasonable;
- no large mandatory frontend framework bundle.

Bootstrap, Tailwind runtime or similar frameworks must not be required production dependencies of the default theme.

## 21. Progressive enhancement

Core storefront content should render on the server.

JavaScript may enhance drawers, sliders, galleries, autocomplete, quick interactions and progressive cart updates.

Without JavaScript, a usable baseline page must remain available wherever technically practical.

## 22. Accessibility

Minimum requirements:

- semantic HTML;
- keyboard navigation;
- visible focus;
- skip navigation;
- correct labels;
- ARIA only where semantic HTML is insufficient;
- sufficient contrast;
- reduced-motion support;
- accessible dialogs and drawers;
- accessible menus;
- correct heading hierarchy.

## 23. SEO presentation

The theme must support presentation for:

- page title;
- meta description;
- canonical URL;
- Open Graph;
- social card metadata;
- structured-data slots;
- breadcrumbs;
- semantic product/category markup;
- pagination metadata.

Business data comes from the relevant released contracts/modules.

## 24. Localization

Storefront templates must not hardcode user-facing strings.

Strings resolve through locale keys.

Recommended structure:

```text
locales/
├── en.json
├── uk.json
└── ...
```

The architecture must be ready for RTL languages.

## 25. Icons

Use one consistent icon system.

Do not use emoji as interface icons.

Supported approach should be based on safe SVG assets/components such as an SVG sprite or theme icon registry.

## 26. Images

Theme media presentation must support:

- `srcset`;
- responsive sizes;
- AVIF/WebP where backend support exists;
- lazy loading;
- hero/preload strategy for critical imagery;
- focal points;
- configurable crop behavior.

## 27. Navigation

Default Theme must support presentation for:

- normal menus;
- dropdown navigation;
- multi-level navigation;
- mega-menu module/slot;
- breadcrumbs;
- mobile drawer navigation.

Menu data must not be stored as business content inside theme files.

## 28. Search presentation

Provide UI contracts for:

- search input;
- autocomplete slot;
- recent searches slot;
- popular searches slot;
- search results;
- empty search results.

Search implementation remains outside the theme.

## 29. Cart presentation

Provide presentation for:

- cart icon;
- count badge;
- mini-cart slot;
- cart drawer;
- full cart page;
- totals slot;
- promo-code slot;
- shipping-estimate slot;
- checkout action slot.

Cart state and behavior remain module-owned.

## 30. Checkout shell

Checkout must have a dedicated minimal layout suitable for a security-sensitive flow.

Default composition should include:

- logo;
- checkout content;
- trust/security presentation slots;
- minimal footer;
- minimal unrelated navigation.

A theme must not be able to bypass checkout security contracts.

## 31. Theme editor readiness

The architecture must support a future visual Theme Editor capable of:

- selecting templates;
- adding/removing sections;
- drag-and-drop reordering;
- editing blocks;
- changing settings;
- responsive preview;
- selecting presets;
- preview-before-publish;
- publish;
- rollback.

Presentation configuration must therefore be declarative and must not be hidden inside arbitrary template code.

## 32. Settings schema

Each configurable section/block must describe supported settings declaratively.

Example:

```json
{
  "type": "hero",
  "settings": [
    {
      "id": "heading",
      "type": "text",
      "label": "Heading"
    },
    {
      "id": "alignment",
      "type": "select",
      "options": ["left", "center", "right"]
    }
  ]
}
```

The future Theme Editor should be able to build its controls from public schemas.

## 33. Custom CSS

Custom CSS may be offered as an advanced feature.

It must:

- be clearly separated from normal structured settings;
- not replace schema-based customization;
- provide no server-side execution capability;
- follow platform security and sanitization rules.

## 34. Custom JavaScript

Unrestricted custom JavaScript through Admin is out of scope for the initial Theme API.

If introduced later, it requires an explicit security model.

## 35. Theme JavaScript

Theme-owned JavaScript must be:

- modular;
- dependency-light;
- free of unnecessary global mutable state;
- free of inline event handlers;
- free of `eval`-style execution;
- compatible with Content Security Policy;
- independent of private Core implementation details.

## 36. CSS isolation

Theme CSS must use stable public classes/tokens instead of depending on incidental DOM nesting.

Prefer:

```css
.plaik-product-card {}
```

Avoid selectors tied to arbitrary document positions or private module markup.

Theme UI and module UI must meet at stable released presentation contracts.

## 37. Theme manifest

The manifest must include at least:

- id;
- name;
- version;
- type;
- PLAIK compatibility range;
- Theme API version;
- author;
- license;
- supported layouts/templates;
- assets;
- capabilities;
- required contracts;
- optional slots;
- parent theme reference where applicable.

## 38. Compatibility

A theme must explicitly declare:

- Theme API version;
- minimum/supported PLAIK version range;
- supported public contract versions where needed.

An incompatible theme must fail activation safely.

## 39. Safe activation

Before activation the platform must be able to:

1. validate manifest;
2. validate schemas;
3. validate templates;
4. validate references;
5. validate assets;
6. verify compatibility;
7. compile/prepare required artifacts;
8. preview/verify;
9. activate atomically.

Failed activation must leave the previously active theme intact.

## 40. Failure behavior

An optional module/slot failure must not crash the whole storefront page.

The system should distinguish at least:

- theme fatal error;
- section error;
- block error;
- module-slot error.

Core owns controlled fallback behavior.

## 41. Protected system fallback

Core must contain a separate minimal protected fallback for cases such as:

- active theme missing;
- active theme corrupted;
- template load failure;
- failed activation/rollback edge case;
- storefront safe mode.

The fallback:

- is not a marketplace theme;
- is not user-configurable;
- cannot be removed;
- does not depend on installed packages;
- contains only minimal HTML/CSS;
- contains no business-domain logic.

## 42. Security

Theme packages are untrusted input.

The Theme API and installer must account for:

- path traversal;
- unsafe template execution;
- arbitrary file access;
- XSS;
- unsafe HTML;
- unsafe SVG;
- CSP compatibility;
- unexpected remote asset loading;
- dependency integrity;
- archive extraction safety;
- symlinks;
- oversized assets;
- malformed schemas.

## 43. Remote assets

The default theme must not depend on:

- external font providers;
- third-party CDNs;
- remote JavaScript;
- remote CSS.

It must operate fully from released/local assets.

## 44. Privacy

By default the theme must not emit:

- analytics;
- telemetry;
- fingerprinting;
- tracking pixels;
- external font requests.

Such behavior belongs to explicit integrations/modules governed by platform policy.

## 45. Browser support

Target actively supported modern browsers:

- Chrome/Chromium;
- Firefox;
- Safari;
- Edge;
- current mobile browsers.

Do not accumulate a legacy compatibility layer without a demonstrated requirement.

## 46. Public naming

Use PLAIK-only public namespace conventions.

CSS classes:

```text
.plaik-header
.plaik-product-card
.plaik-section
```

CSS variables:

```text
--plaik-*
```

Public JavaScript/API names:

```text
plaik.*
```

Do not introduce historical or compatibility branding aliases into public theme code or documentation.

## 47. Developer experience

`PLAIK Default` is the reference theme implementation.

Its code must be:

- understandable;
- documented;
- structured;
- explicit rather than magical;
- based only on public APIs;
- suitable as an example for third-party theme developers.

## 48. Theme inheritance

The Theme API may support a `parent` theme.

Inheritance must remain bounded and predictable. Recommended maximum inheritance depth: `1`.

A child theme may override supported presentation artifacts such as:

- templates;
- sections;
- snippets;
- assets;
- settings defaults.

## 49. Frontend philosophy

Default Theme follows:

```text
HTML/CSS first
JavaScript second
```

The public Theme API must not require third-party theme developers to adopt React, Vue, Svelte or another specific frontend framework.

## 50. Definition of Done for Default Theme v1

Default Theme v1 is complete when all of the following are true:

- production-ready home page exists;
- category page exists;
- search page exists;
- product page exists;
- cart presentation exists;
- checkout shell exists;
- account shell exists;
- header/footer architecture is builder-ready;
- sections exist;
- blocks exist;
- slots exist;
- settings schema exists;
- presets exist;
- responsive behavior is complete;
- accessibility baseline is verified;
- SEO baseline is verified;
- localization is supported;
- safe theme activation exists;
- protected system fallback is separate from Default Theme;
- theme has no mandatory external CDN dependency;
- public naming uses PLAIK-only namespaces;
- no business-domain implementation lives in the theme package;
- official modules can integrate presentation through stable released slots/contracts;
- applicable public/private boundary and validation gates pass.

## 51. Product goal

The target is a theme system that combines:

```text
section/block composition flexibility
+
high storefront configurability
+
strong component isolation
+
PLAIK module/package boundaries
+
performance-first server rendering
```

A user should be able to build substantially different storefronts from one `PLAIK Default` codebase without forking the theme, while the theme remains a presentation layer rather than a monolithic implementation of store business logic.
