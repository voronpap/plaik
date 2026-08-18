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

Theme API v1 on-disk layout used by Core discover and load:

```text
default/
├── manifest.json
├── settings.json
├── presets/
│   ├── default.json
│   ├── minimal.json
│   ├── fashion.json
│   ├── electronics.json
│   ├── auto-parts.json
│   └── large-catalog.json
├── templates/
│   ├── layouts/
│   │   ├── full-width.html
│   │   └── checkout.html
│   ├── pages/
│   │   ├── home.json
│   │   ├── category.json
│   │   ├── search.json
│   │   ├── product.json
│   │   ├── cart.json
│   │   ├── checkout.json
│   │   ├── account.json
│   │   ├── page.json
│   │   ├── contact.json
│   │   ├── error.json
│   │   ├── error-403.json
│   │   ├── error-404.json
│   │   ├── error-500.json
│   │   └── maintenance.json
│   ├── sections/
│   └── blocks/
├── sections/
├── blocks/
├── assets/
│   └── css/
└── locales/
    ├── en.json
    └── uk.json
```

Global design tokens live in `settings.json`. Presets live in `presets/<id>.json` and must not mutate theme source files. Page compositions live in `templates/pages/<type>.json`. Section and block schemas live next to their HTML under `sections/` and `blocks/` plus `templates/sections|blocks/`. Slot ids stay in the `storefront.*` / `control.*` namespaces. Tablet presentation is CSS; Theme API overlays remain `narrow` / `wide` only.

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

## 50. Storefront usability requirements

Usability is a compatibility requirement, not optional visual polish. `PLAIK Default` must provide a complete, understandable and efficient purchasing experience across desktop, tablet, touch and mobile devices.

### 50.1 Mobile is a primary storefront target

Mobile must not be a reduced or merely compressed desktop experience.

Requirements:

- all critical storefront flows must remain available on mobile;
- layouts must reflow without loss of functionality at narrow viewports down to 320 CSS px where content semantics permit;
- portrait and landscape orientation must work;
- browser zoom, OS text scaling and text enlargement up to 200% must not make critical content or actions inaccessible;
- safe-area insets must be respected on devices with notches/home indicators;
- virtual keyboards must not hide the active field, validation message or primary form action;
- no critical action may require hover;
- desktop, tablet and mobile may have separate presentation composition, but must not require duplicated business data.

### 50.2 Touch and pointer interaction

The default theme should use at least 44x44 CSS px practical hit areas for primary touch controls where layout permits, while never violating the current accessibility baseline for minimum target size.

Requirements:

- controls must have sufficient spacing to prevent accidental activation;
- swipe, drag, pinch and other gestures may enhance interaction but must not be the only way to complete an action;
- drag-and-drop interfaces require an alternative single-pointer/keyboard mechanism;
- touch feedback must be immediate and visible;
- destructive controls must not be positioned so close to primary actions that accidental activation is likely.

### 50.3 Keyboard and focus behavior

Every critical storefront flow must be operable with keyboard only.

Requirements:

- logical focus order follows visual/task order;
- focus indicators are clearly visible;
- sticky headers, sticky buy bars, drawers and overlays must not obscure keyboard focus;
- opening a dialog/drawer moves focus correctly and closing it restores focus to the triggering control;
- Escape closes dismissible overlays where expected;
- focus must never become trapped outside an intentional modal interaction.

### 50.4 Navigation and orientation

Users must always understand where they are and how to continue.

Requirements:

- logo/home, catalog navigation, search, account and cart remain predictably discoverable;
- category hierarchy and breadcrumbs are used where they improve orientation;
- the browser Back/Forward actions must behave naturally;
- returning from a product page should preserve useful category/search context such as scroll position, sort order and active filters where technically possible;
- mobile navigation must expose the complete supported catalog hierarchy without requiring desktop-only interactions;
- sticky navigation must not consume an unreasonable share of a small viewport.

### 50.5 Search usability

Search is a first-class storefront flow.

The theme must provide presentation contracts for:

- a clearly discoverable search field/action;
- explicit search submission on touch/mobile;
- accessible autocomplete;
- keyboard navigation of suggestions;
- recent/popular suggestions when the corresponding module supports them;
- typo/synonym/model/OEM/VIN-oriented results supplied by search modules;
- useful no-results states.

A no-results page must not be a dead end. It should provide presentation space for query correction, alternative categories, suggestions, filter reset and other module-provided recovery actions.

### 50.6 Category, filtering and sorting usability

Requirements:

- active filters must remain clearly visible and individually removable;
- `Clear all` must be available when multiple filters are active;
- result count and current sort state must be understandable;
- mobile filters must use an accessible drawer/sheet or equivalent mobile-first pattern rather than forcing a desktop sidebar into a narrow viewport;
- large filter groups must support scalable presentation, including search within values when provided by the filtering module;
- applying filters must not unnecessarily reset context or produce large unexpected layout jumps;
- filtering state should survive product-detail round trips and browser history where the routing contract supports it.

### 50.7 Product-card usability

A product card must expose enough information to decide whether opening the product is worthwhile.

The standard card contract should support clear presentation of:

- primary image;
- understandable product name;
- current price and previous price where relevant;
- availability/status;
- important variant/attribute information;
- badges without excessive visual noise;
- optional rating, wishlist, compare and quick-action slots.

For technical/Auto Parts storefronts, the presentation contract must support high-value identifiers and fitment status supplied by modules, including brand/OEM/reference information where configured.

Hover-only secondary information is not acceptable for information required to make a purchase decision.

### 50.8 Product-page usability

The product page must establish a clear decision hierarchy.

The default composition must make the following discoverable without unnecessary hunting when the corresponding data/module exists:

- product identity;
- media;
- price;
- availability;
- variants/options;
- fitment/compatibility status;
- delivery/fulfilment information;
- primary purchase action.

Requirements:

- media gallery supports touch and keyboard interaction;
- hidden/additional images are clearly discoverable;
- zoom is an enhancement, not a requirement to inspect the primary image;
- on mobile, long secondary information should use vertical disclosure patterns such as accessible accordions when appropriate;
- horizontal tab systems must not make important content effectively undiscoverable on narrow screens;
- a mobile sticky purchase bar may be used, but it must respect safe areas, keyboard/focus visibility and available viewport space.

### 50.9 Cart usability

Cart presentation must be resistant to accidental state changes and clear about totals.

Requirements:

- quantity changes use obvious controls and may provide direct numeric entry where large quantities are realistic;
- removal must be explicit and should offer undo/recovery where supported;
- updates to quantity, promotion, shipping or removal must visibly update affected totals;
- loading/pending state must prevent contradictory duplicate actions without hiding what is happening;
- failed cart mutations must keep the previous known-good state visible and provide a retry/recovery path;
- cart drawer and full-cart page must expose the same essential state consistently.

### 50.10 Checkout usability

Checkout must minimize friction without weakening security or correctness.

Requirements:

- guest checkout must be supported by presentation whenever the checkout module allows it;
- account creation must not be visually presented as mandatory when it is optional;
- users must not be asked to re-enter information already supplied in the same checkout flow unless required for security or correctness;
- forms must use appropriate HTML input types, `autocomplete` and `inputmode` values;
- required and optional fields must be understandable before submission;
- entered data must survive recoverable validation/network errors;
- the order-review state must clearly show items, quantities, discounts, shipping, taxes/fees when applicable, and final payable total before confirmation;
- fulfilment choices should show human-readable delivery expectations when the shipping module provides them;
- submitting the final order must have an unambiguous pending/success/failure state and must be compatible with idempotent order submission.

### 50.11 Forms and validation

Every form error must answer three questions: what happened, where it happened, and how to fix it.

Requirements:

- validation messages appear next to the relevant control and are also accessible to assistive technology;
- user input must not be cleared after a recoverable error;
- validation should not aggressively report errors while the user is still entering a valid value;
- generic protocol/internal error strings must not be shown as the only user-facing explanation;
- long forms must move focus or otherwise guide the user to the first actionable error after submission;
- paste and password-manager use must not be blocked in authentication flows.

### 50.12 Async states and feedback

Every asynchronous storefront action must have a deterministic visible state.

Supported states include, where relevant:

```text
idle -> pending -> success | recoverable error | terminal error
```

Requirements:

- prefer local feedback for the affected component rather than blocking the whole page with a global spinner;
- skeletons/placeholders must reserve appropriate space and avoid unnecessary layout shift;
- `Add to cart` must immediately communicate whether the action succeeded or failed;
- disabled controls should communicate the reason when it is not obvious;
- retry must be available for recoverable network/service failures where safe.

### 50.13 Performance as usability

Performance targets apply to real user experience, not only synthetic desktop tests.

Where field measurement is available, the target at the 75th percentile should meet the current Core Web Vitals good thresholds, with the initial reference targets:

- LCP <= 2.5 s;
- INP <= 200 ms;
- CLS <= 0.1.

Targets should be evaluated separately for mobile and desktop where data allows.

The theme must avoid:

- excessive main-thread JavaScript;
- layout instability caused by media, banners or async module slots;
- interaction delays introduced by decorative effects;
- loading desktop-sized media unnecessarily on mobile.

### 50.14 Cognitive load and visual hierarchy

The default theme must prefer clarity over decorative density.

Requirements:

- one primary action should visually dominate each decision context;
- destructive actions must be visually distinct from primary actions;
- identical actions must use consistent labels across pages;
- color must not be the only carrier of meaning;
- badges, banners, popups and promotional elements must not overwhelm product/navigation tasks;
- important information must not depend on unusually precise pointer movement or memory of a previous screen.

### 50.15 Honest commerce UI

The default theme must not include or encourage deceptive interaction patterns.

Do not implement as default-theme behavior:

- fake scarcity or false stock urgency;
- fake countdown timers;
- hidden recurring charges;
- preselected paid extras without a legitimate product requirement;
- disguised advertising;
- misleading button hierarchy;
- intentionally difficult opt-out/cancel paths;
- visual tricks that make consent/refusal asymmetrical without a legitimate reason.

### 50.16 Accessibility baseline

`PLAIK Default` targets WCAG 2.2 AA as the minimum reference accessibility baseline unless the project adopts a newer compatible baseline.

This includes, at minimum:

- semantic structure;
- keyboard operability;
- visible and unobscured focus;
- sufficient color contrast;
- text resizing/reflow;
- accessible authentication;
- consistent help placement where help is provided;
- reduced-motion handling;
- accessible dialogs, drawers, menus and live updates;
- no critical meaning communicated only by color, position, hover or motion.

Accessibility is built into normal presentation and must not depend on a separate "accessibility mode".

### 50.17 Responsive content integrity

Responsive configuration may alter presentation, but should preserve content integrity.

Requirements:

- mobile-specific hiding of content must be deliberate and schema-controlled;
- critical commerce information/actions must not disappear merely to simplify the mobile layout;
- responsive reordering must preserve understandable reading and focus order;
- long translated strings must not overlap or be clipped;
- RTL layout must not break action order, icons or drawers;
- dynamic type/text scaling must not produce inaccessible fixed-height components.

### 50.18 State and context preservation

The storefront should preserve user effort where safe and appropriate.

This includes:

- cart state;
- active filters/sort;
- vehicle/fitment selection supplied by modules;
- search context;
- partially completed checkout fields after recoverable errors;
- scroll/context when returning to product listings.

Authentication, locale/currency changes, reload and browser history should not unnecessarily discard those states.

Sensitive state must still follow Core/module privacy and security rules.

### 50.19 Resilience to weak devices and networks

The default theme must remain usable on realistically constrained mobile hardware and networks.

Requirements:

- avoid long main-thread tasks caused by theme code;
- do not require large JS bundles for primary content;
- primary content remains readable while enhancements load;
- network failures produce recoverable local states instead of blank pages where possible;
- images and optional content degrade gracefully;
- retry behavior must not create duplicate durable actions.

### 50.20 Theme/module UX contracts

Theme compatibility must include required UI states, not just successful markup rendering.

Public presentation contracts for critical components must account for states such as:

- loading;
- empty;
- success;
- validation error;
- service/network error;
- unavailable/out of stock;
- disabled with reason;
- partial module availability.

A third-party module may own business behavior, but the Theme API must provide stable means to render these states without forcing the theme to import private module implementation.

Optional enhancements such as quick view, animation, sticky controls, carousels and swipe interaction must remain removable without breaking the primary commerce flow.

## 51. Usability verification gates

Usability requirements must be verified through repeatable checks before Default Theme v1 is considered complete.

The minimum verification matrix must cover:

- keyboard-only navigation through home -> category/search -> product -> cart -> checkout shell;
- screen-reader smoke checks for landmarks, headings, forms, dialogs, errors and dynamic cart feedback;
- narrow viewport around 320 CSS px;
- common mobile widths and tablet widths;
- portrait and landscape orientation;
- browser zoom/text resize to 200%;
- touch interaction without hover;
- safe-area behavior for sticky top/bottom UI;
- virtual-keyboard behavior in search, account and checkout forms;
- reduced-motion preference;
- Back/Forward navigation and restoration of relevant listing context;
- no-JavaScript baseline for server-rendered primary content where the architecture promises progressive enhancement;
- slow network and constrained-CPU behavior;
- long product titles and long translated strings;
- RTL presentation smoke checks;
- empty, loading, unavailable, validation-error, network-error and retry states;
- out-of-stock and partially available module states;
- large catalog/filter-value sets;
- product quantities of 1 and realistically large values;
- checkout validation failure and payment/service failure presentation supplied through public module contracts;
- prevention of duplicate final actions during pending submission;
- Core Web Vitals measurement with separate mobile/desktop interpretation when field data exists.

Theme Editor responsive preview is useful but does not replace testing in real browser/device conditions.

Usability failures in a critical purchase flow are release-blocking defects for the Default Theme, even if the page is visually correct.

## 52. Definition of Done for Default Theme v1

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
- mobile is verified as a primary storefront target rather than a reduced desktop fallback;
- critical flows are usable by touch and keyboard;
- accessibility baseline is verified;
- required error/loading/empty/unavailable states are verified;
- usability verification gates in this specification pass;
- SEO baseline is verified;
- localization is supported;
- safe theme activation exists;
- protected system fallback is separate from Default Theme;
- theme has no mandatory external CDN dependency;
- public naming uses PLAIK-only namespaces;
- no business-domain implementation lives in the theme package;
- official modules can integrate presentation through stable released slots/contracts;
- applicable public/private boundary and validation gates pass.

## 53. Product goal

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
+
mobile-first, accessible and verifiable storefront usability
```

A user should be able to build substantially different storefronts from one `PLAIK Default` codebase without forking the theme, while the theme remains a presentation layer rather than a monolithic implementation of store business logic.