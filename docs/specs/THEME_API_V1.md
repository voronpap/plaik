# PLAIK Theme API v1

## 1. Purpose

Theme API v1 defines the public presentation contract between PLAIK Core, `plaik-sdk`, themes and installable modules/integrations.

It evolves the current layout-and-hook theme system into a declarative composition model without discarding the existing safe foundations in Core.

The target model is:

```text
Page Template
  -> Sections
    -> Blocks
      -> Slots
        -> Module / integration UI
```

Theme API v1 is presentation-only. It must not move catalog, pricing, cart, checkout, orders, payment, shipping, inventory, search, reviews, fitment or other business-domain logic into themes.

## 2. Ownership boundaries

### Core owns

Core owns runtime mechanisms and gatekeeping:

- theme discovery and installation integration;
- active-theme state per store;
- compatibility checks;
- inheritance validation;
- safe path and asset validation;
- sandboxed rendering;
- composition loading and validation;
- revisioned settings state;
- draft/prepare/preview/publish lifecycle;
- atomic activation and rollback;
- protected system fallback;
- slot projection and deterministic render order;
- failure isolation and diagnostics.

### `plaik-sdk` owns

The public SDK owns stable contracts and validators for:

- Theme API versioning;
- manifest schemas;
- page-template schemas;
- section schemas;
- block schemas;
- slot identifiers;
- settings schemas;
- preset schemas;
- UI state contracts;
- compatibility declarations;
- public validation helpers.

### Themes own

Themes own presentation only:

- page compositions;
- sections and blocks;
- templates/snippets;
- CSS and safe theme JavaScript;
- design tokens;
- configurable presentation schema;
- presets;
- responsive presentation behavior;
- visual rendering of public UI states.

### Packages own

Modules and integrations own their business behavior and data. They may contribute UI only through released public Theme/SDK contracts and declared slots.

A theme must never import private implementation from another package.

## 3. Compatibility model

Every Theme API v1 theme must declare at least:

```text
theme_api: 1
plaik: <supported version range>
contracts: <supported public contract ranges where required>
```

Compatibility validation happens before a theme can be prepared or activated.

An incompatible theme must fail closed and must not modify active storefront state.

## 4. Theme manifest v1

A v1 theme manifest must describe package identity and presentation capabilities without embedding executable server logic.

Required fields should include:

- `id`;
- `type = theme`;
- `name`;
- `version`;
- `theme_api`;
- PLAIK compatibility range;
- author/license metadata;
- optional `parent`;
- declared page templates;
- declared section definitions;
- declared block definitions where theme-owned;
- declared assets;
- declared slots/capabilities where applicable;
- settings schema reference;
- preset references;
- locale declarations.

Unknown manifest fields must be rejected unless a future Theme API revision explicitly allows extension namespaces.

## 5. Inheritance

Theme inheritance is supported but intentionally bounded.

Theme API v1 maximum inheritance depth is `1`:

```text
child -> parent
```

Nested chains such as `child -> parent -> grandparent` are invalid.

Core must reject:

- missing parents;
- inheritance cycles;
- self-parenting;
- depth greater than one;
- incompatible parent/child Theme API versions.

A child theme may override only declared public presentation artifacts such as templates, sections, snippets, assets and settings defaults.

## 6. Page templates

A page template is a declarative composition document, normally JSON.

Reference page types include:

- `home`;
- `product`;
- `category`;
- `search`;
- `cart`;
- `checkout`;
- `account`;
- `page`;
- `error`;
- `maintenance`.

A page template must define ordered section instances rather than embedding the entire page implementation in one HTML file.

Example:

```json
{
  "schema_version": 1,
  "sections": {
    "hero-main": {
      "type": "hero",
      "settings": {}
    },
    "featured-main": {
      "type": "product-grid",
      "settings": {}
    }
  },
  "order": ["hero-main", "featured-main"]
}
```

Core must validate:

- schema version;
- unique instance IDs;
- known section types;
- deterministic order;
- settings against the section schema;
- valid block references;
- valid slot references;
- safe and bounded document size;
- no unknown executable directives.

## 7. Sections

A section is a reusable top-level presentation unit.

A section definition must declare:

- stable section type ID;
- template/snippet reference;
- allowed settings;
- allowed blocks;
- block cardinality limits where applicable;
- supported slots;
- responsive presentation options;
- accessibility-relevant structural constraints where required.

Section instances may be reordered, enabled/disabled and configured without editing template code.

The public schema must be declarative and must not permit arbitrary Python execution.

## 8. Blocks

A block is a fine-grained reusable presentation unit inside a section.

Examples include:

- heading;
- text;
- image;
- icon;
- button;
- badge;
- divider;
- price presentation;
- product title presentation;
- product image presentation;
- module slot.

Block definitions must declare their allowed settings and nesting constraints.

Nested blocks are allowed only where explicitly declared by schema.

Core must reject recursive or unbounded nesting structures.

## 9. Slots

Slots are the primary Theme API v1 integration mechanism between themes and package UI.

Slot names use dotted stable identifiers, for example:

```text
header.search
header.account
header.cart
home.hero.after
category.filters
category.sort
product.price.after
product.purchase
product.reviews
product.recommendations
cart.summary
cart.actions
footer.columns
```

Slot identifiers are public contracts and must be versioned through `plaik-sdk` when semantic compatibility changes.

A slot definition may declare:

- accepted contribution type;
- multiplicity;
- ordering rules;
- fallback behavior;
- required UI states;
- context fields available to contributed UI.

Packages may contribute UI only to declared slots they are compatible with.

## 10. Relationship to existing hooks

The current hook system remains valid during migration but is not the final composition model for Theme API v1.

Existing hooks may continue to support simple extension points while slots become the stable structured presentation contract.

Migration should avoid a flag day:

```text
existing HookRegistry  = compatibility path for camelCase web hooks
new SlotRegistry       = authoritative Theme API v1 path for dotted slots
```

Core must not silently reinterpret a hook as a semantically different slot.
A package contribution is rendered by exactly one of those paths, never both,
unless the package explicitly declares both a hook and a slot.

## 11. Theme settings schema

Theme configuration must be schema-driven.

Global settings may include:

- colors;
- typography;
- spacing;
- container widths;
- radii;
- borders;
- shadows;
- media behavior;
- responsive presentation options.

Each setting definition must declare:

- stable ID;
- value type;
- validation constraints;
- default value where appropriate;
- editor metadata such as label/control type;
- optional responsive override rules.

Settings schemas belong to public contracts and are validated before a configuration revision can be prepared.

## 12. Presets

A preset is a validated set of theme configuration values and optional page-composition defaults for one theme codebase.

A preset must not duplicate the full theme implementation.

Presets may alter:

- design tokens;
- section composition defaults;
- card presentation;
- header/footer composition;
- spacing;
- product/category layouts.

Preset application creates or updates a configuration revision; it does not mutate theme source files.

## 13. Revisioned theme configuration

Theme settings and page composition must use revisioned state rather than editing live source files.

Reference lifecycle:

```text
Draft
  -> Validate
  -> Prepare
  -> Preview
  -> Publish atomically
```

A revision should contain or reference:

- theme ID/version;
- Theme API version;
- global settings values;
- page-template composition values;
- selected preset identity if relevant;
- validation result;
- immutable revision identifier;
- creation/update metadata.

Published revisions must be immutable. A new change creates a new revision.

## 14. Prepare phase

Preparation occurs before any active storefront state changes.

Prepare must validate at least:

- manifest and compatibility;
- inheritance;
- page-template schemas;
- section/block schemas;
- slot references;
- settings values;
- preset references;
- locales;
- assets;
- safe template paths;
- template parseability;
- render-time public contract references.

Preparation may build deterministic derived artifacts, caches or indexes, but must not make the revision active.

## 15. Preview

Prepared revisions must be previewable without replacing the live published revision.

Preview must be isolated by explicit revision identity or preview capability/token and must not alter normal visitor state.

Preview must use the same renderer and public contracts as production as far as practical.

Preview-only bypasses of compatibility/security checks are forbidden.

## 16. Publish and rollback

Publishing a prepared revision or activating a theme must be atomic from the storefront perspective.

The existing audited, journaled theme operation model remains the durability foundation.

A publish operation must either:

- make the complete prepared target active; or
- leave the previous published state active.

Partial live configuration is forbidden.

Rollback targets a previously valid published revision/theme state and must preserve the same durable-operation guarantees.

## 17. Protected system fallback

`PLAIK Default` is not the protected system fallback.

Core must own a separate minimal fallback renderer for catastrophic theme failures and safe-mode operation.

The protected fallback:

- is part of Core runtime;
- cannot be removed or replaced by a package;
- has no business-domain logic;
- has minimal local HTML/CSS;
- does not depend on installed packages;
- does not depend on the normal active-theme state being valid;
- is intentionally not a general-purpose storefront theme.

Normal theme inheritance/default behavior and catastrophic system fallback must remain distinct concepts.

## 18. Rendering model

Web rendering resolves, in order:

1. active theme and published configuration revision;
2. compatible parent where present;
3. page-template composition;
4. section instances;
5. block instances;
6. slot contributions;
7. declared assets;
8. final sandboxed SSR output.

Theme API v1 remains HTML/server-rendering first. JavaScript is progressive enhancement, not a mandatory application runtime.

Core must continue to use sandboxed template execution, automatic escaping and strict undefined behavior or equivalent safety properties.

## 19. Assets

Theme assets must be declared.

Core must reject:

- unsafe paths;
- path traversal;
- symlink escapes;
- undeclared served theme assets;
- unsupported executable asset types where policy forbids them.

The default theme must not require third-party CDN, remote CSS, remote JavaScript or remote font dependencies.

## 20. Required UI state contracts

Critical module/theme presentation contracts must cover more than success markup.

At minimum, public component contracts must support where relevant:

```text
idle
pending
loading
empty
success
validation-error
service-error
network-error
unavailable
out-of-stock
disabled-with-reason
partial-availability
```

A theme may choose the visual treatment but must not make required states impossible to render.

Packages own business-state semantics; Theme API defines the stable presentation envelope.

## 21. Failure isolation

Core should distinguish at least:

- theme fatal failure;
- page-template failure;
- section failure;
- block failure;
- slot contribution failure.

Optional slot/package failure should not automatically crash the whole storefront page when a safe degraded result is possible.

Failure handling must not hide security or data-integrity failures that require fail-closed behavior.

## 22. Security invariants

Theme packages are untrusted input.

Theme API v1 must preserve or strengthen protections for:

- path traversal;
- symlink escape;
- arbitrary file reads;
- unsafe template execution;
- XSS;
- unsafe HTML/SVG;
- CSP compatibility;
- archive extraction safety;
- malformed/oversized schemas;
- oversized assets;
- undeclared remote dependencies;
- injection through settings, locale values or module-contributed presentation data.

No Theme API feature may grant server-side arbitrary code execution to theme authors.

## 23. Public SDK contracts

`plaik-sdk` should expose stable types/validators for at least:

```text
ThemeApiVersion
ThemeManifestV1
ThemeCompatibility
PageTemplate
SectionDefinition
SectionInstance
BlockDefinition
BlockInstance
SlotDefinition
SlotContribution
ThemeSettingsSchema
ThemeSettingsValues
ThemePreset
ThemeConfigurationRevision
UiState
```

Core may use these public contracts but public packages must not depend on private Core implementation classes.

## 24. Context passed to presentation

Render context must be explicit, documented and versioned.

Themes and package UI must not receive arbitrary internal Core objects.

Context should contain only stable presentation-safe values and public contract objects required for rendering.

Reserved render-context names must remain protected from package/theme override.

## 25. Determinism

Given the same:

- theme version;
- published revision;
- page type;
- public render context;
- enabled slot contributions and order;

composition resolution must be deterministic.

Ordering ties must use stable deterministic rules.

## 26. Caching

Theme API v1 must permit caching without making cache identity ambiguous.

At minimum, cache identity for theme composition must account for:

- store;
- active theme version;
- published configuration revision;
- locale where relevant;
- page/template identity;
- module/slot composition generation where relevant.

A revision publish must invalidate or version-bypass stale presentation artifacts deterministically.

## 27. Localization

Theme strings must resolve through locale contracts rather than hardcoded storefront text.

Locale files are declared theme assets/data and must be validated.

The API must permit RTL-ready presentation and long translations without changing business data contracts.

## 28. Responsive presentation

Responsive behavior is part of theme configuration, not a separate mobile theme.

Theme API v1 may support schema-controlled overrides for:

- visibility;
- order;
- columns;
- alignment;
- spacing;
- media behavior.

Responsive configuration must not require duplicated business data.

Critical commerce actions/data must not disappear solely because a narrow breakpoint is active.

## 29. Accessibility and usability compatibility

Theme API compatibility includes the ability to render accessible and usable critical states.

The Default Theme targets the usability and accessibility gates defined in `DEFAULT_THEME_REQUIREMENTS.md`.

Theme API v1 must not force inaccessible interaction patterns such as hover-only required actions, gesture-only required actions or unlabelled status rendering.

## 30. Current Core reuse

Theme API v1 should evolve, not replace without cause, the current safe foundation:

- `ThemeRegistry`;
- `ActiveThemeStore`;
- `ThemeManager`;
- `ThemeActivationCoordinator`;
- `TemplateResolver`;
- sandboxed `WebRenderer`;
- package web validation;
- path/symlink safety checks;
- operation journaling and audit.

Implementation should prefer extending these responsibilities or introducing focused adjacent components rather than rebuilding lifecycle logic from scratch.

## 31. Expected Core additions

The v1 implementation is expected to introduce focused components equivalent to:

```text
ThemeApiCompatibilityValidator
PageTemplateResolver
SectionRegistry
BlockRegistry
SlotRegistry
ThemeSettingsValidator
ThemeRevisionStore
ThemeCompiler / ThemePreparer
ThemePreviewResolver
ThemeCompositionResolver
ProtectedSystemFallbackRenderer
```

Names are not normative; responsibilities are.

## 32. Migration from current layouts/hooks

Migration should be incremental.

### Stage 1

Keep current layouts/hooks operational and add v1 contracts/validators.

### Stage 2

Allow Theme API v1 themes to declare page templates, sections, blocks and slots while legacy layout rendering remains available for compatibility.

### Stage 3

Make v1 composition the normal path for `PLAIK Default` and official v1 themes.

### Stage 4

Deprecate old hook/layout-only contracts only after public replacement contracts are stable and documented.

No public theme/package should be forced to import private migration helpers.

## 33. Definition of Done for Theme API v1

Theme API v1 is implementation-ready when:

- public schemas exist in `plaik-sdk`;
- Core validates Theme API version and compatibility;
- inheritance depth is bounded to one;
- JSON page templates are validated and resolved;
- sections and blocks have public declarative schemas;
- dotted slots have stable public identifiers and deterministic ordering;
- settings and presets are schema-validated;
- theme configuration is revisioned;
- draft/validate/prepare/preview/publish flow exists;
- publish/activation is atomic and rollback-capable;
- protected system fallback is distinct from `PLAIK Default`;
- required UI-state presentation contracts exist;
- current sandbox/path/symlink protections remain enforced;
- official packages can contribute UI without private Core imports;
- `PLAIK Default` can implement the requirements in `DEFAULT_THEME_REQUIREMENTS.md` without bypassing public contracts;
- public/private repository boundaries and applicable release gates pass.

## 34. Product principle

Theme API v1 should make this true:

> A powerful storefront theme can be highly configurable without becoming a business-logic monolith, and a powerful module can contribute storefront UI without depending on a theme's private implementation.

That separation is the core compatibility guarantee of PLAIK theming.
