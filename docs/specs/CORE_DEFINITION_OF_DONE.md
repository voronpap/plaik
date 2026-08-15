# Core 0.2 Definition of Done

Status: Core 0.2 platform-kernel acceptance complete.

This document defines the public completion boundary for the PLAIK Core. It intentionally excludes private deployment topology, operational evidence, host-specific configuration and business-domain packages.

## Core scope

Core is complete for 0.2 when the platform provides and verifies:

- secure installation and immutable installation identity;
- versioned Core schema migration and recovery behavior;
- authentication, sessions, RBAC, permissions and audit boundaries;
- signed package lifecycle with dependency, compatibility and migration checks;
- stable Contracts and SDK extension boundaries;
- isolated Installer, Admin and Web application compositions;
- theme-first server rendering with a bundled default theme;
- bounded jobs, events, hooks, slots, caches and extension runtime resources;
- backup, restore, rollback and repair contracts for authoritative platform state;
- explicit failure handling for durable multi-step operations;
- packaging and release artifacts that can be reproduced and validated.

## Isolation contract

Installer, Admin and Web are independent application compositions. Each one is an independent
  failure domain: process health, routing, startup and failure in one application must not implicitly become the authority for another.

Store/tenant and extension ownership boundaries fail closed. Extensions may use public Core/SDK surfaces but must not depend on another extension's private implementation or private storage.

## External scope

Commerce modules, integrations, themes beyond the bundled default theme, and composed business packs are extension work. They are not required to declare Core 0.2 complete.

Production deployment topology, secrets, exact service identities, host-specific paths, capacity measurements, incident evidence and disaster-recovery evidence are private operational concerns. Public Core documentation defines the contract; private acceptance controls prove it against supported deployment profiles.

## Quality gates

Core acceptance requires:

- unit, contract, integration, migration, packaging and security tests to pass;
- supported source and installed-package layouts to behave equivalently;
- public repositories to contain no legacy product namespace or deployment-specific private evidence;
- public SDK compatibility surfaces to stay explicit and versioned;
- no business-domain implementation to be introduced into Core;
- documentation and rollback/recovery contracts to match executable behavior.

A new fundamental Core responsibility requires an explicit architecture decision rather than silent scope expansion.
