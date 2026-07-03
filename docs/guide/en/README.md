# Kengela Guide

> **kokéngela** _(Lingala)_ - to watch over, to guard, to stay vigilant.
> Kengela is a **Zero Trust identity & access** foundation for **multi-tenant** TypeScript
> applications: **authentication + authorization + identity federation + compliance**, built from
> pure ports (`@kengela/contracts`), a vendor-free core, and interchangeable adapters.

This guide covers installing, using, and developing the monorepo. **Every code snippet relies on the
real signatures** of the `@kengela/*` packages, verified against the source. Each page is
self-contained (it also serves as a GitHub wiki page).

> 🇫🇷 **Version française** : [Guide français](../README.md) (wiki : _FR-Accueil_). 🇬🇧 You are reading the English version.

## Table of contents — the fundamentals

| #   | Page                                                   | Topic                                                                                                                          |
| --- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| 0   | [Getting started](./00-getting-started.md)             | Install (dual ESM+CJS), compose a first PDP, run an end-to-end `check()`: allow, deny, step-up.                                |
| 1   | [Architecture](./01-architecture.md)                   | The 3 rings, the "a port is an airlock" doctrine, the anti-vendor lint, the Zero Trust decision flow, the `Principal` bridge.  |
| 2   | [Authorization](./02-authorization.md)                 | Permission grammar, grants & relations, declarative policies (CEL), conditional access, obligations & step-up, decision logs.  |
| 3   | [Authentication](./03-authentication.md)               | Timing-safe credentials (argon2id / bcrypt + `needsRehash`), sessions, full MFA/TOTP, better-auth, crypto-shredding.           |
| 4   | [Identity federation](./04-identity-federation.md)     | `iam-mapping` (6 sources → `DirectoryProfile`), the Kengela SCIM schema, `scim-server` (discovery + validation + Entra), LDAP. |
| 5   | [NestJS integration](./05-nestjs-integration.md)       | `KengelaAuthzGuard`, decorators, the `KENGELA_PDP` token, `StepUpRequiredException`, an example module.                        |
| 6   | [Compliance & PII](./06-compliance-pii.md)             | Classification, minimization, redaction, retention, erasure (crypto-shredding), `PiiAccessLogSink`.                            |
| 7   | [Developing an adapter](./07-developing-an-adapter.md) | Add an adapter: implement a port, a NARROW vendor interface, a test fake, `DEBT.md`, strict conventions, dual build.           |
| 8   | [Security](./08-security.md)                           | Zero Trust posture, red/blue audit summary, and how to re-run the adversarial audit.                                           |

## Implementation recipes — "how do I wire Kengela into my app?"

Each recipe is **copy-paste**, backed by the code's **real signatures**, and separates what is
**provided by Kengela** from what **the application writes itself**. Pick the one that matches your
identity backend.

| Scenario                                                                      | Recipe                                                                  |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **NestJS + native auth (argon2) + Prisma** — the recommended default path     | [Recipe: NestJS + native + Prisma](./10-recipe-nestjs-native-prisma.md) |
| **better-auth** as the authentication backend (delegated session)             | [Recipe: better-auth](./11-recipe-better-auth.md)                       |
| **SCIM 2.0 provisioning from Microsoft Entra ID** (Azure AD)                  | [Recipe: SCIM / Entra](./12-recipe-scim-entra.md)                       |
| **LDAP / Active Directory** directory federation                              | [Recipe: LDAP / AD](./13-recipe-ldap.md)                                |
| **RBAC + ABAC (CEL) authorization**, obligations, step-up, decision logs      | [Recipe: RBAC/ABAC authorization](./14-recipe-authz-rbac-abac.md)       |
| **GDPR compliance**: per-tenant field encryption, crypto-shredding, retention | [Recipe: PII / GDPR](./15-recipe-pii-compliance.md)                     |

### Combined recipes (several building blocks together)

| Combo                                                                                      | Recipe                                                      |
| ------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| **better-auth + PII** — account delegated to better-auth, field encryption + erasure       | [Combo: better-auth + PII](./16-combo-better-auth-pii.md)   |
| **SCIM/Entra + authorization** — user provisioned from Entra → grants → RBAC/ABAC decision | [Combo: SCIM/Entra + authz](./17-combo-scim-entra-authz.md) |
| **Full stack** — NestJS + native + Prisma + MFA + authz + PII in a single composition root | [Combo: full stack](./18-combo-full-stack.md)               |

## The 12 packages at a glance

| Package                               | Ring        | Role                                                                                                         |
| ------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------ |
| `@kengela/contracts`                  | contracts   | Pure ports & types - the project's invariant, zero vendor, zero implementation.                              |
| `@kengela/authz-core`                 | core        | Authorization engine: scoped RBAC + org relation + ABAC (CEL) + step-up; deny-by-default, fail-closed.       |
| `@kengela/iam-mapping`                | core        | Normalize 6 IdP sources → `DirectoryProfile` + canonical SCIM schema + rule engine.                          |
| `@kengela/pii`                        | core        | GDPR compliance: classification, minimization, redaction, retention.                                         |
| `@kengela/adapter-expr-cel`           | adapter     | CEL engine (ABAC conditions + deterministic date functions).                                                 |
| `@kengela/adapter-authn-native`       | adapter     | Timing-safe credentials, sessions, MFA/TOTP, AES-256-GCM, field cipher + crypto-shredding.                   |
| `@kengela/adapter-authn-better-auth`  | adapter     | `IdentityPort` on top of better-auth (peer dependency).                                                      |
| `@kengela/adapter-persistence-prisma` | adapter     | `AuthorizationRepository` / `SessionStore` / `PolicyStore` / MFA & PII stores via a narrow Prisma interface. |
| `@kengela/adapter-directory-ldap`     | adapter     | AD / LDAP connector (ldapts) → `DirectoryProfile`.                                                           |
| `@kengela/scim-server`                | adapter     | SCIM 2.0 core: Users + Groups + discovery + Entra compliance + validation.                                   |
| `@kengela/nestjs`                     | integration | Deny-by-default guard + decorators + step-up.                                                                |
| `@kengela/connector-translog`         | connector   | Maps the TransLog Pro schema onto the Kengela ports (integration reference).                                 |

## Guiding principles (keep these in mind)

1. **Zero Trust**: no implicit trust. The decision point (PDP) is **deny-by-default**, evaluated
   **per request**, reloading grants (anti-staleness).
2. **Fail-closed**: any uncertainty (unevaluable condition, expired session, unresolvable tenant)
   resolves to a **denial**, never to access.
3. **Multi-tenant isolation at the core**: the tenant boundary is checked inside the PDP itself, not
   blindly delegated to the app.
4. **A port is an airlock, not a hideout**: the core knows no vendor; each adapter wraps a technology
   behind a NARROW interface and records its debt in `DEBT.md`.
5. **A la carte composition**: an application installs only the packages it uses.

## Verify everything

```sh
pnpm install
pnpm -r build && pnpm -r test   # TS6 strict, ESLint strictTypeChecked, all green
pnpm lint:arch                  # anti-vendor guardrail on the core (dependency-cruiser)
```

See also [`PUBLISHING.md`](../../../PUBLISHING.md) (npm publishing & consumption) and
[`docs/SECURITY-AUDIT-REPORT.md`](../../SECURITY-AUDIT-REPORT.md) (security audit).
