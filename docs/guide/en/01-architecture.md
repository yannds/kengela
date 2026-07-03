# 01 - Architecture

Kengela is a **hexagonal architecture** (ports & adapters) in service of a **Zero Trust** doctrine.
This page describes the 3 rings, the "the port is an airlock" rule, the anti-vendor guardrail, the
decision flow, and the `Principal` bridge between authentication and authorization.

## The 3 rings

```
        ┌──────────────────────────────────────────────┐
        │            APPLICATIONS (composent)          │   ← votre app, TransLog, ...
        │  ┌────────────────────────────────────────┐  │
        │  │        ADAPTERS (implémentent)         │  │   ← expr-cel, authn-native, prisma,
        │  │  ┌──────────────────────────────────┐  │  │      ldap, scim-server, better-auth,
        │  │  │        CORE (dépend des ports)   │  │  │      nestjs, connector-translog
        │  │  │   authz-core · iam-mapping · pii │  │  │
        │  │  │  ┌────────────────────────────┐  │  │  │
        │  │  │  │  CONTRACTS (ports & types) │  │  │  │   ← @kengela/contracts
        │  │  │  └────────────────────────────┘  │  │  │      (aucune implémentation, aucun vendor)
        │  │  └──────────────────────────────────┘  │  │
        │  └────────────────────────────────────────┘  │
        └──────────────────────────────────────────────┘
```

| Ring                  | Packages                                                                                                                                                 | Rule                                                                                                                                                       |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **contracts**         | `@kengela/contracts`                                                                                                                                     | **Only** types and interfaces. Zero implementation, zero vendor import. This is the invariant: the stable shape the core, adapters and apps all depend on. |
| **core**              | `authz-core`, `iam-mapping`, `pii`                                                                                                                       | **Pure** logic (testable off-infra), which **depends on the ports**. No npm vendor import (enforced by the lint).                                          |
| **adapters**          | `adapter-expr-cel`, `adapter-authn-native`, `adapter-persistence-prisma`, `adapter-directory-ldap`, `scim-server`, `adapter-authn-better-auth`, `nestjs` | **Implement** a port on top of a concrete technology (Prisma, ldapts, otplib, cel-js, better-auth, NestJS). The vendor **lives here**, and nowhere else.   |
| **apps / connectors** | `connector-translog`, your application                                                                                                                   | **Compose**: pick one adapter per port and wire it all together.                                                                                           |

**The direction of dependencies always points inward**: adapters know the contracts, the core knows
the contracts, but **the contracts know no one**. Replacing Prisma with another ORM, or otplib with
another TOTP lib, never touches the core.

## Doctrine: "the port is an airlock, not a hideout"

Wrapping a vendor behind a port is **not** a way to hide weak code. It is an **airlock**: we expose
to the rest of the system only the strictly necessary surface, we trace what is weak, and we keep a
migration target.

This materializes as three habits:

1. **NARROW interface over the vendor.** An adapter does not depend on a whole framework, but on a
   tiny interface that describes _exactly_ the methods used. Real examples:
   - `PrismaLike` (adapter-persistence-prisma): describes the `grant`, `role`, `session` and
     `policy` delegates and only the methods called. We import **nothing** from `@prisma/client`; a
     real `PrismaClient` is _structurally compatible_.
   - `LdapClientLike` (adapter-directory-ldap): `bind` / `search` / `unbind`, nothing else. No
     directory-write method is declared (read-only).
   - `BetterAuthLike` (adapter-authn-better-auth): only `api.getSession`.
2. **`DEBT.md` per adapter.** Anything wrapped but not yet migrated is listed in a debt registry with
   its status, its problem and its target (`DEBT.template.md` at the root provides the template). A
   resolved debt is **removed** from the file.
3. **Fail-closed at the narrowing.** An unreadable union value (an unknown `scope`, an invalid
   `effect`) makes the grant/rule _fall_ rather than widening it. Never a phantom widening.

## The anti-vendor lint (build guardrail)

The "the core knows no vendor" rule is not just a convention: it is **mechanically verified** by
`dependency-cruiser`.

```sh
pnpm lint:arch
```

The configuration (`.dependency-cruiser.mjs`) forbids any core package (`contracts`, `authz-core`,
`iam-mapping`, ...) from importing an npm package outside the monorepo, and forbids circular
dependencies:

```js
{
  name: 'core-no-vendor',
  severity: 'error',
  from: { path: '^packages/(contracts|authz-core|authn-core|iam-mapping|policy)/src' },
  to: { dependencyTypes: ['npm', 'npm-dev', 'npm-optional', 'npm-peer'], pathNot: ['^packages/'] },
}
```

If one day an import of `argon2` or `@prisma/client` slips into `authz-core`, **the build breaks**.
This is the safety net that protects the purity of the core over time.

## The Zero Trust decision flow

Every access request traverses the layered PDP (`LayeredDecisionPoint`). The order is **fixed** and
**fail-closed**:

```
AccessRequest
     │
     ▼
[0] Isolation multi-tenant  ─ resource.tenantId ≠ principal.tenantId ? → relation ramenée à `none`
     │                          (seul un grant `global` du plan plateforme peut alors couvrir)
     ▼
[1] Plancher RBAC           ─ aucun grant actif couvrant la permission à la relation → DENY (no_grant)
     │
     ▼
[2] Policies (resource,action) applicables ? ─ aucune → ALLOW (le RBAC suffit)
     │
     ▼   (condition CEL inévaluable → DENY condition_error : FAIL-CLOSED)
[3] DENY explicite prioritaire  ─ une règle `deny` matchée l'emporte (deny-wins)
     │
     ▼
[4] Gate ABAC positif       ─ s'il existe des règles `allow` mais qu'aucune ne matche → DENY (no_matching_allow)
     │
     ▼
[5] Step-up                 ─ des règles `step_up` matchées → STEP_UP + obligations
     │
     ▼
[6] ALLOW
```

The key points, each a **control proven by test** (see [08-security.md](./08-security.md)):

- **RBAC floor**: no right, nothing. RBAC is the necessary condition, never sufficient on its own if
  policies exist.
- **deny-wins**: an explicit `deny` wins regardless of evaluation order.
- **ABAC gate**: as soon as a policy lays down `allow` rules (declarative scoping, e.g. "same
  agency"), at least one must match.
- **Step-up**: authorization can **require an authentication factor** (MFA, passkey, re-auth). This
  is the intimate authz → authn link.
- **Fail-closed**: an unevaluable condition (missing variable, invalid expression, non-boolean)
  resolves to **DENY**, never to access.
- **Anti-staleness**: grants are **reloaded on every check** via the `AuthorizationRepository`. A
  revoked right stops acting immediately; we do not trust a role cache carried by the `Principal`.

Any decision (allow/deny/step_up) can be **traced** in a `DecisionLogSink` with its `reason` and its
`signals` (including `crossTenant`), for ZTNA observability.

## Multi-tenant isolation at the core

Tenant isolation is **the** central control of the lib, and it is defended _inside_ the PDP, not
delegated to the app. The `tenantScopedRelation()` helper (`authz-core/src/engine.ts`) applies the
rule:

```ts
export function tenantScopedRelation(
  principalTenantId: TenantId,
  resourceTenantId: TenantId,
  resolved: OrgRelation,
): OrgRelation {
  return principalTenantId === resourceTenantId ? resolved : 'none';
}
```

Even if the `RelationResolver` provided by the app is wrong (or is compromised) and returns `tenant`
for a resource of **another** tenant, the relation is reduced to `none`, and only a `global`-scoped
grant can cover it. A non-platform `Principal` never crosses the boundary. A `crossTenant` signal is
emitted to the decision log.

## The `Principal` bridge (authn ↔ authz)

The `Principal` is **produced by authentication** and **consumed by authorization**. It carries
everything a Zero Trust decision may require:

```ts
interface Principal {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly roles: readonly string[]; // multi-rôle (union des grants)
  readonly orgUnitId?: string;
  readonly agencyId?: string;
  readonly coverageUnits?: readonly string[];
  readonly activeStationId?: string;
  readonly mfaLevel: 'none' | 'totp' | 'passkey'; // force d'authn atteinte (step-up)
  readonly authMethod:
    'credential' | 'passwordless' | 'oidc' | 'saml' | 'passkey' | 'impersonation';
  readonly ctx: AuthContext; // géo / device / risque / authTime → conditional access
}
```

- `mfaLevel` + `authMethod` state **how** the user authenticated: this is what the step-up rules
  query.
- `ctx: AuthContext` carries the **ZTNA signals** (IP, geo, trusted device, `riskScore`,
  `authTime`). An application feeds them via a `ContextProvider` (GeoIP, fingerprint, risk engine).
  These signals become **decision inputs**, not merely audit.

> **Two distinct `DirectoryProfile`.** Caution: `@kengela/contracts` exposes a minimal
> `DirectoryProfile` type (on the federation ports side), whereas `@kengela/iam-mapping` exposes a
> **richer** `DirectoryProfile` (email, firstName, lastName, attributes, claims), used by the mapping
> and PII compliance. Pages 04 and 06 import the one from `iam-mapping`.

## Cross-cutting repo conventions

- **TypeScript 6, maximal `strict`**: `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`,
  `isolatedDeclarations`, `verbatimModuleSyntax`, etc. (see `tsconfig.base.json`).
- **ESLint `strictTypeChecked` + `stylisticTypeChecked`**.
- **ESM / NodeNext**, Node >= 24, explicit `.js` imports in the TS sources.
- **Vitest** for the tests, hermetic (in-memory fakes, no network and no real DB).
