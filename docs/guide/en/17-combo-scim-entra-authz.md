# Combo 17 — Entra provisioning via SCIM + authorization decision (RBAC + CEL)

> COMBO: two recipes assembled end to end. A user is PROVISIONED from Microsoft Entra ID
> via SCIM 2.0 (recipe 12) — account creation + mapping of groups to application roles —
> THEN their access is DECIDED by the layered PDP RBAC + CEL condition (recipe 14). The
> through-line: provisioning LAYS DOWN the grants, the PDP READS them on every request.

---

## 1. The building blocks and the flow

Two phases, two families of real symbols:

- **Provisioning (SCIM → roles)** — the pure handlers of `@kengela/scim-server`
  (`handleUsersPost`, …) persist the account via the `ScimStore` port; then
  `profileFromScim` (`@kengela/iam-mapping`) normalizes the SCIM body into a
  `DirectoryProfile`, `evaluateMappings` derives `roleKeys`, and `toContractsProfile`
  projects to the minimal `contracts` form for persistence.
- **Decision (RBAC + ABAC)** — `LayeredDecisionPoint` (`@kengela/authz-core`) evaluates,
  PER REQUEST: the RBAC floor (grants reloaded via `PrismaAuthorizationRepository`), the
  org relation via `PrincipalRelationResolver`, then CEL conditions via
  `CelExpressionEngine` (`@kengela/adapter-expr-cel`) over the policies loaded by
  `PrismaPolicyStore`. The `KengelaAuthzGuard` (`@kengela/nestjs`) wires all of this onto
  a route.

### Execution thread

```
Entra ──SCIM POST /Users──► handleUsersPost(store, req) ──► ScimStore (account persisted)
                                     │
   (mapping, second phase)          ▼
   profileFromScim(scimBody) ──► DirectoryProfile (rich)
        │                              │
        ▼                              ▼
   evaluateMappings(profile, rules) ──► roleKeys ──► GRANTS laid down (app repos)
        │
   toContractsProfile(rich,{source,active}) ──► ScimRepository.upsertUserByEmail
                                     │
   ─────────────────────────────────┴──────────────  (later, at access time)
                                     ▼
   AccessRequest ──► LayeredDecisionPoint.check ──► Decision { allow | deny | step_up }
        RBAC (grants) + relation (PrincipalRelationResolver) + CEL (CelExpressionEngine)
```

### Port → adapter table

| Port (`@kengela/contracts`) | Concrete adapter                                              | Package                               |
| --------------------------- | ------------------------------------------------------------- | ------------------------------------- |
| `ScimStore` (scim-server)   | `PrismaScimStore` (you write)                                 | your app                              |
| `AuthorizationRepository`   | `PrismaAuthorizationRepository`                               | `@kengela/adapter-persistence-prisma` |
| `PolicyStore`               | `PrismaPolicyStore`                                           | `@kengela/adapter-persistence-prisma` |
| `RelationResolver`          | `PrincipalRelationResolver`                                   | `@kengela/authz-core`                 |
| `ExpressionEnginePort`      | `CelExpressionEngine`                                         | `@kengela/adapter-expr-cel`           |
| `PolicyDecisionPoint`       | `LayeredDecisionPoint`                                        | `@kengela/authz-core`                 |
| — (pure functions)          | `profileFromScim` / `evaluateMappings` / `toContractsProfile` | `@kengela/iam-mapping`                |

> `RbacDecisionPoint` (RBAC only, no policies) also exists in `@kengela/authz-core`: use it
> if this tenant has NO ABAC conditions. This combo uses the layered PDP
> `LayeredDecisionPoint` (RBAC + CEL).

---

## 2. Installation

```sh
npm add @kengela/scim-server @kengela/iam-mapping @kengela/authz-core \
        @kengela/adapter-expr-cel @kengela/adapter-persistence-prisma \
        @kengela/nestjs @kengela/contracts
```

---

## 3. Phase 1 — provision then map roles

The SCIM handlers talk to the `ScimStore` port (Prisma implementation you write in your
app, see recipe 12). An Entra `POST /Users` creates or reconciles the account by email:

```ts
import { handleUsersPost, type ScimStore, type ScimRequest } from '@kengela/scim-server';

// scimBody = raw SCIM body pushed by Entra ; store = your PrismaScimStore.
const req: ScimRequest = { tenantId, body: scimBody };
const res = await handleUsersPost(store, req); // 201 (created) or 200 (reconciled, no duplicate)
```

Role mapping is a SECOND phase, fed by the same SCIM data:

```ts
import {
  profileFromScim,
  evaluateMappings,
  toContractsProfile,
  type IdpMappingRule,
} from '@kengela/iam-mapping';
import { activeOf } from '@kengela/scim-server';

const rich = profileFromScim(scimBody); // rich DirectoryProfile (email, groups, attributes, claims)

const rules: IdpMappingRule[] = [
  {
    id: 'admins',
    priority: 0,
    stopOnMatch: true,
    any: [{ source: 'GROUP', op: 'iequals', value: 'Kengela-Admins' }],
    assignRoleKeys: ['ADM'],
  },
  {
    id: 'finance',
    priority: 10,
    all: [{ source: 'ATTRIBUTE', key: 'department', op: 'iequals', value: 'Finance' }],
    assignRoleKeys: ['VAL'],
    orgUnit: { by: 'name', fromAttribute: 'department' },
  },
];

const mapping = evaluateMappings(rich, rules);
// mapping.roleKeys => ['ADM'] and/or ['VAL'] depending on Entra groups/attributes.

// Projection to the minimal contracts form for federation persistence:
const active = activeOf(scimBody);
const profile = toContractsProfile(rich, { source: 'scim', active });
// await scimRepository.upsertUserByEmail(tenantId, profile);
// then: apply mapping.roleKeys as GRANTS via your repos (tenant's Grant/Role table).
```

`evaluateMappings` is deterministic (sort by `priority` then `id`), accumulates roles as a
union, honors `stopOnMatch`. The rules are per-tenant configurable (never hardcoded).

Once the `roleKeys` are translated into `Grant` rows (via the tenant's `Role` catalog), the
PDP reloads them on every `check` — no cache: revoking a right takes effect immediately.

---

## 4. Phase 2 — decide an access (RBAC + CEL)

`LayeredDecisionPoint` decides per request. Real order (`policy-pdp.ts`): 1. RBAC floor
(else `deny no_grant`); 2. policies applicable to `(resource, action)`; 3. explicit deny
wins; 4. positive ABAC gate (if `allow` rules exist, at least one must match); 5. `step_up`; 6. otherwise `allow`. Fail-closed: a non-evaluable CEL condition => `deny condition_error`.

```ts
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import {
  PrismaAuthorizationRepository,
  PrismaPolicyStore,
} from '@kengela/adapter-persistence-prisma';
import type { AccessRequest, Decision } from '@kengela/contracts';

const pdp = new LayeredDecisionPoint({
  grants: new PrismaAuthorizationRepository(db), // reloads the grants from the SCIM mapping
  policies: new PrismaPolicyStore(db), // tenant ABAC policies
  relations: new PrincipalRelationResolver(), // org relation from the Principal
  expr: new CelExpressionEngine(), // CEL conditions, read-only sandbox
});

const request: AccessRequest = {
  principal, // provisioned + mapped roles
  action: 'read',
  resource: { type: 'invoice', tenantId: principal.tenantId, attributes: { unitId: 'agc-dakar' } },
};
const decision: Decision = await pdp.check(request);
// decision.effect === 'allow' | 'deny' | 'step_up' ; decision.reason traces the cause.
```

A `PolicyRule`'s CEL condition (the `when` column) receives `{ principal, resource, env }`
and must return a boolean. Example rule "same agency as the principal":

```
resource.attributes.unitId == principal.agencyId
```

The CEL engine forbids the `matches` function (unbounded regex, anti-ReDoS): express
conditions via `==`, `in`, `startsWith`, `contains`.

---

## Full example (copy-paste)

A single block: SCIM provisioning + role mapping, then composition of the layered PDP and
exposure via the NestJS guard. Ready to paste (`db` = a PrismaClient structurally
compatible with `PrismaLike`; `store` = your Prisma `ScimStore`, see recipe 12).

```ts
import { handleUsersPost, activeOf, type ScimStore, type ScimRequest } from '@kengela/scim-server';
import {
  profileFromScim,
  evaluateMappings,
  toContractsProfile,
  type IdpMappingRule,
} from '@kengela/iam-mapping';
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import {
  PrismaAuthorizationRepository,
  PrismaPolicyStore,
} from '@kengela/adapter-persistence-prisma';
import type { PrismaLike } from '@kengela/adapter-persistence-prisma';
import { KengelaAuthzGuard, KENGELA_PDP, RequirePermission } from '@kengela/nestjs';
import { Controller, Get, UseGuards } from '@nestjs/common';
import type {
  AccessRequest,
  Decision,
  PolicyDecisionPoint,
  Principal,
  TenantId,
} from '@kengela/contracts';

// ── Phase 1: SCIM provisioning + role mapping ────────────────────────────────
const TENANT_MAPPING_RULES: IdpMappingRule[] = [
  {
    id: 'admins',
    priority: 0,
    stopOnMatch: true,
    any: [{ source: 'GROUP', op: 'iequals', value: 'Kengela-Admins' }],
    assignRoleKeys: ['ADM'],
  },
  {
    id: 'finance',
    priority: 10,
    all: [{ source: 'ATTRIBUTE', key: 'department', op: 'iequals', value: 'Finance' }],
    assignRoleKeys: ['VAL'],
    orgUnit: { by: 'name', fromAttribute: 'department' },
  },
];

/**
 * Receives an Entra POST /Users: persists the account (pure SCIM handler), normalizes the
 * profile, derives the roles and projects the contracts form for federation.
 */
export async function provisionFromScim(
  store: ScimStore,
  tenantId: TenantId,
  scimBody: Record<string, unknown>,
): Promise<{ readonly status: number; readonly roleKeys: readonly string[] }> {
  // 1. SCIM persistence (email reconciliation, never a duplicate).
  const req: ScimRequest = { tenantId, body: scimBody };
  const res = await handleUsersPost(store, req);

  // 2. Role mapping from Entra groups/attributes.
  const rich = profileFromScim(scimBody);
  const mapping = evaluateMappings(rich, TENANT_MAPPING_RULES);

  // 3. Contracts projection (for ScimRepository.upsertUserByEmail in the app).
  const profile = toContractsProfile(rich, { source: 'scim', active: activeOf(scimBody) });
  void profile; // await scimRepository.upsertUserByEmail(tenantId, profile);

  // 4. Translate mapping.roleKeys into Grant rows via the tenant's Role catalog (app repos).
  return { status: res.status, roleKeys: mapping.roleKeys };
}

// ── Phase 2: layered authorization decision ──────────────────────────────────
/** Composes the PDP: RBAC (grants from the mapping) + org relation + tenant CEL conditions. */
export function buildPdp(db: PrismaLike): PolicyDecisionPoint {
  return new LayeredDecisionPoint({
    grants: new PrismaAuthorizationRepository(db),
    policies: new PrismaPolicyStore(db),
    relations: new PrincipalRelationResolver(),
    expr: new CelExpressionEngine(),
  });
}

/** Direct check (service level) with a loaded resource + its ABAC attributes. */
export async function canReadInvoice(
  pdp: PolicyDecisionPoint,
  principal: Principal,
  invoice: { readonly id: string; readonly unitId: string },
): Promise<boolean> {
  const request: AccessRequest = {
    principal,
    action: 'read',
    resource: {
      type: 'invoice',
      id: invoice.id,
      tenantId: principal.tenantId,
      attributes: { unitId: invoice.unitId }, // material for the CEL condition (same agency)
    },
  };
  const decision: Decision = await pdp.check(request);
  return decision.effect === 'allow';
}

// ── NestJS exposure: the guard wires the same PDP onto routes ────────────────
@Controller('invoices')
@UseGuards(KengelaAuthzGuard)
export class InvoiceController {
  // The evaluated permission is `invoice.read`; the guard builds the AccessRequest at the
  // TYPE level. ABAC conditions on a PRECISE resource (same agency) are checked at the
  // service level via canReadInvoice(pdp, principal, invoice).
  @Get()
  @RequirePermission('invoice', 'read')
  public list(): { readonly ok: true } {
    return { ok: true };
  }
}

// Module wiring (sketch): provide the PDP under the KENGELA_PDP token.
export const authzProvider = {
  provide: KENGELA_PDP,
  useFactory: (db: PrismaLike): PolicyDecisionPoint => buildPdp(db),
  inject: [/* your PrismaClient token */],
};
```

### Real-symbol recap

- SCIM: `handleUsersPost`, `activeOf`, `ScimStore`, `ScimRequest` (`@kengela/scim-server`).
- Mapping: `profileFromScim`, `evaluateMappings`, `toContractsProfile`, `IdpMappingRule`
  (`@kengela/iam-mapping`).
- Authz: `LayeredDecisionPoint`, `RbacDecisionPoint`, `PrincipalRelationResolver`
  (`@kengela/authz-core`); `CelExpressionEngine` (`@kengela/adapter-expr-cel`).
- Persistence: `PrismaAuthorizationRepository`, `PrismaPolicyStore`, `PrismaLike`
  (`@kengela/adapter-persistence-prisma`).
- NestJS: `KengelaAuthzGuard`, `KENGELA_PDP`, `RequirePermission` (`@kengela/nestjs`).
- Contracts: `AccessRequest`, `Decision`, `PolicyDecisionPoint`, `Principal` (`@kengela/contracts`).
