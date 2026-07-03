# 00 - Getting started

This page installs Kengela into an application, composes a **minimal decision point (PDP)**, and
runs a first end-to-end `check()` across its three outcomes: **allow**, **deny**, **step-up**.

## Prerequisites

- **Node.js >= 24**, **pnpm** (the monorepo uses pnpm 10, but a consuming app may use
  npm/yarn/pnpm).
- TypeScript (recommended): the foundation is written in strict TS6 and ships complete types.

## Install

Each application installs **only** the packages it needs. For a first RBAC check, the contracts and
the authorization core are enough:

```sh
npm add @kengela/contracts @kengela/authz-core
```

For a database-backed PDP plus a NestJS integration, you would add, for example:

```sh
npm add @kengela/nestjs @kengela/adapter-persistence-prisma @kengela/adapter-authn-native
```

### Dual build: both `import` AND `require` work

Every package is published in **dual format** (ESM + CommonJS). Each `package.json`'s `exports`
field routes to the right build depending on how you load the module:

```jsonc
"exports": {
  ".": {
    "types":   "./dist/esm/index.d.ts",
    "import":  "./dist/esm/index.js",   // ESM
    "require": "./dist/cjs/index.js"    // CommonJS
  }
}
```

Concretely, both styles work with no configuration:

```ts
// ESM / TypeScript
import { RbacDecisionPoint } from '@kengela/authz-core';
```

```js
// CommonJS
const { RbacDecisionPoint } = require('@kengela/authz-core');
```

> Implementation detail: the ESM build emits to `dist/esm` and the CJS build to `dist/cjs`, each with
> a marker `package.json` (`{"type":"module"}` / `{"type":"commonjs"}`) so that Node interprets each
> subtree correctly.

## Composing a minimal PDP

The PDP is the central component: it answers "**is this Principal allowed to perform this action on
this resource?**". The core provides two implementations of `PolicyDecisionPoint`:

- **`RbacDecisionPoint`** - the RBAC layer alone (grants × organizational relation).
- **`LayeredDecisionPoint`** - RBAC **floor** + ABAC conditions (CEL) + conditional access +
  step-up (see [02-authorization.md](./02-authorization.md)).

Let's start with `RbacDecisionPoint`. It needs two dependencies (two **ports**):

- an **`AuthorizationRepository`** that loads a user's grants;
- a **`RelationResolver`** that resolves the organizational actor ↔ resource relation.

Below, in-memory implementations (perfect for a test or a prototype):

```ts
import { RbacDecisionPoint } from '@kengela/authz-core';
import type {
  AccessRequest,
  AuthorizationRepository,
  Principal,
  RelationResolver,
} from '@kengela/contracts';

// 1. Where the rights come from (hard-coded here; in prod, a Prisma adapter).
const grants: AuthorizationRepository = {
  async loadGrantsForUser() {
    return [{ permission: 'data.orders.read', scope: 'tenant', source: 'MANUAL' }];
  },
  async loadRole() {
    return null;
  },
};

// 2. The position of the resource relative to the actor (self/unit/subtree/tenant/none).
const relations: RelationResolver = {
  async resolveRelation() {
    return 'tenant';
  },
};

// 3. The PDP.
const pdp = new RbacDecisionPoint({ grants, relations });
```

## First `check()`: ALLOW

A `Principal` is the "bridge" produced by authentication and consumed by authorization (see
[01-architecture.md](./01-architecture.md)). The required permission is built by the PDP as
`` `${resource.type}.${action}` ``:

```ts
const principal: Principal = {
  userId: 'u1',
  tenantId: 't1',
  roles: ['agent'],
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: Date.now() },
};

const request: AccessRequest = {
  principal,
  action: 'read',
  resource: { type: 'data.orders', id: 'o1', tenantId: 't1' },
};

const decision = await pdp.check(request);
// required = 'data.orders.read'; the grant 'data.orders.read' (tenant scope) covers the
// 'tenant' relation → allow.
console.log(decision.effect); // 'allow'
console.log(decision.reason); // 'rbac_grant'
```

A `Decision` is **never** a plain boolean: it carries the `effect`, a human-readable `reason`, the
`signals` (for audit) and any `obligations` (see step-up below).

## DENY (deny-by-default)

Remove the grant, or request a scope the grant does not cover, and the PDP denies by default:

```ts
const noGrant: AuthorizationRepository = {
  async loadGrantsForUser() {
    return []; // no rights
  },
  async loadRole() {
    return null;
  },
};

const strictPdp = new RbacDecisionPoint({ grants: noGrant, relations });
const denied = await strictPdp.check(request);
console.log(denied.effect); // 'deny'
console.log(denied.reason); // 'no_grant'
```

Multi-tenant isolation is **enforced at the core**: if `resource.tenantId !== principal.tenantId`,
the relation is reduced to `none`, and only a `global`-scoped grant (platform plane) can cover it. A
`Principal` of tenant `t1` therefore never crosses over to a resource of tenant `t2`, even if the
`RelationResolver` mistakenly returns a broad relation.

## STEP-UP (conditional authorization)

Step-up arises from a **declarative policy**: it requires the layered PDP, a `PolicyStore` and an
expression engine (`@kengela/adapter-expr-cel`). Example: reading an order is allowed, but
**refunding** it requires a passkey re-authentication.

```sh
npm add @kengela/adapter-expr-cel
```

```ts
import { LayeredDecisionPoint } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import type { Policy, PolicyStore } from '@kengela/contracts';

const policies: PolicyStore = {
  async loadPolicies() {
    const policy: Policy = {
      resource: 'data.orders',
      action: 'refund',
      rules: [
        {
          effect: 'step_up',
          obligations: [{ type: 'require_passkey' }],
          reason: 'refund_needs_passkey',
        },
      ],
    };
    return [policy];
  },
};

const layered = new LayeredDecisionPoint({
  grants, // must cover data.orders.refund at the RBAC level (floor)
  relations,
  policies,
  expr: new CelExpressionEngine(),
});

const decision = await layered.check({
  principal,
  action: 'refund',
  resource: { type: 'data.orders', id: 'o1', tenantId: 't1' },
});

console.log(decision.effect); // 'step_up'
console.log(decision.obligations); // [{ type: 'require_passkey' }]
```

On the application side, `step_up` translates into a **challenge** (re-triggering an MFA/passkey)
rather than a bare 403. With `@kengela/nestjs`, the guard automatically raises a
`StepUpRequiredException` (see [05-nestjs-integration.md](./05-nestjs-integration.md)).

## What's next?

- Understand the model: [01-architecture.md](./01-architecture.md).
- Write policies (CEL, obligations): [02-authorization.md](./02-authorization.md).
- Wire up authentication (passwords, MFA, sessions): [03-authentication.md](./03-authentication.md).
- Federate identities (SSO, SCIM, LDAP): [04-identity-federation.md](./04-identity-federation.md).
