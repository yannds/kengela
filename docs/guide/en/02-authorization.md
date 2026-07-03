# 02 - Authorization

Authorization is the heart of Kengela (`@kengela/authz-core` + `@kengela/adapter-expr-cel`). This
page covers the permission grammar, grants and relations, writing declarative policies (CEL),
conditional access, obligations / step-up and decision logs.

## Permission grammar

A permission is a **dotted string** `plane.resource.action`, where `resource` may span several
segments. It is compatible with the Atrium and TransLog catalogs.

```
data.cashier.register.read
│    │       │        └── action
│    │       └──────────── resource (multi-segments)
│    └──────────────────── (segment de resource)
└───────────────────────── plane : platform | control | data | public
```

Valid segments: `^[a-z0-9*_-]+$`, at least 2 segments (otherwise `PermissionSyntaxError`).

### Coverage (`permissionCovers`)

A grant _covers_ a required permission according to these rules:

| Grant pattern                 | Meaning                                             |
| ----------------------------- | --------------------------------------------------- |
| **non-terminal** `*` segment  | wildcard over **exactly one** segment               |
| **terminal** `*` segment      | **prefix** wildcard (covers all remaining segments) |
| literal segment               | strict segment equality                             |
| (without a terminal wildcard) | the lengths must be **equal**                       |

Examples:

| Grant               | Covers                       | Does not cover                         |
| ------------------- | ---------------------------- | -------------------------------------- |
| `data.cashier.*`    | `data.cashier.register.read` | `data.orders.read`                     |
| `data.*.read`       | `data.orders.read`           | `data.a.b.read` (wildcard = 1 segment) |
| `data.cashier.read` | `data.cashier.read`          | everything else                        |

> **How the required permission is built.** The PDP forms the permission to check as
> `` `${resource.type}.${action}` ``. Thus, for `resource.type = 'data.orders'` and
> `action = 'read'`, the required permission is `data.orders.read`.

## Grants, scopes and relations

A **grant** is a right with provenance and expiry:

```ts
interface Grant {
  readonly permission: PermissionString;
  readonly scope: Scope; // own ⊂ unit ⊂ subtree ⊂ tenant ⊂ global
  readonly source: 'MANUAL' | 'IDP' | 'DELEGATION';
  readonly expiresAt?: Date; // grant expiré = inopérant (exclu au check)
}
```

The **scope** (`Scope`) of a grant and the organizational **relation** (`OrgRelation`) resolved
between the actor and the resource are compared by rank:

| Rank | Scope     | Covered relation                           |
| ---- | --------- | ------------------------------------------ |
| 0    | `own`     | `self`                                     |
| 1    | `unit`    | `unit`                                     |
| 2    | `subtree` | `subtree`                                  |
| 3    | `tenant`  | `tenant`                                   |
| 4    | `global`  | `none` (no org link: only `global` covers) |

A right granted at a scope **covers all narrower scopes**:
`scopeCoversRelation(grantScope, relation)` is true iff `SCOPE_RANK[grantScope] >=
relationRank(relation)`. This is what lets a `tenant` cover a `self`, but **never** the reverse.

The relation is resolved by a `RelationResolver` that the application provides (against its org
chart):

```ts
interface RelationResolver {
  resolveRelation(principal: Principal, resource: ResourceRef): Promise<OrgRelation>;
}
```

Grants are loaded by an `AuthorizationRepository`:

```ts
interface AuthorizationRepository {
  loadGrantsForUser(userId: UserId, tenantId: TenantId): Promise<readonly Grant[]>;
  loadRole(roleKey: string, tenantId: TenantId): Promise<Role | null>;
}
```

## The two PDPs

| Class                  | What it decides                                               | Dependencies                                                |
| ---------------------- | ------------------------------------------------------------- | ----------------------------------------------------------- |
| `RbacDecisionPoint`    | RBAC only: grants × relation                                  | `grants`, `relations`, `log?`, `clock?`                     |
| `LayeredDecisionPoint` | RBAC floor **+** ABAC policies + conditional access + step-up | `grants`, `relations`, `policies`, `expr`, `log?`, `clock?` |

```ts
import { RbacDecisionPoint, LayeredDecisionPoint } from '@kengela/authz-core';
```

Both implement `PolicyDecisionPoint`, whose `checkMany()` processes a batch of requests (avoiding the
N+1 on collection filtering).

## Writing a declarative policy

A `Policy` targets a `(resource, action)` pair (with `*` as wildcard) and carries a list of rules:

```ts
interface Policy {
  readonly resource: string; // type de ressource, ou '*'
  readonly action: string; // action, ou '*'
  readonly rules: readonly PolicyRule[];
}

interface PolicyRule {
  readonly effect: 'allow' | 'deny' | 'step_up';
  readonly scope?: Scope; // restreint la règle à une portée
  readonly when?: string; // condition CEL ; absente = toujours vrai
  readonly obligations?: readonly Obligation[];
  readonly reason?: string;
}
```

Policies are supplied by a `PolicyStore` (files versioned in CI, tenant overrides in the database, or
hybrid):

```ts
interface PolicyStore {
  loadPolicies(tenantId: TenantId): Promise<readonly Policy[]>;
}
```

### Example: "same agency" ABAC scoping

Allow reading an order **only** if it belongs to the actor's agency:

```ts
const policy: Policy = {
  resource: 'data.orders',
  action: 'read',
  rules: [
    {
      effect: 'allow',
      when: 'resource.attributes.agencyId == principal.agencyId',
    },
  ],
};
```

Reminder of the **ABAC gate**: as soon as an `allow` rule exists for `(resource, action)`, at least
one must match, otherwise `DENY no_matching_allow`. The resource attributes (`agencyId`, `ownerId`,
`amount`, ...) come from `resource.attributes` and are evaluated by CEL.

## CEL conditions (the expression engine)

`@kengela/adapter-expr-cel` implements `ExpressionEnginePort` on top of
[`@marcbachmann/cel-js`](https://github.com/marcbachmann/cel-js). The context exposed to expressions
is `{ principal, resource, env, tenant }`:

```ts
interface ExpressionContext {
  readonly principal: Principal;
  readonly resource: ResourceRef;
  readonly env: AuthContext & { readonly now: number };
  readonly tenant?: Readonly<Record<string, unknown>>;
}
```

```ts
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';

const expr = new CelExpressionEngine(); // horloge système par défaut
const engine = new CelExpressionEngine({ clock }); // horloge injectable (tests déterministes)
```

An expression **must return a boolean**; otherwise `CelEvaluationError` is thrown (and the PDP
catches it as `deny condition_error`). Compilations are cached.

### Date functions (deterministic via `Clock`)

Three functions are injected for temporal conditions (deadline, business-hours):

| CEL function                | Return         | Meaning                                          |
| --------------------------- | -------------- | ------------------------------------------------ |
| `now()`                     | int (epoch ms) | current timestamp (via `Clock`)                  |
| `daysUntil(x)`              | int            | calendar days until `x` (bigint/number/Date/ISO) |
| `businessDaysBetween(a, b)` | int            | business days (Mon-Fri), bounds included         |

```ts
// La ressource expire dans plus de 7 jours ?
const rule: PolicyRule = { effect: 'allow', when: 'daysUntil(resource.attributes.dueDate) > 7' };
```

### Anti-ReDoS: `matches` is **forbidden** in CEL

The CEL `matches` function would compile an **unbounded** `RegExp`: a catastrophic regex (`(a+)+`)
would cause exponential backtracking (ReDoS → DoS of the PDP) on adversarial input. The Kengela
doctrine bounds **every** regex; `matches` is therefore **rejected at compile time** (fail-closed) by
`assertNoUnboundedRegex()`. Express access conditions via `==`, `in`, `startsWith`, `contains`:

```ts
// ❌ rejeté : CelEvaluationError « matches interdite »
'resource.attributes.name.matches("(a+)+")';

// ✅ équivalents sûrs
'resource.attributes.tier in ["gold", "platinum"]';
'resource.attributes.code.startsWith("EU-")';
```

## Obligations and step-up

A matched `step_up` rule turns the decision into `STEP_UP` carrying **obligations**:

```ts
interface Obligation {
  readonly type: 'require_mfa' | 'require_passkey' | 'reauthenticate' | 'notify';
  readonly params?: Readonly<Record<string, unknown>>;
}
```

Example: refunds require a passkey **and** a low-risk context:

```ts
const refundPolicy: Policy = {
  resource: 'data.orders',
  action: 'refund',
  rules: [
    {
      effect: 'step_up',
      when: 'principal.mfaLevel != "passkey"',
      obligations: [{ type: 'require_passkey' }],
      reason: 'refund_needs_passkey',
    },
    {
      effect: 'deny',
      when: 'env.riskScore > 80',
      reason: 'refund_high_risk',
    },
  ],
};
```

Reminder deny-wins: if both rules match, the `deny` (high risk) prevails over the `step_up`.

On the application side, `step_up` triggers a **challenge** (re-triggering an MFA/passkey), not a
final refusal. With `@kengela/nestjs`, this becomes a `StepUpRequiredException` (see
[05-nestjs-integration.md](./05-nestjs-integration.md)).

## Decision logs (ZTNA observability)

Every decision can be traced for audit via `DecisionLogSink`:

```ts
interface DecisionLogSink {
  record(entry: {
    readonly request: AccessRequest;
    readonly decision: Decision;
    readonly at: number;
  }): Promise<void> | void;
}
```

A `Decision` carries everything needed for audit:

```ts
interface Decision {
  readonly effect: 'allow' | 'deny' | 'step_up';
  readonly obligations?: readonly Obligation[];
  readonly matchedPolicy?: string;
  readonly reason: string; // 'rbac_grant', 'no_grant', 'no_matching_allow', 'condition_error', ...
  readonly signals?: Readonly<Record<string, unknown>>; // { relation, crossTenant? }
}
```

```ts
const log: DecisionLogSink = {
  record({ request, decision, at }) {
    console.log(
      at,
      request.principal.userId,
      `${request.resource.type}.${request.action}`,
      decision.effect,
      decision.reason,
      decision.signals,
    );
  },
};

const pdp = new LayeredDecisionPoint({ grants, relations, policies, expr, log });
```

The `signals` capture in particular the resolved `relation` and the `crossTenant` flag: enough to
reconstruct _why_ an access was granted or denied.
