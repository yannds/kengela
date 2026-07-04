# Recipe 14 - Modeling authorization: RBAC + ABAC (CEL), obligations, step-up and logging

> Foundation: `@kengela/contracts` (the ports), `@kengela/authz-core` (the pure core: RBAC +
> layered PDP), `@kengela/adapter-expr-cel` (the CEL adapter). TypeScript ESM.
> Doctrine: **Zero Trust, deny-by-default, evaluated PER REQUEST, fail-closed.**

This page starts from the permission grammar, builds a pure RBAC decision, then stacks declarative
ABAC (CEL conditions), obligations / step-up (conditional access) and decision logging. Every
symbol used is verified in the package code.

---

## 1. Permission grammar and scopes

### 1.1 Permission format

A permission is a dotted string `plane.resource.action` where `resource` may span several
segments (`grant.ts`). The PDP never builds the string by hand on the caller side: it derives it
from the request, via `` `${resource.type}.${action}` `` (see `pdp.ts` line 50 and
`policy-pdp.ts` line 66). So if `resource.type = 'data.cashier.register'` and
`action = 'read'`, the required permission is `data.cashier.register.read`.

Pattern→required matching is done by `permissionCovers(grantPermission, required)`:

| Grant pattern       | Covers                                                    | Does not cover     |
| ------------------- | --------------------------------------------------------- | ------------------ |
| `data.cashier.*`    | `data.cashier.register.read` (terminal wildcard = prefix) | `data.orders.read` |
| `data.*.read`       | `data.orders.read` (single-segment wildcard)              | `data.a.b.read`    |
| `data.cashier.read` | `data.cashier.read` (strict equality)                     | everything else    |

Real rules (`permissionCovers`, `grant.ts`):

- `*` **terminal** segment → prefix wildcard (covers all remaining segments);
- `*` **non-terminal** segment → wildcard over exactly one segment;
- otherwise strict segment equality, **and** the lengths must be equal (absent a terminal wildcard).

`assertPermissionSyntax(permission)` validates the shape (≥ 2 segments, each segment `^[a-z0-9*_-]+$`)
and **throws** `PermissionSyntaxError` otherwise (fail-closed at grant ingestion time).

### 1.2 Scopes (`Scope`) and org relations (`OrgRelation`)

A right granted at a scope covers all narrower scopes. The real order is read in `scope.ts`:

```ts
// scope.ts - SCOPE_RANK : de la plus étroite (0) à la plus large (4)
export const SCOPE_RANK: Readonly<Record<Scope, number>> = {
  own: 0, // ⊂
  unit: 1, // ⊂
  subtree: 2, // ⊂
  tenant: 3, // ⊂
  global: 4,
};
```

i.e. `own ⊂ unit ⊂ subtree ⊂ tenant ⊂ global`.

The **relation** (`OrgRelation = 'self' | 'unit' | 'subtree' | 'tenant' | 'none'`) is the position
of the resource relative to the actor, resolved upstream by a `RelationResolver`. It is converted
into the minimal required scope rank by `relationRank`:

| Resolved relation | Minimal required rank | Interpretation                            |
| ----------------- | --------------------- | ----------------------------------------- |
| `self`            | `own` (0)             | the resource is the actor's own           |
| `unit`            | `unit` (1)            | same organizational unit                  |
| `subtree`         | `subtree` (2)         | the actor's org subtree                   |
| `tenant`          | `tenant` (3)          | same tenant                               |
| `none`            | `global` (4)          | **no link**: only a `global` grant covers |

The bridge: `scopeCoversRelation(grantScope, relation)` returns
`SCOPE_RANK[grantScope] >= relationRank(relation)`. A `unit` grant therefore covers a `self` or
`unit` relation, but not `subtree`/`tenant`/`none`.

---

## 2. RBAC: deciding with grants and scopes

### 2.1 The vocabulary (`Grant`, `Role`)

A `Grant` (contracts) is **flat**: no `id`, no role reference. It carries a permission pattern, a
scope, a provenance and an optional expiry. A `Role` groups grants together.

```ts
import type { Grant, Role } from '@kengela/contracts';

const grants: readonly Grant[] = [
  { permission: 'data.cashier.*', scope: 'unit', source: 'MANUAL' },
  { permission: 'data.orders.read', scope: 'subtree', source: 'IDP' },
  // Grant délégué temporaire : cesse d'agir tout seul après expiresAt.
  {
    permission: 'data.refund.approve',
    scope: 'unit',
    source: 'DELEGATION',
    expiresAt: new Date('2026-07-10T00:00:00Z'),
  },
];

const cashierRole: Role = { key: 'cashier', tenantId: 'tnt_acme', grants };
```

> `activeGrants(grants, now)` (`engine.ts`) filters out expired grants: a grant without `expiresAt`
> is always active; otherwise it is active as long as `expiresAt.getTime() > now`.

### 2.2 The pure core (no PDP)

Three composable pure functions (`engine.ts`) - useful in unit tests and to understand the
mechanics:

```ts
import { grantCovers, isAuthorized, activeGrants } from '@kengela/authz-core';

// grantCovers = permissionCovers(motif, requis) && scopeCoversRelation(portée, relation)
grantCovers(
  { permission: 'data.cashier.*', scope: 'unit', source: 'MANUAL' },
  'data.cashier.register.read',
  'self',
); // true (préfixe + unit ⊇ own)

// isAuthorized : deny-by-default. Aucun grant couvrant => false.
isAuthorized(grants, 'data.cashier.register.read', 'self', Date.now()); // true
```

### 2.3 The RBAC PDP (`RbacDecisionPoint`)

`RbacDecisionPoint` implements `PolicyDecisionPoint`. It does **not** trust the cached
`Principal.roles`: it **reloads the grants on every check** via the `AuthorizationRepository`
(anti-staleness - a revoked right stops working immediately).

```ts
import { RbacDecisionPoint } from '@kengela/authz-core';
import type {
  AuthorizationRepository,
  RelationResolver,
  AccessRequest,
  Decision,
} from '@kengela/contracts';

// L'app fournit ces deux ports (voir §6).
const grantsRepo: AuthorizationRepository = /* charge depuis VOTRE base */ myRepo;
const relations: RelationResolver = /* résout la position org */ myResolver;

const pdp = new RbacDecisionPoint({
  grants: grantsRepo,
  relations,
  log: myDecisionLog, // optionnel (§5)
  clock: { now: () => Date.now() }, // optionnel - défaut = horloge système
});

const request: AccessRequest = {
  principal: {
    userId: 'usr_42',
    tenantId: 'tnt_acme',
    roles: ['cashier'],
    agencyId: 'agc_lome',
    mfaLevel: 'totp',
    authMethod: 'credential',
    ctx: { authTime: Date.now(), riskScore: 12, device: { trusted: true } },
  },
  action: 'read',
  resource: {
    type: 'data.cashier.register',
    id: 'reg_7',
    tenantId: 'tnt_acme',
    attributes: { agencyId: 'agc_lome', ownerId: 'usr_42' },
  },
};

const decision: Decision = await pdp.check(request);
// -> { effect: 'allow', reason: 'rbac_grant', matchedPolicy: 'data.cashier.register.read',
//      signals: { relation: 'self' } }
```

`checkMany(requests)` evaluates a batch in parallel (`Promise.all`) - this is what we use to filter
a collection without N+1:

```ts
const decisions: readonly Decision[] = await pdp.checkMany(rows.map(toAccessRequest));
const visible = rows.filter((_, i) => decisions[i].effect === 'allow');
```

An RBAC refusal returns `{ effect: 'deny', reason: 'no_grant', signals: { relation } }`.

### 2.4 Multi-tenant isolation: `tenantScopedRelation`

Defense in depth, called by **both** PDPs before any coverage. If the resource does not belong to
the principal's tenant, the resolved relation is **brought back to `none`** - so only a `global`
grant (platform plan) can cover, even if the `RelationResolver` made a mistake and returned a
too-broad relation.

```ts
// engine.ts
export function tenantScopedRelation(
  principalTenantId: TenantId,
  resourceTenantId: TenantId,
  resolved: OrgRelation,
): OrgRelation {
  return principalTenantId === resourceTenantId ? resolved : 'none';
}
```

The PDP additionally marks `signals.crossTenant = true` when the tenants differ (traceability).
**Tenant equality always takes precedence over the org chart.**

---

## 3. ABAC/CEL: declarative conditions on top of the RBAC floor

### 3.1 Writing a `Policy`

A `Policy` targets `(resource, action)` (`*` = wildcard) and carries `PolicyRule[]`. Each rule has
an `effect` (`allow` | `deny` | `step_up`), an optional `scope`, an optional CEL `when` condition
(absence = always true), `obligations` and a `reason`.

```ts
import type { Policy } from '@kengela/contracts';

const refundPolicy: Policy = {
  resource: 'data.refund',
  action: 'approve',
  rules: [
    // (a) Scoping déclaratif : n'autorise que dans la MÊME agence.
    { effect: 'allow', when: 'resource.attributes.agencyId == principal.agencyId' },

    // (b) Fenêtre métier : refus hors jour ouvré (lun-ven).
    {
      effect: 'deny',
      reason: 'outside_business_hours',
      when: 'businessDaysBetween(now(), now()) != 1',
    },

    // (c) Conditional access : au-delà d'un seuil de risque, exiger un passkey.
    //     has() garde l'accès à un champ optionnel (riskScore absent => pas d'erreur, cf. §5).
    {
      effect: 'step_up',
      when: 'has(env.riskScore) && env.riskScore >= 50',
      obligations: [{ type: 'require_passkey' }],
    },
  ],
};
```

Three more realistic conditions, all in bounded operators:

```txt
// Appartenance / propriété
resource.attributes.ownerId == principal.userId

// Fenêtre horaire (UTC). env.now est un JS number => `double` côté CEL, et l'arithmétique
// (/ et %) EXIGE des int : on convertit avec int(...). (% n'a AUCUN overload double.)
(int(env.now) / 3600000) % 24 >= 6 && (int(env.now) / 3600000) % 24 < 20

// Fraîcheur de session : ré-auth si l'authentification date de + de 15 min.
// now() renvoie un int ; env.authTime est un double => on convertit avant la soustraction.
now() - int(env.authTime) > 900000
```

> **Numeric types (verified against `@marcbachmann/cel-js` 7.6.1).** The `now()` function returns
> an **`int`**; the numbers injected into the context (`env.now`, `env.authTime`, `env.riskScore`…)
> are JS `number`s, hence **`double`** on the CEL side. **Arithmetic** (`-`, `/`, `%`) has **no**
> mixed overload: `int - double`, `double / int` and even `double % double` **throw**
> (`no such overload: …`) → deny `condition_error`. So convert any context operand with `int(...)`
> before a computation (`int(env.now)`, `int(env.authTime)`). **Comparisons** (`>`, `>=`, `<`, `==`),
> in contrast, tolerate the int/double mix: `env.riskScore >= 50` is well-typed (the only risk there
> being the ABSENCE of the field, see §5).
>
> **Tenant time zone.** `env.now` and `now()` are in **UTC** (epoch ms). For a time zone, add the
> offset on the int side: `(int(env.now) + int(tenant.tzOffsetMs)) …`, or precompute it in the app
> and expose an attribute. `businessDaysBetween(now(), now())` equals `1` if today (UTC) is a
> business day (Mon-Fri), `0` on weekends - that is the "business day" check above.

### 3.2 Wiring the CEL adapter

The `CelExpressionEngine` adapter implements `ExpressionEnginePort`. The vendor
(`@marcbachmann/cel-js`) lives **only** here. Real init (constructor, `cel-expression-engine.ts`):
it registers the context variables in dynamic access and the deterministic date functions
(via `Clock`).

```ts
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';

// L'init interne (pour info) - vous n'appelez QUE le constructeur :
//   new Environment()
//     .registerVariable('principal', 'dyn')
//     .registerVariable('resource', 'dyn')
//     .registerVariable('env', 'dyn')
//     .registerVariable('tenant', 'dyn')
//     .registerFunction('now(): int', () => BigInt(clock.now()))
//     .registerFunction('daysUntil(dyn): int', (t) => BigInt(daysBetween(now, toEpochMs(t))))
//     .registerFunction('businessDaysBetween(dyn, dyn): int', ...)

const expr = new CelExpressionEngine({ clock: { now: () => Date.now() } });
```

The functions available in an expression: `now()` (epoch ms), `daysUntil(x)` (calendar days until
`x`), `businessDaysBetween(a, b)` (business days, bounds included). `x`, `a`, `b` accept
bigint/number/Date/ISO string (`toEpochMs`). `evaluateBoolean` **requires** a boolean output,
otherwise it throws `CelEvaluationError`.

### 3.3 `matches` is FORBIDDEN (ReDoS) - why

`assertNoUnboundedRegex` rejects any expression containing `matches(` (after neutralizing the
content of string literals, so as not to confuse code with a string). Reason: `cel-js` compiles
`matches` into an **unbounded** `new RegExp(pattern).test(input)`; a catastrophic regex like
`(a+)+` triggers exponential backtracking on an adversarial input - a **DoS of the PDP**. The
Kengela doctrine bounds EVERY regex; an access condition is therefore written with `==`, `in`,
`startsWith`, `contains`, never an unbounded regex. The violation throws `CelEvaluationError` -
hence a fail-closed deny downstream.

### 3.4 The layered PDP (`LayeredDecisionPoint`)

It stacks everything in the exact following order (`policy-pdp.ts`):

```txt
1. Plancher RBAC          - sans grant actif couvrant (perm × relation) => deny 'no_grant'
2. Policies applicables   - filtrées sur (resource.type, action), on aplatit leurs règles
                            (0 règle applicable => allow 'rbac_grant', le RBAC suffit)
3. Deny explicite gagne   - une règle 'deny' matchée => deny (deny-wins)
4. Gate ABAC positif      - s'il existe des règles 'allow' mais AUCUNE matchée => deny 'no_matching_allow'
5. Step-up                - les règles 'step_up' matchées imposent leurs obligations
6. Sinon                  - allow 'rbac_grant'
```

```ts
import { LayeredDecisionPoint } from '@kengela/authz-core';
import type { PolicyStore } from '@kengela/contracts';

const policies: PolicyStore = {
  loadPolicies: async (_tenantId) => [refundPolicy],
};

const layered = new LayeredDecisionPoint({
  grants: grantsRepo, // AuthorizationRepository  (plancher RBAC)
  relations, // RelationResolver
  policies, // PolicyStore              (couche ABAC)
  expr, // ExpressionEnginePort     (CelExpressionEngine)
  log: myDecisionLog, // optionnel
  clock: { now: () => Date.now() },
});

const d = await layered.check(refundRequest);
```

> The CEL context is built by the PDP:
> `ctx = { principal, resource, env: { ...principal.ctx, ...request.env, now } }`.
> So `env` exposes `authTime`, `riskScore`, `geo`, `device`… (coming from `principal.ctx`),
> overridden by `request.env`, plus `now` (epoch ms of the injected clock). A rule can also filter
> by `scope`: `#ruleApplies` short-circuits via `scopeCoversRelation(rule.scope, relation)` even
> before evaluating `when`.

On the `refundPolicy` example, with the principal above (same agency, `riskScore 12`) on a Tuesday:
rule (a) matches (allow), (b) does not match (business day), (c) does not match (risk < 50) →
`{ effect: 'allow', reason: 'rbac_grant', matchedPolicy: 'data.refund.approve', signals: { relation } }`.

---

## 4. Obligations & step-up (conditional access)

A `Decision` is **never** a boolean: it can return `effect: 'step_up'` with `obligations`. If
`step_up` rules match, the PDP aggregates their obligations and returns:

```ts
// Principal à risque élevé (riskScore 72) => la règle (c) matche.
const decision = await layered.check({ ...refundRequest, principal: riskyPrincipal });
// -> { effect: 'step_up', reason: 'step_up_required',
//      obligations: [{ type: 'require_passkey' }], signals: { relation } }
```

Possible obligation types (`Obligation`, contracts):
`'require_mfa' | 'require_passkey' | 'reauthenticate' | 'notify'`, with a free `params?`.

How the app reacts - the PDP decides, the app **executes** the obligation then replays the check:

```ts
async function enforce(request: AccessRequest): Promise<'ok' | 'blocked'> {
  const d = await layered.check(request);
  if (d.effect === 'allow') return 'ok';
  if (d.effect === 'deny') return 'blocked';

  // effect === 'step_up' : satisfaire chaque obligation, PUIS re-vérifier.
  for (const ob of d.obligations ?? []) {
    if (ob.type === 'require_passkey' && request.principal.mfaLevel !== 'passkey') {
      await promptPasskey(request.principal.userId); // challenge MFA côté app
    }
    if (ob.type === 'reauthenticate') await promptReauth(request.principal.userId);
  }
  // Rejeu avec un principal dont mfaLevel/authTime ont été relevés :
  const after = await layered.check(withElevatedSession(request));
  return after.effect === 'allow' ? 'ok' : 'blocked';
}
```

Step-up is therefore **data-driven**: raising `Principal.mfaLevel` to `passkey` (or refreshing
`ctx.authTime`) makes the `when` condition fall back and lets the replay through. No imperative
"MFA level" code is wired into the PDP.

---

## 5. Decision logging (`DecisionLogSink`)

**Both** PDPs emit every decision to the optional `DecisionLogSink` - RBAC via
`this.#deps.log?.record(...)`, layered via `#emit(...)`. The logged entry is
`{ request, decision, at }` (`at` = the clock's `now`).

```ts
import type { DecisionLogSink } from '@kengela/contracts';

const myDecisionLog: DecisionLogSink = {
  record: ({ request, decision, at }) => {
    // Ne journalisez pas d'aveugle : redaction PII selon votre politique.
    logger.info('authz.decision', {
      at,
      user: request.principal.userId,
      tenant: request.principal.tenantId,
      action: request.action,
      resource: `${request.resource.type}:${request.resource.id ?? '-'}`,
      effect: decision.effect, // allow | deny | step_up
      reason: decision.reason, // 'no_grant' | 'no_matching_allow' | 'condition_error' | ...
      matchedPolicy: decision.matchedPolicy,
      signals: decision.signals, // { relation, crossTenant? }
      obligations: decision.obligations,
    });
  },
};
```

What surfaces as `reason` depending on the path:

- `no_grant` - RBAC floor not crossed;
- `rbac_grant` - authorized (RBAC alone, or after the ABAC/step-up gate is crossed);
- matched `deny` rule - `rule.reason ?? 'policy_deny'`;
- `no_matching_allow` - there are `allow` rules but none matched (positive gate);
- `step_up_required` - obligations to satisfy;
- **`condition_error` - FAIL-CLOSED**.

### Fail-closed on evaluation error

If a CEL condition cannot be evaluated (missing variable, non-boolean, forbidden `matches`,
invalid expression), `evaluateBoolean` **throws**. The `LayeredDecisionPoint` catches around the
`rules.filter(...)` and returns **deny**:

```ts
// policy-pdp.ts (extrait fidèle)
try {
  matched = rules.filter((r) => this.#ruleApplies(r, relation, ctx));
} catch {
  return this.#emit(
    request,
    { effect: 'deny', reason: 'condition_error', signals: { relation } },
    now,
  );
}
```

A broken policy **closes** access (Zero Trust) instead of opening it - and the `deny`
`condition_error` decision is logged, which makes the failure observable.

**Missing field - verified behavior (`cel-js` 7.6.1).** Accessing an absent key **throws**
`No such key: <key>`, at any level: `env.riskScore` when `env` has no `riskScore`, just like
`principal.ctx.riskScore` when `ctx` (or `riskScore`) is missing. Since `riskScore` is **optional**
(`AuthContext.riskScore?`), a bare `env.riskScore >= 50` condition on a principal without a score
throws → `LayeredDecisionPoint` catches → deny `condition_error`. The tolerant form is the `has()`
macro, which short-circuits absence **without** an error:

```txt
has(env.riskScore) && env.riskScore >= 50   // false si absent, sinon compare
```

The optional-access operator `.?` (`env.?riskScore`) is **not** supported by this version of the
vendor (parse error `Expected IDENTIFIER, got QUESTION`): use `has()`, never `.?`.

---

## 6. Callout - what Kengela computes vs what the app provides

> **Kengela (authz-core + CEL adapter) COMPUTES:**
>
> - permission×scope×relation coverage (`grantCovers`, `permissionCovers`, `scopeCoversRelation`);
> - the layered decision order: RBAC floor → deny-wins → positive ABAC gate → step-up → allow;
> - fail-closed multi-tenant isolation (`tenantScopedRelation`);
> - the sandboxed evaluation of CEL conditions and the refusal of unbounded regexes;
> - fail-closed on evaluation error and the emission of decisions to the log.
>
> **The application PROVIDES (via the contracts ports):**
>
> - `AuthorizationRepository.loadGrantsForUser` - the **grants from ITS database** (reloaded on every check);
> - `RelationResolver.resolveRelation` - the **org relation** actor↔resource (org chart);
> - `PolicyStore.loadPolicies` - the **declarative policies** (files versioned in CI and/or tenant overrides in the database);
> - the **request context**: `Principal` (including `ctx: AuthContext` - geo/device/risk/authTime, produced by authn) and `ResourceRef.attributes` (the ABAC material);
> - the implementations of `Clock`, `DecisionLogSink`, and the execution of obligations (MFA/passkey challenge, re-auth).
>
> The core is **pure** (zero vendor/infra dependency); the CEL vendor is confined to the adapter.
> The PDP never trusts the cache (`Principal.roles`) for grants: SSoT = the repo.

---

### Symbol recap (all verified in the source)

| Symbol                                                                                                         | Package / file                              | Key signature                           |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------- | --------------------------------------- |
| `SCOPE_RANK`, `scopeCoversRelation`, `relationRank`                                                            | authz-core/`scope.ts`                       | `own0<unit1<subtree2<tenant3<global4`   |
| `permissionCovers`, `grantCovers`, `assertPermissionSyntax`                                                    | authz-core/`grant.ts`, `engine.ts`          | pattern + scope coverage                |
| `tenantScopedRelation`, `activeGrants`, `isAuthorized`                                                         | authz-core/`engine.ts`                      | isolation + expiry filtering            |
| `RbacDecisionPoint`                                                                                            | authz-core/`pdp.ts`                         | `check` / `checkMany` → `Decision`      |
| `LayeredDecisionPoint`                                                                                         | authz-core/`policy-pdp.ts`                  | RBAC→deny-wins→gate→step-up             |
| `CelExpressionEngine`, `assertNoUnboundedRegex`                                                                | adapter-expr-cel/`cel-expression-engine.ts` | `evaluateBoolean` ; `matches` forbidden |
| `now` / `daysUntil` / `businessDaysBetween`                                                                    | adapter-expr-cel/`dates.ts`                 | epoch ms, business days Mon-Fri         |
| `Grant` `Role` `Policy` `PolicyRule` `Decision` `Obligation` `AccessRequest` `Principal` `ResourceRef` + ports | contracts/`index.ts`                        | stable contracts                        |
| `PrincipalRelationResolver`                                                                                    | authz-core/`relation-resolver.ts`           | relation derived from `Principal`, pure |

---

## Complete example (copy-paste)

A single ESM module that assembles all the machinery of this page: grants + ABAC/CEL policy, an
in-memory `AuthorizationRepository`, the default `PrincipalRelationResolver`, the
`CelExpressionEngine`, a `DecisionLogSink`, the `LayeredDecisionPoint`, a single `check`, the
`checkMany` filtering and the step-up loop. The CEL expressions are written in the verified
affirmative form (int-safe + `has()`).

```ts
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import type {
  AccessRequest,
  AuthorizationRepository,
  Decision,
  DecisionLogSink,
  Grant,
  Policy,
  PolicyStore,
  Principal,
  Role,
} from '@kengela/contracts';

// 1. Grants (plancher RBAC). Grant plat : motif + portée + provenance + expiration option.
const grants: readonly Grant[] = [
  { permission: 'data.cashier.*', scope: 'unit', source: 'MANUAL' },
  { permission: 'data.refund.approve', scope: 'unit', source: 'MANUAL' },
  {
    permission: 'data.refund.approve',
    scope: 'unit',
    source: 'DELEGATION',
    expiresAt: new Date('2026-07-10T00:00:00Z'),
  },
];
const cashierRole: Role = { key: 'cashier', tenantId: 'tnt_acme', grants };

// 2. Repo de grants : rechargé À CHAQUE check (anti-staleness). Ici en mémoire.
const grantsRepo: AuthorizationRepository = {
  loadGrantsForUser: async (_userId, _tenantId) => grants,
  loadRole: async (roleKey, tenantId) =>
    roleKey === cashierRole.key && tenantId === cashierRole.tenantId ? cashierRole : null,
};

// 3. RelationResolver par défaut, pur (relation déduite du Principal, deny-by-default).
const relations = new PrincipalRelationResolver();

// 4. Policies déclaratives (couche ABAC). Conditions CEL int-safe + has().
const refundPolicy: Policy = {
  resource: 'data.refund',
  action: 'approve',
  rules: [
    { effect: 'allow', when: 'resource.attributes.agencyId == principal.agencyId' },
    {
      effect: 'deny',
      reason: 'outside_business_hours',
      when: 'businessDaysBetween(now(), now()) != 1',
    },
    {
      effect: 'step_up',
      when: 'has(env.riskScore) && env.riskScore >= 50',
      obligations: [{ type: 'require_passkey' }],
    },
  ],
};
const policies: PolicyStore = { loadPolicies: async (_tenantId) => [refundPolicy] };

// 5. Adapter CEL (le vendor @marcbachmann/cel-js vit ICI) + horloge injectable.
const expr = new CelExpressionEngine({ clock: { now: () => Date.now() } });

// 6. Journal des décisions (optionnel).
const decisionLog: DecisionLogSink = {
  record: ({ request, decision, at }) => {
    // eslint-disable-next-line no-console
    console.log('authz.decision', {
      at,
      user: request.principal.userId,
      effect: decision.effect,
      reason: decision.reason,
    });
  },
};

// 7. PDP en couches : RBAC -> deny-wins -> gate ABAC -> step-up.
const layered = new LayeredDecisionPoint({
  grants: grantsRepo,
  relations,
  policies,
  expr,
  log: decisionLog,
  clock: { now: () => Date.now() },
});

// 8. Une requête d'accès.
const principal: Principal = {
  userId: 'usr_42',
  tenantId: 'tnt_acme',
  roles: ['cashier'],
  agencyId: 'agc_lome',
  mfaLevel: 'totp',
  authMethod: 'credential',
  ctx: { authTime: Date.now(), riskScore: 12, device: { trusted: true } },
};
const refundRequest: AccessRequest = {
  principal,
  action: 'approve',
  resource: {
    type: 'data.refund',
    id: 'rfd_7',
    tenantId: 'tnt_acme',
    attributes: { agencyId: 'agc_lome', ownerId: 'usr_42' },
  },
};

// 9. Décision unitaire.
const decision: Decision = await layered.check(refundRequest);

// 10. Filtrage d'une collection sans N+1 (checkMany en parallèle).
async function visibleRows<T>(
  rows: readonly T[],
  toRequest: (row: T) => AccessRequest,
): Promise<readonly T[]> {
  const decisions = await layered.checkMany(rows.map(toRequest));
  return rows.filter((_, i) => decisions[i].effect === 'allow');
}

// 11. Boucle step-up : le PDP DÉCIDE, l'app EXÉCUTE l'obligation, puis rejoue.
async function enforce(request: AccessRequest): Promise<'ok' | 'blocked'> {
  const d = await layered.check(request);
  if (d.effect === 'allow') return 'ok';
  if (d.effect === 'deny') return 'blocked';
  for (const ob of d.obligations ?? []) {
    if (ob.type === 'require_passkey' && request.principal.mfaLevel !== 'passkey') {
      await promptPasskey(request.principal.userId);
    }
    if (ob.type === 'reauthenticate') await promptReauth(request.principal.userId);
  }
  const after = await layered.check(withElevatedSession(request));
  return after.effect === 'allow' ? 'ok' : 'blocked';
}

// Stubs applicatifs à brancher sur TON authn (challenge MFA/passkey, ré-auth, session élevée).
declare function promptPasskey(userId: string): Promise<void>;
declare function promptReauth(userId: string): Promise<void>;
declare function withElevatedSession(request: AccessRequest): AccessRequest;

export { layered, decision, visibleRows, enforce };
```
