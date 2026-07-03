# 02 - Autorisation

L'autorisation est le cœur de Kengela (`@kengela/authz-core` + `@kengela/adapter-expr-cel`). Cette
page couvre la grammaire des permissions, les grants et relations, l'écriture de policies
déclaratives (CEL), le conditional access, les obligations / step-up et les decision logs.

## Grammaire des permissions

Une permission est une **chaîne pointée** `plane.resource.action`, où `resource` peut compter
plusieurs segments. Elle est compatible avec les catalogues Atrium et TransLog.

```
data.cashier.register.read
│    │       │        └── action
│    │       └──────────── resource (multi-segments)
│    └──────────────────── (segment de resource)
└───────────────────────── plane : platform | control | data | public
```

Segments valides : `^[a-z0-9*_-]+$`, au moins 2 segments (sinon `PermissionSyntaxError`).

### Couverture (`permissionCovers`)

Un grant _couvre_ une permission requise selon ces règles :

| Motif du grant               | Signification                                            |
| ---------------------------- | -------------------------------------------------------- |
| segment `*` **non terminal** | joker sur **exactement un** segment                      |
| segment `*` **terminal**     | joker de **préfixe** (couvre tous les segments restants) |
| segment littéral             | égalité stricte de segment                               |
| (sans joker terminal)        | les longueurs doivent être **égales**                    |

Exemples :

| Grant               | Couvre                       | Ne couvre pas                       |
| ------------------- | ---------------------------- | ----------------------------------- |
| `data.cashier.*`    | `data.cashier.register.read` | `data.orders.read`                  |
| `data.*.read`       | `data.orders.read`           | `data.a.b.read` (joker = 1 segment) |
| `data.cashier.read` | `data.cashier.read`          | tout le reste                       |

> **Comment la permission requise est construite.** Le PDP forme la permission à vérifier comme
> `` `${resource.type}.${action}` ``. Ainsi, pour `resource.type = 'data.orders'` et
> `action = 'read'`, la permission requise est `data.orders.read`.

## Grants, portées et relations

Un **grant** est un droit avec provenance et expiration :

```ts
interface Grant {
  readonly permission: PermissionString;
  readonly scope: Scope; // own ⊂ unit ⊂ subtree ⊂ tenant ⊂ global
  readonly source: 'MANUAL' | 'IDP' | 'DELEGATION';
  readonly expiresAt?: Date; // grant expiré = inopérant (exclu au check)
}
```

La **portée** (`Scope`) d'un grant et la **relation** organisationnelle (`OrgRelation`) résolue entre
l'acteur et la ressource sont comparées par rang :

| Rang | Scope     | Relation couverte                              |
| ---- | --------- | ---------------------------------------------- |
| 0    | `own`     | `self`                                         |
| 1    | `unit`    | `unit`                                         |
| 2    | `subtree` | `subtree`                                      |
| 3    | `tenant`  | `tenant`                                       |
| 4    | `global`  | `none` (aucun lien org : seul `global` couvre) |

Un droit accordé à une portée **couvre toutes les portées plus étroites** :
`scopeCoversRelation(grantScope, relation)` est vrai ssi `SCOPE_RANK[grantScope] >=
relationRank(relation)`. C'est ce qui permet à un `tenant` de couvrir un `self`, mais **jamais**
l'inverse.

La relation est résolue par un `RelationResolver` que fournit l'application (sur son organigramme) :

```ts
interface RelationResolver {
  resolveRelation(principal: Principal, resource: ResourceRef): Promise<OrgRelation>;
}
```

Les grants sont chargés par un `AuthorizationRepository` :

```ts
interface AuthorizationRepository {
  loadGrantsForUser(userId: UserId, tenantId: TenantId): Promise<readonly Grant[]>;
  loadRole(roleKey: string, tenantId: TenantId): Promise<Role | null>;
}
```

## Les deux PDP

| Classe                 | Ce qu'elle tranche                                               | Dépendances                                                 |
| ---------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------- |
| `RbacDecisionPoint`    | RBAC seul : grants × relation                                    | `grants`, `relations`, `log?`, `clock?`                     |
| `LayeredDecisionPoint` | RBAC plancher **+** policies ABAC + conditional access + step-up | `grants`, `relations`, `policies`, `expr`, `log?`, `clock?` |

```ts
import { RbacDecisionPoint, LayeredDecisionPoint } from '@kengela/authz-core';
```

Les deux implémentent `PolicyDecisionPoint`, dont `checkMany()` traite un lot de requêtes (évite le
N+1 sur le filtrage de collections).

## Écrire une policy déclarative

Une `Policy` cible un couple `(resource, action)` (avec `*` en joker) et porte une liste de règles :

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

Les policies sont fournies par un `PolicyStore` (fichiers versionnés en CI, overrides tenant en base,
ou hybride) :

```ts
interface PolicyStore {
  loadPolicies(tenantId: TenantId): Promise<readonly Policy[]>;
}
```

### Exemple : scoping ABAC « même agence »

Autoriser la lecture d'une commande **seulement** si elle appartient à l'agence de l'acteur :

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

Rappel du **gate ABAC** : dès qu'une règle `allow` existe pour `(resource, action)`, il faut qu'au
moins une matche, sinon `DENY no_matching_allow`. Les attributs de la ressource (`agencyId`,
`ownerId`, `amount`, ...) proviennent de `resource.attributes` et sont évalués par CEL.

## Conditions CEL (le moteur d'expressions)

`@kengela/adapter-expr-cel` implémente `ExpressionEnginePort` au-dessus de
[`@marcbachmann/cel-js`](https://github.com/marcbachmann/cel-js). Le contexte exposé aux expressions
est `{ principal, resource, env, tenant }` :

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

Une expression **doit retourner un booléen** ; sinon `CelEvaluationError` est levée (et le PDP la
rattrape en `deny condition_error`). Les compilations sont mises en cache.

### Fonctions de dates (déterministes via `Clock`)

Trois fonctions sont injectées pour les conditions temporelles (échéance, business-hours) :

| Fonction CEL                | Retour         | Sens                                                   |
| --------------------------- | -------------- | ------------------------------------------------------ |
| `now()`                     | int (epoch ms) | horodatage courant (via `Clock`)                       |
| `daysUntil(x)`              | int            | jours calendaires jusqu'à `x` (bigint/number/Date/ISO) |
| `businessDaysBetween(a, b)` | int            | jours ouvrés (lun-ven), bornes incluses                |

```ts
// La ressource expire dans plus de 7 jours ?
const rule: PolicyRule = { effect: 'allow', when: 'daysUntil(resource.attributes.dueDate) > 7' };
```

### Anti-ReDoS : `matches` est **interdit** dans CEL

La fonction CEL `matches` compilerait une `RegExp` **non bornée** : une regex catastrophique
(`(a+)+`) provoquerait un backtracking exponentiel (ReDoS → DoS du PDP) sur une entrée adverse. La
doctrine Kengela borne **toute** regex ; `matches` est donc **rejeté à la compilation** (fail-closed)
par `assertNoUnboundedRegex()`. Exprimez les conditions d'accès via `==`, `in`, `startsWith`,
`contains` :

```ts
// ❌ rejeté : CelEvaluationError « matches interdite »
'resource.attributes.name.matches("(a+)+")';

// ✅ équivalents sûrs
'resource.attributes.tier in ["gold", "platinum"]';
'resource.attributes.code.startsWith("EU-")';
```

## Obligations et step-up

Une règle `step_up` matchée transforme la décision en `STEP_UP` porteur d'**obligations** :

```ts
interface Obligation {
  readonly type: 'require_mfa' | 'require_passkey' | 'reauthenticate' | 'notify';
  readonly params?: Readonly<Record<string, unknown>>;
}
```

Exemple : les remboursements exigent une passkey **et** un contexte peu risqué :

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

Rappel deny-wins : si les deux règles matchent, le `deny` (risque élevé) l'emporte sur le `step_up`.

Côté application, `step_up` déclenche un **défi** (relancer une MFA/passkey), pas un refus définitif.
Avec `@kengela/nestjs`, cela devient une `StepUpRequiredException` (voir
[05-nestjs-integration.md](./05-nestjs-integration.md)).

## Decision logs (observabilité ZTNA)

Chaque décision peut être tracée pour l'audit via `DecisionLogSink` :

```ts
interface DecisionLogSink {
  record(entry: {
    readonly request: AccessRequest;
    readonly decision: Decision;
    readonly at: number;
  }): Promise<void> | void;
}
```

Une `Decision` porte tout le nécessaire à l'audit :

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

Les `signals` capturent notamment la `relation` résolue et le drapeau `crossTenant` : de quoi
reconstruire _pourquoi_ un accès a été accordé ou refusé.
</content>
