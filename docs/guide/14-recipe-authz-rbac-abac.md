# Recette 14 — Modéliser l'autorisation : RBAC + ABAC (CEL), obligations, step-up et journalisation

> Socle : `@kengela/contracts` (les ports), `@kengela/authz-core` (le cœur pur : RBAC + PDP en
> couches), `@kengela/adapter-expr-cel` (l'adapter CEL). TypeScript ESM.
> Doctrine : **Zero Trust, deny-by-default, évalué PAR REQUÊTE, fail-closed.**

Cette page part de la grammaire des permissions, construit une décision RBAC pure, puis empile
l'ABAC déclaratif (conditions CEL), les obligations / step-up (conditional access) et la
journalisation des décisions. Chaque symbole employé est vérifié dans le code du paquet.

---

## 1. Grammaire des permissions et portées

### 1.1 Format d'une permission

Une permission est une chaîne pointée `plane.resource.action` où `resource` peut compter
plusieurs segments (`grant.ts`). Le PDP ne fabrique jamais la chaîne à la main côté appelant :
il la dérive de la requête, par `` `${resource.type}.${action}` `` (cf. `pdp.ts` ligne 50 et
`policy-pdp.ts` ligne 66). Donc si `resource.type = 'data.cashier.register'` et
`action = 'read'`, la permission requise est `data.cashier.register.read`.

La correspondance motif→requis est faite par `permissionCovers(grantPermission, required)` :

| Motif du grant      | Couvre                                                  | Ne couvre pas      |
| ------------------- | ------------------------------------------------------- | ------------------ |
| `data.cashier.*`    | `data.cashier.register.read` (joker terminal = préfixe) | `data.orders.read` |
| `data.*.read`       | `data.orders.read` (joker 1 segment)                    | `data.a.b.read`    |
| `data.cashier.read` | `data.cashier.read` (égalité stricte)                   | tout le reste      |

Règles réelles (`permissionCovers`, `grant.ts`) :

- segment `*` **terminal** → joker de préfixe (couvre tous les segments restants) ;
- segment `*` **non terminal** → joker sur exactement un segment ;
- sinon égalité stricte de segment, **et** les longueurs doivent être égales (à défaut de joker
  terminal).

`assertPermissionSyntax(permission)` valide la forme (≥ 2 segments, chaque segment `^[a-z0-9*_-]+$`)
et **lève** `PermissionSyntaxError` sinon (fail-closed dès l'ingestion des grants).

### 1.2 Les portées (`Scope`) et les relations org (`OrgRelation`)

Un droit accordé à une portée couvre toutes les portées plus étroites. L'ordre réel est lu dans
`scope.ts` :

```ts
// scope.ts — SCOPE_RANK : de la plus étroite (0) à la plus large (4)
export const SCOPE_RANK: Readonly<Record<Scope, number>> = {
  own: 0, // ⊂
  unit: 1, // ⊂
  subtree: 2, // ⊂
  tenant: 3, // ⊂
  global: 4,
};
```

soit `own ⊂ unit ⊂ subtree ⊂ tenant ⊂ global`.

La **relation** (`OrgRelation = 'self' | 'unit' | 'subtree' | 'tenant' | 'none'`) est la position
de la ressource par rapport à l'acteur, résolue en amont par un `RelationResolver`. On la convertit
en rang de portée minimal requis par `relationRank` :

| Relation résolue | Rang minimal requis | Interprétation                                 |
| ---------------- | ------------------- | ---------------------------------------------- |
| `self`           | `own` (0)           | la ressource est celle de l'acteur             |
| `unit`           | `unit` (1)          | même unité organisationnelle                   |
| `subtree`        | `subtree` (2)       | sous-arbre org de l'acteur                     |
| `tenant`         | `tenant` (3)        | même tenant                                    |
| `none`           | `global` (4)        | **aucun lien** : seul un grant `global` couvre |

Le pont : `scopeCoversRelation(grantScope, relation)` renvoie
`SCOPE_RANK[grantScope] >= relationRank(relation)`. Un grant `unit` couvre donc une relation
`self` ou `unit`, mais pas `subtree`/`tenant`/`none`.

---

## 2. RBAC : décider avec des grants et des portées

### 2.1 Le vocabulaire (`Grant`, `Role`)

Un `Grant` (contracts) est **plat** : pas d'`id`, pas de référence de rôle. Il porte un motif de
permission, une portée, une provenance et une expiration optionnelle. Un `Role` regroupe des grants.

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

> `activeGrants(grants, now)` (`engine.ts`) filtre les grants expirés : un grant sans `expiresAt`
> est toujours actif ; sinon il l'est tant que `expiresAt.getTime() > now`.

### 2.2 Le cœur pur (sans PDP)

Trois fonctions pures composables (`engine.ts`) — utiles en test unitaire et pour comprendre la
mécanique :

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

### 2.3 Le PDP RBAC (`RbacDecisionPoint`)

`RbacDecisionPoint` implémente `PolicyDecisionPoint`. Il ne fait **pas** confiance à
`Principal.roles` mis en cache : il **recharge les grants à chaque check** via
l'`AuthorizationRepository` (anti-staleness — un droit révoqué cesse d'agir immédiatement).

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
  clock: { now: () => Date.now() }, // optionnel — défaut = horloge système
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

`checkMany(requests)` évalue un lot en parallèle (`Promise.all`) — c'est ce qu'on utilise pour
filtrer une collection sans N+1 :

```ts
const decisions: readonly Decision[] = await pdp.checkMany(rows.map(toAccessRequest));
const visible = rows.filter((_, i) => decisions[i].effect === 'allow');
```

Un refus RBAC renvoie `{ effect: 'deny', reason: 'no_grant', signals: { relation } }`.

### 2.4 Isolation multi-tenant : `tenantScopedRelation`

Défense en profondeur, appelée par **les deux** PDP avant toute couverture. Si la ressource
n'appartient pas au tenant du principal, la relation résolue est **ramenée à `none`** — donc seul
un grant `global` (plan plateforme) peut couvrir, même si le `RelationResolver` s'est trompé et a
renvoyé une relation trop large.

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

Le PDP marque en outre `signals.crossTenant = true` quand les tenants diffèrent (traçabilité).
**L'égalité de tenant prime toujours sur l'organigramme.**

---

## 3. ABAC/CEL : conditions déclaratives par-dessus le plancher RBAC

### 3.1 Écrire une `Policy`

Une `Policy` cible `(resource, action)` (`*` = joker) et porte des `PolicyRule[]`. Chaque règle a
un `effect` (`allow` | `deny` | `step_up`), une `scope` optionnelle, une condition CEL `when`
optionnelle (absence = toujours vrai), des `obligations` et une `reason`.

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
    { effect: 'step_up', when: 'env.riskScore >= 50', obligations: [{ type: 'require_passkey' }] },
  ],
};
```

Trois conditions réalistes de plus, toutes en opérateurs bornés :

```txt
// Appartenance / propriété
resource.attributes.ownerId == principal.userId

// Fenêtre horaire (UTC) — env.now est un epoch ms (int)
(env.now / 3600000) % 24 >= 6 && (env.now / 3600000) % 24 < 20

// Fraîcheur de session : ré-auth si l'authentification date de + de 15 min
now() - env.authTime > 900000
```

> Caveat horaire : `env.now` et `now()` sont en **UTC** (epoch ms). Pour un fuseau tenant,
> appliquez l'offset dans l'expression (`+ tenant.tzOffsetMs`) ou pré-calculez côté app et
> exposez un attribut. `businessDaysBetween(now(), now())` vaut `1` si aujourd'hui (UTC) est un
> jour ouvré (lun-ven), `0` le week-end — c'est le check « jour ouvré » du dessus.

### 3.2 Brancher l'adapter CEL

L'adapter `CelExpressionEngine` implémente `ExpressionEnginePort`. Le vendor
(`@marcbachmann/cel-js`) vit **uniquement** ici. Init réelle (constructeur, `cel-expression-engine.ts`) :
il enregistre les variables de contexte en accès dynamique et les fonctions de dates
déterministes (via `Clock`).

```ts
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';

// L'init interne (pour info) — vous n'appelez QUE le constructeur :
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

Les fonctions disponibles dans une expression : `now()` (epoch ms), `daysUntil(x)` (jours
calendaires jusqu'à `x`), `businessDaysBetween(a, b)` (jours ouvrés, bornes incluses). `x`, `a`,
`b` acceptent bigint/number/Date/string ISO (`toEpochMs`). `evaluateBoolean` **exige** un booléen
en sortie, sinon lève `CelEvaluationError`.

### 3.3 `matches` est INTERDIT (ReDoS) — pourquoi

`assertNoUnboundedRegex` refuse toute expression contenant `matches(` (après avoir neutralisé le
contenu des chaînes littérales, pour ne pas confondre du code avec une chaîne). Raison :
`cel-js` compile `matches` en `new RegExp(pattern).test(input)` **non borné** ; une regex
catastrophique type `(a+)+` provoque un backtracking exponentiel sur une entrée adverse — un
**DoS du PDP**. La doctrine Kengela borne TOUTE regex ; une condition d'accès s'écrit donc avec
`==`, `in`, `startsWith`, `contains`, jamais un regex non borné. La violation lève
`CelEvaluationError` — donc deny fail-closed en aval.

### 3.4 Le PDP en couches (`LayeredDecisionPoint`)

Il empile tout dans l'ordre exact suivant (`policy-pdp.ts`) :

```txt
1. Plancher RBAC          — sans grant actif couvrant (perm × relation) => deny 'no_grant'
2. Policies applicables   — filtrées sur (resource.type, action), on aplatit leurs règles
                            (0 règle applicable => allow 'rbac_grant', le RBAC suffit)
3. Deny explicite gagne   — une règle 'deny' matchée => deny (deny-wins)
4. Gate ABAC positif      — s'il existe des règles 'allow' mais AUCUNE matchée => deny 'no_matching_allow'
5. Step-up                — les règles 'step_up' matchées imposent leurs obligations
6. Sinon                  — allow 'rbac_grant'
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

> Le contexte CEL est construit par le PDP :
> `ctx = { principal, resource, env: { ...principal.ctx, ...request.env, now } }`.
> Donc `env` expose `authTime`, `riskScore`, `geo`, `device`… (issus de `principal.ctx`),
> surchargés par `request.env`, plus `now` (epoch ms de l'horloge injectée). Une règle peut aussi
> filtrer par `scope` : `#ruleApplies` court-circuite via `scopeCoversRelation(rule.scope, relation)`
> avant même d'évaluer `when`.

Sur l'exemple `refundPolicy`, avec le principal ci-dessus (même agence, `riskScore 12`) un mardi :
la règle (a) matche (allow), (b) ne matche pas (jour ouvré), (c) ne matche pas (risque < 50) →
`{ effect: 'allow', reason: 'rbac_grant', matchedPolicy: 'data.refund.approve', signals: { relation } }`.

---

## 4. Obligations & step-up (conditional access)

Une `Decision` n'est **jamais** un booléen : elle peut renvoyer `effect: 'step_up'` avec des
`obligations`. Si des règles `step_up` matchent, le PDP agrège leurs obligations et renvoie :

```ts
// Principal à risque élevé (riskScore 72) => la règle (c) matche.
const decision = await layered.check({ ...refundRequest, principal: riskyPrincipal });
// -> { effect: 'step_up', reason: 'step_up_required',
//      obligations: [{ type: 'require_passkey' }], signals: { relation } }
```

Types d'obligation possibles (`Obligation`, contracts) :
`'require_mfa' | 'require_passkey' | 'reauthenticate' | 'notify'`, avec `params?` libre.

Comment l'app réagit — le PDP décide, l'app **exécute** l'obligation puis rejoue le check :

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

Le step-up est ainsi **piloté par la donnée** : élever `Principal.mfaLevel` à `passkey` (ou
rafraîchir `ctx.authTime`) fait retomber la condition `when` et laisse passer au rejeu. Aucun
code impératif de « niveau MFA » n'est câblé dans le PDP.

---

## 5. Journalisation des décisions (`DecisionLogSink`)

Les **deux** PDP émettent chaque décision vers le `DecisionLogSink` optionnel — RBAC via
`this.#deps.log?.record(...)`, en couches via `#emit(...)`. L'entrée journalisée est
`{ request, decision, at }` (`at` = `now` de l'horloge).

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

Ce qui remonte comme `reason` selon le chemin :

- `no_grant` — plancher RBAC non franchi ;
- `rbac_grant` — autorisé (RBAC seul, ou après gate ABAC/step-up franchi) ;
- règle `deny` matchée — `rule.reason ?? 'policy_deny'` ;
- `no_matching_allow` — il existe des règles `allow` mais aucune n'a matché (gate positif) ;
- `step_up_required` — obligations à satisfaire ;
- **`condition_error` — FAIL-CLOSED**.

### Fail-closed sur erreur d'évaluation

Si une condition CEL ne peut pas être évaluée (variable absente, non-booléen, `matches` interdit,
expression invalide), `evaluateBoolean` **lève**. Le `LayeredDecisionPoint` rattrape autour du
`rules.filter(...)` et renvoie **deny** :

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

Une policy cassée **ferme** l'accès (Zero Trust) au lieu de l'ouvrir — et la décision `deny`
`condition_error` est journalisée, ce qui rend la panne observable. Piège fréquent :
`env.riskScore` est **optionnel** (`AuthContext.riskScore?`). Une condition `env.riskScore >= 50`
sur un principal sans score peut lever → deny. Écrivez des conditions tolérantes (`has()` /
valeur par défaut fournie par l'app) si l'absence doit être permissive.

---

## 6. Encadré — ce que calcule Kengela vs ce que fournit l'app

> **Kengela (authz-core + adapter CEL) CALCULE :**
>
> - la couverture permission×portée×relation (`grantCovers`, `permissionCovers`, `scopeCoversRelation`) ;
> - l'ordre de décision en couches : plancher RBAC → deny-wins → gate ABAC positif → step-up → allow ;
> - l'isolation multi-tenant fail-closed (`tenantScopedRelation`) ;
> - l'évaluation sandboxée des conditions CEL et le refus des regex non bornées ;
> - le fail-closed sur erreur d'évaluation et l'émission des décisions au log.
>
> **L'application FOURNIT (via les ports contracts) :**
>
> - `AuthorizationRepository.loadGrantsForUser` — les **grants depuis SA base** (rechargés à chaque check) ;
> - `RelationResolver.resolveRelation` — la **relation org** acteur↔ressource (organigramme) ;
> - `PolicyStore.loadPolicies` — les **policies déclaratives** (fichiers versionnés en CI et/ou overrides tenant en base) ;
> - le **contexte de requête** : `Principal` (dont `ctx: AuthContext` — geo/device/risque/authTime, produit par l'authn) et `ResourceRef.attributes` (matière de l'ABAC) ;
> - les implémentations de `Clock`, `DecisionLogSink`, et l'exécution des obligations (challenge MFA/passkey, ré-auth).
>
> Le cœur est **pur** (zéro dépendance vendor/infra) ; le vendor CEL est confiné dans l'adapter.
> Le PDP ne fait jamais confiance au cache (`Principal.roles`) pour les grants : SSoT = le repo.

---

### Récapitulatif des symboles (tous vérifiés dans le source)

| Symbole                                                                                                        | Paquet / fichier                            | Signature clé                          |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------- |
| `SCOPE_RANK`, `scopeCoversRelation`, `relationRank`                                                            | authz-core/`scope.ts`                       | `own0<unit1<subtree2<tenant3<global4`  |
| `permissionCovers`, `grantCovers`, `assertPermissionSyntax`                                                    | authz-core/`grant.ts`, `engine.ts`          | couverture motif + portée              |
| `tenantScopedRelation`, `activeGrants`, `isAuthorized`                                                         | authz-core/`engine.ts`                      | isolation + filtrage expiration        |
| `RbacDecisionPoint`                                                                                            | authz-core/`pdp.ts`                         | `check` / `checkMany` → `Decision`     |
| `LayeredDecisionPoint`                                                                                         | authz-core/`policy-pdp.ts`                  | RBAC→deny-wins→gate→step-up            |
| `CelExpressionEngine`, `assertNoUnboundedRegex`                                                                | adapter-expr-cel/`cel-expression-engine.ts` | `evaluateBoolean` ; `matches` interdit |
| `now` / `daysUntil` / `businessDaysBetween`                                                                    | adapter-expr-cel/`dates.ts`                 | epoch ms, jours ouvrés lun-ven         |
| `Grant` `Role` `Policy` `PolicyRule` `Decision` `Obligation` `AccessRequest` `Principal` `ResourceRef` + ports | contracts/`index.ts`                        | contrats stables                       |
