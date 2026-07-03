# 00 - Démarrage rapide

Cette page installe Kengela dans une application, compose un **point de décision (PDP) minimal**, et
exécute un premier `check()` de bout en bout dans ses trois issues : **allow**, **deny**, **step-up**.

## Prérequis

- **Node.js >= 24**, **pnpm** (le monorepo est en pnpm 10, mais une app consommatrice peut utiliser
  npm/yarn/pnpm).
- TypeScript (recommandé) : le socle est écrit en TS6 strict et expose des types complets.

## Installer

Chaque application n'installe **que** les paquets dont elle a besoin. Pour un premier check RBAC, il
suffit des contrats et du cœur d'autorisation :

```sh
npm add @kengela/contracts @kengela/authz-core
```

Pour un PDP en base + une intégration NestJS, on ajoute par exemple :

```sh
npm add @kengela/nestjs @kengela/adapter-persistence-prisma @kengela/adapter-authn-native
```

### Dual build : `import` ET `require` fonctionnent

Chaque paquet est publié en **double format** (ESM + CommonJS). Le champ `exports` de chaque
`package.json` route vers le bon build selon la façon dont vous chargez le module :

```jsonc
"exports": {
  ".": {
    "types":   "./dist/esm/index.d.ts",
    "import":  "./dist/esm/index.js",   // ESM
    "require": "./dist/cjs/index.js"    // CommonJS
  }
}
```

Concrètement, les deux styles marchent sans configuration :

```ts
// ESM / TypeScript
import { RbacDecisionPoint } from '@kengela/authz-core';
```

```js
// CommonJS
const { RbacDecisionPoint } = require('@kengela/authz-core');
```

> Détail d'implémentation : le build ESM sort dans `dist/esm` et le build CJS dans `dist/cjs`, chacun
> avec un `package.json` marqueur (`{"type":"module"}` / `{"type":"commonjs"}`) pour que Node
> interprète correctement chaque sous-arbre.

## Composer un PDP minimal

Le PDP est le composant central : il répond à « **ce Principal a-t-il le droit de faire cette action
sur cette ressource ?** ». Le cœur fournit deux implémentations de `PolicyDecisionPoint` :

- **`RbacDecisionPoint`** - la couche RBAC seule (grants × relation organisationnelle).
- **`LayeredDecisionPoint`** - RBAC **plancher** + conditions ABAC (CEL) + conditional access +
  step-up (voir [02-authorization.md](./02-authorization.md)).

Commençons par `RbacDecisionPoint`. Il a besoin de deux dépendances (deux **ports**) :

- un **`AuthorizationRepository`** qui charge les grants d'un utilisateur ;
- un **`RelationResolver`** qui résout la relation organisationnelle acteur ↔ ressource.

Ci-dessous, des implémentations en mémoire (parfaites pour un test ou un prototype) :

```ts
import { RbacDecisionPoint } from '@kengela/authz-core';
import type {
  AccessRequest,
  AuthorizationRepository,
  Principal,
  RelationResolver,
} from '@kengela/contracts';

// 1. D'où viennent les droits (ici en dur ; en prod, un adapter Prisma).
const grants: AuthorizationRepository = {
  async loadGrantsForUser() {
    return [{ permission: 'data.orders.read', scope: 'tenant', source: 'MANUAL' }];
  },
  async loadRole() {
    return null;
  },
};

// 2. La position de la ressource par rapport à l'acteur (self/unit/subtree/tenant/none).
const relations: RelationResolver = {
  async resolveRelation() {
    return 'tenant';
  },
};

// 3. Le PDP.
const pdp = new RbacDecisionPoint({ grants, relations });
```

## Premier `check()` : ALLOW

Un `Principal` est le « pont » produit par l'authentification et consommé par l'autorisation (voir
[01-architecture.md](./01-architecture.md)). La permission requise est construite par le PDP comme
`` `${resource.type}.${action}` `` :

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
// required = 'data.orders.read' ; le grant 'data.orders.read' (scope tenant) couvre la relation
// 'tenant' → allow.
console.log(decision.effect); // 'allow'
console.log(decision.reason); // 'rbac_grant'
```

Une `Decision` n'est **jamais** un simple booléen : elle porte l'`effect`, une `reason` lisible, les
`signals` (pour l'audit) et d'éventuelles `obligations` (voir step-up plus bas).

## DENY (deny-by-default)

Retirez le grant, ou demandez une portée que le grant ne couvre pas, et le PDP refuse par défaut :

```ts
const noGrant: AuthorizationRepository = {
  async loadGrantsForUser() {
    return []; // aucun droit
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

L'isolation multi-tenant est **défendue au cœur** : si `resource.tenantId !== principal.tenantId`, la
relation est ramenée à `none`, et seul un grant de portée `global` (plan plateforme) peut couvrir.
Un `Principal` du tenant `t1` ne franchit donc jamais vers une ressource du tenant `t2`, même si le
`RelationResolver` renvoie par erreur une relation large.

## STEP-UP (autorisation conditionnelle)

Le step-up naît d'une **policy déclarative** : il faut le PDP en couches, un `PolicyStore` et un
moteur d'expressions (`@kengela/adapter-expr-cel`). Exemple : lire une commande est autorisé, mais
la **rembourser** exige une re-authentification passkey.

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
  grants, // doit couvrir data.orders.refund au niveau RBAC (plancher)
  relations,
  policies,
  expr: new CelExpressionEngine(),
});

const decision = await layered.check({
  principal,
  action: 'refund',
  resource: { type: 'data.orders', id: 'o1', tenantId: 't1' },
});

console.log(decision.effect);      // 'step_up'
console.log(decision.obligations); // [{ type: 'require_passkey' }]
```

Côté application, `step_up` se traduit en **défi** (relancer une MFA/passkey) plutôt qu'en 403 sec.
Avec `@kengela/nestjs`, le guard lève automatiquement une `StepUpRequiredException`
(voir [05-nestjs-integration.md](./05-nestjs-integration.md)).

## Et ensuite ?

- Comprendre le modèle : [01-architecture.md](./01-architecture.md).
- Écrire des policies (CEL, obligations) : [02-authorization.md](./02-authorization.md).
- Brancher l'authentification (mots de passe, MFA, sessions) : [03-authentication.md](./03-authentication.md).
- Fédérer des identités (SSO, SCIM, LDAP) : [04-identity-federation.md](./04-identity-federation.md).
</content>
