# Recette 11 - better-auth comme backend d'authentification (authn délégué)

> Objectif : garder la gestion de **login / session** de [better-auth](https://better-auth.com)
> (OIDC, OAuth, SSO, cookies, DB de sessions) mais faire consommer la session vérifiée
> par le reste du socle Kengela via le port `IdentityPort`. L'authz (PDP), la tenancy et
> l'audit ne voient qu'un `Principal` : ils ignorent d'où il vient.

---

## 1. Pourquoi / quand ce backend

Choisis `@kengela/adapter-authn-better-auth` quand **better-auth est déjà (ou sera) ta
source de vérité d'authentification** : tu veux ses providers OIDC/OAuth, ses routes de
login, sa table de sessions et ses cookies, sans réimplémenter ce muscle.

Kengela ne cherche pas à remplacer better-auth. L'adapter fait **une seule chose** :

- il prend une **preuve de session** (cookie ou bearer) reçue par ta requête HTTP,
- il la fait vérifier par **ton** instance better-auth (`auth.api.getSession`),
- il projette l'utilisateur better-auth en `Principal` Kengela (le pont authn → authz).

La classe réelle exposée est **`BetterAuthIdentity`** (`implements IdentityPort`). Elle
**n'implémente que `verifySession`** : elle ne fait **ni login, ni signup, ni MFA, ni
création de session** - tout cela reste géré par better-auth côté app. C'est un adapter
volontairement **minimal** ; il ne « possède » rien, il traduit.

### better-auth = peerDependency (à installer par TON app)

L'adapter **n'embarque pas** better-auth. Dans son `package.json` :

```jsonc
// packages/adapter-authn-better-auth/package.json
"dependencies":   { "@kengela/contracts": "workspace:*" },
"peerDependencies":     { "better-auth": ">=1" },
"peerDependenciesMeta": { "better-auth": { "optional": true } }
```

Conséquences :

- La contrainte peer déclarée dans le `package.json` de l'adapter est **exactement
  `"better-auth": ">=1"`** (aucune borne haute) : toute version better-auth `>= 1.0.0` est
  supportée, et l'app fige la version exacte qu'elle installe. Ce n'est pas une approximation
  de la doc - c'est la valeur littérale du champ `peerDependencies`.
- La peer est `optional: true` : installer l'adapter ne te force pas à tirer better-auth
  (utile si tu ne le composes pas), **mais dès que tu instancies `BetterAuthIdentity`
  avec une vraie instance, better-auth DOIT être présent dans les `node_modules` de ton
  app**. Kengela ne l'installera jamais pour toi.

---

## 2. Installation

```sh
# l'adapter Kengela + le vendor (peer) que TU installes toi-même
npm add @kengela/adapter-authn-better-auth
npm add better-auth        # peerDependency - obligatoire pour ce backend
```

> Rappel `PUBLISHING.md` : chaque app n'installe QUE les paquets dont elle a besoin.
> Les vendors « frameworks à configurer » (better-auth, SAML, LDAP…) sont en
> `peerDependency` - jamais tirés implicitement.

---

## 3. La surface NARROW `BetterAuthLike`

Kengela **ne dépend pas de tout better-auth**. Il dépend uniquement d'une interface
étroite déclarée dans l'adapter (`better-auth-like.ts`) - la seule capacité qu'il
consomme : vérifier une session.

```ts
// @kengela/adapter-authn-better-auth (better-auth-like.ts)
export interface BetterAuthUser {
  readonly id: string;
  readonly email?: string;
  readonly [key: string]: unknown; // champs libres : tenantId, roles, etc.
}

export type BetterAuthSession = Readonly<Record<string, unknown>>;

export interface BetterAuthLike {
  readonly api: {
    getSession(input: {
      readonly headers: Headers;
    }): Promise<{ readonly user: BetterAuthUser; readonly session: BetterAuthSession } | null>;
  };
}
```

Points clés :

- L'adapter ne connaît **que `auth.api.getSession({ headers })`**. Il ignore l'OIDC, les
  routes, la DB, les plugins - better-auth gère tout ça côté app.
- Une **vraie instance better-auth est structurellement compatible** avec
  `BetterAuthLike` : `betterAuth({...}).api.getSession` a la bonne forme. On la **NARROW**
  explicitement à `BetterAuthLike` au câblage via un unique cast `as unknown as BetterAuthLike`
  (voir §4). Ce n'est **pas** un contournement : c'est le contrat. Kengela oublie
  volontairement tout de better-auth **sauf** `getSession`.
- `BetterAuthUser` est **ouvert** (`[key: string]: unknown`) : c'est là que tes champs
  métier (`tenantId`, rôles…) sont lus par les extracteurs.

> Pourquoi `as unknown as BetterAuthLike` et pas un cast simple ? Le type de retour réel
> de `betterAuth({...}).api.getSession` est **structurellement plus riche** (better-auth y
> ajoute ses propres champs) que la forme minimale `{ user, session } | null` déclarée par
> `BetterAuthLike`. TypeScript refuse donc un cast direct entre deux types qu'il juge
> insuffisamment liés ; le pont `as unknown` est la façon **standard et documentée**
> d'affirmer une surface narrow. Le cast est **sain** parce qu'à l'exécution une vraie
> instance better-auth fournit bien `api.getSession({ headers })` renvoyant
> `{ user, session } | null` - la seule capacité que l'adapter appelle. On assume ce cast
> une fois, au composition root, et jamais ailleurs.

---

## 4. Wiring (composition root)

### 4.1 Ton instance better-auth (à toi)

```ts
// app/auth/better-auth.ts  - 100 % côté application
import { betterAuth } from 'better-auth';

export const auth = betterAuth({
  database: /* ton adapter DB better-auth */,
  // providers OIDC/OAuth, plugins, cookies... : config PROPRE à ton app
  // Assure-toi que la session porte de quoi résoudre le tenant (voir §4.2).
});
```

### 4.2 Brancher sur `BetterAuthIdentity`

Le constructeur réel :

```ts
// @kengela/adapter-authn-better-auth (better-auth-identity.ts)
export interface BetterAuthIdentityConfig {
  readonly auth: BetterAuthLike;
  /** Extrait le tenant depuis l'utilisateur (défaut : champ `tenantId`). */
  readonly extractTenantId?: (user: BetterAuthUser) => string | null;
  /** Extrait les rôles (défaut : aucun ; l'authz recharge les grants). */
  readonly extractRoles?: (user: BetterAuthUser) => readonly string[];
}

export class BetterAuthIdentity implements IdentityPort {
  constructor(config: BetterAuthIdentityConfig);
  verifySession(credential: SessionCredential): Promise<Principal | null>;
}
```

Fail-closed important : **si `extractTenantId` renvoie `null`, la session est refusée**
(`verifySession` retourne `null`). Une session better-auth sans tenant résoluble n'est
pas un `Principal` valide pour un socle multi-tenant.

### 4.3 Provider NestJS (`useFactory`) exposant `IdentityPort`

```ts
import { BetterAuthIdentity, type BetterAuthLike } from '@kengela/adapter-authn-better-auth';
import type { IdentityPort } from '@kengela/contracts';
import { auth } from './auth/better-auth';

export const IDENTITY_PORT = Symbol('IdentityPort');

export const identityProvider = {
  provide: IDENTITY_PORT,
  useFactory: (): IdentityPort =>
    new BetterAuthIdentity({
      // Une vraie instance better-auth expose bien `api.getSession`. On la NARROW
      // explicitement à BetterAuthLike (la seule capacité consommée) via un cast
      // volontaire `as unknown as BetterAuthLike` - voir §3 : contrat, pas contournement.
      auth: auth as unknown as BetterAuthLike,

      // ton mapping métier -> tenant (défaut = user.tenantId)
      extractTenantId: (user) =>
        typeof user['tenantId'] === 'string' ? (user['tenantId'] as string) : null,

      // optionnel : projeter des rôles portés par la session better-auth.
      // Sinon [] : l'authz (AuthorizationRepository) rechargera les grants.
      extractRoles: () => [],
    }),
};
```

Tout le reste du socle (le PDP `PolicyDecisionPoint`, les guards, l'audit) dépend de
`IDENTITY_PORT` / `IdentityPort` - **jamais** de better-auth directement.

---

## 5. Flux d'exécution

### 5.1 Login / session : c'est better-auth, pas Kengela

Le **login**, la **création** et la **lecture/rotation** de session sont assurés par
better-auth (ses routes + sa DB). Kengela n'expose **aucune** API de login pour ce
backend : `IdentityPort` (`packages/contracts`) ne contient que

```ts
export interface IdentityPort {
  verifySession(credential: SessionCredential): Promise<Principal | null>;
}
```

> Honnêteté d'API : il n'y a **pas** de méthode `authenticate` sur `IdentityPort`, ni sur
> `BetterAuthIdentity`. `authenticate(...) → AuthOutcome` appartient à un **autre** port,
> `CredentialAuthenticator` (voir §5.3), qui n'est **pas** implémenté par l'adapter
> better-auth. Avec ce backend, l'« authenticate » se fait via les routes de better-auth.

### 5.2 Vérification de session (le vrai job de l'adapter)

À chaque requête protégée, tu passes le cookie ou le bearer à `verifySession` :

```ts
import type { SessionCredential } from '@kengela/contracts';

// cookie brut (header Cookie) OU token bearer
const credential: SessionCredential = { strategy: 'cookie', token: req.headers.cookie ?? '' };
// ou : { strategy: 'bearer', token: '<jwt/opaque>' }

const principal = await identity.verifySession(credential);
if (principal === null) {
  // session absente / invalide / SANS tenant résoluble -> 401
}
```

Ce que fait `BetterAuthIdentity.verifySession` en interne :

1. Construit un `Headers` et y pose `cookie: <token>` (stratégie `cookie`) ou
   `authorization: Bearer <token>` (stratégie `bearer`).
2. Appelle `auth.api.getSession({ headers })`.
3. Si `null` → retourne `null`.
4. Résout le tenant via `extractTenantId(user)` ; si `null` → retourne `null` (fail-closed).
5. Sinon projette un `Principal` :

```ts
{
  userId:   result.user.id,
  tenantId,                       // via extractTenantId
  roles:    extractRoles(user),   // [] par défaut
  mfaLevel: 'none',               // better-auth ne remonte pas ce niveau ici
  authMethod: 'oidc',             // fixé : authn déléguée
  ctx: { authTime: /* session.createdAt -> ms, sinon 0 */ },
}
```

> Le `ctx` ZTNA (géo/device/risque) **n'est pas** fourni par better-auth. Enrichis-le
> ailleurs via un `ContextProvider` (port `@kengela/contracts`) si tu fais du conditional
> access. Ici seul `authTime` (fraîcheur) est renseigné depuis `session.createdAt`.

### 5.3 `AuthOutcome` - pour mémoire (chemin natif, PAS ce backend)

`AuthOutcome` est le résultat d'un login **par identifiants**, produit par le port
`CredentialAuthenticator` (implémenté par l'adapter **natif**, §6). L'adapter better-auth
ne le produit jamais. Union réelle des variantes (`packages/contracts`) :

```ts
type AuthOutcome =
  | { kind: 'authenticated'; principal: Principal }
  | { kind: 'mfa_required'; userId: UserId; tenantId: TenantId } // porte userId + tenantId
  | { kind: 'tenant_choice'; candidates: readonly TenantId[] } // login mobile multi-tenant
  | { kind: 'invalid_credentials' }
  | { kind: 'captcha_required' };
```

Si tu as besoin de ce flux (MFA step-up, choix de tenant) **et** que tu délègues à
better-auth, gère-le avec les mécanismes de better-auth ; Kengela n'intervient qu'après,
au moment du `verifySession`.

---

## 6. Encadré : ce que Kengela fournit vs ce que tu branches

| Kengela fournit (dans l'adapter)                           | Tu branches (côté app)                                                |
| ---------------------------------------------------------- | --------------------------------------------------------------------- |
| `BetterAuthIdentity implements IdentityPort`               | L'**instance better-auth réelle** (`betterAuth({...})`)               |
| L'interface narrow `BetterAuthLike` (contrat de session)   | La config better-auth : providers OIDC/OAuth, DB, cookies, plugins    |
| La projection user better-auth → `Principal` (fail-closed) | Les extracteurs `extractTenantId` / `extractRoles` (mapping métier)   |
| La lecture de session via `auth.api.getSession`            | Le **login, signup, MFA, création/rotation de session** (better-auth) |
| L'enrichissement `authTime` depuis `session.createdAt`     | Le `ctx` ZTNA complet (géo/device/risque) via un `ContextProvider`    |

Kengela ne stocke aucune session, n'émet aucun cookie, ne connaît aucun provider. Il
**consomme** la session que better-auth a déjà vérifiée.

### Basculer vers l'auth native - sans toucher au reste

Le point de couplage stable est le `Principal` : le PDP `PolicyDecisionPoint`, les guards,
la tenancy et l'audit ne dépendent **que** de lui, jamais du backend d'authn. Pour passer
à `@kengela/adapter-authn-native`, tu ne changes **que le composition root** (le
`useFactory`) ; le downstream authz est intact.

Nuance honnête : les deux adapters ne sont **pas** un simple échange 1-pour-1 sur le même
port.

- `adapter-authn-better-auth` implémente **`IdentityPort`** (`verifySession → Principal`) :
  better-auth possède le login **et** la session.
- `adapter-authn-native` implémente **`CredentialAuthenticator`**
  (`authenticate → AuthOutcome`) + les briques (hashers argon2/bcrypt, `TotpMfaService`,
  field cipher…). En natif, **tu** composes le login (AuthOutcome) avec un `SessionStore`
  et ta propre lecture de session.

Autrement dit : better-auth te donne l'authn « clé en main » derrière `IdentityPort` ; le
natif te donne les pièces pour la construire toi-même. Dans les deux cas, **ce que
l'authz voit ne change pas** - c'est toujours un `Principal`.

---

## Exemple complet (copier-coller)

Un seul fichier assemblant tout le code fonctionnel de la recette : ton instance
better-auth, le provider NestJS exposant `IdentityPort`, et la vérification de session à
chaque requête protégée. Rien d'autre n'est requis côté Kengela - l'authz ne voit que le
`Principal`.

```ts
// app/auth/identity.ts - composition root de l'authn déléguée à better-auth
import { betterAuth } from 'better-auth';
import {
  BetterAuthIdentity,
  type BetterAuthLike,
  type BetterAuthUser,
} from '@kengela/adapter-authn-better-auth';
import type { IdentityPort, Principal, SessionCredential } from '@kengela/contracts';

// 1. TON instance better-auth (100 % côté app) : providers OIDC/OAuth, DB, cookies, plugins.
//    Assure-toi que la session porte de quoi résoudre le tenant (ex. user.tenantId).
export const auth = betterAuth({
  database: /* ton adapter DB better-auth */ undefined as never,
  // providers OIDC/OAuth, plugins, cookies... : config PROPRE à ton app.
});

// 2. Provider NestJS exposant IdentityPort. Le reste du socle (PDP, guards, audit) ne
//    dépend que de ce token - jamais de better-auth directement.
export const IDENTITY_PORT = Symbol('IdentityPort');

export const identityProvider = {
  provide: IDENTITY_PORT,
  useFactory: (): IdentityPort =>
    new BetterAuthIdentity({
      // Narrowing volontaire de l'instance réelle vers la surface consommée (voir §3).
      auth: auth as unknown as BetterAuthLike,

      // Mapping métier -> tenant (fail-closed : null => session refusée).
      extractTenantId: (user: BetterAuthUser): string | null =>
        typeof user['tenantId'] === 'string' ? (user['tenantId'] as string) : null,

      // Optionnel : projeter des rôles portés par la session. Sinon [] : l'authz
      // (AuthorizationRepository) rechargera les grants.
      extractRoles: (): readonly string[] => [],
    }),
};

// 3. Vérification de session à chaque requête protégée (cookie brut OU bearer).
export async function authenticateRequest(
  identity: IdentityPort,
  req: { readonly headers: { readonly cookie?: string; readonly authorization?: string } },
): Promise<Principal | null> {
  const credential: SessionCredential = req.headers.authorization
    ? { strategy: 'bearer', token: req.headers.authorization.replace(/^Bearer\s+/i, '') }
    : { strategy: 'cookie', token: req.headers.cookie ?? '' };

  // null si : session absente / invalide / SANS tenant résoluble (fail-closed) -> 401.
  return identity.verifySession(credential);
}
```

---

## Récap des symboles réels

- Paquet : `@kengela/adapter-authn-better-auth` - peer `better-auth >= 1` (optional).
- Exports : `BetterAuthIdentity`, `BetterAuthIdentityConfig`, `BetterAuthLike`,
  `BetterAuthUser`, `BetterAuthSession`.
- Port implémenté : `IdentityPort.verifySession(SessionCredential) → Promise<Principal | null>`.
- `SessionCredential = { strategy: 'cookie' | 'bearer'; token: string }`.
- **Non** implémenté ici : `authenticate` / `AuthOutcome` / `SessionStore` (chemin natif).
