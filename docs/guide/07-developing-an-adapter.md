# 07 - Développer un adapter

Un adapter **implémente un port** de `@kengela/contracts` au-dessus d'une techno concrète. C'est le
seul endroit où un vendor npm a le droit d'exister. Cette page décrit la recette complète, dans le
respect des conventions strictes du repo.

## Le contrat en une phrase

> **Le port est un sas, pas une planque.** On enveloppe l'existant derrière une interface NARROW ; ce
> qui est faible est tracé dans `DEBT.md` avec une cible de migration ; le fail-closed est la règle.

## Étape 1 - Choisir le port à implémenter

Ouvrez `packages/contracts/src/index.ts` : c'est l'API stable. Repérez l'interface visée. Exemples :

| Besoin                   | Port                                    | Adapter de référence                               |
| ------------------------ | --------------------------------------- | -------------------------------------------------- |
| Charger les droits       | `AuthorizationRepository`               | `adapter-persistence-prisma`, `connector-translog` |
| Vérifier une session SSO | `IdentityPort`                          | `adapter-authn-better-auth`                        |
| Évaluer une condition    | `ExpressionEnginePort`                  | `adapter-expr-cel`                                 |
| Hasher un mot de passe   | `PasswordHasher`                        | `adapter-authn-native`                             |
| Chiffrer par tenant      | `KeyManagementPort` / `FieldCipherPort` | `adapter-authn-native`                             |
| Lire un annuaire         | (source → `DirectoryProfile`)           | `adapter-directory-ldap`                           |

## Étape 2 - Définir une interface vendor NARROW

Ne dépendez **jamais** de tout un SDK. Décrivez, dans un fichier `*-like.ts`, **exactement** les
méthodes que vous appelez, avec des types explicites. La vraie lib doit être _structurellement
compatible_ (aucun import du vendor dans ce fichier).

Exemple réel (`adapter-authn-better-auth/src/better-auth-like.ts`) :

```ts
export interface BetterAuthUser {
  readonly id: string;
  readonly email?: string;
  readonly [key: string]: unknown;
}

export type BetterAuthSession = Readonly<Record<string, unknown>>;

export interface BetterAuthLike {
  readonly api: {
    getSession(input: { readonly headers: Headers }): Promise<{
      readonly user: BetterAuthUser;
      readonly session: BetterAuthSession;
    } | null>;
  };
}
```

Autres exemples à imiter : `PrismaLike` (délégués + méthodes réellement utilisés, unions gardées en
`string`), `LdapClientLike` (`bind`/`search`/`unbind`, **aucune** méthode d'écriture). Une **fabrique
injectable** permet de passer le vrai client en prod et un fake en test.

## Étape 3 - Implémenter le port (fail-closed)

L'implémentation traduit le vendor vers le port. Toute donnée d'union illisible **tombe** (fail-closed)
plutôt que d'être élargie. Exemple de narrowing (connector-translog) : un jeton de portée inconnu fait
tomber le grant, il ne l'élargit pas.

```ts
import type { IdentityPort, Principal, SessionCredential } from '@kengela/contracts';
import type { BetterAuthLike, BetterAuthUser } from './better-auth-like.js';

export class BetterAuthIdentity implements IdentityPort {
  readonly #auth: BetterAuthLike;
  // ...

  public async verifySession(credential: SessionCredential): Promise<Principal | null> {
    const result = await this.#auth.api.getSession({ headers: /* ... */ new Headers() });
    if (result === null) return null;
    const tenantId = this.#extractTenantId(result.user);
    if (tenantId === null) return null; // fail-closed : pas de tenant → refus
    return {
      userId: result.user.id,
      tenantId,
      roles: this.#extractRoles(result.user), // par défaut [] : l'authz recharge les grants
      mfaLevel: 'none',
      authMethod: 'oidc',
      ctx: { authTime: /* ... */ 0 },
    };
  }
}
```

Règles importantes :

- **Jamais de confiance aveugle au payload.** Les rôles/mfa ne sont **pas** hérités du vendor ;
  l'autorisation recharge les grants depuis la source de vérité.
- **Isolation tenant.** Toute opération est bornée au `tenantId`.
- **Pas d'`any`.** Les entrées inconnues sont `unknown` et narrowées explicitement.

## Étape 4 - Écrire un fake pour les tests

Les tests sont **hermétiques** : aucun réseau, aucune DB réelle. Vous testez contre un **fake en
mémoire** qui satisfait votre interface narrow (et le port). C'est possible _précisément parce que_
l'interface est narrow.

```ts
import { describe, it, expect } from 'vitest';
import { BetterAuthIdentity } from '../src/better-auth-identity.js';
import type { BetterAuthLike } from '../src/better-auth-like.js';

const fakeAuth: BetterAuthLike = {
  api: {
    getSession: async () => ({
      user: { id: 'u1', tenantId: 't1' },
      session: { createdAt: new Date() },
    }),
  },
};

describe('BetterAuthIdentity', () => {
  it('projette un Principal quand le tenant est résoluble', async () => {
    const identity = new BetterAuthIdentity({ auth: fakeAuth });
    const principal = await identity.verifySession({ strategy: 'cookie', token: 'x' });
    expect(principal?.tenantId).toBe('t1');
  });

  it('refuse (null) une session sans tenant', async () => {
    const noTenant: BetterAuthLike = {
      api: { getSession: async () => ({ user: { id: 'u1' }, session: {} }) },
    };
    const identity = new BetterAuthIdentity({ auth: noTenant });
    expect(await identity.verifySession({ strategy: 'bearer', token: 'x' })).toBeNull();
  });
});
```

Pensez aussi à des **tests adverses** `security-*.test.ts` (voir [08-security.md](./08-security.md)).

## Étape 5 - Tenir le `DEBT.md`

Copiez `DEBT.template.md` (racine) dans votre paquet et remplissez le registre. Tout ce qui est
enveloppé sans être migré y figure avec état, problème et cible :

```md
# DEBT.md — @kengela/adapter-xxx

| #   | Ce qui est enveloppé | Etat                    | Problème                       | Cible de migration           | Prio |
| --- | -------------------- | ----------------------- | ------------------------------ | ---------------------------- | ---- |
| 1   | Client `xxx`         | enveloppe via `XxxLike` | pas de test d'intégration réel | job CI avec service éphémère | P1   |
```

`Etat` : `enveloppe` (parité, non migré) · `en cours` · `migre` · `retire`. **Une dette résolue est
supprimée du fichier**, pas laissée cochée.

## Étape 6 - Configurer le dual build (ESM + CJS)

Chaque paquet publie en **double format** pour que `import` et `require` fonctionnent. Copiez la
structure d'un adapter existant :

`package.json` (extrait) :

```jsonc
{
  "type": "module",
  "exports": {
    ".": {
      "types": "./dist/esm/index.d.ts",
      "import": "./dist/esm/index.js",
      "require": "./dist/cjs/index.js",
    },
  },
  "main": "./dist/cjs/index.js",
  "module": "./dist/esm/index.js",
  "types": "./dist/esm/index.d.ts",
  "files": ["dist"],
  "scripts": {
    "build": "tsc -p tsconfig.build.json && tsc -p tsconfig.build.cjs.json && node ../../scripts/write-dist-markers.mjs dist",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "test": "vitest run",
  },
}
```

Le script `write-dist-markers.mjs` pose un `package.json` marqueur dans `dist/esm` (`type: module`)
et `dist/cjs` (`type: commonjs`) pour que Node interprète chaque sous-arbre correctement.

### Vendor : dependency ou peerDependency ?

| Cas                                                                                  | Déclaration                               |
| ------------------------------------------------------------------------------------ | ----------------------------------------- |
| Lib embarquée (argon2, ldapts, cel-js, otplib)                                       | `dependencies` (installée avec l'adapter) |
| **Framework à configurer par l'app** (better-auth, `@nestjs/*`, Prisma runtime)      | `peerDependencies` (l'app l'installe)     |
| Interface narrow uniquement (aucun runtime vendor, ex. `adapter-persistence-prisma`) | aucune dépendance vendor                  |

## Étape 7 - Passer les garde-fous

Avant de considérer l'adapter terminé, tout doit être vert :

```sh
pnpm -r build            # TS6 strict, dual ESM+CJS
pnpm -r test             # Vitest, hermétique
pnpm exec eslint .       # strictTypeChecked
pnpm lint:arch           # anti-vendor (le cœur reste pur) + no-circular
pnpm exec prettier --check "packages/**/*.ts"
```

Rappels de conventions (`tsconfig.base.json`, `eslint.config.mjs`) :

- **ESM / NodeNext** : imports relatifs en `.js` explicites dans les sources TS.
- **`isolatedDeclarations`** : les exports publics doivent avoir des types explicites (pas
  d'inférence sur la frontière du paquet).
- **`exactOptionalPropertyTypes`** : ne posez pas une clé optionnelle à `undefined` ; omettez-la.
- **`verbatimModuleSyntax`** : `import type` pour les types.
- **Pas d'`any`, pas de non-null `!` gratuit** : narrowing explicite, fail-closed.

## Checklist

- [ ] Interface vendor NARROW dans `*-like.ts` (aucun import du vendor).
- [ ] Fabrique injectable (vrai client en prod, fake en test).
- [ ] Implémentation fail-closed, isolée par tenant, sans confiance au payload.
- [ ] Tests hermétiques + `security-*.test.ts` adverses.
- [ ] `DEBT.md` à jour.
- [ ] Dual build (`exports` types/import/require + `write-dist-markers`).
- [ ] `build` / `test` / `eslint` / `lint:arch` / `prettier` verts.
</content>
