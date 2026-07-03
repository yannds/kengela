# Publication & consommation

Kengela est publié sur **npmjs.com** (public, scope `@kengela`), sous licence Apache-2.0.

## Publier une version

```sh
# 1. Bumper les versions (toutes ou par paquet), ex :
pnpm -r exec npm version 0.1.0 --no-git-tag-version   # ou manuellement

# 2. Commit + tag
git commit -am "release: v0.1.0"
git tag v0.1.0 && git push --tags
```

Le workflow `.github/workflows/release.yml` publie automatiquement sur push du tag
(secret CI requis : `NPM_TOKEN`). Le protocole `workspace:*` est remplacé par la
version réelle au moment du `pnpm publish`.

Publication manuelle (poste dev, `npm login` fait) :

```sh
pnpm -r build && pnpm -r --filter './packages/*' publish --access public
```

## Consommer depuis une application (ex. TransLog, npm)

Registre public par défaut, rien à configurer :

```sh
npm add @kengela/contracts @kengela/authz-core @kengela/nestjs \
        @kengela/adapter-persistence-prisma @kengela/adapter-authn-native
```

Chaque application n'installe QUE les paquets dont elle a besoin (le reste — SAML,
LDAP, better-auth... — reste optionnel).

## Dépendances vendor des adapters

Les adapters embarquent leur vendor **sauf** ceux qui sont des frameworks à configurer
par l'app, déclarés en `peerDependency` :

| Adapter | Vendor | Installé avec l'adapter ? |
|---|---|---|
| `adapter-authn-native` | argon2, bcryptjs, otplib | Oui (dependency) |
| `adapter-expr-cel` | @marcbachmann/cel-js | Oui (dependency) |
| `adapter-directory-ldap` | ldapts | Oui (dependency) |
| `adapter-persistence-prisma` | (aucun — interface narrow) | — |
| **`adapter-authn-better-auth`** | **better-auth** | **NON — peerDependency : `npm add better-auth` dans ton app** |

