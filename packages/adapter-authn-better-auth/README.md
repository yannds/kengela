# @kengela/adapter-authn-better-auth

Adapter `IdentityPort` au-dessus d'une instance **better-auth** que **ton application**
configure. L'adapter ne fait qu'envelopper la vérification de session (cookie/bearer) et
projeter l'utilisateur en `Principal` ; better-auth reste le framework OIDC/OAuth/SSO côté app.

## ⚠️ better-auth n'est PAS installé par Kengela

`better-auth` est déclaré en **`peerDependency` optionnelle**. Installer
`@kengela/adapter-authn-better-auth` **n'installe pas** better-auth, et Kengela ne le bundle
pas. C'est **volontaire** : better-auth est un framework (routes, base de données, plugins)
que ton app doit configurer elle-même — le bundler imposerait sa version et sa config.

**Ton app doit donc l'installer explicitement :**

```sh
npm add better-auth
```

## Usage

```ts
import { betterAuth } from 'better-auth'; // installé par TON app (peer)
import { BetterAuthIdentity } from '@kengela/adapter-authn-better-auth';

const auth = betterAuth({/* ta config OIDC/OAuth, DB, plugins... */});
const identity = new BetterAuthIdentity({
  auth,
  // optionnel : d'où lire le tenant / les rôles sur l'utilisateur better-auth
  extractTenantId: (user) => (typeof user['tenantId'] === 'string' ? user['tenantId'] : null),
});

const principal = await identity.verifySession({ strategy: 'bearer', token });
// principal === null si session invalide ou tenant non résoluble (fail-closed)
```
