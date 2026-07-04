# @kengela/adapter-authn-better-auth

> An `IdentityPort` adapter over a better-auth instance configured by your application (OIDC, OAuth, SSO).

This package wraps session verification (cookie or bearer) from a better-auth instance and projects the resolved user into a Kengela `Principal`. It is the adapter ring: better-auth stays the OIDC/OAuth/SSO framework on the application side, and this adapter only bridges its session into the contracts model.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/adapter-authn-better-auth
```

`better-auth` is declared as an optional peer dependency: this package does not install or bundle it. Your application must install and configure it explicitly:

```sh
npm install better-auth
```

This is deliberate. better-auth is a framework (routes, database, plugins) that your app owns; bundling it would force its version and configuration.

## Usage

```ts
import { betterAuth } from 'better-auth'; // installed by your app (peer)
import { BetterAuthIdentity } from '@kengela/adapter-authn-better-auth';

const auth = betterAuth({/* your OIDC/OAuth config, DB, plugins */});

const identity = new BetterAuthIdentity({
  auth,
  extractTenantId: (user) => (typeof user['tenantId'] === 'string' ? user['tenantId'] : null),
});

const principal = await identity.verifySession({ strategy: 'bearer', token });
// principal === null if the session is invalid or the tenant is unresolvable (fail-closed)
```

## Key exports

- `BetterAuthIdentity` - the `IdentityPort` implementation over a better-auth instance.
- `BetterAuthIdentityConfig` - configuration (auth instance, tenant and role extractors).
- `BetterAuthLike`, `BetterAuthUser`, `BetterAuthSession` - narrow types the real better-auth instance satisfies.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
