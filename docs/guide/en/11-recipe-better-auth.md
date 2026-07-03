# Recipe 11 — better-auth as the authentication backend (delegated authn)

> Goal: keep better-auth's **login / session** management ([better-auth](https://better-auth.com):
> OIDC, OAuth, SSO, cookies, session DB) but have the verified session consumed by the
> rest of the Kengela core through the `IdentityPort` port. Authz (the PDP), tenancy and
> audit only ever see a `Principal`: they don't care where it came from.

---

## 1. Why / when this backend

Choose `@kengela/adapter-authn-better-auth` when **better-auth already is (or will be) your
authentication source of truth**: you want its OIDC/OAuth providers, its login routes, its
session table and its cookies, without reimplementing that muscle.

Kengela doesn't try to replace better-auth. The adapter does **one single thing**:

- it takes a **session proof** (cookie or bearer) received by your HTTP request,
- it has it verified by **your** better-auth instance (`auth.api.getSession`),
- it projects the better-auth user into a Kengela `Principal` (the authn → authz bridge).

The real class it exposes is **`BetterAuthIdentity`** (`implements IdentityPort`). It
**only implements `verifySession`**: it does **no login, no signup, no MFA, no session
creation** — all of that stays handled by better-auth on the app side. It is a deliberately
**minimal** adapter; it doesn't "own" anything, it translates.

### better-auth = peerDependency (installed by YOUR app)

The adapter **does not bundle** better-auth. In its `package.json`:

```jsonc
// packages/adapter-authn-better-auth/package.json
"dependencies":   { "@kengela/contracts": "workspace:*" },
"peerDependencies":     { "better-auth": ">=1" },
"peerDependenciesMeta": { "better-auth": { "optional": true } }
```

Consequences:

- The peer constraint declared in the adapter's `package.json` is **exactly
  `"better-auth": ">=1"`** (no upper bound): any better-auth version `>= 1.0.0` is supported,
  and the app pins the exact version it installs. This isn't a doc approximation — it is the
  literal value of the `peerDependencies` field.
- The peer is `optional: true`: installing the adapter does not force you to pull in
  better-auth (useful if you don't compose it), **but as soon as you instantiate
  `BetterAuthIdentity` with a real instance, better-auth MUST be present in your app's
  `node_modules`**. Kengela will never install it for you.

---

## 2. Installation

```sh
# the Kengela adapter + the vendor (peer) that YOU install yourself
npm add @kengela/adapter-authn-better-auth
npm add better-auth        # peerDependency — mandatory for this backend
```

> Reminder from `PUBLISHING.md`: each app installs ONLY the packages it needs.
> Vendors that are "frameworks to configure" (better-auth, SAML, LDAP…) are
> `peerDependency` — never pulled in implicitly.

---

## 3. The NARROW `BetterAuthLike` surface

Kengela **does not depend on all of better-auth**. It depends only on a narrow interface
declared in the adapter (`better-auth-like.ts`) — the single capability it consumes: verify
a session.

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

Key points:

- The adapter only knows **`auth.api.getSession({ headers })`**. It ignores OIDC, routes,
  the DB, plugins — better-auth handles all of that on the app side.
- A **real better-auth instance is structurally compatible** with `BetterAuthLike`:
  `betterAuth({...}).api.getSession` has the right shape. You **NARROW** it explicitly to
  `BetterAuthLike` at wiring time via a single `as unknown as BetterAuthLike` cast (see §4).
  This is **not** a workaround: it is the contract. Kengela deliberately forgets everything
  about better-auth **except** `getSession`.
- `BetterAuthUser` is **open** (`[key: string]: unknown`): that's where your business fields
  (`tenantId`, roles…) are read by the extractors.

> Why `as unknown as BetterAuthLike` and not a plain cast? The real return type of
> `betterAuth({...}).api.getSession` is **structurally richer** (better-auth adds its own
> fields) than the minimal `{ user, session } | null` shape declared by `BetterAuthLike`.
> TypeScript therefore refuses a direct cast between two types it deems insufficiently
> related; the `as unknown` bridge is the **standard, documented** way to assert a narrow
> surface. The cast is **sound** because at runtime a real better-auth instance does provide
> `api.getSession({ headers })` returning `{ user, session } | null` — the only capability
> the adapter calls. You take on that cast once, at the composition root, and nowhere else.

---

## 4. Wiring (composition root)

### 4.1 Your better-auth instance (yours)

```ts
// app/auth/better-auth.ts  — 100 % côté application
import { betterAuth } from 'better-auth';

export const auth = betterAuth({
  database: /* ton adapter DB better-auth */,
  // providers OIDC/OAuth, plugins, cookies... : config PROPRE à ton app
  // Assure-toi que la session porte de quoi résoudre le tenant (voir §4.2).
});
```

### 4.2 Wiring onto `BetterAuthIdentity`

The real constructor:

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

Important fail-closed rule: **if `extractTenantId` returns `null`, the session is refused**
(`verifySession` returns `null`). A better-auth session with no resolvable tenant is not a
valid `Principal` for a multi-tenant core.

### 4.3 NestJS provider (`useFactory`) exposing `IdentityPort`

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
      // volontaire `as unknown as BetterAuthLike` — voir §3 : contrat, pas contournement.
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

Everything else in the core (the `PolicyDecisionPoint` PDP, the guards, audit) depends on
`IDENTITY_PORT` / `IdentityPort` — **never** on better-auth directly.

---

## 5. Execution flow

### 5.1 Login / session: that's better-auth, not Kengela

**Login**, session **creation** and **read/rotation** are handled by better-auth (its
routes + its DB). Kengela exposes **no** login API for this backend: `IdentityPort`
(`packages/contracts`) contains only

```ts
export interface IdentityPort {
  verifySession(credential: SessionCredential): Promise<Principal | null>;
}
```

> API honesty: there is **no** `authenticate` method on `IdentityPort`, nor on
> `BetterAuthIdentity`. `authenticate(...) → AuthOutcome` belongs to **another** port,
> `CredentialAuthenticator` (see §5.3), which is **not** implemented by the better-auth
> adapter. With this backend, "authenticate" happens via better-auth's routes.

### 5.2 Session verification (the adapter's real job)

On every protected request, you pass the cookie or the bearer to `verifySession`:

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

What `BetterAuthIdentity.verifySession` does internally:

1. Builds a `Headers` and sets `cookie: <token>` on it (`cookie` strategy) or
   `authorization: Bearer <token>` (`bearer` strategy).
2. Calls `auth.api.getSession({ headers })`.
3. If `null` → returns `null`.
4. Resolves the tenant via `extractTenantId(user)`; if `null` → returns `null` (fail-closed).
5. Otherwise projects a `Principal`:

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

> The ZTNA `ctx` (geo/device/risk) is **not** provided by better-auth. Enrich it elsewhere
> via a `ContextProvider` (`@kengela/contracts` port) if you do conditional access. Here
> only `authTime` (freshness) is filled from `session.createdAt`.

### 5.3 `AuthOutcome` — for reference (native path, NOT this backend)

`AuthOutcome` is the result of a login **by credentials**, produced by the
`CredentialAuthenticator` port (implemented by the **native** adapter, §6). The better-auth
adapter never produces it. Real union of variants (`packages/contracts`):

```ts
type AuthOutcome =
  | { kind: 'authenticated'; principal: Principal }
  | { kind: 'mfa_required'; userId: UserId; tenantId: TenantId } // porte userId + tenantId
  | { kind: 'tenant_choice'; candidates: readonly TenantId[] } // login mobile multi-tenant
  | { kind: 'invalid_credentials' }
  | { kind: 'captcha_required' };
```

If you need this flow (MFA step-up, tenant choice) **and** you delegate to better-auth,
handle it with better-auth's mechanisms; Kengela only steps in afterwards, at the
`verifySession` moment.

---

## 6. Box: what Kengela provides vs what you wire

| Kengela provides (in the adapter)                           | You wire (app side)                                                  |
| ----------------------------------------------------------- | -------------------------------------------------------------------- |
| `BetterAuthIdentity implements IdentityPort`                | The **real better-auth instance** (`betterAuth({...})`)              |
| The narrow `BetterAuthLike` interface (session contract)    | The better-auth config: OIDC/OAuth providers, DB, cookies, plugins   |
| The better-auth user → `Principal` projection (fail-closed) | The `extractTenantId` / `extractRoles` extractors (business mapping) |
| Session reading via `auth.api.getSession`                   | **Login, signup, MFA, session creation/rotation** (better-auth)      |
| `authTime` enrichment from `session.createdAt`              | The full ZTNA `ctx` (geo/device/risk) via a `ContextProvider`        |

Kengela stores no session, emits no cookie, knows no provider. It **consumes** the session
better-auth has already verified.

### Switching to native auth — without touching the rest

The stable coupling point is the `Principal`: the `PolicyDecisionPoint` PDP, the guards,
tenancy and audit depend **only** on it, never on the authn backend. To switch to
`@kengela/adapter-authn-native`, you change **only the composition root** (the
`useFactory`); the downstream authz is intact.

Honest nuance: the two adapters are **not** a simple 1-for-1 swap on the same port.

- `adapter-authn-better-auth` implements **`IdentityPort`** (`verifySession → Principal`):
  better-auth owns login **and** the session.
- `adapter-authn-native` implements **`CredentialAuthenticator`**
  (`authenticate → AuthOutcome`) + the building blocks (argon2/bcrypt hashers,
  `TotpMfaService`, field cipher…). With native, **you** compose login (AuthOutcome) with a
  `SessionStore` and your own session reading.

Put differently: better-auth gives you turnkey authn behind `IdentityPort`; native gives
you the pieces to build it yourself. In both cases, **what authz sees does not change** —
it's always a `Principal`.

---

## Full example (copy-paste)

A single file assembling all the functional code of the recipe: your better-auth instance,
the NestJS provider exposing `IdentityPort`, and session verification on every protected
request. Nothing else is required on the Kengela side — authz only sees the `Principal`.

```ts
// app/auth/identity.ts — composition root de l'authn déléguée à better-auth
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
//    dépend que de ce token — jamais de better-auth directement.
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

## Recap of the real symbols

- Package: `@kengela/adapter-authn-better-auth` — peer `better-auth >= 1` (optional).
- Exports: `BetterAuthIdentity`, `BetterAuthIdentityConfig`, `BetterAuthLike`,
  `BetterAuthUser`, `BetterAuthSession`.
- Implemented port: `IdentityPort.verifySession(SessionCredential) → Promise<Principal | null>`.
- `SessionCredential = { strategy: 'cookie' | 'bearer'; token: string }`.
- **Not** implemented here: `authenticate` / `AuthOutcome` / `SessionStore` (native path).
