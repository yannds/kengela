# 07 - Developing an adapter

An adapter **implements a port** of `@kengela/contracts` on top of a concrete technology. It is the
only place where an npm vendor is allowed to exist. This page describes the complete recipe, in line
with the repo's strict conventions.

## The contract in one sentence

> **The port is an airlock, not a hideout.** You wrap the existing thing behind a NARROW interface;
> whatever is weak is tracked in `DEBT.md` with a migration target; fail-closed is the rule.

## Step 1 - Choose the port to implement

Open `packages/contracts/src/index.ts`: it is the stable API. Locate the target interface. Examples:

| Need                  | Port                                    | Reference adapter                                  |
| --------------------- | --------------------------------------- | -------------------------------------------------- |
| Load grants           | `AuthorizationRepository`               | `adapter-persistence-prisma`, `connector-translog` |
| Verify an SSO session | `IdentityPort`                          | `adapter-authn-better-auth`                        |
| Evaluate a condition  | `ExpressionEnginePort`                  | `adapter-expr-cel`                                 |
| Hash a password       | `PasswordHasher`                        | `adapter-authn-native`                             |
| Encrypt per tenant    | `KeyManagementPort` / `FieldCipherPort` | `adapter-authn-native`                             |
| Read a directory      | (source → `DirectoryProfile`)           | `adapter-directory-ldap`                           |

## Step 2 - Define a NARROW vendor interface

**Never** depend on a whole SDK. In a `*-like.ts` file, describe **exactly** the methods you call,
with explicit types. The real lib must be _structurally compatible_ (no import of the vendor in this
file).

Real example (`adapter-authn-better-auth/src/better-auth-like.ts`):

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

Other examples to imitate: `PrismaLike` (delegates + methods actually used, unions kept as
`string`), `LdapClientLike` (`bind`/`search`/`unbind`, **no** write method). An **injectable
factory** lets you pass the real client in prod and a fake in tests.

## Step 3 - Implement the port (fail-closed)

The implementation translates the vendor into the port. Any unreadable union value **falls**
(fail-closed) rather than being widened. Narrowing example (connector-translog): an unknown scope
token makes the grant fall, it does not widen it.

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
    if (tenantId === null) return null; // fail-closed: no tenant → refuse
    return {
      userId: result.user.id,
      tenantId,
      roles: this.#extractRoles(result.user), // default []: authz reloads the grants
      mfaLevel: 'none',
      authMethod: 'oidc',
      ctx: { authTime: /* ... */ 0 },
    };
  }
}
```

Important rules:

- **Never blindly trust the payload.** Roles/mfa are **not** inherited from the vendor;
  authorization reloads the grants from the source of truth.
- **Tenant isolation.** Every operation is bounded to the `tenantId`.
- **No `any`.** Unknown inputs are `unknown` and narrowed explicitly.

## Step 4 - Write a fake for the tests

Tests are **hermetic**: no network, no real DB. You test against an **in-memory fake** that satisfies
your narrow interface (and the port). This is possible _precisely because_ the interface is narrow.

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
  it('projects a Principal when the tenant is resolvable', async () => {
    const identity = new BetterAuthIdentity({ auth: fakeAuth });
    const principal = await identity.verifySession({ strategy: 'cookie', token: 'x' });
    expect(principal?.tenantId).toBe('t1');
  });

  it('refuses (null) a session without a tenant', async () => {
    const noTenant: BetterAuthLike = {
      api: { getSession: async () => ({ user: { id: 'u1' }, session: {} }) },
    };
    const identity = new BetterAuthIdentity({ auth: noTenant });
    expect(await identity.verifySession({ strategy: 'bearer', token: 'x' })).toBeNull();
  });
});
```

Also think about **adversarial tests** `security-*.test.ts` (see [08-security.md](./08-security.md)).

## Step 5 - Keep the `DEBT.md`

Copy `DEBT.template.md` (root) into your package and fill in the register. Everything that is wrapped
without being migrated appears there with its state, problem and target:

```md
# DEBT.md - @kengela/adapter-xxx

| #   | What is wrapped | State               | Problem                  | Migration target              | Prio |
| --- | --------------- | ------------------- | ------------------------ | ----------------------------- | ---- |
| 1   | `xxx` client    | wraps via `XxxLike` | no real integration test | CI job with ephemeral service | P1   |
```

`State`: `wraps` (parity, not migrated) · `in progress` · `migrated` · `removed`. **A resolved debt
is deleted from the file**, not left ticked off.

## Step 6 - Configure the dual build (ESM + CJS)

Each package publishes in **both formats** so that `import` and `require` work. Copy the structure of
an existing adapter:

`package.json` (excerpt):

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

The `write-dist-markers.mjs` script drops a marker `package.json` into `dist/esm` (`type: module`)
and `dist/cjs` (`type: commonjs`) so that Node interprets each subtree correctly.

### Vendor: dependency or peerDependency?

| Case                                                                           | Declaration                                 |
| ------------------------------------------------------------------------------ | ------------------------------------------- |
| Embedded lib (argon2, ldapts, cel-js, otplib)                                  | `dependencies` (installed with the adapter) |
| **Framework configured by the app** (better-auth, `@nestjs/*`, Prisma runtime) | `peerDependencies` (the app installs it)    |
| Narrow interface only (no vendor runtime, e.g. `adapter-persistence-prisma`)   | no vendor dependency                        |

## Step 7 - Pass the guardrails

Before considering the adapter done, everything must be green:

```sh
pnpm -r build            # TS6 strict, dual ESM+CJS
pnpm -r test             # Vitest, hermetic
pnpm exec eslint .       # strictTypeChecked
pnpm lint:arch           # anti-vendor (the core stays pure) + no-circular
pnpm exec prettier --check "packages/**/*.ts"
```

Convention reminders (`tsconfig.base.json`, `eslint.config.mjs`):

- **ESM / NodeNext**: relative imports with explicit `.js` in the TS sources.
- **`isolatedDeclarations`**: public exports must have explicit types (no inference on the package
  boundary).
- **`exactOptionalPropertyTypes`**: do not set an optional key to `undefined`; omit it.
- **`verbatimModuleSyntax`**: `import type` for types.
- **No `any`, no gratuitous non-null `!`**: explicit narrowing, fail-closed.

## Checklist

- [ ] NARROW vendor interface in `*-like.ts` (no import of the vendor).
- [ ] Injectable factory (real client in prod, fake in tests).
- [ ] Fail-closed implementation, isolated per tenant, no trust in the payload.
- [ ] Hermetic tests + adversarial `security-*.test.ts`.
- [ ] `DEBT.md` up to date.
- [ ] Dual build (`exports` types/import/require + `write-dist-markers`).
- [ ] `build` / `test` / `eslint` / `lint:arch` / `prettier` green.
