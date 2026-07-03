# Recipe 10 — NestJS app from scratch: native auth (argon2) + Prisma persistence + authorization

> **Default / recommended path.** We start from an empty NestJS app and wire the Kengela
> foundation to protect a route end to end: login (timing-safe argon2 hash) → session →
> Zero Trust decision (RBAC + policies) on every request. Every symbol below is real and
> verified against the sources (`@kengela/contracts`, `@kengela/adapter-authn-native`,
> `@kengela/adapter-persistence-prisma`, `@kengela/authz-core`, `@kengela/adapter-expr-cel`,
> `@kengela/nestjs`).

---

## 1. What this scenario sets up

Kengela is a foundation of **ports** (pure interfaces, `@kengela/contracts`) that **adapters**
implement and that the **app composes**. This scenario wires the following ports:

| Port (`@kengela/contracts`)  | Adapter wired                                     | Package                               | Who writes it  |
| ---------------------------- | ------------------------------------------------- | ------------------------------------- | -------------- |
| `PasswordHasher`             | `Argon2PasswordHasher`                            | `@kengela/adapter-authn-native`       | provided       |
| `CredentialAuthenticator`    | `NativeCredentialAuthenticator`                   | `@kengela/adapter-authn-native`       | provided       |
| `CredentialStore`            | `PrismaCredentialStore` (default) _or your own_   | `@kengela/adapter-persistence-prisma` | provided / you |
| `SessionStore`               | `PrismaSessionStore`                              | `@kengela/adapter-persistence-prisma` | provided       |
| `AuthorizationRepository`    | `PrismaAuthorizationRepository`                   | `@kengela/adapter-persistence-prisma` | provided       |
| `PolicyStore`                | `PrismaPolicyStore`                               | `@kengela/adapter-persistence-prisma` | provided       |
| `ExpressionEnginePort` (CEL) | `CelExpressionEngine`                             | `@kengela/adapter-expr-cel`           | provided       |
| `RelationResolver`           | `PrincipalRelationResolver` (default) _or yours_  | `@kengela/authz-core`                 | provided / you |
| `PolicyDecisionPoint` (PDP)  | `RbacDecisionPoint` **or** `LayeredDecisionPoint` | `@kengela/authz-core`                 | provided       |
| NestJS guard + decorators    | `KengelaAuthzGuard`, `@RequirePermission`, …      | `@kengela/nestjs`                     | provided       |

> **Two ports now ship a GENERIC default adapter** — used as-is in this recipe, to be replaced
> by your own only if your shape differs:
>
> - `CredentialStore` — `PrismaCredentialStore` (`@kengela/adapter-persistence-prisma`) resolves a
>   credential against the generic `Account(providerId='credential')` + `User` model (same
>   conventions as `TranslogCredentialStore`). Constructor: `new PrismaCredentialStore(prisma, { providerId? })`.
>   If YOUR schema differs, write your own; `@kengela/connector-translog` shows a real example.
> - `RelationResolver` — `PrincipalRelationResolver` (`@kengela/authz-core`) computes the org
>   relation from fields already carried by the `Principal` (`orgUnitId`/`agencyId`/`coverageUnits`)
>   against the `ResourceRef` (`attributes.ownerId`/`unitId`…), deny-by-default. Pure constructor,
>   no I/O: `new PrincipalRelationResolver({ ownerAttributeKeys?, unitAttributeKeys? })`. An org
>   chart computed OUTSIDE the token (units traversed in the database) remains the job of an app resolver.

**Choosing the PDP:**

- `RbacDecisionPoint` — pure RBAC (grants × org relation). Simplest to start.
- `LayeredDecisionPoint` — RBAC (floor) **+** declarative ABAC policies (CEL conditions) **+**
  step-up. Additionally requires a `PolicyStore` and an `ExpressionEnginePort`. This is the one
  that unlocks conditional `deny` and `step_up`. We use it in this recipe.

---

## 2. Installation

Provided by Kengela (`@kengela/*` registry):

```bash
pnpm add @kengela/contracts \
         @kengela/adapter-authn-native \
         @kengela/adapter-persistence-prisma \
         @kengela/authz-core \
         @kengela/adapter-expr-cel \
         @kengela/nestjs
```

To install (real third-party dependencies):

```bash
# @node-rs/argon2 is the native dependency of the authn adapter (argon2id hash/verify)
pnpm add @node-rs/argon2

# NestJS + Prisma + reflect-metadata (the @kengela/nestjs index already imports 'reflect-metadata')
pnpm add @nestjs/common @nestjs/core reflect-metadata @prisma/client
pnpm add -D prisma
```

> With npm: replace `pnpm add` with `npm i`. The library is **ESM/TypeScript**; keep
> `"type": "module"` and a modern `moduleResolution` (`NodeNext`/`Bundler`).

---

## 3. Minimal Prisma schema

The models below are **derived from the real delegates** of `PrismaLike` and `CredentialPrismaLike`
(`adapter-persistence-prisma/src/prisma-like.ts`). The generated `PrismaClient` is
**structurally compatible**: its real rows are supersets of the NARROW rows (`GrantRow`, `RoleRow`,
`SessionRow`, `PolicyRow`, `PolicyRuleRow`, `AccountRow`, `CredentialUserRow`) → it "passes" where
`PrismaLike` / `CredentialPrismaLike` is expected, with no import of `@prisma/client` in the adapter.

```prisma
// prisma/schema.prisma
generator client { provider = "prisma-client-js" }
datasource db    { provider = "postgresql"; url = env("DATABASE_URL") }

/// Read by PrismaAuthorizationRepository.loadGrantsForUser (grant.findMany where { userId, tenantId })
/// AND exposed as the Role.grants relation (role.findFirst include { grants: true }).
/// -> Grant carries BOTH `userId?` AND `roleId?`: both columns are MANDATED by the delegate
///    signatures (see §7). Each row is attached to one OR the other: a direct user grant
///    (userId) or a role grant (roleId).
model Grant {
  id         String    @id @default(cuid())
  userId     String?
  tenantId   String
  roleId     String?
  role       Role?     @relation(fields: [roleId], references: [id])
  permission String    // "plane.resource.action" (PermissionString)
  scope      String    // 'own'|'unit'|'subtree'|'tenant'|'global' (narrowing fail-closed en mapping)
  source     String    // 'MANUAL'|'IDP'|'DELEGATION'
  expiresAt  DateTime?
  @@index([userId, tenantId])
}

/// Read by PrismaAuthorizationRepository.loadRole (role.findFirst where { key, tenantId } include grants)
model Role {
  id       String  @id @default(cuid())
  key      String
  tenantId String
  grants   Grant[]
  @@unique([key, tenantId])
}

/// Read/written by PrismaSessionStore. `ctx` = opaque JSON column (serialized AuthContext).
model Session {
  token     String   @id @unique
  userId    String
  tenantId  String
  createdAt DateTime
  expiresAt DateTime
  ctx       Json     // SessionRow.ctx: unknown -> Json côté base
  @@index([userId])
}

/// Read by PrismaPolicyStore (policy.findMany where { tenantId } include { rules: true })
model Policy {
  id       String       @id @default(cuid())
  resource String       // "*" ou type de ressource
  action   String       // "*" ou action
  tenantId String
  rules    PolicyRule[]
}

model PolicyRule {
  id          String  @id @default(cuid())
  policyId    String
  policy      Policy  @relation(fields: [policyId], references: [id])
  effect      String  // 'allow'|'deny'|'step_up'
  scope       String? // Scope | null
  when        String? // condition CEL | null
  obligations Json?   // Obligation[] sérialisées (narrowing fail-closed en mapping)
  reason      String?
}

/// Password identity, read by PrismaCredentialStore (account.findFirst/findMany).
/// providerId='credential', accountId=email, password=argon2id hash (null allowed).
model Account {
  id         String  @id @default(cuid())
  userId     String
  tenantId   String
  providerId String  // 'credential'
  accountId  String  // email
  password   String? // argon2id hash ; null if the identity has no password (yet)
  @@unique([tenantId, providerId, accountId])
  @@index([providerId, accountId])
}

/// Account state, read by PrismaCredentialStore (user.findFirst/findMany) and joined to the account.
model User {
  id         String    @id @default(cuid())
  tenantId   String
  isActive   Boolean   @default(true)
  deletedAt  DateTime?
  mfaEnabled Boolean   @default(false)
  roles      String[]  @default([]) // list column (CredentialUserRow.roles)
}
```

> **Union columns as `String`.** In the database, `scope`/`source`/`effect` remain `string`;
> narrowing to the contracts' literal unions is done **fail-closed** in the adapter's `mapping.ts`
> (any unknown value drops the grant/rule, never a phantom `allow`).
>
> **Does your schema differ?** If your password identity does not follow the `Account`/`User`
> convention above (e.g. a single `User` model with `email`/`passwordHash`), keep the other models
> and write your own `CredentialStore` — see the `AppCredentialStore` variant in §7.

---

## 4. Composition root (NestJS module)

A single module wires everything via `useFactory`. Real points to respect:

- `NativeCredentialAuthenticator` is instantiated via its **static async factory**
  `NativeCredentialAuthenticator.create(store, hasher)` (it precomputes the anti-enumeration decoy
  hash). The direct constructor also exists: `new NativeCredentialAuthenticator(store, hasher, dummyHash)`.
- The Prisma stores take the client (`PrismaLike` / `CredentialPrismaLike`) as the **first argument**
  of the constructor.
- The `LayeredDecisionPoint` PDP takes a **deps object** `{ grants, relations, policies, expr, log?, clock? }`.
- The PDP injection token on the NestJS side is the **symbol** `KENGELA_PDP`
  (`@kengela/nestjs`, `tokens.ts`).

```ts
// src/kengela/kengela.tokens.ts
export const CREDENTIAL_AUTHENTICATOR = Symbol('CREDENTIAL_AUTHENTICATOR');
export const SESSION_STORE = Symbol('SESSION_STORE');
export const PASSWORD_HASHER = Symbol('PASSWORD_HASHER');
export const CREDENTIAL_STORE = Symbol('CREDENTIAL_STORE');
```

```ts
// src/kengela/kengela.module.ts
import { Module } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

import type {
  CredentialAuthenticator,
  CredentialStore,
  PasswordHasher,
  SessionStore,
} from '@kengela/contracts';
import { Argon2PasswordHasher, NativeCredentialAuthenticator } from '@kengela/adapter-authn-native';
import {
  PrismaSessionStore,
  PrismaAuthorizationRepository,
  PrismaPolicyStore,
  PrismaCredentialStore,
} from '@kengela/adapter-persistence-prisma';
import type { PrismaLike, CredentialPrismaLike } from '@kengela/adapter-persistence-prisma';
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import { KENGELA_PDP } from '@kengela/nestjs';

import {
  CREDENTIAL_AUTHENTICATOR,
  SESSION_STORE,
  PASSWORD_HASHER,
  CREDENTIAL_STORE,
} from './kengela.tokens.js';

// -- 4.a The real PrismaClient (structural superset of PrismaLike) -----------
const prisma = new PrismaClient();

@Module({
  providers: [
    { provide: PASSWORD_HASHER, useClass: Argon2PasswordHasher },

    // 4.b CredentialStore — default adapter Account(providerId='credential') + User.
    //     providerId defaults to 'credential' ; override via { providerId } if needed.
    {
      provide: CREDENTIAL_STORE,
      useFactory: (): CredentialStore =>
        new PrismaCredentialStore(prisma as unknown as CredentialPrismaLike),
    },

    // 4.c Static ASYNC factory (precomputes the timing-safe decoy hash).
    {
      provide: CREDENTIAL_AUTHENTICATOR,
      inject: [CREDENTIAL_STORE, PASSWORD_HASHER],
      useFactory: (
        store: CredentialStore,
        hasher: PasswordHasher,
      ): Promise<CredentialAuthenticator> => NativeCredentialAuthenticator.create(store, hasher),
    },

    {
      provide: SESSION_STORE,
      useFactory: (): SessionStore => new PrismaSessionStore(prisma as unknown as PrismaLike),
    },

    // 4.d Layered PDP: RBAC + policies (CEL) + step-up.
    //     Default, pure RelationResolver: relation derived from the Principal, deny-by-default.
    {
      provide: KENGELA_PDP,
      useFactory: () =>
        new LayeredDecisionPoint({
          grants: new PrismaAuthorizationRepository(prisma as unknown as PrismaLike),
          relations: new PrincipalRelationResolver(),
          policies: new PrismaPolicyStore(prisma as unknown as PrismaLike),
          expr: new CelExpressionEngine(),
          // log, clock : optionnels (DecisionLogSink, Clock)
        }),
    },
  ],
  exports: [
    CREDENTIAL_AUTHENTICATOR,
    SESSION_STORE,
    PASSWORD_HASHER,
    CREDENTIAL_STORE,
    KENGELA_PDP,
  ],
})
export class KengelaModule {}
```

> **`prisma as unknown as PrismaLike` / `as unknown as CredentialPrismaLike`: INTENTIONAL
> structural compatibility.** The generated `PrismaClient` satisfies these NARROW surfaces (same
> delegate signatures + optional `$transaction`); the double cast is there ONLY because the
> generated client is nominally distinct and much wider than the expected surface — not to hide an
> incompatibility. No runtime surprise as long as the schema respects the NARROW columns (§3). This
> is the contract documented at the top of `prisma-like.ts`.
>
> **Pure RBAC?** Replace the `KENGELA_PDP` provider with
> `new RbacDecisionPoint({ grants, relations })` (no `policies`/`expr`).
>
> **Non-standard resource attributes?** `PrincipalRelationResolver` reads by default
> `attributes.ownerId` (owner) and `attributes.unitId` / `orgUnitId` / `agencyId` (unit). For other
> names: `new PrincipalRelationResolver({ ownerAttributeKeys: ['createdBy'], unitAttributeKeys: ['stationId'] })`.

---

## 5. Global guard + decorators

We register `KengelaAuthzGuard` as `APP_GUARD`: **deny-by-default** — any route without
`@RequirePermission` **nor** `@PublicRoute` is refused (`ForbiddenException('route_not_annotated')`).

```ts
// src/app.module.ts
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { KengelaAuthzGuard } from '@kengela/nestjs';
import { KengelaModule } from './kengela/kengela.module.js';
import { AuthController } from './auth.controller.js';
import { InvoicesController } from './invoices.controller.js';

@Module({
  imports: [KengelaModule],
  controllers: [AuthController, InvoicesController],
  providers: [{ provide: APP_GUARD, useClass: KengelaAuthzGuard }],
})
export class AppModule {}
```

Real decorators (`@kengela/nestjs`, `decorators.ts` + `current-principal.decorator.ts`):

```ts
// src/invoices.controller.ts
import { Controller, Get } from '@nestjs/common';
import { RequirePermission, PublicRoute, CurrentPrincipal } from '@kengela/nestjs';
import type { Principal } from '@kengela/contracts';

@Controller('invoices')
export class InvoicesController {
  // evaluated permission = `resourceType.action` = "data.invoice.read"
  @Get()
  @RequirePermission('data.invoice', 'read')
  list(@CurrentPrincipal() principal: Principal) {
    return { tenant: principal.tenantId, user: principal.userId };
  }
}
```

```ts
// open route: the guard lets it through with no decision
@PublicRoute()
@Get('health')
health() { return { ok: true }; }
```

> **Fail-closed precedence** (read in `authz.guard.ts`): the **handler** annotation ALWAYS takes
> precedence over the **class** one. A class-level `@PublicRoute()` can never neutralize a
> handler-level `@RequirePermission`.
>
> **The guard only evaluates the resource TYPE level** (`{ type, tenantId }`, tenant taken from the
> `Principal`). ABAC conditions on the **attributes** of a specific resource (e.g. "same agency",
> `resource.attributes.ownerId`) are checked at the **service level** by calling `pdp.check(request)`
> directly with the loaded resource.

The guard reads the `Principal` from `req.user`. An upstream authn middleware/guard must set it:

```ts
// src/session.middleware.ts (excerpt) — resolves the session into a Principal and sets req.user
const handle = await sessionStore.get(token);          // SessionHandle | null
if (handle !== null) {
  const record = await credentialStore.findByEmail(/* ... */);
  req.user = /* Principal reconstruit depuis handle + record.roles */;
}
```

---

## 6. End-to-end flow

### 6.a Login (timing-safe hash + verify → session)

```ts
// src/auth.controller.ts
import { Controller, Post, Body, Inject, UnauthorizedException } from '@nestjs/common';
import { PublicRoute } from '@kengela/nestjs';
import type { CredentialAuthenticator, SessionStore, AuthContext } from '@kengela/contracts';
import { CREDENTIAL_AUTHENTICATOR, SESSION_STORE } from './kengela/kengela.tokens.js';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(CREDENTIAL_AUTHENTICATOR) private readonly authn: CredentialAuthenticator,
    @Inject(SESSION_STORE) private readonly sessions: SessionStore,
  ) {}

  @Post('login')
  @PublicRoute()
  async login(@Body() body: { email: string; password: string; tenantId: string }) {
    const ctx: AuthContext = { authTime: Date.now() }; // authTime requis
    const outcome = await this.authn.authenticate({
      email: body.email,
      password: body.password,
      tenantId: body.tenantId,
      ctx,
    });

    switch (outcome.kind) {
      case 'authenticated': {
        // Création de session (token opaque 32o hex, TTL en ms).
        const handle = await this.sessions.create({
          userId: outcome.principal.userId,
          tenantId: outcome.principal.tenantId,
          ctx,
          ttlMs: 1000 * 60 * 60 * 8, // 8 h
        });
        return { token: handle.token, expiresAt: handle.expiresAt };
      }
      case 'mfa_required':
        return { next: 'mfa', userId: outcome.userId };
      case 'tenant_choice':
        return { next: 'choose_tenant', candidates: outcome.candidates };
      case 'captcha_required':
        return { next: 'captcha' };
      case 'invalid_credentials':
      default:
        throw new UnauthorizedException('invalid_credentials');
    }
  }
}
```

Under the hood, `NativeCredentialAuthenticator.authenticate` **always** performs a `hasher.verify`
(against the decoy hash if the email is unknown) → constant response time, account enumeration
resistance. The argon2id hash comes from `Argon2PasswordHasher` (OWASP: m=19456 KiB, t=2, p=1);
`needsRehash()` enables transparent migration of an old hash on the next successful login.

### 6.b Protected request → `allow` decision

`GET /invoices` with a valid `Authorization` → the middleware sets `req.user` (Principal) →
`KengelaAuthzGuard.canActivate` builds:

```ts
const request: AccessRequest = {
  principal, // req.user
  action: 'read',
  resource: { type: 'data.invoice', tenantId: principal.tenantId },
};
```

`LayeredDecisionPoint.check`: reloads the grants (**anti-staleness**: a revoked right stops
working immediately, we do not trust the cached `Principal.roles`), resolves the org relation,
applies the RBAC floor then the policies. If an active grant covers `data.invoice.read` at the
right scope and no rule opposes it → `{ effect: 'allow', reason: 'rbac_grant' }` → **200**.

### 6.c `deny` example

- **No grant** covering the permission → `{ effect: 'deny', reason: 'no_grant' }`
  → `ForbiddenException('no_grant')` → **403**.
- **Cross-tenant**: `principal.tenantId !== resource.tenantId` → the relation is forced to
  `'none'` (defense in depth) → no tenant grant covers → `deny`.
- **Explicit `deny` policy** matched (deny-wins) → `{ effect: 'deny', reason: <policy.reason> }`.
- **Unevaluable CEL condition** (missing variable / invalid expression) → **fail-closed**
  `{ effect: 'deny', reason: 'condition_error' }`.

### 6.d `step_up` example

A policy on `(data.invoice, read)` with a rule `effect: 'step_up'` carrying the obligation
`require_passkey` (e.g. when `env.riskScore` is high) makes the PDP return
`{ effect: 'step_up', reason: 'step_up_required', obligations: [{ type: 'require_passkey' }] }`.
The guard then throws:

```ts
throw new StepUpRequiredException(decision.obligations ?? [], decision.reason);
// -> HTTP 403 { statusCode: 403, error: 'step_up_required', reason, obligations }
```

The client reads `error: 'step_up_required'` + `obligations`, triggers the required authn factor
(passkey / re-auth / MFA), replays the request with a `Principal` whose `ctx`/`mfaLevel` now
satisfies the condition → `allow`. This is the intimate link **authz → authn**: access is
conditional on an authentication strength.

Example policy (one `Policy` row + one step-up `PolicyRule` row in the database):

```jsonc
// Policy { resource: "data.invoice", action: "read", tenantId }
// PolicyRule { effect: "step_up", when: "has(env.riskScore) && env.riskScore > 50",
//              obligations: [{ "type": "require_passkey" }] }
```

> `has(env.riskScore) && …` is the tolerant form: `riskScore` is optional, and accessing an absent
> field in CEL **throws** (hence deny `condition_error`). The `has()` guard short-circuits absence
> without an error — see recipe 14 §5.

---

## 7. Callout — "already available" vs "to write"

**Code already provided by Kengela (direct import, zero rewrite):**

- `Argon2PasswordHasher`, `NativeCredentialAuthenticator` (+ `.create` factory) — `@kengela/adapter-authn-native`
- `PrismaSessionStore`, `PrismaAuthorizationRepository`, `PrismaPolicyStore`, `PrismaCredentialStore`
  (+ `PrismaMfaSecretStore`, `PrismaMfaChallengeStore` if MFA) — `@kengela/adapter-persistence-prisma`
- `RbacDecisionPoint`, `LayeredDecisionPoint`, `PrincipalRelationResolver` (+ `activeGrants`,
  `grantCovers`, `tenantScopedRelation`) — `@kengela/authz-core`
- `CelExpressionEngine` — `@kengela/adapter-expr-cel`
- `KengelaAuthzGuard`, `RequirePermission`, `PublicRoute`, `CurrentPrincipal`,
  `StepUpRequiredException`, `KENGELA_PDP` — `@kengela/nestjs`

**What you write yourself:**

- **The Prisma schema** (§3) + generating the `PrismaClient`.
- **`CredentialStore`** — ONLY if your schema differs from the default: `PrismaCredentialStore`
  covers the generic `Account(providerId='credential')` + `User` model. Otherwise mirror
  `TranslogCredentialStore` (`@kengela/connector-translog`), fail-closed join. Minimal variant for a
  single-table `User` model (`email`/`passwordHash`):

  ```ts
  import type { CredentialStore } from '@kengela/contracts';
  import { PrismaClient } from '@prisma/client';

  class AppCredentialStore implements CredentialStore {
    constructor(private readonly db: PrismaClient) {}

    async findByEmail(email: string, tenantId: string) {
      const u = await this.db.user.findUnique({ where: { email_tenantId: { email, tenantId } } });
      if (u === null) return null;
      return {
        userId: u.id,
        tenantId: u.tenantId,
        passwordHash: u.passwordHash,
        isActive: u.isActive,
        mfaEnabled: u.mfaEnabled,
        roles: u.roleId !== null ? [u.roleId] : [],
      };
    }

    async findByEmailAcrossTenants(email: string) {
      const rows = await this.db.user.findMany({ where: { email } });
      return rows.map((u) => ({
        userId: u.id,
        tenantId: u.tenantId,
        passwordHash: u.passwordHash,
        isActive: u.isActive,
        mfaEnabled: u.mfaEnabled,
        roles: u.roleId !== null ? [u.roleId] : [],
      }));
    }
  }
  ```

- **`RelationResolver`** — `PrincipalRelationResolver` (`@kengela/authz-core`) is enough as long as
  the relation can be derived from the `Principal`; write your own to wire an org chart computed in
  the database (`self`/`unit`/`subtree`/`tenant`/`none`). Minimal variant:

  ```ts
  import type { RelationResolver, Principal, ResourceRef, OrgRelation } from '@kengela/contracts';

  class AppRelationResolver implements RelationResolver {
    async resolveRelation(principal: Principal, resource: ResourceRef): Promise<OrgRelation> {
      if (principal.tenantId !== resource.tenantId) return 'none';
      if (resource.attributes?.ownerId === principal.userId) return 'self';
      return 'tenant';
    }
  }
  ```

- **The composition root** (§4) + the **authn middleware** that resolves the session into a
  `Principal` and sets it on `req.user`.
- Optional: `DecisionLogSink` (decision log), `Clock` (deterministic tests),
  `ContextProvider` (geo/device/risk enrichment for conditional access).

### Modeling decisions settled (no residual uncertainty)

- **`Grant` dual attachment — MANDATED, not optional.** The `grant` delegate serves two reads in
  `prisma-like.ts`: `GrantDelegate.findMany({ where: { userId, tenantId } })` (used by
  `PrismaAuthorizationRepository.loadGrantsForUser`) **requires** the `userId` column; and the
  `Role.grants` relation, loaded by `RoleDelegate.findFirst({ where: { key, tenantId }, include: { grants: true } })`,
  **requires** a `roleId` foreign key on `Grant`. The §3 model therefore carries `userId?` **and**
  `roleId?`, each row attached to one OR the other (direct user grant vs role grant). The
  `GrantRow`/`RoleRow` types only expose `permission`/`scope`/`source`/`expiresAt` (the attachment
  columns are read only by the `where`/`include` clauses), yet both columns remain required by
  those signatures.
- **Cast `PrismaClient → PrismaLike` / `CredentialPrismaLike` — intentional structural
  compatibility.** The double cast `as unknown as …` is the documented usage (top of
  `prisma-like.ts`): the generated client is a superset of the NARROW surfaces, nominally distinct,
  hence the cast. No runtime risk as long as the §3 schema is respected.

---

## Complete example (copy-paste)

The 5 files below make a NestJS app protected end to end with this recipe's default path
(`PrismaCredentialStore` + `PrincipalRelationResolver` + `LayeredDecisionPoint`). Add the §3 Prisma
schema, run `prisma generate`, then paste as-is.

```ts
// src/kengela/kengela.tokens.ts
export const CREDENTIAL_AUTHENTICATOR = Symbol('CREDENTIAL_AUTHENTICATOR');
export const SESSION_STORE = Symbol('SESSION_STORE');
export const PASSWORD_HASHER = Symbol('PASSWORD_HASHER');
export const CREDENTIAL_STORE = Symbol('CREDENTIAL_STORE');

// ---------------------------------------------------------------------------
// src/kengela/kengela.module.ts
import { Module } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import type {
  CredentialAuthenticator,
  CredentialStore,
  PasswordHasher,
  SessionStore,
} from '@kengela/contracts';
import { Argon2PasswordHasher, NativeCredentialAuthenticator } from '@kengela/adapter-authn-native';
import {
  PrismaSessionStore,
  PrismaAuthorizationRepository,
  PrismaPolicyStore,
  PrismaCredentialStore,
} from '@kengela/adapter-persistence-prisma';
import type { PrismaLike, CredentialPrismaLike } from '@kengela/adapter-persistence-prisma';
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import { KENGELA_PDP } from '@kengela/nestjs';
import {
  CREDENTIAL_AUTHENTICATOR,
  SESSION_STORE,
  PASSWORD_HASHER,
  CREDENTIAL_STORE,
} from './kengela.tokens.js';

const prisma = new PrismaClient();

@Module({
  providers: [
    { provide: PASSWORD_HASHER, useClass: Argon2PasswordHasher },
    {
      provide: CREDENTIAL_STORE,
      useFactory: (): CredentialStore =>
        new PrismaCredentialStore(prisma as unknown as CredentialPrismaLike),
    },
    {
      provide: CREDENTIAL_AUTHENTICATOR,
      inject: [CREDENTIAL_STORE, PASSWORD_HASHER],
      useFactory: (
        store: CredentialStore,
        hasher: PasswordHasher,
      ): Promise<CredentialAuthenticator> => NativeCredentialAuthenticator.create(store, hasher),
    },
    {
      provide: SESSION_STORE,
      useFactory: (): SessionStore => new PrismaSessionStore(prisma as unknown as PrismaLike),
    },
    {
      provide: KENGELA_PDP,
      useFactory: () =>
        new LayeredDecisionPoint({
          grants: new PrismaAuthorizationRepository(prisma as unknown as PrismaLike),
          relations: new PrincipalRelationResolver(),
          policies: new PrismaPolicyStore(prisma as unknown as PrismaLike),
          expr: new CelExpressionEngine(),
        }),
    },
  ],
  exports: [
    CREDENTIAL_AUTHENTICATOR,
    SESSION_STORE,
    PASSWORD_HASHER,
    CREDENTIAL_STORE,
    KENGELA_PDP,
  ],
})
export class KengelaModule {}

// ---------------------------------------------------------------------------
// src/app.module.ts
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { KengelaAuthzGuard } from '@kengela/nestjs';
import { KengelaModule } from './kengela/kengela.module.js';
import { AuthController } from './auth.controller.js';
import { InvoicesController } from './invoices.controller.js';

@Module({
  imports: [KengelaModule],
  controllers: [AuthController, InvoicesController],
  providers: [{ provide: APP_GUARD, useClass: KengelaAuthzGuard }],
})
export class AppModule {}

// ---------------------------------------------------------------------------
// src/invoices.controller.ts
import { Controller, Get } from '@nestjs/common';
import { RequirePermission, CurrentPrincipal } from '@kengela/nestjs';
import type { Principal } from '@kengela/contracts';

@Controller('invoices')
export class InvoicesController {
  @Get()
  @RequirePermission('data.invoice', 'read')
  list(@CurrentPrincipal() principal: Principal) {
    return { tenant: principal.tenantId, user: principal.userId };
  }
}

// ---------------------------------------------------------------------------
// src/auth.controller.ts
import { Controller, Post, Body, Inject, UnauthorizedException } from '@nestjs/common';
import { PublicRoute } from '@kengela/nestjs';
import type { CredentialAuthenticator, SessionStore, AuthContext } from '@kengela/contracts';
import { CREDENTIAL_AUTHENTICATOR, SESSION_STORE } from './kengela/kengela.tokens.js';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(CREDENTIAL_AUTHENTICATOR) private readonly authn: CredentialAuthenticator,
    @Inject(SESSION_STORE) private readonly sessions: SessionStore,
  ) {}

  @Post('login')
  @PublicRoute()
  async login(@Body() body: { email: string; password: string; tenantId: string }) {
    const ctx: AuthContext = { authTime: Date.now() };
    const outcome = await this.authn.authenticate({
      email: body.email,
      password: body.password,
      tenantId: body.tenantId,
      ctx,
    });

    switch (outcome.kind) {
      case 'authenticated': {
        const handle = await this.sessions.create({
          userId: outcome.principal.userId,
          tenantId: outcome.principal.tenantId,
          ctx,
          ttlMs: 1000 * 60 * 60 * 8,
        });
        return { token: handle.token, expiresAt: handle.expiresAt };
      }
      case 'mfa_required':
        return { next: 'mfa', userId: outcome.userId };
      case 'tenant_choice':
        return { next: 'choose_tenant', candidates: outcome.candidates };
      case 'captcha_required':
        return { next: 'captcha' };
      case 'invalid_credentials':
      default:
        throw new UnauthorizedException('invalid_credentials');
    }
  }
}
```
