# Combo 18 — Full-stack: a "fully wired" NestJS app (reference recipe)

> MASTER COMBO: a single NestJS app that composes ALL the socle's building blocks in ONE
> composition root — native authn (timing-safe argon2), Prisma persistence, opaque
> sessions, MFA/TOTP, RBAC + ABAC (CEL) authorization with organizational relation, and
> encrypted PII + erasure. This is the REFERENCE recipe: it aggregates recipes 10, 14 and
> 15 under a single factory and a single module.

---

## 1. The building blocks and the flow

Five layers, everything injected by port, a single wiring point:

- **Native authn** — `Argon2PasswordHasher` (`PasswordHasher`) + `PrismaCredentialStore`
  (`CredentialStore`) feed `NativeCredentialAuthenticator` (`CredentialAuthenticator`,
  timing-safe compare even on an unknown email).
- **Sessions** — `PrismaSessionStore` (`SessionStore`): 32-byte opaque token, atomic
  rotation, fail-closed on expiry.
- **MFA/TOTP** — `TotpMfaService` composes `TotpVerifier` + `AesGcmKeyManagement` (secret
  encrypted at-rest per tenant) + `PrismaMfaSecretStore` + `PrismaMfaChallengeStore`.
- **Authorization** — `LayeredDecisionPoint` (RBAC via `PrismaAuthorizationRepository` +
  policies via `PrismaPolicyStore` + relation via `PrincipalRelationResolver` + conditions
  via `CelExpressionEngine`), exposed by `KengelaAuthzGuard`.
- **PII** — `AesGcmFieldCipher` (per-tenant) + `SubjectFieldCipher` / `SubjectCryptoShredder`
  (per-subject, via `PrismaSubjectKeyStore`) + `PrismaPiiAccessLogSink`.

### Execution flow

```
POST /auth/login (email + password)
   │
   ▼ NativeCredentialAuthenticator.authenticate ──► AuthOutcome
        ├─ 'invalid_credentials'                  -> 401
        ├─ 'mfa_required' { userId, tenantId }    -> TotpMfaService.challenge -> challengeId
        └─ 'authenticated' { principal }          -> PrismaSessionStore.create -> opaque token
   │
   ▼ (MFA) POST /auth/mfa  TotpMfaService.verify(challengeId, code) -> session created
   │
Protected request (cookie/bearer -> Principal placed on req.user)
   │
   ▼ KengelaAuthzGuard.canActivate ──► LayeredDecisionPoint.check ──► allow | deny | step_up
        RBAC (grants) + relation (PrincipalRelationResolver) + CEL policies (CelExpressionEngine)
   │
   ▼ service handler: reads/writes encrypted PII (AesGcmFieldCipher / SubjectFieldCipher),
        logs the access (PrismaPiiAccessLogSink), erases on request (SubjectCryptoShredder).
```

### Port → adapter table

| Port (`@kengela/contracts`)            | Concrete adapter                                   | Package                               |
| -------------------------------------- | -------------------------------------------------- | ------------------------------------- |
| `PasswordHasher`                       | `Argon2PasswordHasher`                             | `@kengela/adapter-authn-native`       |
| `CredentialStore`                      | `PrismaCredentialStore`                            | `@kengela/adapter-persistence-prisma` |
| `CredentialAuthenticator`              | `NativeCredentialAuthenticator`                    | `@kengela/adapter-authn-native`       |
| `SessionStore`                         | `PrismaSessionStore`                               | `@kengela/adapter-persistence-prisma` |
| `MfaService`                           | `TotpMfaService`                                   | `@kengela/adapter-authn-native`       |
| `MfaSecretStore` / `MfaChallengeStore` | `PrismaMfaSecretStore` / `PrismaMfaChallengeStore` | `@kengela/adapter-persistence-prisma` |
| `KeyManagementPort`                    | `AesGcmKeyManagement`                              | `@kengela/adapter-authn-native`       |
| `AuthorizationRepository`              | `PrismaAuthorizationRepository`                    | `@kengela/adapter-persistence-prisma` |
| `PolicyStore`                          | `PrismaPolicyStore`                                | `@kengela/adapter-persistence-prisma` |
| `RelationResolver`                     | `PrincipalRelationResolver`                        | `@kengela/authz-core`                 |
| `ExpressionEnginePort`                 | `CelExpressionEngine`                              | `@kengela/adapter-expr-cel`           |
| `PolicyDecisionPoint`                  | `LayeredDecisionPoint`                             | `@kengela/authz-core`                 |
| `FieldCipherPort`                      | `AesGcmFieldCipher`                                | `@kengela/adapter-authn-native`       |
| `SubjectKeyStore`                      | `PrismaSubjectKeyStore`                            | `@kengela/adapter-persistence-prisma` |
| `ErasurePort`                          | `SubjectCryptoShredder`                            | `@kengela/adapter-authn-native`       |
| `PiiAccessLogSink`                     | `PrismaPiiAccessLogSink`                           | `@kengela/adapter-persistence-prisma` |

---

## 2. Installation

```sh
npm add @kengela/adapter-authn-native @kengela/adapter-persistence-prisma \
        @kengela/authz-core @kengela/adapter-expr-cel @kengela/nestjs \
        @kengela/pii @kengela/contracts
```

---

## 3. Two HKDF contexts (domain separation)

A single master key, two DISTINCT cryptographic uses. `AesGcmKeyManagement` derives the
per-tenant key in a configurable CONTEXT (`info`). NEVER share the same context between the
MFA secret and PII encryption:

```ts
import { AesGcmKeyManagement } from '@kengela/adapter-authn-native';

// masterKey: Uint8Array >= 32 bytes, loaded from the vault (Vault), NEVER hardcoded.
const mfaKeyMgmt = new AesGcmKeyManagement(masterKey); // default 'kengela:mfa'
const piiKeyMgmt = new AesGcmKeyManagement(masterKey, { context: 'kengela:pii' });
```

---

## 4. Native authn + sessions + MFA

`NativeCredentialAuthenticator.create` pre-computes a decoy hash (systematic compare,
anti-enumeration). The outcome drives what follows: direct session, or MFA challenge.

```ts
import {
  Argon2PasswordHasher,
  NativeCredentialAuthenticator,
  TotpVerifier,
  TotpMfaService,
} from '@kengela/adapter-authn-native';
import {
  PrismaCredentialStore,
  PrismaSessionStore,
  PrismaMfaSecretStore,
  PrismaMfaChallengeStore,
} from '@kengela/adapter-persistence-prisma';

const hasher = new Argon2PasswordHasher();
const credentials = new PrismaCredentialStore(db); // Account + User (narrow surface)
const authenticator = await NativeCredentialAuthenticator.create(credentials, hasher);

const sessions = new PrismaSessionStore(db);

const mfa = new TotpMfaService(
  new TotpVerifier(),
  mfaKeyMgmt,
  new PrismaMfaSecretStore(db.mfaSecret),
  new PrismaMfaChallengeStore(db.mfaChallenge),
);
```

---

## 5. Layered authorization

```ts
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import {
  PrismaAuthorizationRepository,
  PrismaPolicyStore,
} from '@kengela/adapter-persistence-prisma';

const pdp = new LayeredDecisionPoint({
  grants: new PrismaAuthorizationRepository(db),
  policies: new PrismaPolicyStore(db),
  relations: new PrincipalRelationResolver(), // org relation (self/unit/subtree/tenant) from the Principal
  expr: new CelExpressionEngine(), // CEL conditions, read-only sandbox
});
```

The `KengelaAuthzGuard` is deny-by-default: a route without `@RequirePermission` nor
`@PublicRoute` is DENIED. Precedence handler > class (fail-closed).

---

## 6. PII

```ts
import {
  AesGcmFieldCipher,
  SubjectFieldCipher,
  SubjectCryptoShredder,
} from '@kengela/adapter-authn-native';
import { PrismaSubjectKeyStore, PrismaPiiAccessLogSink } from '@kengela/adapter-persistence-prisma';

const tenantCipher = new AesGcmFieldCipher(piiKeyMgmt); // per-tenant, base64
const subjectKeys = new PrismaSubjectKeyStore(db.subjectKey, { keyManagement: piiKeyMgmt });
const subjectCipher = new SubjectFieldCipher(subjectKeys); // per-subject (shreddable)
const shredder = new SubjectCryptoShredder(subjectKeys); // ErasurePort
const piiAudit = new PrismaPiiAccessLogSink(db.piiAccessLog); // art. 30 log
```

---

## Full example (copy-paste)

A single block: the `buildAuthCore` factory that composes ALL the blocks, a `LoginService`
orchestrating login/MFA/session, and the NestJS module wiring the PDP + the global guard.
Ready to paste (`db` = a PrismaClient satisfying the narrow surfaces `PrismaLike` /
`CredentialPrismaLike` + the MFA/PII delegates; `masterKey` = a >= 32-byte key loaded from
the vault, NEVER hardcoded).

```ts
import {
  Argon2PasswordHasher,
  NativeCredentialAuthenticator,
  TotpVerifier,
  TotpMfaService,
  AesGcmKeyManagement,
  AesGcmFieldCipher,
  SubjectFieldCipher,
  SubjectCryptoShredder,
} from '@kengela/adapter-authn-native';
import {
  PrismaCredentialStore,
  PrismaSessionStore,
  PrismaMfaSecretStore,
  PrismaMfaChallengeStore,
  PrismaAuthorizationRepository,
  PrismaPolicyStore,
  PrismaSubjectKeyStore,
  PrismaPiiAccessLogSink,
  type PrismaLike,
  type CredentialPrismaLike,
  type SubjectKeyDelegate,
  type PiiAccessLogDelegate,
  type MfaSecretDelegate,
  type MfaChallengeDelegate,
} from '@kengela/adapter-persistence-prisma';
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import {
  KengelaAuthzGuard,
  KENGELA_PDP,
  RequirePermission,
  PublicRoute,
  CurrentPrincipal,
} from '@kengela/nestjs';
import {
  Body,
  Controller,
  Get,
  Module,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { isPii } from '@kengela/pii';
import type {
  AccessRequest,
  AuthContext,
  AuthOutcome,
  CredentialAuthenticator,
  Decision,
  MfaService,
  PolicyDecisionPoint,
  Principal,
  SessionStore,
  TenantId,
} from '@kengela/contracts';

/** Full Prisma surface expected by this combo (a real PrismaClient satisfies it). */
type FullPrismaLike = PrismaLike &
  CredentialPrismaLike & {
    readonly mfaSecret: MfaSecretDelegate;
    readonly mfaChallenge: MfaChallengeDelegate;
    readonly subjectKey: SubjectKeyDelegate;
    readonly piiAccessLog: PiiAccessLogDelegate;
  };

/** All the socle's capabilities, composed into a single object. */
export interface AuthCore {
  readonly authenticator: CredentialAuthenticator;
  readonly sessions: SessionStore;
  readonly mfa: MfaService;
  readonly pdp: PolicyDecisionPoint;
  readonly tenantCipher: AesGcmFieldCipher;
  readonly subjectCipher: SubjectFieldCipher;
  readonly shredder: SubjectCryptoShredder;
  readonly piiAudit: PrismaPiiAccessLogSink;
}

/**
 * SINGLE COMPOSITION ROOT. Assembles native authn + sessions + MFA + authz + PII.
 * `masterKey` (>= 32 bytes) comes from the vault; two distinct HKDF CONTEXTS
 * cryptographically separate the MFA secret from PII encryption.
 */
export async function buildAuthCore(db: FullPrismaLike, masterKey: Uint8Array): Promise<AuthCore> {
  // 1. Domain separation: one master key, two uses.
  const mfaKeyMgmt = new AesGcmKeyManagement(masterKey); // 'kengela:mfa' (default)
  const piiKeyMgmt = new AesGcmKeyManagement(masterKey, { context: 'kengela:pii' });

  // 2. Native authn (timing-safe) + opaque sessions.
  const hasher = new Argon2PasswordHasher();
  const authenticator = await NativeCredentialAuthenticator.create(
    new PrismaCredentialStore(db),
    hasher,
  );
  const sessions = new PrismaSessionStore(db);

  // 3. MFA/TOTP (secret encrypted at-rest per tenant).
  const mfa = new TotpMfaService(
    new TotpVerifier(),
    mfaKeyMgmt,
    new PrismaMfaSecretStore(db.mfaSecret),
    new PrismaMfaChallengeStore(db.mfaChallenge),
  );

  // 4. Layered authorization: RBAC + org relation + CEL policies.
  const pdp = new LayeredDecisionPoint({
    grants: new PrismaAuthorizationRepository(db),
    policies: new PrismaPolicyStore(db),
    relations: new PrincipalRelationResolver(),
    expr: new CelExpressionEngine(),
  });

  // 5. PII: per-tenant + per-subject encryption (crypto-shredding) + log.
  const subjectKeys = new PrismaSubjectKeyStore(db.subjectKey, { keyManagement: piiKeyMgmt });
  const tenantCipher = new AesGcmFieldCipher(piiKeyMgmt);
  const subjectCipher = new SubjectFieldCipher(subjectKeys);
  const shredder = new SubjectCryptoShredder(subjectKeys);
  const piiAudit = new PrismaPiiAccessLogSink(db.piiAccessLog);

  return { authenticator, sessions, mfa, pdp, tenantCipher, subjectCipher, shredder, piiAudit };
}

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 h

/** Login orchestration: credentials -> (MFA ?) -> opaque session. */
export class LoginService {
  readonly #core: AuthCore;
  public constructor(core: AuthCore) {
    this.#core = core;
  }

  public async login(input: {
    readonly email: string;
    readonly password: string;
    readonly tenantId: TenantId;
    readonly ctx: AuthContext;
  }): Promise<
    | { readonly kind: 'session'; readonly token: string }
    | { readonly kind: 'mfa'; readonly challengeId: string }
    | { readonly kind: 'rejected' }
  > {
    const outcome: AuthOutcome = await this.#core.authenticator.authenticate(input);
    switch (outcome.kind) {
      case 'authenticated': {
        const handle = await this.#core.sessions.create({
          userId: outcome.principal.userId,
          tenantId: outcome.principal.tenantId,
          ctx: outcome.principal.ctx,
          ttlMs: SESSION_TTL_MS,
        });
        return { kind: 'session', token: handle.token };
      }
      case 'mfa_required': {
        const { challengeId } = await this.#core.mfa.challenge({
          tenantId: outcome.tenantId,
          userId: outcome.userId,
        });
        return { kind: 'mfa', challengeId };
      }
      default:
        return { kind: 'rejected' }; // invalid_credentials / tenant_choice / captcha_required
    }
  }

  /** Verifies the TOTP code then opens the session (the challenge carries tenant + user). */
  public async completeMfa(input: {
    readonly challengeId: string;
    readonly code: string;
    readonly userId: string;
    readonly tenantId: TenantId;
    readonly ctx: AuthContext;
  }): Promise<{ readonly token: string } | null> {
    const ok = await this.#core.mfa.verify(input.challengeId, input.code);
    if (!ok) {
      return null;
    }
    const handle = await this.#core.sessions.create({
      userId: input.userId,
      tenantId: input.tenantId,
      ctx: input.ctx,
      ttlMs: SESSION_TTL_MS,
    });
    return { token: handle.token };
  }
}

// ── NestJS exposure: a single module wires PDP + global guard + services ──────
@Controller('invoices')
export class InvoiceController {
  readonly #core: AuthCore;
  public constructor(core: AuthCore) {
    this.#core = core;
  }

  /** Protected route: the global guard decides `invoice.read` (RBAC + context). */
  @Get()
  @RequirePermission('invoice', 'read')
  public async list(@CurrentPrincipal() principal: Principal): Promise<{ readonly ok: true }> {
    // ABAC condition on a PRECISE resource (same agency): direct call to the PDP.
    const request: AccessRequest = {
      principal,
      action: 'read',
      resource: {
        type: 'invoice',
        tenantId: principal.tenantId,
        attributes: { unitId: principal.agencyId ?? '' },
      },
    };
    const decision: Decision = await this.#core.pdp.check(request);
    if (decision.effect !== 'allow') {
      throw new UnauthorizedException(decision.reason);
    }
    return { ok: true };
  }
}

@Controller('me')
export class ProfileController {
  readonly #core: AuthCore;
  public constructor(core: AuthCore) {
    this.#core = core;
  }

  /** Reads the subject's PII, decrypted, with an access log (art. 30). */
  @Get('profile')
  @RequirePermission('user', 'read')
  public async profile(
    @CurrentPrincipal() principal: Principal,
    @Body() stored: Readonly<Record<string, string>>,
  ): Promise<Record<string, string | null>> {
    const out: Record<string, string | null> = {};
    const readFields: string[] = [];
    for (const [key, value] of Object.entries(stored)) {
      if (isPii(key)) {
        out[key] = await this.#core.subjectCipher.decryptFor(
          principal.tenantId,
          principal.userId,
          value,
        );
        readFields.push(key);
      } else {
        out[key] = value;
      }
    }
    await this.#core.piiAudit.record({
      tenantId: principal.tenantId,
      subjectId: principal.userId,
      actorId: principal.userId,
      fields: readFields,
      purpose: 'account.profile.read',
      at: Date.now(),
    });
    return out;
  }

  /** Right to erasure (art. 17): crypto-shredding of the subject's key. */
  @Post('erase')
  @RequirePermission('user', 'delete')
  public async erase(@CurrentPrincipal() principal: Principal): Promise<{ readonly erased: true }> {
    await this.#core.shredder.eraseSubject(principal.tenantId, principal.userId);
    return { erased: true };
  }
}

/** Injection token for the composed AuthCore. */
export const AUTH_CORE = Symbol('AUTH_CORE');
/** Injection token for the application PrismaClient. */
export const APP_DB = Symbol('APP_DB');
/** Injection token for the master key (loaded from the vault at startup). */
export const MASTER_KEY = Symbol('MASTER_KEY');

@Module({
  controllers: [InvoiceController, ProfileController],
  providers: [
    {
      provide: AUTH_CORE,
      useFactory: (db: FullPrismaLike, masterKey: Uint8Array): Promise<AuthCore> =>
        buildAuthCore(db, masterKey),
      inject: [APP_DB, MASTER_KEY],
    },
    // The guard reads the PDP under KENGELA_PDP; we derive it from the AuthCore.
    {
      provide: KENGELA_PDP,
      useFactory: (core: AuthCore): PolicyDecisionPoint => core.pdp,
      inject: [AUTH_CORE],
    },
    {
      provide: LoginService,
      useFactory: (core: AuthCore): LoginService => new LoginService(core),
      inject: [AUTH_CORE],
    },
    {
      provide: InvoiceController,
      useFactory: (core: AuthCore): InvoiceController => new InvoiceController(core),
      inject: [AUTH_CORE],
    },
    {
      provide: ProfileController,
      useFactory: (core: AuthCore): ProfileController => new ProfileController(core),
      inject: [AUTH_CORE],
    },
    // GLOBAL deny-by-default guard: every non-annotated route is denied.
    { provide: APP_GUARD, useClass: KengelaAuthzGuard },
  ],
})
export class AuthModule {}

// PublicRoute() remains available for the rare open routes (health, login itself):
@Controller('health')
export class HealthController {
  @Get()
  @PublicRoute()
  public ok(): { readonly status: 'ok' } {
    return { status: 'ok' };
  }
}
```

### Real-symbol recap

- Native: `Argon2PasswordHasher`, `NativeCredentialAuthenticator` (`.create`),
  `TotpVerifier`, `TotpMfaService`, `AesGcmKeyManagement` (`{ context }` option),
  `AesGcmFieldCipher`, `SubjectFieldCipher`, `SubjectCryptoShredder`
  (`@kengela/adapter-authn-native`).
- Persistence: `PrismaCredentialStore`, `PrismaSessionStore`, `PrismaMfaSecretStore`,
  `PrismaMfaChallengeStore`, `PrismaAuthorizationRepository`, `PrismaPolicyStore`,
  `PrismaSubjectKeyStore`, `PrismaPiiAccessLogSink` + surfaces `PrismaLike` /
  `CredentialPrismaLike` + delegates (`@kengela/adapter-persistence-prisma`).
- Authz: `LayeredDecisionPoint`, `PrincipalRelationResolver` (`@kengela/authz-core`);
  `CelExpressionEngine` (`@kengela/adapter-expr-cel`).
- NestJS: `KengelaAuthzGuard`, `KENGELA_PDP`, `RequirePermission`, `PublicRoute`,
  `CurrentPrincipal` (`@kengela/nestjs`).
- Pure PII: `isPii` (`@kengela/pii`).
- Contracts: `CredentialAuthenticator`, `AuthOutcome`, `SessionStore`, `MfaService`,
  `PolicyDecisionPoint`, `AccessRequest`, `Decision`, `Principal`, `AuthContext`
  (`@kengela/contracts`).
