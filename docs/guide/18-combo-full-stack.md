# Combo 18 - Full-stack : app NestJS « tout branché » (recette de référence)

> COMBO MAÎTRE : une seule app NestJS qui compose TOUTES les briques du socle en UN seul
> composition root - authn native (argon2 timing-safe), persistance Prisma, sessions
> opaques, MFA/TOTP, autorisation RBAC + ABAC (CEL) avec relation organisationnelle, et
> PII chiffrées + effacement. C'est la recette de RÉFÉRENCE : elle agrège les recettes 10,
> 14 et 15 sous une seule fabrique et un seul module.

---

## 1. Les briques et le flux

Cinq couches, tout injecté par port, un seul point de câblage :

- **Authn native** - `Argon2PasswordHasher` (`PasswordHasher`) + `PrismaCredentialStore`
  (`CredentialStore`) alimentent `NativeCredentialAuthenticator` (`CredentialAuthenticator`,
  compare timing-safe même sur e-mail inconnu).
- **Sessions** - `PrismaSessionStore` (`SessionStore`) : token opaque 32 octets, rotation
  atomique, fail-closed sur expiration.
- **MFA/TOTP** - `TotpMfaService` compose `TotpVerifier` + `AesGcmKeyManagement` (secret
  chiffré at-rest par tenant) + `PrismaMfaSecretStore` + `PrismaMfaChallengeStore`.
- **Autorisation** - `LayeredDecisionPoint` (RBAC via `PrismaAuthorizationRepository` +
  policies via `PrismaPolicyStore` + relation via `PrincipalRelationResolver` + conditions
  via `CelExpressionEngine`), exposé par `KengelaAuthzGuard`.
- **PII** - `AesGcmFieldCipher` (per-tenant) + `SubjectFieldCipher` / `SubjectCryptoShredder`
  (per-sujet, via `PrismaSubjectKeyStore`) + `PrismaPiiAccessLogSink`.

### Flux d'exécution

```
POST /auth/login (email + password)
   │
   ▼ NativeCredentialAuthenticator.authenticate ──► AuthOutcome
        ├─ 'invalid_credentials'                  -> 401
        ├─ 'mfa_required' { userId, tenantId }    -> TotpMfaService.challenge -> challengeId
        └─ 'authenticated' { principal }          -> PrismaSessionStore.create -> token opaque
   │
   ▼ (MFA) POST /auth/mfa  TotpMfaService.verify(challengeId, code) -> session créée
   │
Requête protégée (cookie/bearer -> Principal posé sur req.user)
   │
   ▼ KengelaAuthzGuard.canActivate ──► LayeredDecisionPoint.check ──► allow | deny | step_up
        RBAC (grants) + relation (PrincipalRelationResolver) + policies CEL (CelExpressionEngine)
   │
   ▼ handler service : lit/écrit des PII chiffrées (AesGcmFieldCipher / SubjectFieldCipher),
        trace l'accès (PrismaPiiAccessLogSink), efface sur demande (SubjectCryptoShredder).
```

### Tableau port → adapter

| Port (`@kengela/contracts`)            | Adapter concret                                    | Paquet                                |
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

## 3. Deux contextes HKDF (séparation de domaine)

Une seule clé maître, deux usages cryptographiques DISTINCTS. `AesGcmKeyManagement` dérive
la clé par tenant dans un CONTEXTE (`info`) configurable. Ne JAMAIS partager le même
contexte entre le secret MFA et le chiffrement PII :

```ts
import { AesGcmKeyManagement } from '@kengela/adapter-authn-native';

// masterKey : Uint8Array >= 32 octets, chargée du coffre (Vault), JAMAIS en dur.
const mfaKeyMgmt = new AesGcmKeyManagement(masterKey); // défaut 'kengela:mfa'
const piiKeyMgmt = new AesGcmKeyManagement(masterKey, { context: 'kengela:pii' });
```

---

## 4. Authn native + sessions + MFA

`NativeCredentialAuthenticator.create` pré-calcule un hash leurre (compare systématique,
anti-énumération). L'outcome pilote la suite : session directe, ou défi MFA.

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
const credentials = new PrismaCredentialStore(db); // Account + User (surface narrow)
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

## 5. Autorisation en couches

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
  relations: new PrincipalRelationResolver(), // relation org (self/unit/subtree/tenant) depuis le Principal
  expr: new CelExpressionEngine(), // conditions CEL sandbox lecture seule
});
```

Le guard `KengelaAuthzGuard` est deny-by-default : une route sans `@RequirePermission` ni
`@PublicRoute` est REFUSÉE. Précédence handler > classe (fail-closed).

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
const subjectCipher = new SubjectFieldCipher(subjectKeys); // per-sujet (shreddable)
const shredder = new SubjectCryptoShredder(subjectKeys); // ErasurePort
const piiAudit = new PrismaPiiAccessLogSink(db.piiAccessLog); // journal art. 30
```

---

## Exemple complet (copier-coller)

Un seul bloc : la fabrique `buildAuthCore` qui compose TOUTES les briques, un service
`LoginService` orchestrant login/MFA/session, et le module NestJS branchant le PDP + le
guard global. Prêt à coller (`db` = un PrismaClient satisfaisant les surfaces narrow
`PrismaLike` / `CredentialPrismaLike` + les délégués MFA/PII ; `masterKey` = clé >= 32
octets chargée du coffre, JAMAIS en dur).

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

/** Surface Prisma complète attendue par ce combo (un vrai PrismaClient la satisfait). */
type FullPrismaLike = PrismaLike &
  CredentialPrismaLike & {
    readonly mfaSecret: MfaSecretDelegate;
    readonly mfaChallenge: MfaChallengeDelegate;
    readonly subjectKey: SubjectKeyDelegate;
    readonly piiAccessLog: PiiAccessLogDelegate;
  };

/** Toutes les capacités du socle, composées en un seul objet. */
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
 * COMPOSITION ROOT UNIQUE. Assemble authn native + sessions + MFA + authz + PII.
 * `masterKey` (>= 32 octets) vient du coffre ; deux CONTEXTES HKDF distincts séparent
 * cryptographiquement le secret MFA du chiffrement PII.
 */
export async function buildAuthCore(db: FullPrismaLike, masterKey: Uint8Array): Promise<AuthCore> {
  // 1. Séparation de domaine : une clé maître, deux usages.
  const mfaKeyMgmt = new AesGcmKeyManagement(masterKey); // 'kengela:mfa' (défaut)
  const piiKeyMgmt = new AesGcmKeyManagement(masterKey, { context: 'kengela:pii' });

  // 2. Authn native (timing-safe) + sessions opaques.
  const hasher = new Argon2PasswordHasher();
  const authenticator = await NativeCredentialAuthenticator.create(
    new PrismaCredentialStore(db),
    hasher,
  );
  const sessions = new PrismaSessionStore(db);

  // 3. MFA/TOTP (secret chiffré at-rest par tenant).
  const mfa = new TotpMfaService(
    new TotpVerifier(),
    mfaKeyMgmt,
    new PrismaMfaSecretStore(db.mfaSecret),
    new PrismaMfaChallengeStore(db.mfaChallenge),
  );

  // 4. Autorisation en couches : RBAC + relation org + policies CEL.
  const pdp = new LayeredDecisionPoint({
    grants: new PrismaAuthorizationRepository(db),
    policies: new PrismaPolicyStore(db),
    relations: new PrincipalRelationResolver(),
    expr: new CelExpressionEngine(),
  });

  // 5. PII : chiffrement per-tenant + per-sujet (crypto-shredding) + journal.
  const subjectKeys = new PrismaSubjectKeyStore(db.subjectKey, { keyManagement: piiKeyMgmt });
  const tenantCipher = new AesGcmFieldCipher(piiKeyMgmt);
  const subjectCipher = new SubjectFieldCipher(subjectKeys);
  const shredder = new SubjectCryptoShredder(subjectKeys);
  const piiAudit = new PrismaPiiAccessLogSink(db.piiAccessLog);

  return { authenticator, sessions, mfa, pdp, tenantCipher, subjectCipher, shredder, piiAudit };
}

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 h

/** Orchestration login : credentials -> (MFA ?) -> session opaque. */
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

  /** Vérifie le code TOTP puis ouvre la session (le challenge porte tenant + user). */
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

// ── Exposition NestJS : un seul module câble PDP + guard global + services ────
@Controller('invoices')
export class InvoiceController {
  readonly #core: AuthCore;
  public constructor(core: AuthCore) {
    this.#core = core;
  }

  /** Route protégée : le guard global tranche `invoice.read` (RBAC + contexte). */
  @Get()
  @RequirePermission('invoice', 'read')
  public async list(@CurrentPrincipal() principal: Principal): Promise<{ readonly ok: true }> {
    // Condition ABAC sur une ressource PRÉCISE (même agence) : appel direct au PDP.
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

  /** Lit les PII du sujet, déchiffrées, avec journal d'accès (art. 30). */
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

  /** Droit à l'effacement (art. 17) : crypto-shredding de la clé du sujet. */
  @Post('erase')
  @RequirePermission('user', 'delete')
  public async erase(@CurrentPrincipal() principal: Principal): Promise<{ readonly erased: true }> {
    await this.#core.shredder.eraseSubject(principal.tenantId, principal.userId);
    return { erased: true };
  }
}

/** Jeton d'injection de l'AuthCore composé. */
export const AUTH_CORE = Symbol('AUTH_CORE');
/** Jeton d'injection du PrismaClient applicatif. */
export const APP_DB = Symbol('APP_DB');
/** Jeton d'injection de la clé maître (chargée du coffre au démarrage). */
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
    // Le guard lit le PDP sous KENGELA_PDP ; on le dérive de l'AuthCore.
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
    // Guard GLOBAL deny-by-default : toute route non annotée est refusée.
    { provide: APP_GUARD, useClass: KengelaAuthzGuard },
  ],
})
export class AuthModule {}

// PublicRoute() reste disponible pour les rares routes ouvertes (health, login lui-même) :
@Controller('health')
export class HealthController {
  @Get()
  @PublicRoute()
  public ok(): { readonly status: 'ok' } {
    return { status: 'ok' };
  }
}
```

### Récap des symboles réels

- Native : `Argon2PasswordHasher`, `NativeCredentialAuthenticator` (`.create`),
  `TotpVerifier`, `TotpMfaService`, `AesGcmKeyManagement` (option `{ context }`),
  `AesGcmFieldCipher`, `SubjectFieldCipher`, `SubjectCryptoShredder`
  (`@kengela/adapter-authn-native`).
- Persistance : `PrismaCredentialStore`, `PrismaSessionStore`, `PrismaMfaSecretStore`,
  `PrismaMfaChallengeStore`, `PrismaAuthorizationRepository`, `PrismaPolicyStore`,
  `PrismaSubjectKeyStore`, `PrismaPiiAccessLogSink` + surfaces `PrismaLike` /
  `CredentialPrismaLike` + délégués (`@kengela/adapter-persistence-prisma`).
- Authz : `LayeredDecisionPoint`, `PrincipalRelationResolver` (`@kengela/authz-core`) ;
  `CelExpressionEngine` (`@kengela/adapter-expr-cel`).
- NestJS : `KengelaAuthzGuard`, `KENGELA_PDP`, `RequirePermission`, `PublicRoute`,
  `CurrentPrincipal` (`@kengela/nestjs`).
- PII pur : `isPii` (`@kengela/pii`).
- Contrats : `CredentialAuthenticator`, `AuthOutcome`, `SessionStore`, `MfaService`,
  `PolicyDecisionPoint`, `AccessRequest`, `Decision`, `Principal`, `AuthContext`
  (`@kengela/contracts`).
