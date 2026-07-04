# Recette 10 - Application NestJS from-scratch : auth native (argon2) + persistence Prisma + autorisation

> **Chemin par défaut / recommandé.** On part d'une app NestJS vide et on branche le socle
> Kengela pour protéger une route de bout en bout : login (hash argon2 timing-safe) → session
> → décision Zero Trust (RBAC + policies) sur chaque requête. Tous les symboles ci-dessous
> sont réels et vérifiés dans les sources (`@kengela/contracts`, `@kengela/adapter-authn-native`,
> `@kengela/adapter-persistence-prisma`, `@kengela/authz-core`, `@kengela/adapter-expr-cel`,
> `@kengela/nestjs`).

---

## 1. Ce que ce scénario met en place

Kengela est un socle de **ports** (interfaces pures, `@kengela/contracts`) que des **adapters**
implémentent et que l'**app compose**. Ce scénario branche les ports suivants :

| Port (`@kengela/contracts`)  | Adapter branché                                   | Paquet                                | Qui l'écrit    |
| ---------------------------- | ------------------------------------------------- | ------------------------------------- | -------------- |
| `PasswordHasher`             | `Argon2PasswordHasher`                            | `@kengela/adapter-authn-native`       | fourni Kengela |
| `CredentialAuthenticator`    | `NativeCredentialAuthenticator`                   | `@kengela/adapter-authn-native`       | fourni Kengela |
| `CredentialStore`            | `PrismaCredentialStore` (défaut) _ou le tien_     | `@kengela/adapter-persistence-prisma` | fourni / toi   |
| `SessionStore`               | `PrismaSessionStore`                              | `@kengela/adapter-persistence-prisma` | fourni Kengela |
| `AuthorizationRepository`    | `PrismaAuthorizationRepository`                   | `@kengela/adapter-persistence-prisma` | fourni Kengela |
| `PolicyStore`                | `PrismaPolicyStore`                               | `@kengela/adapter-persistence-prisma` | fourni Kengela |
| `ExpressionEnginePort` (CEL) | `CelExpressionEngine`                             | `@kengela/adapter-expr-cel`           | fourni Kengela |
| `RelationResolver`           | `PrincipalRelationResolver` (défaut) _ou le tien_ | `@kengela/authz-core`                 | fourni / toi   |
| `PolicyDecisionPoint` (PDP)  | `RbacDecisionPoint` **ou** `LayeredDecisionPoint` | `@kengela/authz-core`                 | fourni Kengela |
| Guard + décorateurs NestJS   | `KengelaAuthzGuard`, `@RequirePermission`, …      | `@kengela/nestjs`                     | fourni Kengela |

> **Deux ports pour lesquels un adapter par défaut GÉNÉRIQUE est désormais livré** - utilisé
> tel quel dans cette recette, à remplacer par le tien seulement si ta forme diffère :
>
> - `CredentialStore` - `PrismaCredentialStore` (`@kengela/adapter-persistence-prisma`) résout
>   un credential sur le modèle générique `Account(providerId='credential')` + `User` (mêmes
>   conventions que `TranslogCredentialStore`). Constructeur : `new PrismaCredentialStore(prisma, { providerId? })`.
>   Si TON schéma diffère, écris le tien ; `@kengela/connector-translog` en donne un exemple réel.
> - `RelationResolver` - `PrincipalRelationResolver` (`@kengela/authz-core`) calcule la relation
>   org à partir des champs déjà portés par le `Principal` (`orgUnitId`/`agencyId`/`coverageUnits`)
>   confrontés à la `ResourceRef` (`attributes.ownerId`/`unitId`…), deny-by-default. Constructeur
>   pur, sans I/O : `new PrincipalRelationResolver({ ownerAttributeKeys?, unitAttributeKeys? })`.
>   Un organigramme calculé HORS jeton (unités traversées en base) reste du ressort d'un resolver app.

**Choix du PDP :**

- `RbacDecisionPoint` - RBAC pur (grants × relation org). Le plus simple pour démarrer.
- `LayeredDecisionPoint` - RBAC (plancher) **+** policies déclaratives ABAC (conditions CEL)
  **+** step-up. Requiert en plus un `PolicyStore` et un `ExpressionEnginePort`. C'est celui
  qui débloque le `deny` conditionnel et le `step_up`. On l'utilise dans cette recette.

---

## 2. Installation

Fournis par Kengela (registre `@kengela/*`) :

```bash
pnpm add @kengela/contracts \
         @kengela/adapter-authn-native \
         @kengela/adapter-persistence-prisma \
         @kengela/authz-core \
         @kengela/adapter-expr-cel \
         @kengela/nestjs
```

À installer (dépendances tierces réelles) :

```bash
# @node-rs/argon2 est la dépendance native de l'adapter authn (hash/verify argon2id)
pnpm add @node-rs/argon2

# NestJS + Prisma + reflect-metadata (l'index @kengela/nestjs importe déjà 'reflect-metadata')
pnpm add @nestjs/common @nestjs/core reflect-metadata @prisma/client
pnpm add -D prisma
```

> En npm : remplace `pnpm add` par `npm i`. La lib est **ESM/TypeScript** ; garde
> `"type": "module"` et un `moduleResolution` moderne (`NodeNext`/`Bundler`).

---

## 3. Schéma Prisma minimal

Les modèles ci-dessous sont **déduits des delegates réels** de `PrismaLike` et
`CredentialPrismaLike` (`adapter-persistence-prisma/src/prisma-like.ts`). Le vrai `PrismaClient`
généré est **structurellement compatible** : ses lignes réelles sont des sur-ensembles des lignes
NARROW (`GrantRow`, `RoleRow`, `SessionRow`, `PolicyRow`, `PolicyRuleRow`, `AccountRow`,
`CredentialUserRow`) → il « passe » là où `PrismaLike` / `CredentialPrismaLike` est attendu, sans
import de `@prisma/client` dans l'adapter.

```prisma
// prisma/schema.prisma
generator client { provider = "prisma-client-js" }
datasource db    { provider = "postgresql"; url = env("DATABASE_URL") }

/// Lu par PrismaAuthorizationRepository.loadGrantsForUser (grant.findMany where { userId, tenantId })
/// ET exposé comme relation Role.grants (role.findFirst include { grants: true }).
/// -> Grant porte À LA FOIS `userId?` ET `roleId?` : les deux colonnes sont IMPOSÉES par les
///    signatures des delegates (cf. §7). Chaque ligne est rattachée à l'un OU l'autre :
///    un grant direct d'utilisateur (userId) ou un grant de rôle (roleId).
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

/// Lu par PrismaAuthorizationRepository.loadRole (role.findFirst where { key, tenantId } include grants)
model Role {
  id       String  @id @default(cuid())
  key      String
  tenantId String
  grants   Grant[]
  @@unique([key, tenantId])
}

/// Lu/écrit par PrismaSessionStore. `ctx` = colonne JSON opaque (AuthContext sérialisé).
model Session {
  token     String   @id @unique
  userId    String
  tenantId  String
  createdAt DateTime
  expiresAt DateTime
  ctx       Json     // SessionRow.ctx: unknown -> Json côté base
  @@index([userId])
}

/// Lu par PrismaPolicyStore (policy.findMany where { tenantId } include { rules: true })
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

/// Identité par mot de passe, lue par PrismaCredentialStore (account.findFirst/findMany).
/// providerId='credential', accountId=email, password=hash argon2id (null autorisé).
model Account {
  id         String  @id @default(cuid())
  userId     String
  tenantId   String
  providerId String  // 'credential'
  accountId  String  // email
  password   String? // hash argon2id ; null si l'identité n'a pas (encore) de mot de passe
  @@unique([tenantId, providerId, accountId])
  @@index([providerId, accountId])
}

/// État du compte, lu par PrismaCredentialStore (user.findFirst/findMany) et joint au compte.
model User {
  id         String    @id @default(cuid())
  tenantId   String
  isActive   Boolean   @default(true)
  deletedAt  DateTime?
  mfaEnabled Boolean   @default(false)
  roles      String[]  @default([]) // colonne liste (CredentialUserRow.roles)
}
```

> **Colonnes d'union en `String`.** Côté base, `scope`/`source`/`effect` restent des `string` ;
> le narrowing vers les unions littérales des contrats est fait **fail-closed** dans le
> `mapping.ts` de l'adapter (toute valeur inconnue fait tomber le grant/la règle, jamais un
> `allow` fantôme).
>
> **Ton schéma diffère ?** Si ton identité par mot de passe ne suit pas la convention
> `Account`/`User` ci-dessus (ex. un seul modèle `User` avec `email`/`passwordHash`), garde les
> autres modèles et écris ton propre `CredentialStore` - voir la variante `AppCredentialStore`
> en §7.

---

## 4. Composition root (module NestJS)

Un seul module câble tout via `useFactory`. Points réels à respecter :

- `NativeCredentialAuthenticator` s'instancie via sa **fabrique statique asynchrone**
  `NativeCredentialAuthenticator.create(store, hasher)` (elle pré-calcule le hash leurre
  anti-énumération). Le constructeur direct existe aussi : `new NativeCredentialAuthenticator(store, hasher, dummyHash)`.
- Les stores Prisma prennent le client (`PrismaLike` / `CredentialPrismaLike`) en **1er argument**
  de constructeur.
- Le PDP `LayeredDecisionPoint` prend un **objet de deps** `{ grants, relations, policies, expr, log?, clock? }`.
- Le jeton d'injection du PDP côté NestJS est le **symbole** `KENGELA_PDP`
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

// -- 4.a Le vrai PrismaClient (sur-ensemble structurel de PrismaLike) --------
const prisma = new PrismaClient();

@Module({
  providers: [
    { provide: PASSWORD_HASHER, useClass: Argon2PasswordHasher },

    // 4.b CredentialStore - adapter par défaut Account(providerId='credential') + User.
    //     providerId par défaut = 'credential' ; surcharge via { providerId } si besoin.
    {
      provide: CREDENTIAL_STORE,
      useFactory: (): CredentialStore =>
        new PrismaCredentialStore(prisma as unknown as CredentialPrismaLike),
    },

    // 4.c Fabrique statique ASYNC (pré-calcule le hash leurre timing-safe).
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

    // 4.d PDP en couches : RBAC + policies (CEL) + step-up.
    //     RelationResolver par défaut, pur : relation déduite du Principal, deny-by-default.
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

> **`prisma as unknown as PrismaLike` / `as unknown as CredentialPrismaLike` : compatibilité
> structurelle VOULUE.** Le `PrismaClient` généré satisfait ces surfaces NARROW (mêmes signatures
> de delegates + `$transaction` optionnel) ; le double cast est là UNIQUEMENT parce que le client
> généré est nominalement distinct et beaucoup plus large que la surface attendue - pas pour
> masquer une incompatibilité. Aucune surprise à l'exécution tant que le schéma respecte les
> colonnes NARROW (§3). C'est le contrat documenté en tête de `prisma-like.ts`.
>
> **RBAC pur ?** Remplace le provider `KENGELA_PDP` par
> `new RbacDecisionPoint({ grants, relations })` (pas de `policies`/`expr`).
>
> **Attributs de ressource non standards ?** `PrincipalRelationResolver` lit par défaut
> `attributes.ownerId` (owner) et `attributes.unitId` / `orgUnitId` / `agencyId` (unité). Pour
> d'autres noms : `new PrincipalRelationResolver({ ownerAttributeKeys: ['createdBy'], unitAttributeKeys: ['stationId'] })`.

---

## 5. Guard global + décorateurs

On enregistre `KengelaAuthzGuard` en `APP_GUARD` : **deny-by-default** - toute route sans
`@RequirePermission` **ni** `@PublicRoute` est refusée (`ForbiddenException('route_not_annotated')`).

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

Décorateurs réels (`@kengela/nestjs`, `decorators.ts` + `current-principal.decorator.ts`) :

```ts
// src/invoices.controller.ts
import { Controller, Get } from '@nestjs/common';
import { RequirePermission, PublicRoute, CurrentPrincipal } from '@kengela/nestjs';
import type { Principal } from '@kengela/contracts';

@Controller('invoices')
export class InvoicesController {
  // permission évaluée = `resourceType.action` = "data.invoice.read"
  @Get()
  @RequirePermission('data.invoice', 'read')
  list(@CurrentPrincipal() principal: Principal) {
    return { tenant: principal.tenantId, user: principal.userId };
  }
}
```

```ts
// route ouverte : le guard laisse passer sans décision
@PublicRoute()
@Get('health')
health() { return { ok: true }; }
```

> **Précédence fail-closed** (lue dans `authz.guard.ts`) : l'annotation du **handler** prime
> TOUJOURS sur celle de la **classe**. Un `@PublicRoute()` de classe ne peut jamais neutraliser
> un `@RequirePermission` de handler.
>
> **Le guard n'évalue que le niveau TYPE** de ressource (`{ type, tenantId }`, tenant tiré du
> `Principal`). Les conditions ABAC sur les **attributs** d'une ressource précise (ex. « même
> agence », `resource.attributes.ownerId`) se vérifient au **niveau service** en appelant
> directement `pdp.check(request)` avec la ressource chargée.

Le guard lit le `Principal` sur `req.user`. Un middleware/guard d'authn amont doit le poser :

```ts
// src/session.middleware.ts (extrait) - résout la session en Principal et pose req.user
const handle = await sessionStore.get(token);          // SessionHandle | null
if (handle !== null) {
  const record = await credentialStore.findByEmail(/* ... */);
  req.user = /* Principal reconstruit depuis handle + record.roles */;
}
```

---

## 6. Flux bout-en-bout

### 6.a Login (hash + verify timing-safe → session)

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

Sous le capot, `NativeCredentialAuthenticator.authenticate` effectue **toujours** un
`hasher.verify` (contre le hash leurre si l'email est inconnu) → temps de réponse constant,
anti-énumération de comptes. Le hash argon2id vient de `Argon2PasswordHasher`
(OWASP : m=19456 KiB, t=2, p=1) ; `needsRehash()` permet la migration transparente d'un
ancien hash au prochain login réussi.

### 6.b Requête protégée → décision `allow`

`GET /invoices` avec `Authorization` valide → le middleware pose `req.user` (Principal) →
`KengelaAuthzGuard.canActivate` construit :

```ts
const request: AccessRequest = {
  principal, // req.user
  action: 'read',
  resource: { type: 'data.invoice', tenantId: principal.tenantId },
};
```

`LayeredDecisionPoint.check` : recharge les grants (**anti-staleness** : un droit révoqué cesse
d'agir immédiatement, on ne fait pas confiance au `Principal.roles` caché), résout la relation
org, applique le plancher RBAC puis les policies. Si un grant actif couvre
`data.invoice.read` à la bonne portée et qu'aucune règle ne s'y oppose →
`{ effect: 'allow', reason: 'rbac_grant' }` → **200**.

### 6.c Exemple `deny`

- **Aucun grant** couvrant la permission → `{ effect: 'deny', reason: 'no_grant' }`
  → `ForbiddenException('no_grant')` → **403**.
- **Cross-tenant** : `principal.tenantId !== resource.tenantId` → la relation est forcée à
  `'none'` (défense en profondeur) → aucun grant tenant ne couvre → `deny`.
- **Policy `deny` explicite** matchée (deny-wins) → `{ effect: 'deny', reason: <policy.reason> }`.
- **Condition CEL inévaluable** (variable absente / expression invalide) → **fail-closed**
  `{ effect: 'deny', reason: 'condition_error' }`.

### 6.d Exemple `step_up`

Une policy sur `(data.invoice, read)` avec une règle `effect: 'step_up'` portant l'obligation
`require_passkey` (ex. quand `env.riskScore` est élevé) fait renvoyer au PDP
`{ effect: 'step_up', reason: 'step_up_required', obligations: [{ type: 'require_passkey' }] }`.
Le guard lève alors :

```ts
throw new StepUpRequiredException(decision.obligations ?? [], decision.reason);
// -> HTTP 403 { statusCode: 403, error: 'step_up_required', reason, obligations }
```

Le client lit `error: 'step_up_required'` + `obligations`, déclenche le facteur d'authn exigé
(passkey / re-auth / MFA), rejoue la requête avec un `Principal` dont le `ctx`/`mfaLevel`
satisfait désormais la condition → `allow`. C'est le lien intime **authz → authn** : l'accès
est conditionnel à une force d'authentification.

Policy d'exemple (une ligne `Policy` + une ligne `PolicyRule` step-up en base) :

```jsonc
// Policy { resource: "data.invoice", action: "read", tenantId }
// PolicyRule { effect: "step_up", when: "has(env.riskScore) && env.riskScore > 50",
//              obligations: [{ "type": "require_passkey" }] }
```

> `has(env.riskScore) && …` est la forme tolérante : `riskScore` est optionnel, et accéder à un
> champ absent en CEL **lève** (donc deny `condition_error`). Le garde `has()` court-circuite
> l'absence sans erreur - voir recette 14 §5.

---

## 7. Encadré - « déjà disponible » vs « à écrire »

**Code déjà fourni par Kengela (import direct, zéro réécriture) :**

- `Argon2PasswordHasher`, `NativeCredentialAuthenticator` (+ fabrique `.create`) - `@kengela/adapter-authn-native`
- `PrismaSessionStore`, `PrismaAuthorizationRepository`, `PrismaPolicyStore`, `PrismaCredentialStore`
  (+ `PrismaMfaSecretStore`, `PrismaMfaChallengeStore` si MFA) - `@kengela/adapter-persistence-prisma`
- `RbacDecisionPoint`, `LayeredDecisionPoint`, `PrincipalRelationResolver` (+ `activeGrants`,
  `grantCovers`, `tenantScopedRelation`) - `@kengela/authz-core`
- `CelExpressionEngine` - `@kengela/adapter-expr-cel`
- `KengelaAuthzGuard`, `RequirePermission`, `PublicRoute`, `CurrentPrincipal`,
  `StepUpRequiredException`, `KENGELA_PDP` - `@kengela/nestjs`

**Ce que tu écris toi-même :**

- **Le schéma Prisma** (§3) + la génération du `PrismaClient`.
- **`CredentialStore`** - SEULEMENT si ton schéma diffère du défaut : `PrismaCredentialStore`
  couvre le modèle générique `Account(providerId='credential')` + `User`. Sinon calque
  `TranslogCredentialStore` (`@kengela/connector-translog`), jointure fail-closed. Variante minimale
  pour un modèle `User` mono-table (`email`/`passwordHash`) :

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

- **`RelationResolver`** - `PrincipalRelationResolver` (`@kengela/authz-core`) suffit tant que la
  relation se déduit du `Principal` ; écris le tien pour brancher un organigramme calculé en base
  (`self`/`unit`/`subtree`/`tenant`/`none`). Variante minimale :

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

- **La composition root** (§4) + le **middleware d'authn** qui résout la session en `Principal`
  et le pose sur `req.user`.
- Optionnel : `DecisionLogSink` (journal des décisions), `Clock` (tests déterministes),
  `ContextProvider` (enrichissement geo/device/risque pour le conditional access).

### Décisions de modélisation tranchées (aucune incertitude résiduelle)

- **`Grant` à double rattachement - IMPOSÉ, pas optionnel.** Le delegate `grant` sert deux lectures
  dans `prisma-like.ts` : `GrantDelegate.findMany({ where: { userId, tenantId } })` (utilisé par
  `PrismaAuthorizationRepository.loadGrantsForUser`) **exige** la colonne `userId` ; et la relation
  `Role.grants`, chargée par `RoleDelegate.findFirst({ where: { key, tenantId }, include: { grants: true } })`,
  **exige** une clé étrangère `roleId` sur `Grant`. Le modèle §3 porte donc `userId?` **et** `roleId?`,
  chaque ligne rattachée à l'un OU l'autre (grant direct d'utilisateur vs grant de rôle). Les types
  `GrantRow`/`RoleRow` n'exposent que `permission`/`scope`/`source`/`expiresAt` (les colonnes de
  rattachement ne sont lues que par les `where`/`include`), mais les deux colonnes restent requises
  par ces signatures.
- **Cast `PrismaClient → PrismaLike` / `CredentialPrismaLike` - compatibilité structurelle voulue.**
  Le double cast `as unknown as …` est le mode d'emploi documenté (tête de `prisma-like.ts`) : le
  client généré est un sur-ensemble des surfaces NARROW, nominalement distinct, d'où le cast. Pas
  de risque runtime tant que le schéma §3 est respecté.

---

## Exemple complet (copier-coller)

Les 5 fichiers ci-dessous forment une app NestJS protégée de bout en bout avec le chemin par
défaut de cette recette (`PrismaCredentialStore` + `PrincipalRelationResolver` + `LayeredDecisionPoint`).
Ajoute le schéma Prisma du §3, `prisma generate`, puis colle tel quel.

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
