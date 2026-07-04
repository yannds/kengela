# Combo 17 - Provisioning Entra via SCIM + décision d'autorisation (RBAC + CEL)

> COMBO : deux recettes assemblées de bout en bout. Un utilisateur est PROVISIONNÉ
> depuis Microsoft Entra ID par SCIM 2.0 (recette 12) - création du compte + mapping
> des groupes vers des rôles applicatifs - PUIS ses accès sont TRANCHÉS par le PDP en
> couches RBAC + condition CEL (recette 14). Le fil rouge : le provisioning POSE les
> grants, le PDP les LIT à chaque requête.

---

## 1. Les briques et le flux

Deux temps, deux familles de symboles réels :

- **Provisioning (SCIM → rôles)** - les handlers purs de `@kengela/scim-server`
  (`handleUsersPost`, …) persistent le compte via le port `ScimStore` ; puis
  `profileFromScim` (`@kengela/iam-mapping`) normalise le corps SCIM en
  `DirectoryProfile`, `evaluateMappings` en tire des `roleKeys`, et `toContractsProfile`
  projette vers la forme minimale de `contracts` pour la persistance.
- **Décision (RBAC + ABAC)** - `LayeredDecisionPoint` (`@kengela/authz-core`) évalue,
  PAR REQUÊTE : plancher RBAC (grants rechargés via `PrismaAuthorizationRepository`),
  relation org via `PrincipalRelationResolver`, puis conditions CEL via
  `CelExpressionEngine` (`@kengela/adapter-expr-cel`) sur les policies chargées par
  `PrismaPolicyStore`. Le guard `KengelaAuthzGuard` (`@kengela/nestjs`) branche tout ça
  sur une route.

### Fil d'exécution

```
Entra ──SCIM POST /Users──► handleUsersPost(store, req) ──► ScimStore (compte persisté)
                                     │
   (mapping, second temps)          ▼
   profileFromScim(scimBody) ──► DirectoryProfile (riche)
        │                              │
        ▼                              ▼
   evaluateMappings(profile, rules) ──► roleKeys ──► GRANTS posés (repos app)
        │
   toContractsProfile(rich,{source,active}) ──► ScimRepository.upsertUserByEmail
                                     │
   ─────────────────────────────────┴──────────────  (plus tard, à l'accès)
                                     ▼
   AccessRequest ──► LayeredDecisionPoint.check ──► Decision { allow | deny | step_up }
        RBAC (grants) + relation (PrincipalRelationResolver) + CEL (CelExpressionEngine)
```

### Tableau port → adapter

| Port (`@kengela/contracts`) | Adapter concret                                               | Paquet                                |
| --------------------------- | ------------------------------------------------------------- | ------------------------------------- |
| `ScimStore` (scim-server)   | `PrismaScimStore` (à écrire)                                  | votre app                             |
| `AuthorizationRepository`   | `PrismaAuthorizationRepository`                               | `@kengela/adapter-persistence-prisma` |
| `PolicyStore`               | `PrismaPolicyStore`                                           | `@kengela/adapter-persistence-prisma` |
| `RelationResolver`          | `PrincipalRelationResolver`                                   | `@kengela/authz-core`                 |
| `ExpressionEnginePort`      | `CelExpressionEngine`                                         | `@kengela/adapter-expr-cel`           |
| `PolicyDecisionPoint`       | `LayeredDecisionPoint`                                        | `@kengela/authz-core`                 |
| - (fonctions pures)         | `profileFromScim` / `evaluateMappings` / `toContractsProfile` | `@kengela/iam-mapping`                |

> `RbacDecisionPoint` (RBAC seul, sans policies) existe aussi dans `@kengela/authz-core` :
> c'est le PDP à utiliser si ce tenant n'a AUCUNE condition ABAC. Ce combo prend le PDP
> en couches `LayeredDecisionPoint` (RBAC + CEL).

---

## 2. Installation

```sh
npm add @kengela/scim-server @kengela/iam-mapping @kengela/authz-core \
        @kengela/adapter-expr-cel @kengela/adapter-persistence-prisma \
        @kengela/nestjs @kengela/contracts
```

---

## 3. Temps 1 - provisionner puis mapper les rôles

Les handlers SCIM parlent au port `ScimStore` (implémentation Prisma à écrire côté app,
cf. recette 12). Un `POST /Users` d'Entra crée ou réconcilie le compte par e-mail :

```ts
import { handleUsersPost, type ScimStore, type ScimRequest } from '@kengela/scim-server';

// scimBody = corps SCIM brut poussé par Entra ; store = votre PrismaScimStore.
const req: ScimRequest = { tenantId, body: scimBody };
const res = await handleUsersPost(store, req); // 201 (créé) ou 200 (réconcilié, sans doublon)
```

Le mapping des rôles est un SECOND temps, alimenté par les mêmes données SCIM :

```ts
import {
  profileFromScim,
  evaluateMappings,
  toContractsProfile,
  type IdpMappingRule,
} from '@kengela/iam-mapping';
import { activeOf } from '@kengela/scim-server';

const rich = profileFromScim(scimBody); // DirectoryProfile riche (email, groups, attributes, claims)

const rules: IdpMappingRule[] = [
  {
    id: 'admins',
    priority: 0,
    stopOnMatch: true,
    any: [{ source: 'GROUP', op: 'iequals', value: 'Kengela-Admins' }],
    assignRoleKeys: ['ADM'],
  },
  {
    id: 'finance',
    priority: 10,
    all: [{ source: 'ATTRIBUTE', key: 'department', op: 'iequals', value: 'Finance' }],
    assignRoleKeys: ['VAL'],
    orgUnit: { by: 'name', fromAttribute: 'department' },
  },
];

const mapping = evaluateMappings(rich, rules);
// mapping.roleKeys => ['ADM'] et/ou ['VAL'] selon les groupes/attributs Entra.

// Projection vers la forme minimale de contracts pour la persistance de fédération :
const active = activeOf(scimBody);
const profile = toContractsProfile(rich, { source: 'scim', active });
// await scimRepository.upsertUserByEmail(tenantId, profile);
// puis : appliquer mapping.roleKeys en GRANTS via vos repos (table Grant/Role du tenant).
```

`evaluateMappings` est déterministe (tri `priority` puis `id`), accumule les rôles en
union, respecte `stopOnMatch`. Les règles sont configurables par tenant (jamais en dur).

Une fois les `roleKeys` traduits en lignes `Grant` (via le catalogue `Role` du tenant),
le PDP les rechargera à chaque `check` - pas de cache : révoquer un droit agit
immédiatement.

---

## 4. Temps 2 - décider un accès (RBAC + CEL)

`LayeredDecisionPoint` tranche par requête. Ordre réel (`policy-pdp.ts`) : 1. plancher
RBAC (sinon `deny no_grant`) ; 2. policies applicables à `(resource, action)` ; 3. deny
explicite prioritaire ; 4. gate ABAC positif (si des `allow` existent, au moins un doit
matcher) ; 5. `step_up` ; 6. sinon `allow`. Fail-closed : une condition CEL non évaluable
=> `deny condition_error`.

```ts
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import {
  PrismaAuthorizationRepository,
  PrismaPolicyStore,
} from '@kengela/adapter-persistence-prisma';
import type { AccessRequest, Decision } from '@kengela/contracts';

const pdp = new LayeredDecisionPoint({
  grants: new PrismaAuthorizationRepository(db), // recharge les grants issus du mapping SCIM
  policies: new PrismaPolicyStore(db), // policies ABAC du tenant
  relations: new PrincipalRelationResolver(), // relation org depuis le Principal
  expr: new CelExpressionEngine(), // conditions CEL, sandbox lecture seule
});

const request: AccessRequest = {
  principal, // provisionné + rôles mappés
  action: 'read',
  resource: { type: 'invoice', tenantId: principal.tenantId, attributes: { unitId: 'agc-dakar' } },
};
const decision: Decision = await pdp.check(request);
// decision.effect === 'allow' | 'deny' | 'step_up' ; decision.reason trace la cause.
```

La condition CEL d'une `PolicyRule` (colonne `when`) reçoit `{ principal, resource, env }`
et doit rendre un booléen. Exemple de règle « même agence que le principal » :

```
resource.attributes.unitId == principal.agencyId
```

Le moteur CEL interdit la fonction `matches` (regex non bornée, anti-ReDoS) : exprimer
les conditions via `==`, `in`, `startsWith`, `contains`.

---

## Exemple complet (copier-coller)

Un seul bloc : provisioning SCIM + mapping des rôles, puis composition du PDP en couches
et exposition via le guard NestJS. Prêt à coller (`db` = un PrismaClient structurellement
compatible avec `PrismaLike` ; `store` = votre `ScimStore` Prisma, cf. recette 12).

```ts
import { handleUsersPost, activeOf, type ScimStore, type ScimRequest } from '@kengela/scim-server';
import {
  profileFromScim,
  evaluateMappings,
  toContractsProfile,
  type IdpMappingRule,
} from '@kengela/iam-mapping';
import { LayeredDecisionPoint, PrincipalRelationResolver } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import {
  PrismaAuthorizationRepository,
  PrismaPolicyStore,
} from '@kengela/adapter-persistence-prisma';
import type { PrismaLike } from '@kengela/adapter-persistence-prisma';
import { KengelaAuthzGuard, KENGELA_PDP, RequirePermission } from '@kengela/nestjs';
import { Controller, Get, UseGuards } from '@nestjs/common';
import type {
  AccessRequest,
  Decision,
  PolicyDecisionPoint,
  Principal,
  TenantId,
} from '@kengela/contracts';

// ── Temps 1 : provisioning SCIM + mapping des rôles ──────────────────────────
const TENANT_MAPPING_RULES: IdpMappingRule[] = [
  {
    id: 'admins',
    priority: 0,
    stopOnMatch: true,
    any: [{ source: 'GROUP', op: 'iequals', value: 'Kengela-Admins' }],
    assignRoleKeys: ['ADM'],
  },
  {
    id: 'finance',
    priority: 10,
    all: [{ source: 'ATTRIBUTE', key: 'department', op: 'iequals', value: 'Finance' }],
    assignRoleKeys: ['VAL'],
    orgUnit: { by: 'name', fromAttribute: 'department' },
  },
];

/**
 * Reçoit un POST /Users d'Entra : persiste le compte (handler SCIM pur), normalise le
 * profil, en dérive les rôles et projette la forme contracts pour la fédération.
 */
export async function provisionFromScim(
  store: ScimStore,
  tenantId: TenantId,
  scimBody: Record<string, unknown>,
): Promise<{ readonly status: number; readonly roleKeys: readonly string[] }> {
  // 1. Persistance SCIM (réconciliation par e-mail, jamais de doublon).
  const req: ScimRequest = { tenantId, body: scimBody };
  const res = await handleUsersPost(store, req);

  // 2. Mapping des rôles depuis les groupes/attributs Entra.
  const rich = profileFromScim(scimBody);
  const mapping = evaluateMappings(rich, TENANT_MAPPING_RULES);

  // 3. Projection contracts (pour ScimRepository.upsertUserByEmail côté app).
  const profile = toContractsProfile(rich, { source: 'scim', active: activeOf(scimBody) });
  void profile; // await scimRepository.upsertUserByEmail(tenantId, profile);

  // 4. Traduire mapping.roleKeys en lignes Grant via le catalogue Role du tenant (repos app).
  return { status: res.status, roleKeys: mapping.roleKeys };
}

// ── Temps 2 : décision d'autorisation en couches ─────────────────────────────
/** Compose le PDP : RBAC (grants du mapping) + relation org + conditions CEL du tenant. */
export function buildPdp(db: PrismaLike): PolicyDecisionPoint {
  return new LayeredDecisionPoint({
    grants: new PrismaAuthorizationRepository(db),
    policies: new PrismaPolicyStore(db),
    relations: new PrincipalRelationResolver(),
    expr: new CelExpressionEngine(),
  });
}

/** Vérification directe (niveau service) avec une ressource chargée + ses attributs ABAC. */
export async function canReadInvoice(
  pdp: PolicyDecisionPoint,
  principal: Principal,
  invoice: { readonly id: string; readonly unitId: string },
): Promise<boolean> {
  const request: AccessRequest = {
    principal,
    action: 'read',
    resource: {
      type: 'invoice',
      id: invoice.id,
      tenantId: principal.tenantId,
      attributes: { unitId: invoice.unitId }, // matière de la condition CEL (même agence)
    },
  };
  const decision: Decision = await pdp.check(request);
  return decision.effect === 'allow';
}

// ── Exposition NestJS : le guard branche le même PDP sur les routes ──────────
@Controller('invoices')
@UseGuards(KengelaAuthzGuard)
export class InvoiceController {
  // La permission évaluée est `invoice.read` ; le guard construit l'AccessRequest au
  // niveau TYPE. Les conditions ABAC sur une ressource PRÉCISE (même agence) se vérifient
  // au niveau service via canReadInvoice(pdp, principal, invoice).
  @Get()
  @RequirePermission('invoice', 'read')
  public list(): { readonly ok: true } {
    return { ok: true };
  }
}

// Câblage du module (esquisse) : fournir le PDP sous le jeton KENGELA_PDP.
export const authzProvider = {
  provide: KENGELA_PDP,
  useFactory: (db: PrismaLike): PolicyDecisionPoint => buildPdp(db),
  inject: [/* votre token PrismaClient */],
};
```

### Récap des symboles réels

- SCIM : `handleUsersPost`, `activeOf`, `ScimStore`, `ScimRequest` (`@kengela/scim-server`).
- Mapping : `profileFromScim`, `evaluateMappings`, `toContractsProfile`, `IdpMappingRule`
  (`@kengela/iam-mapping`).
- Authz : `LayeredDecisionPoint`, `RbacDecisionPoint`, `PrincipalRelationResolver`
  (`@kengela/authz-core`) ; `CelExpressionEngine` (`@kengela/adapter-expr-cel`).
- Persistance : `PrismaAuthorizationRepository`, `PrismaPolicyStore`, `PrismaLike`
  (`@kengela/adapter-persistence-prisma`).
- NestJS : `KengelaAuthzGuard`, `KENGELA_PDP`, `RequirePermission` (`@kengela/nestjs`).
- Contrats : `AccessRequest`, `Decision`, `PolicyDecisionPoint`, `Principal` (`@kengela/contracts`).
