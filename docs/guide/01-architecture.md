# 01 - Architecture

Kengela est une **architecture hexagonale** (ports & adapters) au service d'une doctrine **Zero
Trust**. Cette page décrit les 3 anneaux, la règle « le port est un sas », le garde-fou anti-vendor,
le flux de décision, et le pont `Principal` entre authentification et autorisation.

## Les 3 anneaux

```
        ┌──────────────────────────────────────────────┐
        │            APPLICATIONS (composent)          │   ← votre app, TransLog, ...
        │  ┌────────────────────────────────────────┐  │
        │  │        ADAPTERS (implémentent)         │  │   ← expr-cel, authn-native, prisma,
        │  │  ┌──────────────────────────────────┐  │  │      ldap, scim-server, better-auth,
        │  │  │        CORE (dépend des ports)   │  │  │      nestjs, connector-translog
        │  │  │   authz-core · iam-mapping · pii │  │  │
        │  │  │  ┌────────────────────────────┐  │  │  │
        │  │  │  │  CONTRACTS (ports & types) │  │  │  │   ← @kengela/contracts
        │  │  │  └────────────────────────────┘  │  │  │      (aucune implémentation, aucun vendor)
        │  │  └──────────────────────────────────┘  │  │
        │  └────────────────────────────────────────┘  │
        └──────────────────────────────────────────────┘
```

| Anneau                 | Paquets                                                                                                                                                  | Règle                                                                                                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **contracts**          | `@kengela/contracts`                                                                                                                                     | **Uniquement** des types et interfaces. Zéro implémentation, zéro import vendor. C'est l'invariant : la forme stable dont dépendent le cœur, les adapters et les apps. |
| **core**               | `authz-core`, `iam-mapping`, `pii`                                                                                                                       | Logique **pure** (testable hors infra), qui **dépend des ports**. Aucun import de vendor npm (garanti par le lint).                                                    |
| **adapters**           | `adapter-expr-cel`, `adapter-authn-native`, `adapter-persistence-prisma`, `adapter-directory-ldap`, `scim-server`, `adapter-authn-better-auth`, `nestjs` | **Implémentent** un port au-dessus d'une techno concrète (Prisma, ldapts, otplib, cel-js, better-auth, NestJS). Le vendor **vit ici**, et nulle part ailleurs.         |
| **apps / connecteurs** | `connector-translog`, votre application                                                                                                                  | **Composent** : choisissent un adapter par port et câblent le tout.                                                                                                    |

**Le sens des dépendances va toujours vers l'intérieur** : les adapters connaissent les contrats, le
cœur connaît les contrats, mais **les contrats ne connaissent personne**. Remplacer Prisma par un
autre ORM, ou otplib par une autre lib TOTP, ne touche jamais le cœur.

## Doctrine : « le port est un sas, pas une planque »

Envelopper un vendor derrière un port n'est **pas** une façon de cacher du code faible. C'est un
**sas** : on n'expose au reste du système que la surface strictement nécessaire, on trace ce qui est
faible, et on garde une cible de migration.

Cela se matérialise par trois habitudes :

1. **Interface NARROW du vendor.** Un adapter ne dépend pas de tout un framework, mais d'une
   interface minuscule qui décrit _exactement_ les méthodes utilisées. Exemples réels :
   - `PrismaLike` (adapter-persistence-prisma) : décrit les délégués `grant`, `role`, `session`,
     `policy` et les seules méthodes appelées. On n'importe **rien** de `@prisma/client` ; un vrai
     `PrismaClient` est _structurellement compatible_.
   - `LdapClientLike` (adapter-directory-ldap) : `bind` / `search` / `unbind`, rien d'autre. Aucune
     méthode d'écriture d'annuaire n'est déclarée (lecture seule).
   - `BetterAuthLike` (adapter-authn-better-auth) : uniquement `api.getSession`.
2. **`DEBT.md` par adapter.** Tout ce qui est enveloppé sans être encore migré figure dans un
   registre de dette avec son état, son problème et sa cible (`DEBT.template.md` à la racine donne le
   gabarit). Une dette résolue est **supprimée** du fichier.
3. **Fail-closed au narrowing.** Une valeur d'union illisible (un `scope` inconnu, un `effect`
   invalide) fait _tomber_ le grant/la règle plutôt que de l'élargir. Jamais d'élargissement fantôme.

## Le lint anti-vendor (garde-fou de build)

La règle « le cœur ne connaît aucun vendor » n'est pas qu'une convention : elle est **vérifiée
mécaniquement** par `dependency-cruiser`.

```sh
pnpm lint:arch
```

La configuration (`.dependency-cruiser.mjs`) interdit à tout paquet du cœur (`contracts`,
`authz-core`, `iam-mapping`, ...) d'importer un paquet npm hors du monorepo, et interdit les
dépendances circulaires :

```js
{
  name: 'core-no-vendor',
  severity: 'error',
  from: { path: '^packages/(contracts|authz-core|authn-core|iam-mapping|policy)/src' },
  to: { dependencyTypes: ['npm', 'npm-dev', 'npm-optional', 'npm-peer'], pathNot: ['^packages/'] },
}
```

Si un jour un import de `argon2` ou `@prisma/client` se glisse dans `authz-core`, **la build casse**.
C'est le filet qui protège la pureté du cœur dans la durée.

## Le flux de décision Zero Trust

Chaque requête d'accès traverse le PDP en couches (`LayeredDecisionPoint`). L'ordre est **fixe** et
**fail-closed** :

```
AccessRequest
     │
     ▼
[0] Isolation multi-tenant  ─ resource.tenantId ≠ principal.tenantId ? → relation ramenée à `none`
     │                          (seul un grant `global` du plan plateforme peut alors couvrir)
     ▼
[1] Plancher RBAC           ─ aucun grant actif couvrant la permission à la relation → DENY (no_grant)
     │
     ▼
[2] Policies (resource,action) applicables ? ─ aucune → ALLOW (le RBAC suffit)
     │
     ▼   (condition CEL inévaluable → DENY condition_error : FAIL-CLOSED)
[3] DENY explicite prioritaire  ─ une règle `deny` matchée l'emporte (deny-wins)
     │
     ▼
[4] Gate ABAC positif       ─ s'il existe des règles `allow` mais qu'aucune ne matche → DENY (no_matching_allow)
     │
     ▼
[5] Step-up                 ─ des règles `step_up` matchées → STEP_UP + obligations
     │
     ▼
[6] ALLOW
```

Les points clés, chacun un **contrôle prouvé par test** (voir [08-security.md](./08-security.md)) :

- **RBAC plancher** : sans droit, rien. Le RBAC est la condition nécessaire, jamais suffisante à elle
  seule si des policies existent.
- **deny-wins** : un `deny` explicite gagne quel que soit l'ordre d'évaluation.
- **Gate ABAC** : dès qu'une policy pose des règles `allow` (scoping déclaratif, ex. « même agence »),
  il en faut au moins une qui matche.
- **Step-up** : l'autorisation peut **exiger un facteur d'authentification** (MFA, passkey,
  re-auth). C'est le lien intime authz → authn.
- **Fail-closed** : une condition inévaluable (variable absente, expression invalide, non-booléen)
  se résout en **DENY**, jamais en accès.
- **Anti-staleness** : les grants sont **rechargés à chaque check** via l'`AuthorizationRepository`.
  Un droit révoqué cesse d'agir immédiatement ; on ne fait pas confiance à un cache de rôles porté
  par le `Principal`.

Toute décision (allow/deny/step_up) peut être **tracée** dans un `DecisionLogSink` avec sa `reason`
et ses `signals` (dont `crossTenant`), pour l'observabilité ZTNA.

## Isolation multi-tenant au cœur

L'isolation tenant est **le** contrôle central de la lib, et elle est défendue _dans_ le PDP, pas
déléguée à l'app. L'helper `tenantScopedRelation()` (`authz-core/src/engine.ts`) applique la règle :

```ts
export function tenantScopedRelation(
  principalTenantId: TenantId,
  resourceTenantId: TenantId,
  resolved: OrgRelation,
): OrgRelation {
  return principalTenantId === resourceTenantId ? resolved : 'none';
}
```

Même si le `RelationResolver` fourni par l'app se trompe (ou est compromis) et renvoie `tenant` pour
une ressource d'un **autre** tenant, la relation est ramenée à `none`, et seul un grant de portée
`global` peut couvrir. Un `Principal` non-plateforme ne franchit jamais la frontière. Un signal
`crossTenant` est émis au decision log.

## Le pont `Principal` (authn ↔ authz)

Le `Principal` est **produit par l'authentification** et **consommé par l'autorisation**. Il contient
tout ce qu'une décision Zero Trust peut exiger :

```ts
interface Principal {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly roles: readonly string[]; // multi-rôle (union des grants)
  readonly orgUnitId?: string;
  readonly agencyId?: string;
  readonly coverageUnits?: readonly string[];
  readonly activeStationId?: string;
  readonly mfaLevel: 'none' | 'totp' | 'passkey'; // force d'authn atteinte (step-up)
  readonly authMethod:
    'credential' | 'passwordless' | 'oidc' | 'saml' | 'passkey' | 'impersonation';
  readonly ctx: AuthContext; // géo / device / risque / authTime → conditional access
}
```

- `mfaLevel` + `authMethod` disent **comment** l'utilisateur s'est authentifié : c'est ce que les
  règles de step-up interrogent.
- `ctx: AuthContext` porte les **signaux ZTNA** (IP, géo, device de confiance, `riskScore`,
  `authTime`). Une application les alimente via un `ContextProvider` (GeoIP, fingerprint, risk
  engine). Ces signaux deviennent des **entrées de décision**, pas seulement de l'audit.

> **Deux `DirectoryProfile` distincts.** Attention : `@kengela/contracts` expose un type
> `DirectoryProfile` minimal (côté ports fédération), tandis que `@kengela/iam-mapping` expose un
> `DirectoryProfile` **plus riche** (email, firstName, lastName, attributs, claims), utilisé par le
> mapping et la conformité PII. Les pages 04 et 06 importent celui d'`iam-mapping`.

## Conventions transverses du repo

- **TypeScript 6, `strict` maximal** : `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`,
  `isolatedDeclarations`, `verbatimModuleSyntax`, etc. (voir `tsconfig.base.json`).
- **ESLint `strictTypeChecked` + `stylisticTypeChecked`**.
- **ESM / NodeNext**, Node >= 24, imports `.js` explicites dans les sources TS.
- **Vitest** pour les tests, hermétiques (fakes en mémoire, aucun réseau ni DB réelle).
</content>
