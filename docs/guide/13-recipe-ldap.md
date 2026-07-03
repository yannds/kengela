# Recette 13 — Fédérer les identités depuis un annuaire LDAP / Active Directory

> Objectif : lire les comptes et attributs d'un annuaire **LDAP / Active Directory** (source
> d'annuaire « pull »), les projeter vers le `DirectoryProfile` normalisé de Kengela, puis les
> mapper vers les rôles internes du tenant.

Tous les symboles ci-dessous ont été vérifiés dans le code source ; les rares écarts d'API sont
signalés explicitement en fin de page (« Incertitudes / manques »).

---

## 1. De quoi on parle

### Le port `DirectorySourcePort` (contracts)

Kengela décrit une source d'annuaire par un port minimal, dans `@kengela/contracts` :

```ts
// @kengela/contracts
export interface DirectorySourcePort {
  fetchProfile(raw: unknown, tenantId: TenantId): Promise<DirectoryProfile>;
}
```

Le `DirectoryProfile` **du port contracts** est volontairement resserré :

```ts
// @kengela/contracts — forme de convergence côté application
export interface DirectoryProfile {
  readonly externalId: string;
  readonly email?: string;
  readonly displayName?: string;
  readonly groups: readonly string[];
  readonly attributes: Readonly<Record<string, unknown>>;
  readonly active: boolean;
  readonly source: 'oidc' | 'scim' | 'saml' | 'ldap' | 'graph' | 'google';
}
```

> ATTENTION — il existe **deux** types nommés `DirectoryProfile` (voir §7). Celui de
> `@kengela/iam-mapping` (produit par `profileFromLdap`) n'a **pas** la même forme que celui du
> port. La bascule de l'un à l'autre est du code à écrire (§3).

### `LdapDirectorySource` (l'adapter réel)

`@kengela/adapter-directory-ldap` fournit la classe **`LdapDirectorySource`** (nom réel). Elle ne
fait **que parler LDAP** :

- se lie en LDAP(S) (`bind`), parcourt l'annuaire par **recherche paginée** (Paged Results Control)
  sous une `baseDN`, se délie (`unbind` garanti même en cas d'échec) ;
- renvoie des entrées **normalisées** `LdapEntryParts` (DN + attributs en chaînes, binaires comme
  `objectGUID` en base64) ;
- expose un **health-check** (`checkConnection`) ;
- ne contient **aucune** logique de mapping de rôles : la projection reste dans la lib pure
  `@kengela/iam-mapping`.

Méthodes réelles de la classe :

| Membre              | Signature réelle                                                                                   |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `fetchEntries`      | `fetchEntries(filter?: string, options?: FetchEntriesOptions): Promise<readonly LdapEntryParts[]>` |
| `checkConnection`   | `checkConnection(): Promise<boolean>`                                                              |
| `static toProfiles` | `toProfiles(entries, map?): readonly DirectoryProfile[]` _(profil iam-mapping)_                    |
| `static toRecords`  | `toRecords(entries, map?): readonly DirectoryRecord[]` _(profil + `active`)_                       |

> Il n'y a **pas** de méthode `fetchProfile(raw, tenantId)` sur `LdapDirectorySource` : la classe
> n'implémente donc pas directement `DirectorySourcePort` (voir §3 et §7).

### La surface NARROW `LdapClientLike`

Doctrine du repo : **le port est un sas, pas une planque**. L'adapter n'importe rien de `ldapts`
dans son contrat ; il décrit exactement les 3 méthodes qu'il utilise (lecture seule, aucune
écriture d'annuaire) :

```ts
// @kengela/adapter-directory-ldap — surface étroite lue
export interface LdapClientLike {
  bind(dn: string, password: string): Promise<void>;
  search(baseDN: string, options: LdapSearchOptions): Promise<LdapSearchResult>;
  unbind(): Promise<void>;
}
export type LdapClientFactory = () => LdapClientLike;
```

Le vrai `Client` de `ldapts` satisfait **structurellement** cette interface ; un fake en mémoire
aussi (tests). Kengela dépend donc de `LdapClientLike`, pas du type concret de `ldapts`.

**Statut de `ldapts` dans le package** — vérifié dans le `package.json` de l'adapter : `ldapts`
est une **dépendance directe** (`"ldapts": "^8.1.8"` sous `dependencies`), **PAS** une
`peerDependency` ni une `optionalDependency`. Elle est donc installée transitivement avec
l'adapter ; la fabrique de client par défaut instancie un vrai `new Client(...)` de `ldapts` sans
configuration supplémentaire.

---

## 2. Installation

```bash
npm install @kengela/adapter-directory-ldap
# ldapts est tiré automatiquement (dependency directe ^8.1.8) — aucune install séparée requise.
```

`@kengela/iam-mapping` (lib pure de mapping) est aussi une dépendance de l'adapter, et l'adapter
en ré-exporte les symboles utiles (`profileFromLdap`, `accountActiveFromLdap`, types) pour éviter
une double dépendance.

---

## 3. Wiring

### 3.1 Configuration de connexion (`LdapConnectionConfig`)

Options **réelles** du constructeur (extraites de `LdapConnectionConfig`) :

```ts
import { LdapDirectorySource, type LdapConnectionConfig } from '@kengela/adapter-directory-ldap';

const config: LdapConnectionConfig = {
  url: 'ldaps://dc.corp.local:636', // LDAPS recommandé ; ldap:// en dev seulement
  bindDN: 'CN=svc-kengela,OU=Service,DC=corp,DC=local', // compte de service (lecture)
  bindPassword: process.env.LDAP_BIND_PASSWORD!, // résolu depuis un coffre ; jamais loggé
  baseDN: 'OU=Users,DC=corp,DC=local', // racine de recherche
  // --- optionnels (sinon défauts Active Directory, cf. LDAP_SOURCE_DEFAULTS) ---
  userFilter: '(&(objectCategory=person)(objectClass=user))', // défaut AD
  attributes: ['*', 'memberOf'], // défaut AD
  timeoutMs: 15_000, // défaut
  tlsRejectUnauthorized: true, // défaut ; ne désactiver que pour un annuaire de test
  pageSize: 200, // taille de page paginée
  maxUsers: 1000, // plafond d'entrées par pull
};
```

Les bornes/défauts sont dans `LDAP_SOURCE_DEFAULTS` (exporté) : `userFilter`, `attributes`,
`timeoutMs = 15000`, `pageSize = 200`, `maxUsers = 1000`, `tlsRejectUnauthorized = true`.

### 3.2 Instancier la source (client `ldapts` par défaut)

Le second argument `LdapDirectorySourceOptions` permet d'injecter une fabrique de client
(`clientFactory?: LdapClientFactory`). **Sans** injection, la source construit elle-même un vrai
`Client` de `ldapts` (LDAPS vérifié) depuis la config — c'est le cas nominal :

```ts
const source = new LdapDirectorySource(config); // clientFactory par défaut = ldapts Client réel

// Health-check avant tout pull :
if (!(await source.checkConnection())) {
  throw new Error('Annuaire LDAP injoignable ou identifiants invalides');
}
```

### 3.3 Fournir explicitement un client `LdapClientLike` (optionnel)

Utile pour les tests, un pool, ou un client alternatif. La fabrique retourne quelque chose
d'assignable à `LdapClientLike` :

```ts
import { Client } from 'ldapts';
import type { LdapClientFactory } from '@kengela/adapter-directory-ldap';

const clientFactory: LdapClientFactory = () =>
  new Client({ url: config.url, timeout: 15_000, tlsOptions: { rejectUnauthorized: true } });

const source = new LdapDirectorySource(config, { clientFactory });
```

### 3.4 Exposer via `DirectorySourcePort`

`LdapDirectorySource` n'implémente **pas** `DirectorySourcePort` tel quel : le port attend
`fetchProfile(raw, tenantId)` renvoyant le `DirectoryProfile` **contracts** (avec `active`,
`source`), alors que la source renvoie des `LdapEntryParts` et un `DirectoryProfile`
**iam-mapping** (avec `firstName`/`lastName`/`claims`). On écrit donc un mince adaptateur qui
**reshape** le profil iam-mapping vers la forme contracts :

```ts
import { profileFromLdap, accountActiveFromLdap } from '@kengela/adapter-directory-ldap';
import type { LdapEntryParts } from '@kengela/adapter-directory-ldap';
import type { DirectorySourcePort, DirectoryProfile, TenantId } from '@kengela/contracts';

class LdapDirectoryPort implements DirectorySourcePort {
  async fetchProfile(raw: unknown, _tenantId: TenantId): Promise<DirectoryProfile> {
    const entry = raw as LdapEntryParts; // le port reçoit une entrée normalisée
    const p = profileFromLdap(entry); // DirectoryProfile "iam-mapping"
    return {
      externalId: p.externalId ?? entry.dn, // contracts exige un string non-null
      email: p.email || undefined,
      displayName: p.displayName ?? undefined,
      groups: p.groups,
      attributes: p.attributes as Readonly<Record<string, unknown>>,
      active: accountActiveFromLdap(entry),
      source: 'ldap',
    };
  }
}

export const ldapPort: DirectorySourcePort = new LdapDirectoryPort();
```

> Le passage iam-mapping → contracts (ajout de `active`/`source`, `externalId` non-null,
> `firstName`/`lastName`/`claims` abandonnés) est du **code applicatif à écrire** ; il n'est fourni
> par aucun des deux packages.

---

## 4. Récupérer un profil, puis mapper vers les rôles

### 4.1 Pull des entrées + projection

```ts
import { LdapDirectorySource, profileFromLdap } from '@kengela/adapter-directory-ldap';

// (a) Lecture réseau : bind → search paginé → normalisation → unbind
const entries = await source.fetchEntries(); // readonly LdapEntryParts[]

// (b) Projection vers DirectoryProfile (iam-mapping) — 3 voies possibles :
//   1. helper statique batch :
const profiles = LdapDirectorySource.toProfiles(entries);
//   2. helper batch avec état d'activation (dé-provisioning) :
const records = LdapDirectorySource.toRecords(entries); // { profile, active }[]
//   3. unitaire :
const one = profileFromLdap(entries[0]);
```

`fetchEntries(filter?, options?)` accepte un `filter` LDAP ad hoc et des `FetchEntriesOptions`
réelles : `attributes?`, `max?`, `scope?` (`'base' | 'one' | 'sub'`, défaut `sub`),
`attributeMap?` (`LdapAttributeMap`, attachée à chaque entrée pour la projection).

### 4.2 Attributs → profil (défauts Active Directory)

`profileFromLdap(e: LdapEntryParts)` lit les attributs via `LDAP_AD_ATTRIBUTE_DEFAULTS`,
surchargeables un par un par tenant via `e.attributeMap` (`LdapAttributeMap`). Défauts réels :

| Champ profil                        | Attribut AD par défaut                                             |
| ----------------------------------- | ------------------------------------------------------------------ |
| `email`                             | `mail` (repli `userPrincipalName`)                                 |
| `firstName`                         | `givenName`                                                        |
| `lastName`                          | `sn`                                                               |
| `displayName`                       | `displayName` (replis `cn`, puis `givenName sn`)                   |
| `externalId`                        | `objectGUID` (repli : le DN)                                       |
| `groups`                            | `memberOf` (chaque DN réduit à son **CN**)                         |
| `department` / `division` / `title` | `department` / `division` / `title`                                |
| `employeeNumber`                    | `employeeNumber` (repli `employeeID`)                              |
| `officeLocation`                    | `physicalDeliveryOfficeName`                                       |
| `manager`                           | `manager` (DN réduit à son **CN** — dette V2 : résoudre en e-mail) |
| `costCenter`                        | _(aucun défaut AD ; chaîne vide)_                                  |

`accountActiveFromLdap(e)` lit `userAccountControl` : bit `0x2` (ACCOUNTDISABLE) → compte
désactivé ; attribut absent (OpenLDAP) → considéré **actif**.

### 4.3 Profil → rôles internes (`evaluateMappings`)

Le moteur de mapping est **pur** et **configurable par tenant** (`@kengela/iam-mapping`) :

```ts
import { evaluateMappings, type IdpMappingRule } from '@kengela/iam-mapping';

const rules: IdpMappingRule[] = [
  {
    id: 'rh-admins',
    priority: 0,
    all: [{ source: 'GROUP', op: 'in', value: ['Groupe RH', 'Domain Admins'] }],
    assignRoleKeys: ['ADM'],
    orgUnit: { by: 'code', value: 'RH' },
    stopOnMatch: false,
  },
  {
    id: 'valideurs',
    priority: 10,
    any: [{ source: 'ATTRIBUTE', key: 'title', op: 'contains', value: 'Manager' }],
    assignRoleKeys: ['VAL'],
  },
];

const result = evaluateMappings(profile, rules);
// result.roleKeys           -> union des clés de rôle accordées (ex. ["ADM","VAL"])
// result.orgUnitDirectives  -> directives d'unité par priorité
// result.matchedRuleIds     -> ids des règles ayant matché (audit / dry-run)
```

Conditions (`MappingCondition`) : `source` = `'GROUP' | 'CLAIM' | 'ATTRIBUTE'`, `op` =
`'equals' | 'iequals' | 'contains' | 'matches' | 'in' | 'present'`. `matches` compile une regex
**bornée anti-ReDoS** (fail-closed) via `safeRegexTest`. Évaluation déterministe : tri par
(priorité croissante, `id`), rôles cumulés (union), `stopOnMatch` court-circuite.

> Note : les règles `GROUP` testent `profile.groups`, qui pour LDAP sont les **CN** extraits des DN
> `memberOf`. Utilisez donc le CN du groupe (`"Groupe RH"`), pas son DN complet.

---

## 5. Cas Active Directory — notes spécifiques

- **`memberOf`** : AD renvoie les groupes en **DN complets** (`CN=Groupe RH,OU=...,DC=corp`).
  `profileFromLdap` réduit chaque DN à son **CN** ; c'est ce CN qui alimente `profile.groups` et le
  moteur de règles. `memberOf` est demandé explicitement par défaut (`attributes: ['*','memberOf']`).
- **`sAMAccountName`** : **pas** dans `LDAP_AD_ATTRIBUTE_DEFAULTS` et **pas** consommé par
  `profileFromLdap` (pas de champ « login » dans `DirectoryProfile`). L'e-mail vient de `mail`,
  avec repli sur `userPrincipalName`. Si votre annuaire n'a pas de `mail`, assurez-vous que `UPN`
  est renseigné, ou surchargez `email` via `LdapAttributeMap`. `sAMAccountName` reste toutefois
  récupérable brut (via `attributes: ['sAMAccountName', ...]`) si votre code applicatif en a besoin.
- **Bind DN de service** : `bindDN` doit être un DN complet
  (`CN=svc-kengela,OU=Service,DC=corp,DC=local`) d'un compte de **lecture** ; `bindPassword` est
  résolu depuis un coffre par l'appelant et **n'est jamais journalisé** (ce module ne loggue rien).
- **Dé-provisioning** : AD encode la désactivation dans `userAccountControl` (bit `0x2`). Utilisez
  `toRecords()` / `accountActiveFromLdap()` pour propager `active: false`.
- **`objectGUID`** : binaire → normalisé en **base64** par l'adapter, et sert d'`externalId`
  stable (identifiant immuable, contrairement au DN qui bouge en cas de déplacement d'OU).
- **LDAPS** : `tlsRejectUnauthorized` vaut `true` par défaut ; ne le passez à `false` que contre un
  annuaire de test.

---

## 6. Encadré — fourni par Kengela vs à écrire

| ✅ Fourni par Kengela                                                                                      | ✍️ À écrire côté application                                                                                         |
| ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `LdapDirectorySource` : bind + search paginé + `unbind`, normalisation `LdapEntryParts`                    | La **config de bind** concrète (`LdapConnectionConfig`) : URL, `bindDN`, mot de passe (coffre), `baseDN`, filtres    |
| Fabrique par défaut d'un `Client` `ldapts` (LDAPS vérifié)                                                 | Un **client LDAP concret** alternatif (pool/fake), seulement si vous n'utilisez pas la fabrique par défaut           |
| `LdapClientLike` (surface narrow), `checkConnection`                                                       | L'adaptateur **`DirectorySourcePort`** (reshape iam-mapping → contracts : `active`, `source`, `externalId` non-null) |
| `profileFromLdap`, `accountActiveFromLdap`, `LDAP_AD_ATTRIBUTE_DEFAULTS`, helpers `toProfiles`/`toRecords` | La **carte d'attributs** par tenant (`LdapAttributeMap`) si votre schéma n'est pas AD standard                       |
| Moteur `evaluateMappings` (pur, anti-ReDoS) + types de règles                                              | Les **règles de mapping** (`IdpMappingRule[]`) par tenant → clés de rôle + unités d'organigramme                     |
| Regex sûres (`safeRegexTest`, `SAFE_REGEX_LIMITS`)                                                         | La **persistance** (upsert utilisateurs/rôles), l'orchestration du pull et sa planification                          |

---

## 7. Incertitudes / manques d'API (signalés, non inventés)

1. **Deux `DirectoryProfile` distincts.** Celui de `@kengela/iam-mapping` (retour de
   `profileFromLdap` / `toProfiles`) a la forme `{ email, externalId, firstName, lastName,
displayName, attributes, groups, claims }` (`email: string`, `externalId: string | null`).
   Celui de `@kengela/contracts` (retour du port) a la forme `{ externalId: string, email?,
displayName?, groups, attributes, active, source }`. **Ils ne sont pas interchangeables** ; le
   reshape du §3.4 est obligatoire et n'est fourni nulle part.
2. **`LdapDirectorySource` n'implémente pas `DirectorySourcePort`.** Aucune méthode
   `fetchProfile(raw, tenantId)` n'existe sur la classe ; son API est batch (`fetchEntries`) +
   helpers statiques. Le mapping `raw → LdapEntryParts` dans l'adaptateur du port est une
   **hypothèse** de ma part (le port type `raw: unknown` sans préciser la forme attendue pour LDAP).
3. **`ldapts` = dependency directe, pas peer/optional.** Vérifié dans le `package.json` de
   l'adapter. Aucune install séparée requise ; pas de mécanisme d'optionalité à documenter.
4. **`safe-regex.ts` non lu en détail.** Seuls les symboles exportés sont connus
   (`safeRegexTest`, `compileSafeRegex`, `SAFE_REGEX_LIMITS`, `SafeRegexLimits`) ; les bornes
   exactes anti-ReDoS ne sont pas reproduites ici.
5. **`manager` en dette V2.** `profileFromLdap` réduit le DN du manager à son CN faute de second
   appel LDAP ; il n'est pas résolu en e-mail (documenté tel quel dans la source).
