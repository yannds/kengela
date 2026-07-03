# 04 - Fédération d'identité

La fédération relie l'identité d'entreprise (Entra / AD / ADFS / Okta / Google...) au modèle interne
rôles + organigramme. Trois paquets couvrent le sujet : `@kengela/iam-mapping` (normalisation +
mapping, **pur**), `@kengela/scim-server` (cœur SCIM 2.0), `@kengela/adapter-directory-ldap`
(connecteur AD/LDAP).

> **Note sur `DirectoryProfile`.** Cette page utilise le `DirectoryProfile` **riche** de
> `@kengela/iam-mapping` (email, firstName, lastName, attributs, groupes, claims), distinct du type
> homonyme minimal de `@kengela/contracts`.

## `iam-mapping` : 6 sources → un `DirectoryProfile`

Quelle que soit la source, chaque adapter projette le payload IdP vers **une seule cible normalisée**.
L'application ne raisonne jamais sur la forme brute d'un IdP : une fois le profil normalisé, **le
mapping de rôles et la classification marchent tels quels**, quel que soit le sens de la synchro.

| Source                         | Fonction de projection                | Entrée                                    |
| ------------------------------ | ------------------------------------- | ----------------------------------------- |
| OIDC (Entra / Okta / Keycloak) | `profileFromOidcClaims(claims, map?)` | claims du jeton                           |
| SCIM 2.0                       | `profileFromScim(body, map?)`         | corps SCIM (core + enterprise)            |
| SAML 2.0 (ADFS / Entra / Okta) | `profileFromSaml(assertion)`          | assertion normalisée (nameID + attributs) |
| LDAP / Active Directory        | `profileFromLdap(entry)`              | entrée LDAP (DN + attributs)              |
| Microsoft Graph                | `profileFromGraph(user)`              | utilisateur Graph `/users`                |
| Google Workspace               | `profileFromGoogle(user)`             | utilisateur Admin SDK Directory           |

Il existe aussi `profileFromParts(...)` (reconstruire un profil depuis un état persisté) et
`projectScimUser(user)` (projeter un `KengelaScimUser` typé).

Le `DirectoryProfile` normalisé :

```ts
interface DirectoryProfile {
  readonly email: string;
  readonly externalId: string | null; // sub OIDC / nameID SAML / externalId SCIM
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly attributes: DirectoryAttributes; // department, title, manager, phoneNumber, ...
  readonly groups: readonly string[]; // groupes de sécurité (source du mapping)
  readonly claims: Readonly<Record<string, unknown>>; // bruts, pour règles avancées
}
```

### Cartes d'attributs config-driven

Chaque source accepte une **carte d'attributs** optionnelle par tenant (`OidcAttributeMap`,
`ScimAttributeMap`, `SamlAttributeMap`, `LdapAttributeMap`). L'admin peut surcharger, champ par
champ, le claim/attribut/chemin lu ; **à défaut, une liste de candidats usuels** est essayée (le nom
fourni prime, puis les défauts). Sans surcharge, l'extraction est identique au comportement
historique.

```ts
import { profileFromOidcClaims } from '@kengela/iam-mapping';

const profile = profileFromOidcClaims(idTokenClaims, {
  title: 'jobTitle', // cet IdP met le poste dans `jobTitle`
  groups: 'roles', // et les groupes dans `roles`
});
```

Les défauts sont des sources uniques de vérité exportées (ex. `LDAP_AD_ATTRIBUTE_DEFAULTS`,
`SAML_DEFAULT_ATTRIBUTE_KEYS`, `SCIM_DEFAULT_ATTRIBUTE_KEYS`, `OIDC_DEFAULT_ATTRIBUTE_KEYS`), pour
alimenter aussi la saisie assistée côté admin (jamais en dur dans l'UI).

## Moteur de mapping : profil → rôles + unité

`evaluateMappings(profile, rules)` traduit un `DirectoryProfile` en clés de rôle et directives de
rattachement organisationnel, selon des **règles configurables par tenant** (jamais en dur).

```ts
import { evaluateMappings, type IdpMappingRule } from '@kengela/iam-mapping';

const rules: IdpMappingRule[] = [
  {
    id: 'validators',
    priority: 0,
    all: [{ source: 'GROUP', op: 'iequals', value: 'Validateurs' }],
    assignRoleKeys: ['VAL'],
  },
  {
    id: 'finance-dept',
    priority: 10,
    any: [{ source: 'ATTRIBUTE', key: 'department', op: 'iequals', value: 'Finance' }],
    assignRoleKeys: ['FIN'],
    orgUnit: { by: 'code', fromAttribute: 'costCenter' },
    stopOnMatch: true,
  },
];

const result = evaluateMappings(profile, rules);
// { roleKeys: ['VAL', 'FIN'], orgUnitDirectives: [...], matchedRuleIds: [...] }
```

Comportement (déterministe, fail-closed) :

- Évaluation par **priorité croissante**, départage stable par `id`.
- `all` = ET logique, `any` = OU logique. Une **règle vide** (ni `all` ni `any`) ne matche **jamais**.
- Les rôles s'**accumulent** (union) ; les directives d'unité sont collectées par ordre de priorité ;
  `stopOnMatch` court-circuite le reste.
- Opérateurs (`MatchOp`) : `equals`, `iequals`, `contains`, `matches`, `in`, `present`.

### Anti-ReDoS sur `matches`

L'opérateur `matches` compile une regex fournie par l'admin. Elle passe par `safeRegexTest` : bornes
de longueur (source 200, entrée 1024) + rejet des **quantificateurs imbriqués** (`(a+)+`, `(.+)+`...).
Un motif suspect ou trop long → **fail-closed** (la condition ne matche pas), jamais d'évaluation non
bornée.

```ts
import { compileSafeRegex, safeRegexTest, SAFE_REGEX_LIMITS } from '@kengela/iam-mapping';
```

## Schéma SCIM canonique Kengela

`@kengela/iam-mapping` définit un **superset** SCIM 2.0 (`KengelaScimUser`) qui va au-delà d'un seul
IdP : cœur RFC 7643 + extension enterprise + richesse Okta/Entra/Google. Chaque application pioche le
sous-ensemble utile ; la lib ne fige jamais la liste (bag `extensions`).

```ts
import {
  SCIM_SCHEMA_CORE_USER, // urn:ietf:params:scim:schemas:core:2.0:User
  SCIM_SCHEMA_ENTERPRISE_USER, // ...:extension:enterprise:2.0:User
  SCIM_SCHEMA_GROUP, // ...:core:2.0:Group
  KENGELA_SCIM_ATTRIBUTE_PATHS, // registre des chemins portés (source unique)
  projectScimUser,
  type KengelaScimUser,
} from '@kengela/iam-mapping';
```

## `scim-server` : le cœur SCIM 2.0 (framework-agnostique)

`@kengela/scim-server` fournit un cœur SCIM **sans HTTP** : un port de persistance `ScimStore`, des
**handlers purs** `(store, requête parsée) → réponse`, la sérialisation/parsing, la **découverte** et
la **validation**. Un adapter (NestJS, Express...) résout le tenant, parse le corps, appelle un
handler et sérialise la `ScimResponse` en `application/scim+json`.

### Handlers Users & Groups

```ts
import {
  handleUsersPost,
  handleUsersPostStrict,
  handleUsersGet,
  handleUsersList,
  handleUsersPatch,
  handleUsersPut,
  handleUsersDelete,
  handleGroupsPost,
  handleGroupsGet,
  handleGroupsList,
  handleGroupsPatch,
  handleGroupsPut,
  handleGroupsDelete,
  type ScimStore,
  type ScimRequest,
} from '@kengela/scim-server';

const response = await handleUsersPost(store, {
  tenantId: 't1',
  body: idpPushedUserJson,
});
// { status: 201, body: { ...ressource SCIM... } }
```

Doctrine (RFC 7644), prouvée par test :

- **Provisioning réconcilié par e-mail**, insensible à la casse : `handleUsersPost` est idempotent
  (existant → 200 sans doublon, nouveau → 201).
- **Mode strict** (`handleUsersPostStrict`) : `userName` déjà présent → **409 `uniqueness`** (pour le
  validateur Microsoft Entra, qui attend le rejet du doublon).
- **Déprovisionnement = désactivation** : `handleUsersDelete` désactive (`active=false`), ne supprime
  **jamais** physiquement (204 si effectué).
- **Filtres bornés** : `userName eq` / `externalId eq` supportés + pagination ; un filtre non
  supporté rend une liste vide (jamais d'erreur) ; les filtres sont bornés (anti-ReDoS).
- **PATCH** (§3.5.2) : op inconnue ignorée, path forgé borné.
- **Isolation tenant** : chaque handler est borné au `tenantId` (404 sur un accès cross-tenant).

Le port `ScimStore` (à implémenter par l'app, ex. sur Prisma) expose exactement ce dont les handlers
ont besoin :

```ts
interface ScimStore {
  getUser(tenantId, id): Promise<ScimUserRow | null>;
  findUserByEmail(tenantId, email): Promise<ScimUserRow | null>; // réconciliation insensible à la casse
  listUsers(tenantId, options): Promise<ScimListPage<ScimUserRow>>; // totalResults = total AVANT pagination
  createUser(tenantId, input): Promise<ScimUserRow>;
  replaceUser(tenantId, id, input): Promise<ScimUserRow | null>;
  patchUser(tenantId, id, patch): Promise<ScimUserRow | null>;
  deactivateUser(tenantId, id): Promise<ScimUserRow | null>; // désactive, ne supprime jamais
  // ... Groups : getGroup / listGroups / createGroup / replaceGroup / patchGroup / deleteGroup
}
```

### Endpoints de découverte (auto-description)

Le validateur Microsoft Entra interroge ces endpoints pour se configurer. Handlers purs, sans store :

```ts
import {
  handleServiceProviderConfig, // GET /ServiceProviderConfig
  handleResourceTypes, // GET /ResourceTypes[/:id]
  handleSchemas, // GET /Schemas[/:id]
} from '@kengela/scim-server';

const cfg = handleServiceProviderConfig();
// { status: 200, body: { patch: {supported:true}, filter: {supported:true, maxResults}, bulk:{supported:false}, ... } }
```

La configuration annonce les **capacités réelles** : PATCH supporté, filtre supporté (borné) ;
bulk / sort / etag / changePassword non supportés ; authentification par jeton porteur OAuth. Les
`schemaDefinitions()` décrivent exactement ce que `KengelaScimUser` sait porter, et sont la source de
vérité consommée par la validation.

### Validation de schéma (conformité Entra)

`validateScimUser` / `validateScimGroup` contrôlent une ressource contre le schéma Kengela, **à
l'entrée** (corps poussé par l'IdP) comme **à la sortie** (round-trip). Fail-closed, sans `any` :

```ts
import { validateScimUser } from '@kengela/scim-server';

const { valid, errors } = validateScimUser(pushedBody);
if (!valid) {
  // errors = liste EXHAUSTIVE des écarts (schemas manquant, userName requis, types...)
}
```

Contrôles : `schemas` présent / non vide / URNs reconnues ; attributs requis présents (`userName`
pour User, `displayName` pour Group) ; types scalaires corrects ; multi-valués bien formés.

## Connecteur AD / LDAP

`@kengela/adapter-directory-ldap` est le jumeau « pull » des connecteurs Graph/Google/SCIM. Il se lie
en **LDAPS** (TLS vérifié par défaut), parcourt l'annuaire par recherche paginée, et renvoie des
entrées **normalisées** directement consommables par `profileFromLdap`. Aucun mapping de rôles ici :
l'adapter ne fait que **parler LDAP**.

```ts
import { LdapDirectorySource } from '@kengela/adapter-directory-ldap';

const source = new LdapDirectorySource({
  url: 'ldaps://dc.corp.local:636',
  bindDN: 'CN=svc-read,OU=Service,DC=corp,DC=local',
  bindPassword: vaultSecret, // jamais journalisé
  baseDN: 'OU=Users,DC=corp,DC=local',
  // userFilter, attributes, pageSize, maxUsers, tlsRejectUnauthorized : défauts AD surchargeables
});

const entries = await source.fetchEntries(); // LdapEntryParts[]
const records = LdapDirectorySource.toRecords(entries); // { profile, active }[]
const healthy = await source.checkConnection(); // true/false, sans fuiter le secret
```

Points durcis (prouvés par test) :

- **TLS vérifié par défaut** (`tlsRejectUnauthorized: true`) ; ne le désactiver que pour un annuaire
  de test.
- Le mot de passe de bind **n'est jamais journalisé** (ce module ne journalise rien).
- `unbind()` est **garanti même en cas d'échec** (bloc `finally`).
- Le plafond `maxUsers` est appliqué ; `checkConnection` avale l'erreur sans fuiter le secret.
- Désactivation détectée via `userAccountControl` (bit `ACCOUNTDISABLE` 0x2) → `accountActiveFromLdap`.

Surface **narrow** du client : `LdapClientLike` ne déclare que `bind` / `search` / `unbind` (lecture
seule ; aucune écriture d'annuaire). Un vrai `Client` de `ldapts` la satisfait structurellement, et
un fake en mémoire aussi (tests).

> **Dette (DEBT LDAP #5).** L'adapter transmet le `filter` verbatim (aucune injection introduite),
> mais n'expose pas encore de helper `escapeLdapFilterValue()` : une app qui composerait un filtre
> depuis une entrée utilisateur non échappée resterait exposée à l'injection de filtre LDAP côté
> appelant.
> </content>
