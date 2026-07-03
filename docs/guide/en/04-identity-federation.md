# 04 - Identity federation

Federation connects the enterprise identity (Entra / AD / ADFS / Okta / Google...) to the internal
roles + org-chart model. Three packages cover the topic: `@kengela/iam-mapping` (normalization +
mapping, **pure**), `@kengela/scim-server` (SCIM 2.0 core), `@kengela/adapter-directory-ldap`
(AD/LDAP connector).

> **Note on `DirectoryProfile`.** This page uses the **rich** `DirectoryProfile` from
> `@kengela/iam-mapping` (email, firstName, lastName, attributes, groups, claims), distinct from the
> minimal same-named type in `@kengela/contracts`.

## `iam-mapping`: 6 sources → one `DirectoryProfile`

Whatever the source, each adapter projects the IdP payload onto **a single normalized target**. The
application never reasons about an IdP's raw shape: once the profile is normalized, **role mapping and
classification work as-is**, whatever the direction of the sync.

| Source                         | Projection function                   | Input                                      |
| ------------------------------ | ------------------------------------- | ------------------------------------------ |
| OIDC (Entra / Okta / Keycloak) | `profileFromOidcClaims(claims, map?)` | token claims                               |
| SCIM 2.0                       | `profileFromScim(body, map?)`         | SCIM body (core + enterprise)              |
| SAML 2.0 (ADFS / Entra / Okta) | `profileFromSaml(assertion)`          | normalized assertion (nameID + attributes) |
| LDAP / Active Directory        | `profileFromLdap(entry)`              | LDAP entry (DN + attributes)               |
| Microsoft Graph                | `profileFromGraph(user)`              | Graph `/users` user                        |
| Google Workspace               | `profileFromGoogle(user)`             | Admin SDK Directory user                   |

There is also `profileFromParts(...)` (rebuild a profile from a persisted state) and
`projectScimUser(user)` (project a typed `KengelaScimUser`).

The normalized `DirectoryProfile`:

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

### Config-driven attribute maps

Each source accepts an optional per-tenant **attribute map** (`OidcAttributeMap`, `ScimAttributeMap`,
`SamlAttributeMap`, `LdapAttributeMap`). The admin can override, field by field, the claim/attribute/
path that is read; **failing that, a list of usual candidates** is tried (the provided name wins,
then the defaults). Without an override, extraction is identical to the historical behavior.

```ts
import { profileFromOidcClaims } from '@kengela/iam-mapping';

const profile = profileFromOidcClaims(idTokenClaims, {
  title: 'jobTitle', // cet IdP met le poste dans `jobTitle`
  groups: 'roles', // et les groupes dans `roles`
});
```

The defaults are exported single sources of truth (e.g. `LDAP_AD_ATTRIBUTE_DEFAULTS`,
`SAML_DEFAULT_ATTRIBUTE_KEYS`, `SCIM_DEFAULT_ATTRIBUTE_KEYS`, `OIDC_DEFAULT_ATTRIBUTE_KEYS`), to also
feed the assisted input on the admin side (never hard-coded in the UI).

## Mapping engine: profile → roles + unit

`evaluateMappings(profile, rules)` translates a `DirectoryProfile` into role keys and organizational
attachment directives, according to **per-tenant configurable rules** (never hard-coded).

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

Behavior (deterministic, fail-closed):

- Evaluation by **ascending priority**, stable tie-break by `id`.
- `all` = logical AND, `any` = logical OR. An **empty rule** (neither `all` nor `any`) **never**
  matches.
- Roles **accumulate** (union); unit directives are collected by priority order; `stopOnMatch`
  short-circuits the rest.
- Operators (`MatchOp`): `equals`, `iequals`, `contains`, `matches`, `in`, `present`.

### Anti-ReDoS on `matches`

The `matches` operator compiles a regex supplied by the admin. It goes through `safeRegexTest`:
length bounds (source 200, input 1024) + rejection of **nested quantifiers** (`(a+)+`, `(.+)+`...). A
suspicious or overly long pattern → **fail-closed** (the condition does not match), never an unbounded
evaluation.

```ts
import { compileSafeRegex, safeRegexTest, SAFE_REGEX_LIMITS } from '@kengela/iam-mapping';
```

## Kengela canonical SCIM schema

`@kengela/iam-mapping` defines a SCIM 2.0 **superset** (`KengelaScimUser`) that goes beyond a single
IdP: RFC 7643 core + enterprise extension + Okta/Entra/Google richness. Each application picks the
useful subset; the lib never freezes the list (`extensions` bag).

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

## `scim-server`: the SCIM 2.0 core (framework-agnostic)

`@kengela/scim-server` provides a SCIM core **without HTTP**: a `ScimStore` persistence port, **pure
handlers** `(store, parsed request) → response`, serialization/parsing, **discovery** and
**validation**. An adapter (NestJS, Express...) resolves the tenant, parses the body, calls a handler
and serializes the `ScimResponse` as `application/scim+json`.

### Users & Groups handlers

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

Doctrine (RFC 7644), proven by test:

- **Provisioning reconciled by email**, case-insensitive: `handleUsersPost` is idempotent (existing →
  200 without duplicate, new → 201).
- **Strict mode** (`handleUsersPostStrict`): `userName` already present → **409 `uniqueness`** (for
  the Microsoft Entra validator, which expects the duplicate to be rejected).
- **Deprovisioning = deactivation**: `handleUsersDelete` deactivates (`active=false`), **never**
  physically deletes (204 if performed).
- **Bounded filters**: `userName eq` / `externalId eq` supported + pagination; an unsupported filter
  returns an empty list (never an error); filters are bounded (anti-ReDoS).
- **PATCH** (§3.5.2): unknown op ignored, forged path bounded.
- **Tenant isolation**: each handler is bounded to the `tenantId` (404 on a cross-tenant access).

The `ScimStore` port (to be implemented by the app, e.g. on Prisma) exposes exactly what the handlers
need:

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

### Discovery endpoints (self-description)

The Microsoft Entra validator queries these endpoints to configure itself. Pure handlers, no store:

```ts
import {
  handleServiceProviderConfig, // GET /ServiceProviderConfig
  handleResourceTypes, // GET /ResourceTypes[/:id]
  handleSchemas, // GET /Schemas[/:id]
} from '@kengela/scim-server';

const cfg = handleServiceProviderConfig();
// { status: 200, body: { patch: {supported:true}, filter: {supported:true, maxResults}, bulk:{supported:false}, ... } }
```

The configuration announces the **real capabilities**: PATCH supported, filter supported (bounded);
bulk / sort / etag / changePassword unsupported; OAuth bearer-token authentication. The
`schemaDefinitions()` describe exactly what `KengelaScimUser` can carry, and are the source of truth
consumed by validation.

### Schema validation (Entra conformance)

`validateScimUser` / `validateScimGroup` check a resource against the Kengela schema, both **on entry**
(body pushed by the IdP) and **on exit** (round-trip). Fail-closed, without `any`:

```ts
import { validateScimUser } from '@kengela/scim-server';

const { valid, errors } = validateScimUser(pushedBody);
if (!valid) {
  // errors = liste EXHAUSTIVE des écarts (schemas manquant, userName requis, types...)
}
```

Checks: `schemas` present / non-empty / recognized URNs; required attributes present (`userName` for
User, `displayName` for Group); correct scalar types; well-formed multi-valued.

## AD / LDAP connector

`@kengela/adapter-directory-ldap` is the "pull" twin of the Graph/Google/SCIM connectors. It binds in
**LDAPS** (TLS verified by default), walks the directory via paginated search, and returns
**normalized** entries directly consumable by `profileFromLdap`. No role mapping here: the adapter
only **speaks LDAP**.

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

Hardened points (proven by test):

- **TLS verified by default** (`tlsRejectUnauthorized: true`); only disable it for a test directory.
- The bind password is **never logged** (this module logs nothing).
- `unbind()` is **guaranteed even on failure** (`finally` block).
- The `maxUsers` cap is enforced; `checkConnection` swallows the error without leaking the secret.
- Deactivation detected via `userAccountControl` (bit `ACCOUNTDISABLE` 0x2) → `accountActiveFromLdap`.

The client's **narrow** surface: `LdapClientLike` declares only `bind` / `search` / `unbind` (read-
only; no directory write). A real `Client` from `ldapts` satisfies it structurally, and so does an
in-memory fake (tests).

> **Debt (DEBT LDAP #5).** The adapter passes the `filter` through verbatim (no injection
> introduced), but does not yet expose an `escapeLdapFilterValue()` helper: an app that composed a
> filter from unescaped user input would remain exposed to LDAP filter injection on the caller's side.
