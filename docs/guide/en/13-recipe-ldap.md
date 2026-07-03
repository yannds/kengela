# Recipe 13 — Federating identities from an LDAP / Active Directory directory

> Goal: read the accounts and attributes of an **LDAP / Active Directory** directory (a "pull"
> directory source), project them onto Kengela's normalized `DirectoryProfile`, then map them
> onto the tenant's internal roles.

Every symbol below has been verified in the source code. The design points that might surprise
(two `DirectoryProfile` types, the adapter's lack of `fetchProfile`, the status of `ldapts`,
`sAMAccountName` not consumed) are **affirmed and explained** at the end of the page (§7 "Design
facts"), not left hanging.

---

## 1. What we are talking about

### The `DirectorySourcePort` port (contracts)

Kengela describes a directory source with a minimal port, in `@kengela/contracts`:

```ts
// @kengela/contracts
export interface DirectorySourcePort {
  fetchProfile(raw: unknown, tenantId: TenantId): Promise<DirectoryProfile>;
}
```

The `DirectoryProfile` **of the contracts port** is deliberately narrowed:

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

> CAUTION — there are **two** types named `DirectoryProfile` (see §7). The one from
> `@kengela/iam-mapping` (produced by `profileFromLdap`) does **not** have the same shape as the
> port's. Switching from one to the other is done by `toContractsProfile` (§3).

### `LdapDirectorySource` (the real adapter)

`@kengela/adapter-directory-ldap` provides the class **`LdapDirectorySource`** (real name). It
does **nothing but speak LDAP**:

- binds over LDAP(S) (`bind`), traverses the directory via **paged search** (Paged Results
  Control) under a `baseDN`, unbinds (`unbind` guaranteed even on failure);
- returns **normalized** `LdapEntryParts` entries (DN + attributes as strings, binaries such as
  `objectGUID` in base64);
- exposes a **health-check** (`checkConnection`);
- contains **no** role-mapping logic: the projection stays in the pure library
  `@kengela/iam-mapping`.

Real methods of the class:

| Member              | Real signature                                                                                     |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `fetchEntries`      | `fetchEntries(filter?: string, options?: FetchEntriesOptions): Promise<readonly LdapEntryParts[]>` |
| `checkConnection`   | `checkConnection(): Promise<boolean>`                                                              |
| `static toProfiles` | `toProfiles(entries, map?): readonly DirectoryProfile[]` _(iam-mapping profile)_                   |
| `static toRecords`  | `toRecords(entries, map?): readonly DirectoryRecord[]` _(profile + `active`)_                      |

> There is **no** `fetchProfile(raw, tenantId)` method on `LdapDirectorySource`: the class
> therefore does not directly implement `DirectorySourcePort` (see §3 and §7).

### The NARROW surface `LdapClientLike`

Repo doctrine: **the port is an airlock, not a hideout**. The adapter imports nothing from
`ldapts` into its contract; it describes exactly the 3 methods it uses (read-only, no directory
writes):

```ts
// @kengela/adapter-directory-ldap — surface étroite lue
export interface LdapClientLike {
  bind(dn: string, password: string): Promise<void>;
  search(baseDN: string, options: LdapSearchOptions): Promise<LdapSearchResult>;
  unbind(): Promise<void>;
}
export type LdapClientFactory = () => LdapClientLike;
```

The real `Client` of `ldapts` satisfies this interface **structurally**; so does an in-memory
fake (tests). Kengela therefore depends on `LdapClientLike`, not on the concrete `ldapts` type.

**Status of `ldapts` in the package** — verified in the adapter's `package.json`: `ldapts` is a
**direct dependency** (`"ldapts": "^8.1.8"` under `dependencies`), **NOT** a `peerDependency`
nor an `optionalDependency`. It is therefore installed transitively with the adapter; the
default client factory instantiates a real `new Client(...)` of `ldapts` with no additional
configuration.

---

## 2. Installation

```bash
npm install @kengela/adapter-directory-ldap
# ldapts est tiré automatiquement (dependency directe ^8.1.8) — aucune install séparée requise.
```

`@kengela/iam-mapping` (the pure mapping library) is also a dependency of the adapter, and the
adapter re-exports its useful symbols (`profileFromLdap`, `accountActiveFromLdap`, types) to
avoid a double dependency.

---

## 3. Wiring

### 3.1 Connection configuration (`LdapConnectionConfig`)

**Real** constructor options (extracted from `LdapConnectionConfig`):

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

The bounds/defaults live in `LDAP_SOURCE_DEFAULTS` (exported): `userFilter`, `attributes`,
`timeoutMs = 15000`, `pageSize = 200`, `maxUsers = 1000`, `tlsRejectUnauthorized = true`.

### 3.2 Instantiating the source (default `ldapts` client)

The second argument `LdapDirectorySourceOptions` lets you inject a client factory
(`clientFactory?: LdapClientFactory`). **Without** injection, the source builds a real `Client`
of `ldapts` itself (verified LDAPS) from the config — this is the nominal case:

```ts
const source = new LdapDirectorySource(config); // clientFactory par défaut = ldapts Client réel

// Health-check avant tout pull :
if (!(await source.checkConnection())) {
  throw new Error('Annuaire LDAP injoignable ou identifiants invalides');
}
```

### 3.3 Explicitly providing an `LdapClientLike` client (optional)

Useful for tests, a pool, or an alternative client. The factory returns something assignable to
`LdapClientLike`:

```ts
import { Client } from 'ldapts';
import type { LdapClientFactory } from '@kengela/adapter-directory-ldap';

const clientFactory: LdapClientFactory = () =>
  new Client({ url: config.url, timeout: 15_000, tlsOptions: { rejectUnauthorized: true } });

const source = new LdapDirectorySource(config, { clientFactory });
```

### 3.4 Exposing via `DirectorySourcePort`

`LdapDirectorySource` does **not** implement `DirectorySourcePort` as-is: the port expects
`fetchProfile(raw, tenantId)` returning the **contracts** `DirectoryProfile` (with `active`,
`source`), whereas the source exposes a **batch** API (`fetchEntries`) and helpers that produce
the **iam-mapping** `DirectoryProfile` (with `firstName`/`lastName`/`claims`). This is a
**design fact**, not a gap (§7).

The iam-mapping → contracts bridge is **not** written by hand: `@kengela/iam-mapping` exports
the PURE function **`toContractsProfile(rich, { source, active })`** which projects the rich
profile onto the minimal contracts shape (adding `active`/`source`, non-null `externalId`,
`firstName`/`lastName` folded into `attributes`, `claims` dropped). The port adapter then
reduces to three calls:

```ts
// profileFromLdap / accountActiveFromLdap : ré-exportés par l'adapter (SSoT iam-mapping).
import { profileFromLdap, accountActiveFromLdap } from '@kengela/adapter-directory-ldap';
import type { LdapEntryParts } from '@kengela/adapter-directory-ldap';
// toContractsProfile : depuis iam-mapping (l'adapter ne le ré-exporte pas).
import { toContractsProfile } from '@kengela/iam-mapping';
import type { DirectorySourcePort, DirectoryProfile, TenantId } from '@kengela/contracts';

class LdapDirectoryPort implements DirectorySourcePort {
  async fetchProfile(raw: unknown, _tenantId: TenantId): Promise<DirectoryProfile> {
    const entry = raw as LdapEntryParts; // le port reçoit une entrée normalisée
    const rich = profileFromLdap(entry); // DirectoryProfile "iam-mapping" (riche)
    return toContractsProfile(rich, { source: 'ldap', active: accountActiveFromLdap(entry) });
  }
}

export const ldapPort: DirectorySourcePort = new LdapDirectoryPort();
```

> `toContractsProfile` guarantees a non-null `externalId` (falls back to the email if
> `objectGUID` is missing), omits `email`/`displayName` when empty (`exactOptionalPropertyTypes`)
> and folds `firstName`/`lastName` into `attributes`. `active` and `source` are the two fields
> the rich profile does not carry; they are supplied explicitly here (`accountActiveFromLdap` +
> `'ldap'`). `toContractsProfile` is imported from `@kengela/iam-mapping` — the adapter re-exports
> `profileFromLdap`/`accountActiveFromLdap` but **not** `toContractsProfile`.

---

## 4. Fetching a profile, then mapping to roles

### 4.1 Pulling entries + projection

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

`fetchEntries(filter?, options?)` accepts an ad hoc LDAP `filter` and real `FetchEntriesOptions`:
`attributes?`, `max?`, `scope?` (`'base' | 'one' | 'sub'`, default `sub`), `attributeMap?`
(`LdapAttributeMap`, attached to each entry for the projection).

### 4.2 Attributes → profile (Active Directory defaults)

`profileFromLdap(e: LdapEntryParts)` reads the attributes via `LDAP_AD_ATTRIBUTE_DEFAULTS`,
overridable one by one per tenant via `e.attributeMap` (`LdapAttributeMap`). Real defaults:

| Profile field                       | Default AD attribute                                             |
| ----------------------------------- | ---------------------------------------------------------------- |
| `email`                             | `mail` (fallback `userPrincipalName`)                            |
| `firstName`                         | `givenName`                                                      |
| `lastName`                          | `sn`                                                             |
| `displayName`                       | `displayName` (fallbacks `cn`, then `givenName sn`)              |
| `externalId`                        | `objectGUID` (fallback: the DN)                                  |
| `groups`                            | `memberOf` (each DN reduced to its **CN**)                       |
| `department` / `division` / `title` | `department` / `division` / `title`                              |
| `employeeNumber`                    | `employeeNumber` (fallback `employeeID`)                         |
| `officeLocation`                    | `physicalDeliveryOfficeName`                                     |
| `manager`                           | `manager` (DN reduced to its **CN** — V2 debt: resolve to email) |
| `costCenter`                        | _(no AD default; empty string)_                                  |

`accountActiveFromLdap(e)` reads `userAccountControl`: bit `0x2` (ACCOUNTDISABLE) → disabled
account; attribute absent (OpenLDAP) → considered **active**.

### 4.3 Profile → internal roles (`evaluateMappings`)

The mapping engine is **pure** and **tenant-configurable** (`@kengela/iam-mapping`):

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

Conditions (`MappingCondition`): `source` = `'GROUP' | 'CLAIM' | 'ATTRIBUTE'`, `op` =
`'equals' | 'iequals' | 'contains' | 'matches' | 'in' | 'present'`. `matches` compiles a
**ReDoS-bounded** regex (fail-closed) via `safeRegexTest`. Deterministic evaluation: sorted by
(ascending priority, `id`), roles accumulated (union), `stopOnMatch` short-circuits.

> Note: `GROUP` rules test `profile.groups`, which for LDAP are the **CN**s extracted from the
> `memberOf` DNs. So use the group's CN (`"Groupe RH"`), not its full DN.

---

## 5. Active Directory case — specific notes

- **`memberOf`**: AD returns groups as **full DNs** (`CN=Groupe RH,OU=...,DC=corp`).
  `profileFromLdap` reduces each DN to its **CN**; it is that CN that feeds `profile.groups` and
  the rule engine. `memberOf` is requested explicitly by default (`attributes: ['*','memberOf']`).
- **`sAMAccountName`**: **not** in `LDAP_AD_ATTRIBUTE_DEFAULTS` and **not** consumed by
  `profileFromLdap` (no "login" field in `DirectoryProfile`). The email comes from `mail`, with
  a fallback to `userPrincipalName`. If your directory has no `mail`, make sure `UPN` is set, or
  override `email` via `LdapAttributeMap`. `sAMAccountName` nevertheless remains retrievable raw
  (via `attributes: ['sAMAccountName', ...]`) if your application code needs it.
- **Service Bind DN**: `bindDN` must be a full DN
  (`CN=svc-kengela,OU=Service,DC=corp,DC=local`) of a **read** account; `bindPassword` is
  resolved from a vault by the caller and is **never logged** (this module logs nothing).
- **Deprovisioning**: AD encodes deactivation in `userAccountControl` (bit `0x2`). Use
  `toRecords()` / `accountActiveFromLdap()` to propagate `active: false`.
- **`objectGUID`**: binary → normalized to **base64** by the adapter, and serves as a stable
  `externalId` (immutable identifier, unlike the DN which moves if the OU changes).
- **LDAPS**: `tlsRejectUnauthorized` is `true` by default; only set it to `false` against a test
  directory.

---

## 6. Sidebar — provided by Kengela vs to write

| ✅ Provided by Kengela                                                                                     | ✍️ To write on the application side                                                                                |
| ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `LdapDirectorySource`: bind + paged search + `unbind`, `LdapEntryParts` normalization                      | The concrete **bind config** (`LdapConnectionConfig`): URL, `bindDN`, password (vault), `baseDN`, filters          |
| Default factory of a `Client` `ldapts` (verified LDAPS)                                                    | An alternative **concrete LDAP client** (pool/fake), only if you do not use the default factory                    |
| `LdapClientLike` (narrow surface), `checkConnection`                                                       | The **`DirectorySourcePort`** adapter (reshape iam-mapping → contracts: `active`, `source`, non-null `externalId`) |
| `profileFromLdap`, `accountActiveFromLdap`, `LDAP_AD_ATTRIBUTE_DEFAULTS`, helpers `toProfiles`/`toRecords` | The per-tenant **attribute map** (`LdapAttributeMap`) if your schema is not standard AD                            |
| `evaluateMappings` engine (pure, anti-ReDoS) + rule types                                                  | The per-tenant **mapping rules** (`IdpMappingRule[]`) → role keys + org-chart units                                |
| Safe regexes (`safeRegexTest`, `SAFE_REGEX_LIMITS`)                                                        | The **persistence** (upsert users/roles), the pull orchestration and its scheduling                                |

---

## 7. Design facts (verified by reading, affirmed)

1. **Two distinct `DirectoryProfile` types — by design.** The one from `@kengela/iam-mapping`
   (return of `profileFromLdap` / `toProfiles`) is RICH: `{ email, externalId, firstName,
lastName, displayName, attributes, groups, claims }` (`email: string`, `externalId: string |
null`). The one from `@kengela/contracts` (return of the port) is MINIMAL and STABLE: `{ externalId:
string, email?, displayName?, groups, attributes, active, source }`. They **are not
   interchangeable**; the projection from one to the other is done by **`toContractsProfile`**
   (§3.4), a PURE function exported by `@kengela/iam-mapping`. So it is no longer "code to write":
   it is a library call.
2. **`LdapDirectorySource` does NOT implement `DirectorySourcePort` — an assumed design fact.**
   The class has no `fetchProfile(raw, tenantId)` method: its API is **batch**
   (`fetchEntries(filter?, options?)` + `checkConnection()`) with the static helpers
   `toProfiles` / `toRecords`. An LDAP pull reads **thousands** of entries in a single paged
   search (bind → search → unbind); exposing a per-user `fetchProfile` would force one bind per
   user, contrary to LDAP's "batch" nature. The port adapter (§3.4) bridges
   `LdapEntryParts → contracts`: the port types `raw: unknown`, and for this source `raw` is an
   `LdapEntryParts` (a normalized entry already produced by `fetchEntries`).
3. **`ldapts` = DIRECT dependency, not peer nor optional.** Verified in the adapter's
   `package.json`: `"ldapts": "^8.1.8"` under `dependencies`. No separate install required; the
   default factory instantiates a real `new Client(...)` with no additional configuration.
4. **`sAMAccountName` is NOT consumed by `profileFromLdap`.** Verified: it is not in
   `LDAP_AD_ATTRIBUTE_DEFAULTS` (whose real keys are `mail`, `givenName`, `sn`,
   `displayName`, `objectGUID`, `memberOf`, `department`, `division`, `title`, `employeeNumber`,
   `physicalDeliveryOfficeName`, `manager`; `costCenter` = empty string). There is no "login"
   field in `DirectoryProfile`: the email comes from `mail` (fallback `userPrincipalName`). If
   your application code needs it, `sAMAccountName` remains retrievable **raw** by requesting it
   (`attributes: ['sAMAccountName', ...]`), but it populates no profile field.
5. **`safe-regex.ts` — exported symbols.** `safeRegexTest`, `compileSafeRegex`,
   `SAFE_REGEX_LIMITS`, `SafeRegexLimits`. `matches` compiles a bounded regex (fail-closed); the
   exact bounds live in `SAFE_REGEX_LIMITS`.
6. **`manager` as V2 debt.** `profileFromLdap` reduces the manager's DN to its CN for lack of a
   second LDAP call; it is not resolved to an email (documented as-is in the source).

---

## Complete example (copy-paste)

A single file that assembles all the functional code of the page: bind configuration,
health-check, paged pull, projection onto `DirectoryProfile`, mapping to roles, the
`DirectorySourcePort` adapter (via `toContractsProfile`) and the orchestration of a
`ScimRepository` sync.

```ts
import {
  LdapDirectorySource,
  profileFromLdap,
  accountActiveFromLdap,
  type LdapConnectionConfig,
  type LdapEntryParts,
} from '@kengela/adapter-directory-ldap';
import { evaluateMappings, toContractsProfile, type IdpMappingRule } from '@kengela/iam-mapping';
import type {
  DirectorySourcePort,
  DirectoryProfile,
  ScimRepository,
  TenantId,
} from '@kengela/contracts';

// ── 1. Configuration de bind (résolue depuis la config tenant + coffre) ─────
const config: LdapConnectionConfig = {
  url: 'ldaps://dc.corp.local:636', // LDAPS recommandé
  bindDN: 'CN=svc-kengela,OU=Service,DC=corp,DC=local', // compte de lecture
  bindPassword: process.env.LDAP_BIND_PASSWORD!, // coffre ; jamais loggé
  baseDN: 'OU=Users,DC=corp,DC=local',
  // Optionnels (sinon défauts AD via LDAP_SOURCE_DEFAULTS) :
  userFilter: '(&(objectCategory=person)(objectClass=user))',
  attributes: ['*', 'memberOf'],
  timeoutMs: 15_000,
  tlsRejectUnauthorized: true,
  pageSize: 200,
  maxUsers: 1000,
};

// clientFactory par défaut = vrai Client ldapts (LDAPS vérifié) construit depuis la config.
const source = new LdapDirectorySource(config);

// ── 2. Règles de mapping (par tenant) ───────────────────────────────────────
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

// ── 3. Adaptateur DirectorySourcePort (reshape via toContractsProfile) ──────
class LdapDirectoryPort implements DirectorySourcePort {
  async fetchProfile(raw: unknown, _tenantId: TenantId): Promise<DirectoryProfile> {
    const entry = raw as LdapEntryParts; // une entrée normalisée produite par fetchEntries
    const rich = profileFromLdap(entry); // DirectoryProfile riche (iam-mapping)
    return toContractsProfile(rich, { source: 'ldap', active: accountActiveFromLdap(entry) });
  }
}
export const ldapPort: DirectorySourcePort = new LdapDirectoryPort();

// ── 4. Orchestration d'un pull complet ──────────────────────────────────────
export async function syncLdap(
  tenantId: TenantId,
  scimRepository: ScimRepository,
): Promise<{ synced: number; deactivated: number }> {
  // (a) Health-check avant tout pull.
  if (!(await source.checkConnection())) {
    throw new Error('Annuaire LDAP injoignable ou identifiants invalides');
  }

  // (b) Lecture réseau : bind → search paginé → normalisation → unbind.
  const entries = await source.fetchEntries(); // readonly LdapEntryParts[]

  // (c) Projection + activation en une passe (dé-provisioning).
  const records = LdapDirectorySource.toRecords(entries); // { profile, active }[]

  let synced = 0;
  let deactivated = 0;
  for (let i = 0; i < entries.length; i += 1) {
    const rich = records[i].profile; // DirectoryProfile riche
    const active = records[i].active; // userAccountControl bit 0x2

    // (d) Mapping vers les rôles internes (moteur pur, configurable par tenant).
    const result = evaluateMappings(rich, rules);
    // → result.roleKeys / result.orgUnitDirectives / result.matchedRuleIds

    // (e) Réconciliation : projection RICHE → MINIMAL (contracts), puis upsert.
    const profile = toContractsProfile(rich, { source: 'ldap', active });
    const { id } = await scimRepository.upsertUserByEmail(tenantId, profile);
    synced += 1;

    if (!active) {
      await scimRepository.deactivateUser(tenantId, id);
      deactivated += 1;
    }

    // … appliquer result.roleKeys + result.orgUnitDirectives via vos repos (grants + rattachement).
    void result;
  }

  return { synced, deactivated };
}
```
