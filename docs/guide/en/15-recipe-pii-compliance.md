# Recipe 15 - End-to-end GDPR compliance (PII)

> Kengela, TypeScript / ESM. Classify PII, encrypt sensitive fields at-rest
> (per tenant), erase by crypto-shredding, minimize/redact, apply retention and
> log every access to personal data.

## 1. The 5 building blocks and their ports

GDPR compliance in Kengela rests on five independent, composable building blocks.
Each one relies on a port defined in `@kengela/contracts`, or on a pure function from
the `@kengela/pii` package.

| #    | Block                    | What it solves (GDPR)                              | Real symbol                                                                             | Package                                                                 |
| ---- | ------------------------ | -------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| 1    | Classification           | Know which field is PII (art. 5, art. 30)          | `classify` / `isPii` / `PII_FIELDS`                                                     | `@kengela/pii`                                                          |
| 2    | Field encryption at-rest | At-rest protection, per-tenant isolation (art. 32) | `FieldCipherPort` ← `AesGcmFieldCipher` + `AesGcmKeyManagement` (+ `KeyManagementPort`) | `@kengela/contracts` / `@kengela/adapter-authn-native`                  |
| 2bis | Per-subject encryption   | Basis of crypto-shredding (per-person key)         | `SubjectFieldCipher` + `SubjectKeyStore` ← `PrismaSubjectKeyStore`                      | `@kengela/adapter-authn-native` / `@kengela/adapter-persistence-prisma` |
| 3    | Crypto-shredding         | Right to erasure (art. 17)                         | `ErasurePort` ← `SubjectCryptoShredder`                                                 | `@kengela/contracts` / `@kengela/adapter-authn-native`                  |
| 4    | Minimization / redaction | Minimization (art. 5.1.c), no plaintext in logs    | `minimizeProfile` / `redactProfile`                                                     | `@kengela/pii`                                                          |
| 5    | Retention                | Storage limitation (art. 5.1.e)                    | `retentionExpired` / `DEFAULT_RETENTION`                                                | `@kengela/pii`                                                          |
| -    | Access log               | Auditability of PII access (art. 30)               | `PiiAccessLogSink` ← `PrismaPiiAccessLogSink`                                           | `@kengela/contracts` / `@kengela/adapter-persistence-prisma`            |

Blocks 1, 4 and 5 are **pure functions** (no I/O, trivially unit-testable). Blocks 2,
2bis, 3 and the access log are **ports**: the core depends only on the interface, the
adapter (native AES-GCM or another) is injected at wiring time.

The example subject for the whole recipe: a `DirectoryProfile` user profile
(`@kengela/iam-mapping` package), as returned by the IdP at login / SCIM sync.

```ts
import type { DirectoryProfile } from '@kengela/iam-mapping';

const profile: DirectoryProfile = {
  email: 'awa.diallo@example.com',
  externalId: 'okta|00u1a2b3c',
  firstName: 'Awa',
  lastName: 'Diallo',
  displayName: 'Awa Diallo',
  attributes: {
    phoneNumber: '+221771234567',
    city: 'Dakar',
    country: 'SN',
    department: 'Operations', // rattachement org, PAS une PII
    title: 'Dispatcher', // idem
    employeeNumber: 'EMP-0042', // identifiant indirect => PII
  },
  groups: ['dispatchers'],
  claims: { roles: ['dispatcher'] },
};
```

Shape reminder (`@kengela/iam-mapping/src/profile.ts`): `email` is a non-nullable
`string`; `firstName` / `lastName` / `displayName` / `externalId` are `string | null`;
`attributes` is a `Record`, `claims` a `Record` of raw claims.

---

## 2. Classification - which fields are PII

The registry is defined in `@kengela/pii/src/classification.ts`. Three sensitivity
levels:

```ts
export type PiiSensitivity = 'none' | 'pii' | 'sensitive';
```

- `none`: non-personal (technical identifier, organizational attachment).
- `pii`: personal data (direct or indirect identifiability).
- `sensitive`: special category (art. 9 - health, biometrics). Reserved for extension;
  **no field** of the standard directory is classified `sensitive` today.

Three exported symbols (real signatures):

```ts
export function classify(field: string): PiiSensitivity; // défaut 'none' si inconnu
export function isPii(field: string): boolean; // classify(field) !== 'none'
export const PII_FIELDS: readonly string[]; // liste des champs != 'none'
```

Applied to the example profile:

```ts
import { classify, isPii, PII_FIELDS } from '@kengela/pii';

classify('email'); // 'pii'
classify('phoneNumber'); // 'pii'
classify('employeeNumber'); // 'pii'  (identifiant indirect d'une personne)
classify('manager'); // 'pii'
classify('department'); // 'none' (rattachement org)
classify('title'); // 'none'
classify('costCenter'); // 'none'
classify('inconnu'); // 'none' (défaut prudent : inconnu => non personnel)

isPii('city'); // true
isPii('preferredLanguage'); // false

// Balayage d'un profil : ne garder que les clés d'attributs qui sont des PII.
const piiKeys = Object.keys(profile.attributes).filter(isPii);
// => ['phoneNumber', 'city', 'country', 'employeeNumber']

PII_FIELDS;
// => ['email','firstName','lastName','displayName','phoneNumber','mobilePhone',
//     'streetAddress','city','state','postalCode','country','employeeNumber','manager']
```

Fields classified `pii` in the registry: `email`, `firstName`, `lastName`,
`displayName`, `phoneNumber`, `mobilePhone`, `streetAddress`, `city`, `state`,
`postalCode`, `country`, `employeeNumber`, `manager`.

Fields classified `none` (attachment / preferences, non-personal): `externalId`,
`department`, `division`, `title`, `organization`, `companyName`, `costCenter`,
`officeLocation`, `employeeType`, `preferredLanguage`, `locale`, `timezone`.

> Point of vigilance: `employeeNumber` and `manager` are **PII** (indirect
> identifiability), whereas `title` or `department` are not. Never guess "by hand" -
> going through `classify` / `isPii` remains the single source of truth.

`classify` is the entry key for the retention (§6) and access log (§7) blocks: the
registry says which fields must be encrypted, purged and traced.

---

## 3. Per-tenant at-rest encryption

### Ports

```ts
// @kengela/contracts
export interface KeyManagementPort {
  encrypt(tenantId: TenantId, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(tenantId: TenantId, ciphertext: Uint8Array): Promise<Uint8Array>;
}

export interface FieldCipherPort {
  encryptField(tenantId: TenantId, plaintext: string): Promise<string>;
  decryptField(tenantId: TenantId, ciphertext: string): Promise<string>;
}
```

`TenantId` is a plain `type TenantId = string`.

### Native adapters (AES-256-GCM)

`AesGcmKeyManagement` (`@kengela/adapter-authn-native`) implements `KeyManagementPort`
with **envelope encryption**: a per-tenant key is derived from the master key via
**HKDF-SHA256**, in a **configurable context (`info`)**: `info = <context>:<tenantId>`.
Per-tenant derivation guarantees cross-tenant cryptographic isolation; the context
guarantees **domain separation per usage**. Ciphertext format: `iv(12) || tag(16) || ciphertext`.

The constructor's second argument is `{ context?: string }` - default **`kengela:mfa`**
(backward-compatible: it's the historical context of the at-rest MFA secret). For **PII
field** encryption, derive in a **distinct** context so that a given tenant's "PII field"
key and "MFA secret" key are **never interchangeable**:

```ts
import { AesGcmKeyManagement, AesGcmFieldCipher } from '@kengela/adapter-authn-native';

// masterKey : Uint8Array >= 32 octets (sinon le constructeur throw).
// À charger depuis le coffre (SecretsPort / Vault), JAMAIS en dur.
// Contexte DÉDIÉ aux champs PII : sépare cryptographiquement cet usage du MFA (kengela:mfa).
const keyMgmt = new AesGcmKeyManagement(masterKey, { context: 'kengela:pii-field' });
const fieldCipher = new AesGcmFieldCipher(keyMgmt); // FieldCipherPort

const tenantId = 'tenant-flixbus-sn';

// Chiffrer un champ PII pour stockage (colonne texte base64) :
const encPhone = await fieldCipher.encryptField(tenantId, profile.attributes.phoneNumber as string);
// -> 'k7Qy...=='  (base64 stockable)

// Relire :
const phone = await fieldCipher.decryptField(tenantId, encPhone);
// -> '+221771234567'
```

`AesGcmFieldCipher` simply encodes the plaintext to UTF-8 then delegates to the
`KeyManagementPort`, and returns/reads back **base64** (fit for a text column).

Recommended persistence pattern: encrypt **each PII field** before writing, relying on
`isPii` to know which ones.

```ts
async function encryptPiiAttributes(
  cipher: FieldCipherPort,
  tenantId: TenantId,
  attributes: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(attributes)) {
    out[key] =
      isPii(key) && typeof value === 'string' ? await cipher.encryptField(tenantId, value) : value; // les champs 'none' restent en clair (requêtables)
  }
  return out;
}
```

### Where to wire `SubjectKeyStore`

The **per-tenant** encryption above protects at-rest and isolates tenants, but the key
is shared across the whole tenant: you can't "erase" a single individual by throwing away
the key. For per-person erasure (§4), you need a **per-subject** key via `SubjectKeyStore`

- `SubjectFieldCipher`.

```ts
// @kengela/contracts
export interface SubjectKeyStore {
  getOrCreateKey(tenantId: TenantId, subjectId: string): Promise<Uint8Array>;
  getKey(tenantId: TenantId, subjectId: string): Promise<Uint8Array | null>;
  deleteKey(tenantId: TenantId, subjectId: string): Promise<void>;
}
```

A **persistent store is provided**: `PrismaSubjectKeyStore`
(`@kengela/adapter-persistence-prisma`) implements `SubjectKeyStore` on a dedicated Prisma
table (one row per subject, `key` column). Its constructor takes the Prisma delegate of
the table plus `{ keyManagement?, keyBytes? }` options:

- **`keyManagement`** - if a `KeyManagementPort` (e.g. `AesGcmKeyManagement`, per-tenant
  envelope encryption) is injected, the subject key is **wrapped** before persistence: the
  column never holds plaintext key material. A leak of the database alone reveals nothing
  without the master key. **Absent = plaintext base64 storage**: degraded mode, reserve it
  for development (crypto-shredding stays effective either way, since it relies on
  **deleting** the row, not on encryption).
- **`keyBytes`** - size of the generated key, in bytes. Default **32** (AES-256).

```ts
import { PrismaSubjectKeyStore } from '@kengela/adapter-persistence-prisma';

// `prisma.subjectKey` est le délégué Prisma de ta table (findFirst/create/deleteMany).
// keyManagement (recommandé) : la clé de sujet est chiffrée-at-rest par tenant.
const subjectKeyStore = new PrismaSubjectKeyStore(prisma.subjectKey, {
  keyManagement: keyMgmt, // AesGcmKeyManagement du §3 - wrappe la clé de sujet at-rest
});
```

`SubjectFieldCipher` (`@kengela/adapter-authn-native`) encrypts a field with the subject
key (resolved via `getOrCreateKey`) and decrypts via `getKey` - **returning `null` if the
key has been destroyed**. Base64 format: `iv(12) || tag(16) || ciphertext`.

```ts
import { SubjectFieldCipher } from '@kengela/adapter-authn-native';

const subjectCipher = new SubjectFieldCipher(subjectKeyStore); // SubjectKeyStore injecté
const subjectId = profile.externalId!; // clé stable de la personne concernée

const encEmail = await subjectCipher.encryptFor(tenantId, subjectId, profile.email);
const email = await subjectCipher.decryptFor(tenantId, subjectId, encEmail);
// email === 'awa.diallo@example.com'  (tant que la clé du sujet existe)
```

> Design choice: **per-tenant** encryption (`AesGcmFieldCipher`) for general at-rest
> protection + isolation; **per-subject** encryption (`SubjectFieldCipher`) for any field
> that must be individually crypto-shreddable. The two coexist.

---

## 4. Crypto-shredding - right to erasure (art. 17)

Erasing a person doesn't mean sweeping every table to overwrite their rows. You
**destroy their key**: all their PII encrypted with `SubjectFieldCipher` then become
permanently unreadable.

`SubjectCryptoShredder` (`@kengela/adapter-authn-native`) implements `ErasurePort`:

```ts
// @kengela/contracts
export interface ErasurePort {
  eraseSubject(tenantId: TenantId, subjectId: string): Promise<void>;
}
```

Real implementation (one line: delegate to the store):

```ts
export class SubjectCryptoShredder implements ErasurePort {
  eraseSubject(tenantId: TenantId, subjectId: string): Promise<void> {
    return this.#keys.deleteKey(tenantId, subjectId);
  }
}
```

Call and effect:

```ts
import { SubjectCryptoShredder } from '@kengela/adapter-authn-native';

const shredder = new SubjectCryptoShredder(subjectKeyStore); // ErasurePort

// L'utilisateur exerce son droit à l'effacement :
await shredder.eraseSubject(tenantId, subjectId);

// Effet immédiat : la clé n'existe plus, toute tentative de lecture rend null.
const email = await subjectCipher.decryptFor(tenantId, subjectId, encEmail);
// email === null   <-- donnée « shreddée », irrécupérable, sans réécrire les tables
```

Benefits: O(1) erasure (a single key), proof of irreversibility (the AES key is gone),
and no race with encrypted replicas/backups - a restored backup stays unreadable since it
never contains the key.

> Constraint: only **per-subject** encrypted fields are covered by shredding. A field
> encrypted per tenant (or in plaintext) survives `eraseSubject`. Decide at modeling time
> which fields belong to the subject.

---

## 5. Minimization / redaction

Two pure functions from `@kengela/pii`, two distinct purposes.

### `minimizeProfile` - export / restricted use (art. 5.1.c)

Keeps ONLY the attributes explicitly allowed for the purpose. Raw `claims` are emptied,
disallowed identity fields are set to `null`.

```ts
export function minimizeProfile(
  profile: DirectoryProfile,
  allowedFields: readonly string[],
): DirectoryProfile;
```

```ts
import { minimizeProfile } from '@kengela/pii';

// Une app « dispatch » n'a besoin que du nom d'affichage et du département.
const minimal = minimizeProfile(profile, ['displayName', 'department']);
```

Before → after:

```jsonc
// AVANT (profil complet)
{ "email": "awa.diallo@example.com", "firstName": "Awa", "lastName": "Diallo",
  "displayName": "Awa Diallo",
  "attributes": { "phoneNumber": "+221771234567", "city": "Dakar",
                  "country": "SN", "department": "Operations", ... },
  "claims": { "roles": ["dispatcher"] } }

// APRÈS minimizeProfile(profile, ['displayName','department'])
{ "email": "awa.diallo@example.com",   // email et externalId toujours conservés
  "externalId": "okta|00u1a2b3c",
  "firstName": null, "lastName": null,  // non autorisés => neutralisés
  "displayName": "Awa Diallo",          // autorisé
  "attributes": { "department": "Operations" }, // seul attribut autorisé
  "groups": ["dispatchers"],
  "claims": {} }                        // claims bruts toujours vidés
```

**Asserted** real behavior (verified in `@kengela/pii/src/minimize.ts`): `email`,
`externalId` and `groups` are **always** kept, regardless of `allowedFields`. Only
`firstName` / `lastName` / `displayName` (set to `null` if not allowed) and the
`attributes` (filtered: only allowed **and** defined keys remain) respond to
`allowedFields`; `claims` is **systematically** emptied to `{}`.

> Practical warning: `minimizeProfile` is **not** a way to hide the email or the external
> identifier. `email`, `externalId` and `groups` **always** pass through, even absent from
> `allowedFields`. If your purpose requires removing them (anonymized export, third party
> that mustn't know the email), do it **explicitly after** the call - don't rely on
> `allowedFields` for that. For display/logging, `redactProfile` does mask the email.

### `redactProfile` - logs / display (no plaintext exposure)

Masks identity and any attribute classified `pii`; leaves `none` fields intact.

```ts
export function redactProfile(profile: DirectoryProfile): DirectoryProfile;
```

```ts
import { redactProfile } from '@kengela/pii';
logger.info({ user: redactProfile(profile) }, 'profil chargé');
```

Before → after:

```jsonc
// APRÈS redactProfile(profile)
{
  "email": "a***@example.com", // maskEmail : 1re lettre + domaine
  "firstName": "A***",
  "lastName": "D***",
  "displayName": "A***",
  "attributes": {
    "phoneNumber": "+***", // isPii('phoneNumber') => masqué (1er char + ***)
    "city": "D***", // isPii('city') => masqué
    "country": "S***", // isPii('country') => masqué
    "department": "Operations", // 'none' => inchangé
    "title": "Dispatcher", // 'none' => inchangé
    "employeeNumber": "E***", // 'pii' => masqué
  },
}
```

Real masking rules: email → `<1st letter>***<@domain>` (or `***` if no `@`); any other
`string` value → `<1st letter>***` (or `***` if length ≤ 1). Attribute masking applies
only to `string`-typed values classified `pii`.

> Never log a raw `DirectoryProfile`. Always `redactProfile` first. For an export produced
> to an app or a third party, `minimizeProfile` first.

---

## 6. Retention - deciding a record must be purged (art. 5.1.e)

```ts
export type RetentionPolicy = Readonly<Record<PiiSensitivity, number | null>>;

// Défaut prudent : PII 2 ans, sensible 6 mois, non-personnel illimité.
export const DEFAULT_RETENTION: RetentionPolicy = {
  none: null, // pas de limite
  pii: 730 * 24 * 60 * 60 * 1000, // ~2 ans en ms
  sensitive: 182 * 24 * 60 * 60 * 1000, // ~6 mois en ms
};

export function retentionExpired(
  sensitivity: PiiSensitivity,
  ageMs: number,
  policy?: RetentionPolicy, // défaut DEFAULT_RETENTION
): boolean;
```

`retentionExpired` returns `false` if the limit is `null` (indefinite retention),
otherwise `ageMs > limit`. Combine it with `classify` to decide field by field, or at the
record level.

```ts
import { classify, retentionExpired, DEFAULT_RETENTION } from '@kengela/pii';

const ageMs = Date.now() - record.lastActivityAt; // ancienneté de l'enregistrement

// Décision au niveau d'un champ (ex. téléphone) :
retentionExpired(classify('phoneNumber'), ageMs); // classify => 'pii'
// true si la donnée a plus de 2 ans => à purger

retentionExpired(classify('department'), ageMs); // 'none' => toujours false

// Politique custom par app (durées plus courtes) :
const strict: RetentionPolicy = { ...DEFAULT_RETENTION, pii: 90 * 864e5 };
retentionExpired('pii', ageMs, strict);

// Un enregistrement doit être purgé dès qu'un de ses champs PII a expiré :
const mustPurge = Object.keys(record.attributes).some((field) =>
  retentionExpired(classify(field), ageMs),
);
if (mustPurge) {
  await shredder.eraseSubject(tenantId, record.subjectId); // §4 : crypto-shredding
}
```

> Natural combination: retention **decides** (pure function, in a cron/job) and
> crypto-shredding **executes** the erasure. The trigger (cron, purge job) is to be
> written on the app side (see §8).

---

## 7. PII access log (art. 30, auditability)

```ts
// @kengela/contracts
export interface PiiAccessLogSink {
  record(entry: {
    readonly tenantId: TenantId;
    readonly subjectId: string; // personne concernée
    readonly actorId?: UserId; // acteur (absent = système)
    readonly fields: readonly string[];
    readonly purpose: string; // finalité du traitement
    readonly at: number; // timestamp epoch ms
  }): Promise<void> | void;
}
```

A **persistent sink is provided**: `PrismaPiiAccessLogSink`
(`@kengela/adapter-persistence-prisma`) implements `PiiAccessLogSink` by inserting one
audit row per access (GDPR art. 30). Its constructor takes the Prisma delegate of the log
table; an absent `actorId` is stored as `null` (system access), and `at` (epoch ms) is
converted to a `Date`.

```ts
import { PrismaPiiAccessLogSink } from '@kengela/adapter-persistence-prisma';

// `prisma.piiAccessLog` est le délégué Prisma de ta table d'audit (create).
const audit = new PrismaPiiAccessLogSink(prisma.piiAccessLog); // PiiAccessLogSink
```

On **every PII read/export**, log: who (`actorId`), which subject (`subjectId`), which
fields (`fields`), for what purpose (`purpose`), and when (`at`). Log **only field names**,
never their values.

```ts
async function readProfileForActor(
  cipher: FieldCipherPort,
  audit: PiiAccessLogSink,
  tenantId: TenantId,
  actorId: UserId,
  stored: StoredProfile,
): Promise<DirectoryProfile> {
  const decrypted = await decryptPiiAttributes(cipher, tenantId, stored.attributes);

  // Tracer l'accès : uniquement les champs PII effectivement lus.
  await audit.record({
    tenantId,
    subjectId: stored.subjectId,
    actorId,
    fields: Object.keys(decrypted.attributes).filter(isPii),
    purpose: 'dispatch.profile.read',
    at: Date.now(),
  });

  return decrypted;
}
```

Key points:

- Emit the entry **after** a successful decryption (no access log for a read that failed
  to `null` after shredding - or else with a distinct purpose).
- `actorId` omitted for a purely system access (batch, sync).
- Use `redactProfile` if the log also captures a preview - never a plaintext PII value in
  the sink.

---

## Full example (copy-paste)

A single module assembling all the functional code of the recipe: wiring (per-tenant field
encryption in a **dedicated** HKDF context, per-subject key store **wrapped at-rest**,
crypto-shredder, access log), then the write / traced-read / erasure / retention-purge
paths, and minimization / redaction. The `prisma.*` are **your** Prisma delegates (tables
to define, see §8); `masterKey` comes from the vault.

```ts
import type { DirectoryProfile } from '@kengela/iam-mapping';
import type { FieldCipherPort, PiiAccessLogSink, TenantId, UserId } from '@kengela/contracts';
import {
  classify,
  isPii,
  minimizeProfile,
  redactProfile,
  retentionExpired,
  DEFAULT_RETENTION,
  type RetentionPolicy,
} from '@kengela/pii';
import {
  AesGcmKeyManagement,
  AesGcmFieldCipher,
  SubjectFieldCipher,
  SubjectCryptoShredder,
} from '@kengela/adapter-authn-native';
import { PrismaSubjectKeyStore, PrismaPiiAccessLogSink } from '@kengela/adapter-persistence-prisma';

// ── Câblage (composition root) ───────────────────────────────────────────────
// `prisma` : tes délégués (prisma.subjectKey, prisma.piiAccessLog).
// `masterKey` : Uint8Array >= 32 octets, chargé du coffre (SecretsPort / Vault).
export function wirePii(
  prisma: {
    readonly subjectKey: ConstructorParameters<typeof PrismaSubjectKeyStore>[0];
    readonly piiAccessLog: ConstructorParameters<typeof PrismaPiiAccessLogSink>[0];
  },
  masterKey: Uint8Array,
) {
  // Chiffrement par tenant, dans un contexte HKDF DÉDIÉ aux champs PII (≠ kengela:mfa).
  const keyMgmt = new AesGcmKeyManagement(masterKey, { context: 'kengela:pii-field' });
  const fieldCipher: FieldCipherPort = new AesGcmFieldCipher(keyMgmt);

  // Clé PAR SUJET, wrappée at-rest par le même KMS (jamais de clair en base).
  const subjectKeyStore = new PrismaSubjectKeyStore(prisma.subjectKey, {
    keyManagement: keyMgmt,
  });
  const subjectCipher = new SubjectFieldCipher(subjectKeyStore);
  const shredder = new SubjectCryptoShredder(subjectKeyStore); // ErasurePort
  const audit: PiiAccessLogSink = new PrismaPiiAccessLogSink(prisma.piiAccessLog);

  return { fieldCipher, subjectCipher, shredder, audit };
}

// ── Écriture : chiffrer chaque attribut PII (les champs 'none' restent requêtables) ──
export async function encryptPiiAttributes(
  cipher: FieldCipherPort,
  tenantId: TenantId,
  attributes: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(attributes)) {
    out[key] =
      isPii(key) && typeof value === 'string' ? await cipher.encryptField(tenantId, value) : value;
  }
  return out;
}

async function decryptPiiAttributes(
  cipher: FieldCipherPort,
  tenantId: TenantId,
  attributes: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(attributes)) {
    out[key] =
      isPii(key) && typeof value === 'string' ? await cipher.decryptField(tenantId, value) : value;
  }
  return out;
}

interface StoredProfile {
  readonly subjectId: string;
  readonly attributes: Record<string, unknown>;
}

// ── Lecture TRACÉE : déchiffrer puis journaliser (art. 30) - jamais de valeur en clair ──
export async function readProfileForActor(
  cipher: FieldCipherPort,
  audit: PiiAccessLogSink,
  tenantId: TenantId,
  actorId: UserId,
  stored: StoredProfile,
): Promise<Record<string, unknown>> {
  const decrypted = await decryptPiiAttributes(cipher, tenantId, stored.attributes);
  await audit.record({
    tenantId,
    subjectId: stored.subjectId,
    actorId,
    fields: Object.keys(decrypted).filter(isPii), // uniquement les NOMS de champs PII
    purpose: 'dispatch.profile.read',
    at: Date.now(),
  });
  return decrypted;
}

// ── Effacement (art. 17) : détruire la clé du sujet rend ses PII illisibles à jamais ──
export async function eraseSubject(
  shredder: SubjectCryptoShredder,
  tenantId: TenantId,
  subjectId: string,
): Promise<void> {
  await shredder.eraseSubject(tenantId, subjectId);
}

// ── Rétention (art. 5.1.e) : décider champ par champ, puis crypto-shredder si expiré ──
export async function purgeIfExpired(
  shredder: SubjectCryptoShredder,
  tenantId: TenantId,
  record: StoredProfile & { readonly lastActivityAt: number },
  policy: RetentionPolicy = DEFAULT_RETENTION,
): Promise<boolean> {
  const ageMs = Date.now() - record.lastActivityAt;
  const mustPurge = Object.keys(record.attributes).some((field) =>
    retentionExpired(classify(field), ageMs, policy),
  );
  if (mustPurge) {
    await shredder.eraseSubject(tenantId, record.subjectId);
  }
  return mustPurge;
}

// ── Minimisation (export/tiers) et redaction (journaux/affichage) ─────────────
export function forExport(profile: DirectoryProfile, allowed: readonly string[]): DirectoryProfile {
  // Rappel : email / externalId / groups passent TOUJOURS (voir §5) - retire-les à part si besoin.
  return minimizeProfile(profile, allowed);
}

export function forLogs(profile: DirectoryProfile): DirectoryProfile {
  return redactProfile(profile); // email masqué, attributs 'pii' masqués, 'none' intacts
}
```

---

## 8. Provided vs. to be written

### Provided (ready to use, real symbols)

- **Classification** - `classify`, `isPii`, `PII_FIELDS`, `PiiSensitivity`
  (`@kengela/pii`). Full identity + contact + org registry.
- **Per-tenant at-rest encryption** - `AesGcmKeyManagement` (per-tenant HKDF-SHA256,
  `KeyManagementPort`) + `AesGcmFieldCipher` (`FieldCipherPort`, base64)
  (`@kengela/adapter-authn-native`).
- **Per-subject encryption** - `SubjectFieldCipher` (`encryptFor` / `decryptFor` →
  `null` if key destroyed).
- **Persistent `SubjectKeyStore` (Prisma)** - `PrismaSubjectKeyStore`
  (`@kengela/adapter-persistence-prisma`), options `{ keyManagement?, keyBytes? }`: subject
  key **wrapped at-rest** if a `KeyManagementPort` is injected, idempotent `getOrCreateKey`,
  genuinely destructive `deleteKey`.
- **Persistent `PiiAccessLogSink` (Prisma)** - `PrismaPiiAccessLogSink`
  (`@kengela/adapter-persistence-prisma`): one audit row per access.
- **Crypto-shredding** - `SubjectCryptoShredder` (`ErasurePort.eraseSubject`).
- **Minimization / redaction** - `minimizeProfile`, `redactProfile` (`@kengela/pii`).
- **Retention** - `retentionExpired`, `DEFAULT_RETENTION`, `RetentionPolicy`
  (`@kengela/pii`).
- **Port contracts** - `FieldCipherPort`, `KeyManagementPort`, `SubjectKeyStore`,
  `ErasurePort`, `PiiAccessLogSink` (`@kengela/contracts`).

### To be written on the application side (not provided)

- **Prisma schema + migration** - `PrismaSubjectKeyStore` and `PrismaPiiAccessLogSink` are
  provided, but **the Prisma table** (model `SubjectKey` with a unique key
  `(tenantId, subjectId)` + `key` column, audit model `PiiAccessLog`) and its migration are
  to be defined in **your** `schema.prisma`. Inject a `KeyManagementPort` into
  `PrismaSubjectKeyStore` (option `keyManagement`) so the key is never stored in plaintext;
  destructive propagation to replicas/backups remains an operations choice (expiration).
- **Purge triggers** - cron/job that walks the records, computes the age, applies
  `retentionExpired(classify(field), ageMs)` then calls `ErasurePort.eraseSubject`. The
  decision is provided (pure function), the scheduling is not.
- **ORM / persistence wiring** - plug `encryptField` / `decryptField` (or
  `SubjectFieldCipher`) into the read/write hooks (Prisma middleware / repos), decide column
  by column "plaintext vs tenant-encrypted vs subject-encrypted" from `classify`, and invoke
  `PiiAccessLogSink.record` on every PII read path.
- **Loading the master key / policies** - `AesGcmKeyManagement`'s `masterKey` comes from the
  vault (`SecretsPort` / Vault); `RetentionPolicy` durations are a per-app business choice.
  Nothing is hardcoded.

> Invariant: the core only knows the **ports** (`@kengela/contracts`) and the **pure
> functions** (`@kengela/pii`). Everything that touches disk (keys, log, ORM, cron) is an
> application adapter - that's where the work to be written concentrates.
