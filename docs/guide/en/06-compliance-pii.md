# 06 - Compliance & personal data (PII)

GDPR compliance is **built in by design**, not bolted on afterwards. `@kengela/pii` (core, pure)
covers classification, minimization and redaction; the ports of `@kengela/contracts` cover field
encryption, the access log and erasure; `@kengela/adapter-authn-native` provides the concrete
crypto-shredding (see also [03-authentication.md](./03-authentication.md)).

> The functions of `@kengela/pii` operate on the **rich** `DirectoryProfile` of
> `@kengela/iam-mapping`.

## Classification

`classify(field)` returns a field's sensitivity, across three levels:

| Sensitivity | Meaning                                             | Examples                                                                                      |
| ----------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `none`      | non-personal (technical identifier, org attachment) | `externalId`, `department`, `title`, `costCenter`, `locale`                                   |
| `pii`       | personal data (direct/indirect identifiability)     | `email`, `firstName`, `lastName`, `phoneNumber`, `streetAddress`, `employeeNumber`, `manager` |
| `sensitive` | special category (GDPR art. 9: health, biometrics)  | _(none in a standard directory; provided for extension)_                                      |

```ts
import { classify, isPii, PII_FIELDS } from '@kengela/pii';

classify('email'); // 'pii'
classify('department'); // 'none'
isPii('phoneNumber'); // true
PII_FIELDS; // list of fields classified as personal
```

The registry is the source of truth: an unknown field falls back to `none`.

## Minimization (art. 5.1.c)

`minimizeProfile(profile, allowedFields)` keeps **only** the attributes explicitly allowed for the
app's purpose. Raw `claims` are dropped; unauthorized identity fields are nulled out (`null`).

```ts
import { minimizeProfile } from '@kengela/pii';

const minimal = minimizeProfile(profile, ['email', 'firstName', 'department']);
// firstName kept; lastName/displayName → null; attributes limited to department; claims emptied
```

It is the "data" counterpart of the Kengela principle "each app picks its own subset": you don't
carry attributes you don't need.

## Redaction / masking (logs & display)

`redactProfile(profile)` masks personal data without exposing it in clear, for logs or partial
display. The email is masked while keeping the domain; `pii` fields are reduced to their initial;
non-personal fields stay intact.

```ts
import { redactProfile } from '@kengela/pii';

const safe = redactProfile(profile);
// email 'alice@corp.example' → 'a***@corp.example'; firstName 'Alice' → 'A***'; department unchanged
```

## Retention (art. 5.1.e)

`retentionExpired(sensitivity, ageMs, policy?)` tells whether a datum has exceeded its retention
period. The default policy is **conservative**:

| Sensitivity | Default period (`DEFAULT_RETENTION`) |
| ----------- | ------------------------------------ |
| `none`      | unlimited (`null`)                   |
| `pii`       | 2 years (730 days)                   |
| `sensitive` | 6 months (182 days)                  |

```ts
import { retentionExpired, DEFAULT_RETENTION, type RetentionPolicy } from '@kengela/pii';

const ageMs = Date.now() - createdAt.getTime();
if (retentionExpired('pii', ageMs)) {
  // past retention → purge / anonymization
}

// An app can set its own periods:
const myPolicy: RetentionPolicy = {
  none: null,
  pii: 365 * 24 * 3600 * 1000,
  sensitive: 90 * 24 * 3600 * 1000,
};
retentionExpired('pii', ageMs, myPolicy);
```

## At-rest encryption of PII (`FieldCipherPort`)

Stored PII is encrypted at the **field** level, with cryptographic isolation **per tenant**. The
port:

```ts
interface FieldCipherPort {
  encryptField(tenantId: TenantId, plaintext: string): Promise<string>; // → storable base64
  decryptField(tenantId: TenantId, ciphertext: string): Promise<string>;
}
```

Implementation: `AesGcmFieldCipher` (AES-256-GCM, per-tenant derived key). See
[03-authentication.md](./03-authentication.md#chiffrement-de-champ--crypto-shredding).

## Erasure / right to be forgotten (art. 17) - crypto-shredding

The recommended erasure is **crypto-shredding**: each data subject (`subjectId`) has its own key
(`SubjectKeyStore`); destroying the key makes all of its encrypted PII **permanently unreadable**,
without scanning every table.

```ts
interface SubjectKeyStore {
  getOrCreateKey(tenantId, subjectId): Promise<Uint8Array>;
  getKey(tenantId, subjectId): Promise<Uint8Array | null>;
  deleteKey(tenantId, subjectId): Promise<void>;
}

interface ErasurePort {
  eraseSubject(tenantId: TenantId, subjectId: string): Promise<void>;
}
```

`SubjectFieldCipher` encrypts/decrypts per subject (returns `null` if the key has been destroyed),
`SubjectCryptoShredder` implements `ErasurePort`:

```ts
import { SubjectFieldCipher, SubjectCryptoShredder } from '@kengela/adapter-authn-native';

const cipher = new SubjectFieldCipher(subjectKeyStore);
const shredder = new SubjectCryptoShredder(subjectKeyStore);

await shredder.eraseSubject('t1', 'subject-42');
await cipher.decryptFor('t1', 'subject-42', enc); // null: data "shredded"
```

Proven controls: after erasure, the PII is unreadable; another subject's key does not decrypt it. It
is an _effective_ GDPR erasure that does not depend on an exhaustive table scan.

## PII access log (art. 30) - `PiiAccessLogSink`

Every **read/export** of personal data must be traceable: who, which subject, which fields, which
purpose. The port:

```ts
interface PiiAccessLogSink {
  record(entry: {
    readonly tenantId: TenantId;
    readonly subjectId: string; // data subject
    readonly actorId?: UserId; // absent = system
    readonly fields: readonly string[];
    readonly purpose: string; // processing purpose
    readonly at: number;
  }): Promise<void> | void;
}
```

```ts
const piiLog: PiiAccessLogSink = {
  record(entry) {
    auditDb.insert('pii_access_log', entry);
  },
};

// On every PII access:
piiLog.record({
  tenantId: 't1',
  subjectId: 'subject-42',
  actorId: currentUser.id,
  fields: ['email', 'phoneNumber'],
  purpose: 'support_ticket_resolution',
  at: Date.now(),
});
```

The implementation (the log destination) belongs to the application; the port guarantees that
traceability is part of the contract, not an optional add-on.

## GDPR → Kengela tooling recap

| GDPR requirement                          | Tool                                                                                     |
| ----------------------------------------- | ---------------------------------------------------------------------------------------- |
| Minimization (art. 5.1.c)                 | `minimizeProfile`                                                                        |
| Retention (art. 5.1.e)                    | `retentionExpired`, `DEFAULT_RETENTION`                                                  |
| At-rest encryption                        | `FieldCipherPort` / `AesGcmFieldCipher` (per tenant), `SubjectFieldCipher` (per subject) |
| Erasure / right to be forgotten (art. 17) | `ErasurePort` / `SubjectCryptoShredder` (crypto-shredding)                               |
| Access log (art. 30)                      | `PiiAccessLogSink`                                                                       |
| Log/display masking                       | `redactProfile`                                                                          |
| Classification                            | `classify`, `isPii`, `PII_FIELDS`                                                        |
