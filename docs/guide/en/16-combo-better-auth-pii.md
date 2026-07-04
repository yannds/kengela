# Combo 16 - better-auth (delegated authn) + per-tenant encrypted PII + GDPR erasure

> COMBO: two recipes assembled. We delegate **login / session** to
> [better-auth](https://better-auth.com) (recipe 11), and we protect the account's
> **personal data** with per-tenant field encryption + crypto-shredding (recipe 15).
> The bridge between the two is the `Principal`: better-auth PRODUCES it, the PII layer
> CONSUMES it (`principal.userId` = the PII subject).

---

## 1. The building blocks and the flow

Three responsibilities, three families of real symbols:

- **Delegated authn** - `BetterAuthIdentity` (`@kengela/adapter-authn-better-auth`)
  implements `IdentityPort.verifySession(SessionCredential) → Principal | null`. It does
  NEITHER login NOR signup: better-auth owns the session, the adapter translates it into
  a `Principal`.
- **PII field encryption** - `classify` / `isPii` / `PII_FIELDS` (`@kengela/pii`) say
  WHICH fields are personal; `AesGcmFieldCipher` (per-tenant) and `SubjectFieldCipher`
  (per-subject) encrypt them at-rest. Both derive their keys via `AesGcmKeyManagement`.
- **Erasure (art. 17)** - `SubjectCryptoShredder.eraseSubject` destroys the subject's key
  via `PrismaSubjectKeyStore`: all of that subject's per-subject PII becomes unreadable.
  Every read is logged by `PrismaPiiAccessLogSink` (art. 30).

### Request flow

```
Cookie/Bearer better-auth
        │
        ▼
BetterAuthIdentity.verifySession ──►  Principal { userId, tenantId, ... }
        │                                    │  (userId = PII subjectId)
        │                                    ▼
        │                     SubjectFieldCipher.decryptFor(tenantId, userId, enc)
        │                          │  key resolved via PrismaSubjectKeyStore
        │                          ▼
        │                     PrismaPiiAccessLogSink.record({ subjectId, fields, ... })
        │                          ▼
        │                     decrypted profile returned to the caller
        │
        └── right to erasure ─────► SubjectCryptoShredder.eraseSubject(tenantId, userId)
                                          │  PrismaSubjectKeyStore.deleteKey
                                          ▼
                                     decryptFor(...) === null  (unreadable, irreversible)
```

### Port → adapter table

| Port (`@kengela/contracts`) | Concrete adapter         | Package                               |
| --------------------------- | ------------------------ | ------------------------------------- |
| `IdentityPort`              | `BetterAuthIdentity`     | `@kengela/adapter-authn-better-auth`  |
| `KeyManagementPort`         | `AesGcmKeyManagement`    | `@kengela/adapter-authn-native`       |
| `FieldCipherPort`           | `AesGcmFieldCipher`      | `@kengela/adapter-authn-native`       |
| `SubjectKeyStore`           | `PrismaSubjectKeyStore`  | `@kengela/adapter-persistence-prisma` |
| `ErasurePort`               | `SubjectCryptoShredder`  | `@kengela/adapter-authn-native`       |
| `PiiAccessLogSink`          | `PrismaPiiAccessLogSink` | `@kengela/adapter-persistence-prisma` |
| - (pure functions)          | `classify` / `isPii`     | `@kengela/pii`                        |

`SubjectFieldCipher` does not implement a `contracts` port (it is a concrete block on top
of `SubjectKeyStore`), but it is the centerpiece of crypto-shredding.

---

## 2. Installation

```sh
npm add @kengela/adapter-authn-better-auth @kengela/adapter-authn-native \
        @kengela/adapter-persistence-prisma @kengela/pii @kengela/contracts
npm add better-auth        # peerDependency of the better-auth adapter
```

---

## 3. Authn: better-auth session → Principal

`BetterAuthIdentity` takes a session proof and projects it into a `Principal`. The real
constructor (`better-auth-identity.ts`):

```ts
export interface BetterAuthIdentityConfig {
  readonly auth: BetterAuthLike;
  readonly extractTenantId?: (user: BetterAuthUser) => string | null;
  readonly extractRoles?: (user: BetterAuthUser) => readonly string[];
}
```

Fail-closed: if `extractTenantId` returns `null`, `verifySession` returns `null` - a
session without a resolvable tenant is not a valid `Principal`.

```ts
import { BetterAuthIdentity, type BetterAuthLike } from '@kengela/adapter-authn-better-auth';
import type { IdentityPort, SessionCredential } from '@kengela/contracts';
import { auth } from './auth/better-auth'; // YOUR betterAuth({...}) instance

const identity: IdentityPort = new BetterAuthIdentity({
  auth: auth as unknown as BetterAuthLike,
  extractTenantId: (user) =>
    typeof user['tenantId'] === 'string' ? (user['tenantId'] as string) : null,
});

const credential: SessionCredential = { strategy: 'cookie', token: req.headers.cookie ?? '' };
const principal = await identity.verifySession(credential);
if (principal === null) {
  // 401: missing / invalid session, or no resolvable tenant
}
// principal.userId  = PII subject ; principal.tenantId = encryption tenant.
```

Coupling point: the rest of the combo only knows `principal.userId` and
`principal.tenantId`. Where authn comes from (better-auth or native) is irrelevant.

---

## 4. PII: which fields to encrypt

`classify` is the single source of truth. Never guess by hand.

```ts
import { classify, isPii } from '@kengela/pii';

classify('email'); // 'pii'
classify('phoneNumber'); // 'pii'
classify('department'); // 'none' (org attachment, queryable in the clear)

// Encrypt only attributes classified as PII:
const piiKeys = Object.keys(attributes).filter(isPii);
```

Two encryption levels, two purposes:

- **per-tenant** (`AesGcmFieldCipher`): at-rest protection + cross-tenant isolation, key
  shared across the tenant. Suitable for fields that will not be shredded individually.
- **per-subject** (`SubjectFieldCipher`): one key per person, the basis of crypto-shredding.
  Reserve it for fields that must be erasable account by account.

### HKDF domain separation (IMPORTANT)

`AesGcmKeyManagement` derives a per-tenant key from the master key via HKDF, in a
configurable CONTEXT (`info`). The default is `kengela:mfa` (historical compat). For PII
encryption, use a DIFFERENT context so the PII key can never be interchangeable with the
MFA secret's key:

```ts
import { AesGcmKeyManagement, AesGcmFieldCipher } from '@kengela/adapter-authn-native';

// masterKey: Uint8Array >= 32 bytes, loaded from the vault (Vault), NEVER hardcoded.
const piiKeyMgmt = new AesGcmKeyManagement(masterKey, { context: 'kengela:pii' });
const tenantCipher = new AesGcmFieldCipher(piiKeyMgmt); // FieldCipherPort, base64
```

---

## 5. Per-subject encryption + erasure

`PrismaSubjectKeyStore` stores an AES-256 key per (tenant, subject). Injecting a
`KeyManagementPort` WRAPS this key at-rest (the database alone reveals nothing):

```ts
import { PrismaSubjectKeyStore } from '@kengela/adapter-persistence-prisma';
import { SubjectFieldCipher, SubjectCryptoShredder } from '@kengela/adapter-authn-native';

// `db.subjectKey` = SubjectKeyDelegate (findFirst/create/deleteMany), supplied by PrismaClient.
const subjectKeys = new PrismaSubjectKeyStore(db.subjectKey, { keyManagement: piiKeyMgmt });

const subjectCipher = new SubjectFieldCipher(subjectKeys); // encryptFor / decryptFor
const shredder = new SubjectCryptoShredder(subjectKeys); // ErasurePort.eraseSubject
```

`decryptFor` returns `null` as soon as the subject's key has been destroyed: that is the
effect of crypto-shredding, without rewriting a single table.

```ts
const subjectId = principal.userId; // the subject = the authenticated account

const encEmail = await subjectCipher.encryptFor(principal.tenantId, subjectId, 'awa@ex.com');
await subjectCipher.decryptFor(principal.tenantId, subjectId, encEmail); // 'awa@ex.com'

await shredder.eraseSubject(principal.tenantId, subjectId); // right to erasure
await subjectCipher.decryptFor(principal.tenantId, subjectId, encEmail); // null (unreadable)
```

---

## 6. Access log (art. 30)

`PrismaPiiAccessLogSink.record` inserts one audit row per access - field NAMES only, never
the values.

```ts
import { PrismaPiiAccessLogSink } from '@kengela/adapter-persistence-prisma';

const audit = new PrismaPiiAccessLogSink(db.piiAccessLog); // PiiAccessLogDelegate

await audit.record({
  tenantId: principal.tenantId,
  subjectId: principal.userId,
  actorId: principal.userId, // here the actor reads their own profile
  fields: ['email', 'phoneNumber'], // field names only
  purpose: 'account.profile.read',
  at: Date.now(),
});
```

---

## Full example (copy-paste)

A single block: composition root + `SecureAccountService` linking better-auth, per-subject
PII encryption, access log and erasure. Ready to paste (the `db.subjectKey` /
`db.piiAccessLog` delegates come from a `PrismaClient` structurally compatible with
`SubjectKeyDelegate` / `PiiAccessLogDelegate`).

```ts
import {
  BetterAuthIdentity,
  type BetterAuthLike,
  type BetterAuthUser,
} from '@kengela/adapter-authn-better-auth';
import {
  AesGcmKeyManagement,
  AesGcmFieldCipher,
  SubjectFieldCipher,
  SubjectCryptoShredder,
} from '@kengela/adapter-authn-native';
import {
  PrismaSubjectKeyStore,
  PrismaPiiAccessLogSink,
  type SubjectKeyDelegate,
  type PiiAccessLogDelegate,
} from '@kengela/adapter-persistence-prisma';
import { isPii } from '@kengela/pii';
import type { IdentityPort, Principal, SessionCredential, TenantId } from '@kengela/contracts';

/** NARROW Prisma surface this combo needs (a real PrismaClient satisfies it). */
interface PiiPrismaLike {
  readonly subjectKey: SubjectKeyDelegate;
  readonly piiAccessLog: PiiAccessLogDelegate;
}

/**
 * Account profile service: authn delegated to better-auth, PII encrypted PER SUBJECT
 * (crypto-shredding), access logged, erasure in O(1).
 */
export class SecureAccountService {
  readonly #identity: IdentityPort;
  readonly #subjectCipher: SubjectFieldCipher;
  readonly #shredder: SubjectCryptoShredder;
  readonly #audit: PrismaPiiAccessLogSink;

  public constructor(deps: {
    readonly identity: IdentityPort;
    readonly subjectCipher: SubjectFieldCipher;
    readonly shredder: SubjectCryptoShredder;
    readonly audit: PrismaPiiAccessLogSink;
  }) {
    this.#identity = deps.identity;
    this.#subjectCipher = deps.subjectCipher;
    this.#shredder = deps.shredder;
    this.#audit = deps.audit;
  }

  /** Writes the account's PII attributes, encrypted per subject. Non-PII fields stay clear. */
  public async writeProfile(
    credential: SessionCredential,
    attributes: Readonly<Record<string, string>>,
  ): Promise<Record<string, string>> {
    const principal = await this.#requirePrincipal(credential);
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(attributes)) {
      out[key] = isPii(key)
        ? await this.#subjectCipher.encryptFor(principal.tenantId, principal.userId, value)
        : value;
    }
    return out;
  }

  /** Reads and decrypts stored PII attributes; logs the access (art. 30). */
  public async readProfile(
    credential: SessionCredential,
    stored: Readonly<Record<string, string>>,
  ): Promise<Record<string, string | null>> {
    const principal = await this.#requirePrincipal(credential);
    const out: Record<string, string | null> = {};
    const readPiiFields: string[] = [];
    for (const [key, value] of Object.entries(stored)) {
      if (isPii(key)) {
        // null if the subject's key was destroyed (erased account) => unreadable data.
        out[key] = await this.#subjectCipher.decryptFor(
          principal.tenantId,
          principal.userId,
          value,
        );
        readPiiFields.push(key);
      } else {
        out[key] = value;
      }
    }
    await this.#audit.record({
      tenantId: principal.tenantId,
      subjectId: principal.userId,
      actorId: principal.userId,
      fields: readPiiFields,
      purpose: 'account.profile.read',
      at: Date.now(),
    });
    return out;
  }

  /** Right to erasure (art. 17): destroys the subject's key. All of its PII becomes unreadable. */
  public async eraseSelf(credential: SessionCredential): Promise<void> {
    const principal = await this.#requirePrincipal(credential);
    await this.#shredder.eraseSubject(principal.tenantId, principal.userId);
  }

  async #requirePrincipal(credential: SessionCredential): Promise<Principal> {
    const principal = await this.#identity.verifySession(credential);
    if (principal === null) {
      throw new Error('unauthorized'); // 401: invalid session / no resolvable tenant
    }
    return principal;
  }
}

/**
 * Composition root. `auth` = YOUR better-auth instance; `db` = a PrismaClient (or any
 * surface satisfying PiiPrismaLike); `masterKey` = master key >= 32 bytes loaded from the
 * vault (Vault), NEVER hardcoded.
 */
export function buildSecureAccountService(deps: {
  readonly auth: BetterAuthLike;
  readonly db: PiiPrismaLike;
  readonly masterKey: Uint8Array;
}): SecureAccountService {
  // 1. Delegated authn: better-auth session -> Principal (fail-closed without tenant).
  const identity: IdentityPort = new BetterAuthIdentity({
    auth: deps.auth,
    extractTenantId: (user: BetterAuthUser) =>
      typeof user['tenantId'] === 'string' ? (user['tenantId'] as string) : null,
  });

  // 2. Envelope KMS IN A PII CONTEXT (domain separation from the MFA secret).
  const piiKeyMgmt = new AesGcmKeyManagement(deps.masterKey, { context: 'kengela:pii' });

  // 3. Per-subject encryption (key wrapped at-rest by the KMS) + shredder + log.
  const subjectKeys = new PrismaSubjectKeyStore(deps.db.subjectKey, {
    keyManagement: piiKeyMgmt,
  });
  const subjectCipher = new SubjectFieldCipher(subjectKeys);
  const shredder = new SubjectCryptoShredder(subjectKeys);
  const audit = new PrismaPiiAccessLogSink(deps.db.piiAccessLog);

  // (Optional) PER-TENANT encryption for fields not individually shreddable:
  const _tenantCipher = new AesGcmFieldCipher(piiKeyMgmt); // FieldCipherPort, base64

  return new SecureAccountService({ identity, subjectCipher, shredder, audit });
}

// ── Usage ────────────────────────────────────────────────────────────────────
// const svc = buildSecureAccountService({ auth, db, masterKey });
// const cookie: SessionCredential = { strategy: 'cookie', token: req.headers.cookie ?? '' };
// const enc = await svc.writeProfile(cookie, { email: 'awa@ex.com', department: 'Ops' });
// const dec = await svc.readProfile(cookie, enc);   // { email: 'awa@ex.com', department: 'Ops' }
// await svc.eraseSelf(cookie);                       // crypto-shredding
// const gone = await svc.readProfile(cookie, enc);  // { email: null, department: 'Ops' }
declare const _tenant: TenantId;
```

### Real-symbol recap

- `BetterAuthIdentity`, `BetterAuthLike`, `BetterAuthUser` (`@kengela/adapter-authn-better-auth`).
- `AesGcmKeyManagement` (`{ context }` option), `AesGcmFieldCipher`, `SubjectFieldCipher`
  (`encryptFor` / `decryptFor → null`), `SubjectCryptoShredder` (`eraseSubject`)
  (`@kengela/adapter-authn-native`).
- `PrismaSubjectKeyStore` (`{ keyManagement }` option), `PrismaPiiAccessLogSink`,
  delegates `SubjectKeyDelegate` / `PiiAccessLogDelegate` (`@kengela/adapter-persistence-prisma`).
- `isPii` / `classify` / `PII_FIELDS` (`@kengela/pii`).
- Ports: `IdentityPort`, `SessionCredential`, `Principal`, `FieldCipherPort`,
  `KeyManagementPort`, `SubjectKeyStore`, `ErasurePort`, `PiiAccessLogSink` (`@kengela/contracts`).
