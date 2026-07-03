# 03 - Authentication

Authentication **produces** the `Principal` that authorization consumes. `@kengela/adapter-authn-native`
provides hardened building blocks: timing-safe password hashing, an anti-enumeration authenticator,
full MFA/TOTP, AES-256-GCM encryption and crypto-shredding. `@kengela/adapter-authn-better-auth`
wires up an SSO provider (better-auth). Sessions live in a `SessionStore` (Prisma).

## Timing-safe password hashing

The `PasswordHasher` port mandates three operations, one of which is a **constant-time**
verification:

```ts
interface PasswordHasher {
  hash(plain: string): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>; // temps constant
  needsRehash(hash: string): boolean; // migration transparente
}
```

Two implementations:

| Class                  | Algorithm                          | Parameters                          | Usage                                |
| ---------------------- | ---------------------------------- | ----------------------------------- | ------------------------------------ |
| `Argon2PasswordHasher` | **argon2id** (recommended default) | m = 19456 KiB, t = 2, p = 1 (OWASP) | any new deployment                   |
| `BcryptPasswordHasher` | bcrypt                             | cost 12 (configurable)              | compat / migration from the existing |

```ts
import { Argon2PasswordHasher, BcryptPasswordHasher } from '@kengela/adapter-authn-native';

const hasher = new Argon2PasswordHasher();
const hash = await hasher.hash('correct horse battery staple');
const ok = await hasher.verify('correct horse battery staple', hash); // true
```

### `needsRehash`: frictionless bcrypt → argon2 migration

`needsRehash(hash)` returns `true` if the hash should be recomputed (obsolete algorithm/parameters).
On the **next successful login**, the application re-hashes the password with the target algorithm:

```ts
if (
  (await hasher.verify(password, record.passwordHash)) &&
  hasher.needsRehash(record.passwordHash)
) {
  const upgraded = await hasher.hash(password); // ex. bcrypt → argon2id
  await store.updatePasswordHash(record.userId, upgraded);
}
```

`Argon2PasswordHasher.needsRehash` re-hashes if the hash is not argon2id or if its costs are below
the targets; `BcryptPasswordHasher.needsRehash` re-hashes if the cost is too low or the format is
unknown (e.g. an argon2 hash).

## Credential authentication (anti-enumeration)

`NativeCredentialAuthenticator` implements `CredentialAuthenticator`. Its key property: **a `verify`
is always performed**, even for an unknown email, against a pre-computed **decoy hash**. The response
time therefore does not reveal whether an account exists.

```ts
import { NativeCredentialAuthenticator } from '@kengela/adapter-authn-native';

// La fabrique pré-calcule le hash leurre (un vrai hash aléatoire).
const authenticator = await NativeCredentialAuthenticator.create(credentialStore, hasher);

const outcome = await authenticator.authenticate({
  email: 'alice@corp.example',
  password: '...',
  tenantId: 't1',
  ctx: { authTime: Date.now() },
});
```

The `CredentialStore` (implemented by the app's persistence, e.g. `connector-translog`) resolves a
`CredentialRecord`. The outcome is a discriminated `AuthOutcome`:

| `kind`                | Meaning                                                     |
| --------------------- | ----------------------------------------------------------- |
| `authenticated`       | success, carries the `Principal`                            |
| `mfa_required`        | the account has MFA enabled: demand a code (see below)      |
| `tenant_choice`       | cross-tenant login: several tenants match, the user chooses |
| `invalid_credentials` | failure (unknown account, wrong password, inactive account) |
| `captcha_required`    | (reserved) require a CAPTCHA                                |

Cross-tenant login (`authenticateCrossTenant`) does not short-circuit on the first match: it compares
across **all** tenants (N compares for N candidates), so as not to create a timing oracle. If there
are several matches, it returns `tenant_choice`.

## Hardened opaque sessions

The `SessionStore` port manages opaque tokens with rotation, cap, revocation and expiry. The Prisma
implementation (`PrismaSessionStore`) emits a **32-random-byte** token (64 hex) and takes an
**injectable clock**:

```ts
import { PrismaSessionStore } from '@kengela/adapter-persistence-prisma';

const sessions = new PrismaSessionStore(prisma /* PrismaLike */);

const handle = await sessions.create({
  userId: 'u1',
  tenantId: 't1',
  ctx: { authTime: Date.now() },
  ttlMs: 3_600_000,
});

await sessions.get(handle.token); // null si expiré (fail-closed) ou révoqué
await sessions.rotate(handle.token); // émet un nouveau token, invalide l'ancien (atomique si $transaction)
await sessions.revoke(handle.token);
await sessions.revokeAllForUser('u1');
```

Hardened points (proven by test):

- **Fail-closed expiry**: `get()` returns `null` as soon as `expiresAt <= now`, **even if the row
  still exists** (independent of the cleanup cron). An expired session is never served as valid.
- **Atomic rotation**: if the injected client provides `$transaction`, the rotation is an atomic
  delete+create; otherwise it degrades to sequential operations.

## Full MFA / TOTP

The MFA cycle composes four building blocks:

| Block                     | Port                | Role                                                                           |
| ------------------------- | ------------------- | ------------------------------------------------------------------------------ |
| `TotpVerifier`            | (class)             | RFC 6238: generates a base32 secret, the otpauth URI, verifies a code (otplib) |
| `AesGcmKeyManagement`     | `KeyManagementPort` | encrypts the secret at-rest, **per-tenant key** (HKDF)                         |
| `PrismaMfaSecretStore`    | `MfaSecretStore`    | persists the **already-encrypted** secret                                      |
| `PrismaMfaChallengeStore` | `MfaChallengeStore` | issues/consumes expiring **one-shot** challenges                               |

`TotpMfaService` implements `MfaService` (enroll / challenge / verify) by orchestrating these blocks.
**The secret is never stored in clear**: it is encrypted via the per-tenant envelope KMS before
reaching the store, and decrypted on the fly only to verify a code.

```ts
import { TotpVerifier, TotpMfaService, AesGcmKeyManagement } from '@kengela/adapter-authn-native';
import { PrismaMfaSecretStore, PrismaMfaChallengeStore } from '@kengela/adapter-persistence-prisma';

const mfa = new TotpMfaService(
  new TotpVerifier(),
  new AesGcmKeyManagement(masterKey /* >= 32 octets */),
  new PrismaMfaSecretStore(prisma.mfaSecret), // MfaSecretDelegate
  new PrismaMfaChallengeStore(prisma.mfaChallenge), // MfaChallengeDelegate
  { challengeTtlMs: 120_000 }, // TTL du défi (défaut 2 min)
);

// 1) Enrôlement : renvoie l'URI otpauth + un QR (data URL) à afficher.
const { secretUri, qr } = await mfa.enroll({
  tenantId: 't1',
  userId: 'u1',
  account: 'alice@corp.example',
  issuer: 'MonApp',
});

// 2) Défi : émet un challengeId opaque, valable challengeTtlMs.
const { challengeId } = await mfa.challenge({ tenantId: 't1', userId: 'u1' });

// 3) Vérification : consomme le défi (one-shot) et valide le code.
const valid = await mfa.verify(challengeId, '123456');
```

Proven controls: `challengeId` is **one-shot** (consumed exactly once, expiring), `verify` without an
enrolled secret returns `false`, a forged `challengeId` returns `false`.

> **Known debt (DEBT native #3).** The challenge is one-shot, but the TOTP _code_ itself is not
> memorized: within the step window (~30 s), an already-consumed code could be replayed via a **new**
> `challengeId`. NIST 800-63B §5.1.4.2 recommends an anti-replay cache (documented target).

### The Prisma MFA stores (narrow interface)

`PrismaMfaSecretStore` and `PrismaMfaChallengeStore` depend only on a narrow delegate
(`MfaSecretDelegate` / `MfaChallengeDelegate` from `PrismaLike`): `create`, `findFirst`/`findUnique`,
`delete`/`deleteMany`. `PrismaMfaChallengeStore.consume` **always deletes** the challenge (even if
expired) then checks the expiry - anti-replay of the challenge.

## SSO via better-auth (`IdentityPort`)

`@kengela/adapter-authn-better-auth` provides `BetterAuthIdentity`, which implements `IdentityPort`:
it verifies a session proof (cookie or bearer) via `auth.api.getSession` and projects the user into a
`Principal`. **better-auth is a `peerDependency`**: it is the application that installs and configures
it (OIDC/OAuth/SSO, DB, routes).

```sh
npm add @kengela/adapter-authn-better-auth better-auth
```

```ts
import { BetterAuthIdentity } from '@kengela/adapter-authn-better-auth';
import type { SessionCredential } from '@kengela/contracts';

const identity = new BetterAuthIdentity({
  auth, // instance better-auth (BetterAuthLike)
  extractTenantId: (user) => (typeof user.tenantId === 'string' ? user.tenantId : null),
  // extractRoles : par défaut aucun rôle n'est hérité du payload — l'authz RECHARGE les grants.
});

const credential: SessionCredential = { strategy: 'cookie', token: cookieHeader };
const principal = await identity.verifySession(credential); // Principal | null
```

Fail-closed behavior:

- session missing/invalid → `null`;
- **unresolvable tenant** → `null` (a session without a tenant is refused);
- roles and `mfaLevel` are **never inherited** from the payload: authorization reloads the grants
  from the source of truth.

> The consumed surface is **narrow**: `BetterAuthLike` declares only `api.getSession`. Kengela does
> not drive the framework; it consumes the verified session.

## Field encryption & crypto-shredding

Two distinct needs, two tools.

### Per-**tenant** field encryption (`FieldCipherPort`)

`AesGcmFieldCipher` encrypts a PII string into a storable base64, on top of a `KeyManagementPort`
(per-tenant derived key, HKDF `kengela:mfa:<tenantId>`, format `iv(12) || tag(16) || ciphertext`):

```ts
import { AesGcmKeyManagement, AesGcmFieldCipher } from '@kengela/adapter-authn-native';

const cipher = new AesGcmFieldCipher(new AesGcmKeyManagement(masterKey));
const enc = await cipher.encryptField('t1', 'alice@corp.example');
const dec = await cipher.decryptField('t1', enc); // 'alice@corp.example'
```

Any tampering (iv/tag/ciphertext), a truncation, or a **wrong tenant key** → rejection
(authenticated AES-GCM). Cross-tenant cryptographic isolation guaranteed.

### Per-**subject** encryption + GDPR erasure (art. 17)

Crypto-shredding assigns a key **per data subject**. Destroying the key makes all of their encrypted
PII permanently unreadable, without rewriting every table.

```ts
import { SubjectFieldCipher, SubjectCryptoShredder } from '@kengela/adapter-authn-native';

const cipher = new SubjectFieldCipher(subjectKeyStore /* SubjectKeyStore */);
const enc = await cipher.encryptFor('t1', 'subject-42', 'numéro de passeport');
const clear = await cipher.decryptFor('t1', 'subject-42', enc); // string, ou null si la clé a été détruite

// Effacement (RGPD art. 17) : détruit la clé du sujet → PII illisible (null).
const shredder = new SubjectCryptoShredder(subjectKeyStore);
await shredder.eraseSubject('t1', 'subject-42');
```

Proven controls: after `eraseSubject`, `decryptFor` returns `null`; another subject's key does not
decrypt the PII. The `SubjectKeyStore` port (getOrCreate / get / delete the key) is implemented by
the application. See [06-compliance-pii.md](./06-compliance-pii.md) for the compliance view.
