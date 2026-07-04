# Combo 16 - better-auth (authn délégué) + PII chiffrées par tenant + effacement RGPD

> COMBO : deux recettes assemblées. On délègue le **login / la session** à
> [better-auth](https://better-auth.com) (recette 11), et on protège les **données
> personnelles** du compte par chiffrement de champ per-tenant + crypto-shredding
> (recette 15). Le pont entre les deux est le `Principal` : better-auth le PRODUIT,
> la couche PII le CONSOMME (`principal.userId` = sujet des PII).

---

## 1. Les briques et le flux

Trois responsabilités, trois familles de symboles réels :

- **Authn déléguée** - `BetterAuthIdentity` (`@kengela/adapter-authn-better-auth`)
  implémente `IdentityPort.verifySession(SessionCredential) → Principal | null`. Il ne
  fait NI login, NI signup : better-auth possède la session, l'adapter la traduit en
  `Principal`.
- **Chiffrement de champ PII** - `classify` / `isPii` / `PII_FIELDS` (`@kengela/pii`)
  disent QUELS champs sont personnels ; `AesGcmFieldCipher` (per-tenant) et
  `SubjectFieldCipher` (per-sujet) les chiffrent at-rest. Les deux dérivent leurs clés
  via `AesGcmKeyManagement`.
- **Effacement (art. 17)** - `SubjectCryptoShredder.eraseSubject` détruit la clé du
  sujet via `PrismaSubjectKeyStore` : toutes ses PII per-sujet deviennent illisibles.
  Chaque lecture est tracée par `PrismaPiiAccessLogSink` (art. 30).

### Flux d'une requête

```
Cookie/Bearer better-auth
        │
        ▼
BetterAuthIdentity.verifySession ──►  Principal { userId, tenantId, ... }
        │                                    │  (userId = subjectId PII)
        │                                    ▼
        │                     SubjectFieldCipher.decryptFor(tenantId, userId, enc)
        │                          │  clé résolue via PrismaSubjectKeyStore
        │                          ▼
        │                     PrismaPiiAccessLogSink.record({ subjectId, fields, ... })
        │                          ▼
        │                     profil déchiffré rendu à l'appelant
        │
        └── droit à l'effacement ──► SubjectCryptoShredder.eraseSubject(tenantId, userId)
                                          │  PrismaSubjectKeyStore.deleteKey
                                          ▼
                                     decryptFor(...) === null  (illisible, irréversible)
```

### Tableau port → adapter

| Port (`@kengela/contracts`) | Adapter concret          | Paquet                                |
| --------------------------- | ------------------------ | ------------------------------------- |
| `IdentityPort`              | `BetterAuthIdentity`     | `@kengela/adapter-authn-better-auth`  |
| `KeyManagementPort`         | `AesGcmKeyManagement`    | `@kengela/adapter-authn-native`       |
| `FieldCipherPort`           | `AesGcmFieldCipher`      | `@kengela/adapter-authn-native`       |
| `SubjectKeyStore`           | `PrismaSubjectKeyStore`  | `@kengela/adapter-persistence-prisma` |
| `ErasurePort`               | `SubjectCryptoShredder`  | `@kengela/adapter-authn-native`       |
| `PiiAccessLogSink`          | `PrismaPiiAccessLogSink` | `@kengela/adapter-persistence-prisma` |
| - (fonctions pures)         | `classify` / `isPii`     | `@kengela/pii`                        |

`SubjectFieldCipher` n'implémente pas un port de `contracts` (c'est une brique concrète
au-dessus de `SubjectKeyStore`), mais il est la pièce centrale du crypto-shredding.

---

## 2. Installation

```sh
npm add @kengela/adapter-authn-better-auth @kengela/adapter-authn-native \
        @kengela/adapter-persistence-prisma @kengela/pii @kengela/contracts
npm add better-auth        # peerDependency de l'adapter better-auth
```

---

## 3. Authn : session better-auth → Principal

`BetterAuthIdentity` prend une preuve de session et la projette en `Principal`. Le
constructeur réel (`better-auth-identity.ts`) :

```ts
export interface BetterAuthIdentityConfig {
  readonly auth: BetterAuthLike;
  readonly extractTenantId?: (user: BetterAuthUser) => string | null;
  readonly extractRoles?: (user: BetterAuthUser) => readonly string[];
}
```

Fail-closed : si `extractTenantId` renvoie `null`, `verifySession` retourne `null` - une
session sans tenant résoluble n'est pas un `Principal` valide.

```ts
import { BetterAuthIdentity, type BetterAuthLike } from '@kengela/adapter-authn-better-auth';
import type { IdentityPort, SessionCredential } from '@kengela/contracts';
import { auth } from './auth/better-auth'; // TON instance betterAuth({...})

const identity: IdentityPort = new BetterAuthIdentity({
  auth: auth as unknown as BetterAuthLike,
  extractTenantId: (user) =>
    typeof user['tenantId'] === 'string' ? (user['tenantId'] as string) : null,
});

const credential: SessionCredential = { strategy: 'cookie', token: req.headers.cookie ?? '' };
const principal = await identity.verifySession(credential);
if (principal === null) {
  // 401 : session absente / invalide / sans tenant résoluble
}
// principal.userId  = sujet des PII ; principal.tenantId = tenant de chiffrement.
```

Point de couplage : le reste du combo ne connaît QUE `principal.userId` et
`principal.tenantId`. D'où vient l'authn (better-auth ou natif) est indifférent.

---

## 4. PII : quels champs chiffrer

`classify` est la seule source de vérité. Ne jamais deviner à la main.

```ts
import { classify, isPii } from '@kengela/pii';

classify('email'); // 'pii'
classify('phoneNumber'); // 'pii'
classify('department'); // 'none' (rattachement org, requêtable en clair)

// Ne chiffrer que les attributs classés PII :
const piiKeys = Object.keys(attributes).filter(isPii);
```

Deux niveaux de chiffrement, deux finalités :

- **per-tenant** (`AesGcmFieldCipher`) : protection at-rest + isolation inter-tenant,
  clé commune au tenant. Convient aux champs qu'on ne shreddera pas individuellement.
- **per-sujet** (`SubjectFieldCipher`) : une clé par personne, base du crypto-shredding.
  À réserver aux champs qui devront pouvoir être effacés compte par compte.

### Séparation de domaine HKDF (IMPORTANT)

`AesGcmKeyManagement` dérive une clé par tenant depuis la clé maître via HKDF, dans un
CONTEXTE (`info`) configurable. Le défaut est `kengela:mfa` (compat historique). Pour le
chiffrement PII, utiliser un contexte DIFFÉRENT afin que la clé PII ne soit jamais
interchangeable avec la clé du secret MFA :

```ts
import { AesGcmKeyManagement, AesGcmFieldCipher } from '@kengela/adapter-authn-native';

// masterKey : Uint8Array >= 32 octets, chargée du coffre (Vault), JAMAIS en dur.
const piiKeyMgmt = new AesGcmKeyManagement(masterKey, { context: 'kengela:pii' });
const tenantCipher = new AesGcmFieldCipher(piiKeyMgmt); // FieldCipherPort, base64
```

---

## 5. Chiffrement per-sujet + effacement

`PrismaSubjectKeyStore` stocke une clé AES-256 par (tenant, sujet). Injecter un
`KeyManagementPort` WRAPPE cette clé at-rest (la base seule ne révèle rien) :

```ts
import { PrismaSubjectKeyStore } from '@kengela/adapter-persistence-prisma';
import { SubjectFieldCipher, SubjectCryptoShredder } from '@kengela/adapter-authn-native';

// `db.subjectKey` = SubjectKeyDelegate (findFirst/create/deleteMany), fourni par PrismaClient.
const subjectKeys = new PrismaSubjectKeyStore(db.subjectKey, { keyManagement: piiKeyMgmt });

const subjectCipher = new SubjectFieldCipher(subjectKeys); // encryptFor / decryptFor
const shredder = new SubjectCryptoShredder(subjectKeys); // ErasurePort.eraseSubject
```

`decryptFor` retourne `null` dès que la clé du sujet a été détruite : c'est l'effet du
crypto-shredding, sans réécrire aucune table.

```ts
const subjectId = principal.userId; // le sujet = le compte authentifié

const encEmail = await subjectCipher.encryptFor(principal.tenantId, subjectId, 'awa@ex.com');
await subjectCipher.decryptFor(principal.tenantId, subjectId, encEmail); // 'awa@ex.com'

await shredder.eraseSubject(principal.tenantId, subjectId); // droit à l'effacement
await subjectCipher.decryptFor(principal.tenantId, subjectId, encEmail); // null (illisible)
```

---

## 6. Journal d'accès (art. 30)

`PrismaPiiAccessLogSink.record` insère une ligne d'audit par accès - uniquement les NOMS
de champs, jamais les valeurs.

```ts
import { PrismaPiiAccessLogSink } from '@kengela/adapter-persistence-prisma';

const audit = new PrismaPiiAccessLogSink(db.piiAccessLog); // PiiAccessLogDelegate

await audit.record({
  tenantId: principal.tenantId,
  subjectId: principal.userId,
  actorId: principal.userId, // ici l'acteur lit son propre profil
  fields: ['email', 'phoneNumber'], // noms de champs uniquement
  purpose: 'account.profile.read',
  at: Date.now(),
});
```

---

## Exemple complet (copier-coller)

Un seul bloc : composition root + service `SecureAccountService` reliant better-auth,
chiffrement PII per-sujet, journal d'accès et effacement. Prêt à coller (les délégués
`db.subjectKey` / `db.piiAccessLog` proviennent d'un `PrismaClient` structurellement
compatible avec `SubjectKeyDelegate` / `PiiAccessLogDelegate`).

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

/** Surface Prisma NARROW dont ce combo a besoin (un vrai PrismaClient la satisfait). */
interface PiiPrismaLike {
  readonly subjectKey: SubjectKeyDelegate;
  readonly piiAccessLog: PiiAccessLogDelegate;
}

/**
 * Service de profil de compte : authn déléguée à better-auth, PII chiffrées PAR SUJET
 * (crypto-shredding), accès journalisé, effacement en O(1).
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

  /** Écrit les attributs PII du compte, chiffrés par sujet. Les champs non-PII passent en clair. */
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

  /** Lit et déchiffre les attributs PII stockés ; trace l'accès (art. 30). */
  public async readProfile(
    credential: SessionCredential,
    stored: Readonly<Record<string, string>>,
  ): Promise<Record<string, string | null>> {
    const principal = await this.#requirePrincipal(credential);
    const out: Record<string, string | null> = {};
    const readPiiFields: string[] = [];
    for (const [key, value] of Object.entries(stored)) {
      if (isPii(key)) {
        // null si la clé du sujet a été détruite (compte effacé) => donnée illisible.
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

  /** Droit à l'effacement (art. 17) : détruit la clé du sujet. Toutes ses PII deviennent illisibles. */
  public async eraseSelf(credential: SessionCredential): Promise<void> {
    const principal = await this.#requirePrincipal(credential);
    await this.#shredder.eraseSubject(principal.tenantId, principal.userId);
  }

  async #requirePrincipal(credential: SessionCredential): Promise<Principal> {
    const principal = await this.#identity.verifySession(credential);
    if (principal === null) {
      throw new Error('unauthorized'); // 401 : session invalide / sans tenant résoluble
    }
    return principal;
  }
}

/**
 * Composition root. `auth` = TON instance better-auth ; `db` = un PrismaClient (ou toute
 * surface satisfaisant PiiPrismaLike) ; `masterKey` = clé maître >= 32 octets chargée du
 * coffre (Vault), JAMAIS en dur.
 */
export function buildSecureAccountService(deps: {
  readonly auth: BetterAuthLike;
  readonly db: PiiPrismaLike;
  readonly masterKey: Uint8Array;
}): SecureAccountService {
  // 1. Authn déléguée : session better-auth -> Principal (fail-closed sans tenant).
  const identity: IdentityPort = new BetterAuthIdentity({
    auth: deps.auth,
    extractTenantId: (user: BetterAuthUser) =>
      typeof user['tenantId'] === 'string' ? (user['tenantId'] as string) : null,
  });

  // 2. KMS enveloppe DANS UN CONTEXTE PII (séparation de domaine avec le secret MFA).
  const piiKeyMgmt = new AesGcmKeyManagement(deps.masterKey, { context: 'kengela:pii' });

  // 3. Chiffrement par sujet (clé wrappée at-rest par le KMS) + shredder + journal.
  const subjectKeys = new PrismaSubjectKeyStore(deps.db.subjectKey, {
    keyManagement: piiKeyMgmt,
  });
  const subjectCipher = new SubjectFieldCipher(subjectKeys);
  const shredder = new SubjectCryptoShredder(subjectKeys);
  const audit = new PrismaPiiAccessLogSink(deps.db.piiAccessLog);

  // (Optionnel) chiffrement PAR TENANT pour les champs non shreddables individuellement :
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

### Récap des symboles réels

- `BetterAuthIdentity`, `BetterAuthLike`, `BetterAuthUser` (`@kengela/adapter-authn-better-auth`).
- `AesGcmKeyManagement` (option `{ context }`), `AesGcmFieldCipher`, `SubjectFieldCipher`
  (`encryptFor` / `decryptFor → null`), `SubjectCryptoShredder` (`eraseSubject`)
  (`@kengela/adapter-authn-native`).
- `PrismaSubjectKeyStore` (option `{ keyManagement }`), `PrismaPiiAccessLogSink`,
  délégués `SubjectKeyDelegate` / `PiiAccessLogDelegate` (`@kengela/adapter-persistence-prisma`).
- `isPii` / `classify` / `PII_FIELDS` (`@kengela/pii`).
- Ports : `IdentityPort`, `SessionCredential`, `Principal`, `FieldCipherPort`,
  `KeyManagementPort`, `SubjectKeyStore`, `ErasurePort`, `PiiAccessLogSink` (`@kengela/contracts`).
