# 03 - Authentification

L'authentification **produit** le `Principal` que l'autorisation consomme. `@kengela/adapter-authn-native`
fournit des briques durcies : hash de mot de passe timing-safe, authentificateur anti-énumération,
MFA/TOTP complet, chiffrement AES-256-GCM et crypto-shredding. `@kengela/adapter-authn-better-auth`
branche un fournisseur SSO (better-auth). Les sessions vivent dans un `SessionStore` (Prisma).

## Hash de mot de passe timing-safe

Le port `PasswordHasher` impose trois opérations, dont une vérification **à temps constant** :

```ts
interface PasswordHasher {
  hash(plain: string): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>;   // temps constant
  needsRehash(hash: string): boolean;                       // migration transparente
}
```

Deux implémentations :

| Classe | Algorithme | Paramètres | Usage |
|--------|-----------|------------|-------|
| `Argon2PasswordHasher` | **argon2id** (défaut recommandé) | m = 19456 KiB, t = 2, p = 1 (OWASP) | tout nouveau déploiement |
| `BcryptPasswordHasher` | bcrypt | coût 12 (configurable) | compat / migration depuis l'existant |

```ts
import { Argon2PasswordHasher, BcryptPasswordHasher } from '@kengela/adapter-authn-native';

const hasher = new Argon2PasswordHasher();
const hash = await hasher.hash('correct horse battery staple');
const ok = await hasher.verify('correct horse battery staple', hash); // true
```

### `needsRehash` : migration bcrypt → argon2 sans friction

`needsRehash(hash)` renvoie `true` si le hash devrait être recalculé (algo/paramètres obsolètes). Au
**prochain login réussi**, l'application re-hashe le mot de passe avec l'algorithme cible :

```ts
if (await hasher.verify(password, record.passwordHash) && hasher.needsRehash(record.passwordHash)) {
  const upgraded = await hasher.hash(password); // ex. bcrypt → argon2id
  await store.updatePasswordHash(record.userId, upgraded);
}
```

`Argon2PasswordHasher.needsRehash` re-hashe si le hash n'est pas argon2id ou si ses coûts sont
inférieurs aux cibles ; `BcryptPasswordHasher.needsRehash` re-hashe si le coût est trop bas ou le
format inconnu (ex. un hash argon2).

## Authentification par identifiants (anti-énumération)

`NativeCredentialAuthenticator` implémente `CredentialAuthenticator`. Sa propriété clé : **un
`verify` est toujours effectué**, même pour un e-mail inconnu, contre un **hash leurre** pré-calculé.
Le temps de réponse ne révèle donc pas l'existence d'un compte.

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

Le `CredentialStore` (implémenté par la persistance de l'app, ex. `connector-translog`) résout un
`CredentialRecord`. L'issue est un `AuthOutcome` discriminé :

| `kind` | Signification |
|--------|---------------|
| `authenticated` | succès, porte le `Principal` |
| `mfa_required` | le compte a la MFA activée : réclamer un code (voir plus bas) |
| `tenant_choice` | login cross-tenant : plusieurs tenants correspondent, l'utilisateur choisit |
| `invalid_credentials` | échec (compte inconnu, mot de passe faux, compte inactif) |
| `captcha_required` | (réservé) exiger un CAPTCHA |

Le login **cross-tenant** (`authenticateCrossTenant`) ne court-circuite pas au premier match : il
compare pour **tous** les tenants (N compares pour N candidats), pour ne pas créer d'oracle de
timing. S'il y a plusieurs matches, il renvoie `tenant_choice`.

## Sessions opaques durcies

Le port `SessionStore` gère des tokens opaques avec rotation, plafond, révocation et expiration.
L'implémentation Prisma (`PrismaSessionStore`) émet un token de **32 octets aléatoires** (64 hex) et
prend une **horloge injectable** :

```ts
import { PrismaSessionStore } from '@kengela/adapter-persistence-prisma';

const sessions = new PrismaSessionStore(prisma /* PrismaLike */);

const handle = await sessions.create({
  userId: 'u1',
  tenantId: 't1',
  ctx: { authTime: Date.now() },
  ttlMs: 3_600_000,
});

await sessions.get(handle.token);            // null si expiré (fail-closed) ou révoqué
await sessions.rotate(handle.token);         // émet un nouveau token, invalide l'ancien (atomique si $transaction)
await sessions.revoke(handle.token);
await sessions.revokeAllForUser('u1');
```

Points durcis (prouvés par test) :

- **Expiration fail-closed** : `get()` renvoie `null` dès que `expiresAt <= now`, **même si la ligne
  subsiste** (indépendant du cron de nettoyage). Une session expirée n'est jamais servie comme
  valide.
- **Rotation atomique** : si le client injecté fournit `$transaction`, la rotation est un
  delete+create atomique ; sinon elle dégrade en opérations séquentielles.

## MFA / TOTP complet

Le cycle MFA compose quatre briques :

| Brique | Port | Rôle |
|--------|------|------|
| `TotpVerifier` | (classe) | RFC 6238 : génère un secret base32, l'URI otpauth, vérifie un code (otplib) |
| `AesGcmKeyManagement` | `KeyManagementPort` | chiffre le secret at-rest, **clé par tenant** (HKDF) |
| `PrismaMfaSecretStore` | `MfaSecretStore` | persiste le secret **déjà chiffré** |
| `PrismaMfaChallengeStore` | `MfaChallengeStore` | émet/consomme des défis **one-shot** expirants |

`TotpMfaService` implémente `MfaService` (enroll / challenge / verify) en orchestrant ces briques.
**Le secret n'est jamais stocké en clair** : il est chiffré via le KMS enveloppe par tenant avant
d'atteindre le store, et déchiffré à la volée uniquement pour vérifier un code.

```ts
import {
  TotpVerifier,
  TotpMfaService,
  AesGcmKeyManagement,
} from '@kengela/adapter-authn-native';
import { PrismaMfaSecretStore, PrismaMfaChallengeStore } from '@kengela/adapter-persistence-prisma';

const mfa = new TotpMfaService(
  new TotpVerifier(),
  new AesGcmKeyManagement(masterKey /* >= 32 octets */),
  new PrismaMfaSecretStore(prisma.mfaSecret),      // MfaSecretDelegate
  new PrismaMfaChallengeStore(prisma.mfaChallenge), // MfaChallengeDelegate
  { challengeTtlMs: 120_000 },                      // TTL du défi (défaut 2 min)
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

Contrôles prouvés : `challengeId` **one-shot** (consommé une seule fois, expirant),
`verify` sans secret enrôlé renvoie `false`, un `challengeId` forgé renvoie `false`.

> **Dette connue (DEBT native #3).** Le défi est one-shot, mais le *code* TOTP lui-même n'est pas
> mémorisé : dans la fenêtre de pas (~30 s), un code déjà consommé pourrait être rejoué via un
> **nouveau** `challengeId`. NIST 800-63B §5.1.4.2 recommande un cache anti-rejeu (cible documentée).

### Les stores MFA Prisma (interface narrow)

`PrismaMfaSecretStore` et `PrismaMfaChallengeStore` ne dépendent que d'un délégué narrow
(`MfaSecretDelegate` / `MfaChallengeDelegate` de `PrismaLike`) : `create`, `findFirst`/`findUnique`,
`delete`/`deleteMany`. `PrismaMfaChallengeStore.consume` **supprime toujours** le défi (même expiré)
puis vérifie l'expiration - anti-rejeu du défi.

## SSO via better-auth (`IdentityPort`)

`@kengela/adapter-authn-better-auth` fournit `BetterAuthIdentity`, qui implémente `IdentityPort` :
il vérifie une preuve de session (cookie ou bearer) via `auth.api.getSession` et projette
l'utilisateur en `Principal`. **better-auth est une `peerDependency`** : c'est l'application qui
l'installe et le configure (OIDC/OAuth/SSO, DB, routes).

```sh
npm add @kengela/adapter-authn-better-auth better-auth
```

```ts
import { BetterAuthIdentity } from '@kengela/adapter-authn-better-auth';
import type { SessionCredential } from '@kengela/contracts';

const identity = new BetterAuthIdentity({
  auth,                                    // instance better-auth (BetterAuthLike)
  extractTenantId: (user) => (typeof user.tenantId === 'string' ? user.tenantId : null),
  // extractRoles : par défaut aucun rôle n'est hérité du payload — l'authz RECHARGE les grants.
});

const credential: SessionCredential = { strategy: 'cookie', token: cookieHeader };
const principal = await identity.verifySession(credential); // Principal | null
```

Comportement fail-closed :

- session absente/invalide → `null` ;
- **tenant non résoluble** → `null` (une session sans tenant est refusée) ;
- les rôles et le `mfaLevel` **ne sont jamais hérités** du payload : l'autorisation recharge les
  grants depuis la source de vérité.

> La surface consommée est **narrow** : `BetterAuthLike` ne déclare que `api.getSession`. Kengela ne
> pilote pas le framework ; il consomme la session vérifiée.

## Chiffrement de champ & crypto-shredding

Deux besoins distincts, deux outils.

### Chiffrement de champ par **tenant** (`FieldCipherPort`)

`AesGcmFieldCipher` chiffre une chaîne PII en base64 stockable, au-dessus d'un `KeyManagementPort`
(clé dérivée par tenant, HKDF `kengela:mfa:<tenantId>`, format `iv(12) || tag(16) || ciphertext`) :

```ts
import { AesGcmKeyManagement, AesGcmFieldCipher } from '@kengela/adapter-authn-native';

const cipher = new AesGcmFieldCipher(new AesGcmKeyManagement(masterKey));
const enc = await cipher.encryptField('t1', 'alice@corp.example');
const dec = await cipher.decryptField('t1', enc); // 'alice@corp.example'
```

Toute altération (iv/tag/ciphertext), une troncature, ou une **mauvaise clé tenant** → rejet
(AES-GCM authentifié). Isolation cryptographique inter-tenant garantie.

### Chiffrement par **sujet** + effacement RGPD (art. 17)

Le crypto-shredding attribue une clé **par personne concernée** (data subject). Détruire la clé rend
toutes ses PII chiffrées définitivement illisibles, sans réécrire chaque table.

```ts
import { SubjectFieldCipher, SubjectCryptoShredder } from '@kengela/adapter-authn-native';

const cipher = new SubjectFieldCipher(subjectKeyStore /* SubjectKeyStore */);
const enc = await cipher.encryptFor('t1', 'subject-42', 'numéro de passeport');
const clear = await cipher.decryptFor('t1', 'subject-42', enc); // string, ou null si la clé a été détruite

// Effacement (RGPD art. 17) : détruit la clé du sujet → PII illisible (null).
const shredder = new SubjectCryptoShredder(subjectKeyStore);
await shredder.eraseSubject('t1', 'subject-42');
```

Contrôles prouvés : après `eraseSubject`, `decryptFor` renvoie `null` ; la clé d'un autre sujet ne
déchiffre pas les PII. Le port `SubjectKeyStore` (getOrCreate / get / delete la clé) est implémenté
par l'application. Voir [06-compliance-pii.md](./06-compliance-pii.md) pour la vue conformité.
</content>
