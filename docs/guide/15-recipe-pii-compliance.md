# Recette 15 - Conformité RGPD de bout en bout (PII)

> Kengela, TypeScript / ESM. Classer les PII, chiffrer les champs sensibles at-rest
> (par tenant), effacer par crypto-shredding, minimiser/rédiger, appliquer la
> rétention et journaliser tout accès aux données personnelles.

## 1. Les 5 briques et leurs ports

La conformité RGPD dans Kengela repose sur cinq briques indépendantes et composables.
Chacune s'appuie sur un port défini dans `@kengela/contracts`, ou sur une fonction pure
du paquet `@kengela/pii`.

| #    | Brique                       | Ce qu'elle résout (RGPD)                           | Symbole réel                                                                            | Paquet                                                                  |
| ---- | ---------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| 1    | Classification               | Savoir quel champ est une PII (art. 5, art. 30)    | `classify` / `isPii` / `PII_FIELDS`                                                     | `@kengela/pii`                                                          |
| 2    | Chiffrement de champ at-rest | Protection at-rest, isolation par tenant (art. 32) | `FieldCipherPort` ← `AesGcmFieldCipher` + `AesGcmKeyManagement` (+ `KeyManagementPort`) | `@kengela/contracts` / `@kengela/adapter-authn-native`                  |
| 2bis | Chiffrement par sujet        | Base du crypto-shredding (clé par personne)        | `SubjectFieldCipher` + `SubjectKeyStore` ← `PrismaSubjectKeyStore`                      | `@kengela/adapter-authn-native` / `@kengela/adapter-persistence-prisma` |
| 3    | Crypto-shredding             | Droit à l'effacement (art. 17)                     | `ErasurePort` ← `SubjectCryptoShredder`                                                 | `@kengela/contracts` / `@kengela/adapter-authn-native`                  |
| 4    | Minimisation / redaction     | Minimisation (art. 5.1.c), non-exposition en logs  | `minimizeProfile` / `redactProfile`                                                     | `@kengela/pii`                                                          |
| 5    | Rétention                    | Limitation de conservation (art. 5.1.e)            | `retentionExpired` / `DEFAULT_RETENTION`                                                | `@kengela/pii`                                                          |
| -    | Journal d'accès              | Auditabilité des accès PII (art. 30)               | `PiiAccessLogSink` ← `PrismaPiiAccessLogSink`                                           | `@kengela/contracts` / `@kengela/adapter-persistence-prisma`            |

Les briques 1, 4 et 5 sont des **fonctions pures** (aucune I/O, testables en unitaire
trivial). Les briques 2, 2bis, 3 et le journal sont des **ports** : le noyau ne dépend
que de l'interface, l'adaptateur (natif AES-GCM ou autre) est injecté au câblage.

Le sujet d'exemple pour toute la recette : un profil utilisateur `DirectoryProfile`
(paquet `@kengela/iam-mapping`), tel que renvoyé par l'IdP au login / à la synchro SCIM.

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

Rappel de forme (`@kengela/iam-mapping/src/profile.ts`) : `email` est une `string`
non nullable ; `firstName` / `lastName` / `displayName` / `externalId` sont
`string | null` ; `attributes` est un `Record`, `claims` un `Record` de claims bruts.

---

## 2. Classification - quels champs sont des PII

Le registre est défini dans `@kengela/pii/src/classification.ts`. Trois niveaux de
sensibilité :

```ts
export type PiiSensitivity = 'none' | 'pii' | 'sensitive';
```

- `none` : non personnel (identifiant technique, rattachement organisationnel).
- `pii` : donnée personnelle (identifiabilité directe ou indirecte).
- `sensitive` : catégorie particulière (art. 9 - santé, biométrie). Prévu pour
  extension ; **aucun champ** de l'annuaire standard n'est classé `sensitive` aujourd'hui.

Trois symboles exportés (signatures réelles) :

```ts
export function classify(field: string): PiiSensitivity; // défaut 'none' si inconnu
export function isPii(field: string): boolean; // classify(field) !== 'none'
export const PII_FIELDS: readonly string[]; // liste des champs != 'none'
```

Appliqués au profil d'exemple :

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

Champs classés `pii` dans le registre : `email`, `firstName`, `lastName`,
`displayName`, `phoneNumber`, `mobilePhone`, `streetAddress`, `city`, `state`,
`postalCode`, `country`, `employeeNumber`, `manager`.

Champs classés `none` (rattachement / préférences, non personnels) : `externalId`,
`department`, `division`, `title`, `organization`, `companyName`, `costCenter`,
`officeLocation`, `employeeType`, `preferredLanguage`, `locale`, `timezone`.

> Point de vigilance : `employeeNumber` et `manager` sont **PII** (identifiabilité
> indirecte), alors que `title` ou `department` ne le sont pas. Ne jamais deviner
> « à la main » - passer par `classify` / `isPii` reste la seule source de vérité.

`classify` sert de clé d'entrée aux briques rétention (§6) et journal (§7) : c'est le
registre qui dit quels champs doivent être chiffrés, purgés, et tracés.

---

## 3. Chiffrement at-rest par tenant

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

`TenantId` est un simple `type TenantId = string`.

### Adaptateurs natifs (AES-256-GCM)

`AesGcmKeyManagement` (`@kengela/adapter-authn-native`) implémente `KeyManagementPort`
en **chiffrement enveloppe** : une clé par tenant est dérivée de la clé maître via
**HKDF-SHA256**, dans un **contexte (`info`) configurable** : `info = <context>:<tenantId>`.
La dérivation par tenant garantit l'isolation cryptographique inter-tenant ; le contexte
garantit la **séparation de domaine par usage**. Format du chiffré : `iv(12) || tag(16) || ciphertext`.

Le second argument du constructeur est `{ context?: string }` - défaut **`kengela:mfa`**
(rétro-compatible : c'est le contexte historique du secret MFA at-rest). Pour le
chiffrement de **champ PII**, dérive dans un contexte **distinct** afin que la clé « champ
PII » et la clé « secret MFA » d'un même tenant ne soient **jamais interchangeables** :

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

`AesGcmFieldCipher` encode simplement le plaintext en UTF-8 puis délègue au
`KeyManagementPort`, et rend/relit du **base64** (adapté à une colonne texte).

Pattern de persistance recommandé : chiffrer **chaque champ PII** avant écriture,
en s'appuyant sur `isPii` pour savoir lesquels.

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

### Où brancher `SubjectKeyStore`

Le chiffrement **par tenant** ci-dessus protège at-rest et isole les tenants, mais la
clé est commune à tout le tenant : on ne peut pas « effacer » un seul individu en jetant
la clé. Pour l'effacement par personne (§4), il faut une clé **par sujet** via
`SubjectKeyStore` + `SubjectFieldCipher`.

```ts
// @kengela/contracts
export interface SubjectKeyStore {
  getOrCreateKey(tenantId: TenantId, subjectId: string): Promise<Uint8Array>;
  getKey(tenantId: TenantId, subjectId: string): Promise<Uint8Array | null>;
  deleteKey(tenantId: TenantId, subjectId: string): Promise<void>;
}
```

Un **store persistant est fourni** : `PrismaSubjectKeyStore`
(`@kengela/adapter-persistence-prisma`) implémente `SubjectKeyStore` sur une table Prisma
dédiée (une ligne par sujet, colonne `key`). Son constructeur prend le délégué Prisma de la
table plus des options `{ keyManagement?, keyBytes? }` :

- **`keyManagement`** - si un `KeyManagementPort` (ex. `AesGcmKeyManagement`, chiffrement
  enveloppe par tenant) est injecté, la clé du sujet est **wrappée** avant persistance : la
  colonne ne contient jamais de matériel clair. Une fuite de la base seule ne révèle rien
  sans la clé maître. **Absent = stockage base64 en clair** : mode dégradé, à réserver au
  développement (le crypto-shredding reste effectif dans les deux cas, puisqu'il repose sur
  la **suppression** de la ligne, pas sur le chiffrement).
- **`keyBytes`** - taille de la clé générée, en octets. Défaut **32** (AES-256).

```ts
import { PrismaSubjectKeyStore } from '@kengela/adapter-persistence-prisma';

// `prisma.subjectKey` est le délégué Prisma de ta table (findFirst/create/deleteMany).
// keyManagement (recommandé) : la clé de sujet est chiffrée-at-rest par tenant.
const subjectKeyStore = new PrismaSubjectKeyStore(prisma.subjectKey, {
  keyManagement: keyMgmt, // AesGcmKeyManagement du §3 - wrappe la clé de sujet at-rest
});
```

`SubjectFieldCipher` (`@kengela/adapter-authn-native`) chiffre un champ avec la clé
du sujet (résolue via `getOrCreateKey`) et déchiffre via `getKey` - **retournant `null`
si la clé a été détruite**. Format base64 : `iv(12) || tag(16) || ciphertext`.

```ts
import { SubjectFieldCipher } from '@kengela/adapter-authn-native';

const subjectCipher = new SubjectFieldCipher(subjectKeyStore); // SubjectKeyStore injecté
const subjectId = profile.externalId!; // clé stable de la personne concernée

const encEmail = await subjectCipher.encryptFor(tenantId, subjectId, profile.email);
const email = await subjectCipher.decryptFor(tenantId, subjectId, encEmail);
// email === 'awa.diallo@example.com'  (tant que la clé du sujet existe)
```

> Choix de conception : chiffrement **par tenant** (`AesGcmFieldCipher`) pour la
> protection at-rest générale + isolation ; chiffrement **par sujet**
> (`SubjectFieldCipher`) pour tout champ qui devra pouvoir être crypto-shreddé
> individuellement. Les deux cohabitent.

---

## 4. Crypto-shredding - droit à l'effacement (art. 17)

Effacer une personne ne veut pas dire balayer chaque table pour écraser ses lignes.
On **détruit sa clé** : toutes ses PII chiffrées avec `SubjectFieldCipher` deviennent
alors définitivement illisibles.

`SubjectCryptoShredder` (`@kengela/adapter-authn-native`) implémente `ErasurePort` :

```ts
// @kengela/contracts
export interface ErasurePort {
  eraseSubject(tenantId: TenantId, subjectId: string): Promise<void>;
}
```

Implémentation réelle (une ligne : déléguer au store) :

```ts
export class SubjectCryptoShredder implements ErasurePort {
  eraseSubject(tenantId: TenantId, subjectId: string): Promise<void> {
    return this.#keys.deleteKey(tenantId, subjectId);
  }
}
```

Appel et effet :

```ts
import { SubjectCryptoShredder } from '@kengela/adapter-authn-native';

const shredder = new SubjectCryptoShredder(subjectKeyStore); // ErasurePort

// L'utilisateur exerce son droit à l'effacement :
await shredder.eraseSubject(tenantId, subjectId);

// Effet immédiat : la clé n'existe plus, toute tentative de lecture rend null.
const email = await subjectCipher.decryptFor(tenantId, subjectId, encEmail);
// email === null   <-- donnée « shreddée », irrécupérable, sans réécrire les tables
```

Avantages : effacement O(1) (une clé), preuve d'irréversibilité (la clé AES a disparu),
et pas de course avec les réplicas/backups chiffrés - un backup restauré reste illisible
puisqu'il ne contient jamais la clé.

> Contrainte : seuls les champs chiffrés **par sujet** sont couverts par le shredding.
> Un champ chiffré par tenant (ou en clair) survit à `eraseSubject`. Décider dès la
> modélisation quels champs relèvent du sujet.

---

## 5. Minimisation / redaction

Deux fonctions pures de `@kengela/pii`, deux finalités distinctes.

### `minimizeProfile` - export / usage restreint (art. 5.1.c)

Ne conserve QUE les attributs explicitement autorisés pour la finalité. Les `claims`
bruts sont vidés, les champs d'identité non autorisés passent à `null`.

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

Avant → après :

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

Comportement réel **affirmé** (vérifié dans `@kengela/pii/src/minimize.ts`) : `email`,
`externalId` et `groups` sont **toujours** conservés, quels que soient les `allowedFields`.
Seuls `firstName` / `lastName` / `displayName` (mis à `null` si non autorisés) et les
`attributes` (filtrés : ne restent que les clés autorisées **et** définies) répondent à
`allowedFields` ; `claims` est **systématiquement** vidé à `{}`.

> Avertissement pratique : `minimizeProfile` **n'est pas** un moyen de masquer l'email ni
> l'identifiant externe. `email`, `externalId` et `groups` passent **toujours**, même absents
> de `allowedFields`. Si ta finalité exige de les retirer (export anonymisé, tiers qui n'a
> pas à connaître l'email), fais-le **explicitement après** l'appel - ne compte pas sur
> `allowedFields` pour ça. Pour un affichage/journal, `redactProfile` masque bien l'email.

### `redactProfile` - journaux / affichage (non-exposition en clair)

Masque l'identité et tout attribut classé `pii` ; laisse les champs `none` intacts.

```ts
export function redactProfile(profile: DirectoryProfile): DirectoryProfile;
```

```ts
import { redactProfile } from '@kengela/pii';
logger.info({ user: redactProfile(profile) }, 'profil chargé');
```

Avant → après :

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

Règles de masquage réelles : email → `<1re lettre>***<@domaine>` (ou `***` si pas de
`@`) ; toute autre valeur `string` → `<1re lettre>***` (ou `***` si longueur ≤ 1). Le
masquage d'attribut ne s'applique qu'aux valeurs de type `string` classées `pii`.

> Ne jamais logger un `DirectoryProfile` brut. Toujours `redactProfile` d'abord.
> Pour un export produit à une app ou un tiers, `minimizeProfile` d'abord.

---

## 6. Rétention - décider qu'un enregistrement doit être purgé (art. 5.1.e)

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

`retentionExpired` renvoie `false` si la limite est `null` (rétention indéfinie), sinon
`ageMs > limit`. On combine avec `classify` pour décider champ par champ, ou au niveau
enregistrement.

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

> Combinaison naturelle : la rétention **décide** (fonction pure, dans un cron/job) et
> le crypto-shredding **exécute** l'effacement. Le déclencheur (cron, job de purge) est
> à écrire côté app (voir §8).

---

## 7. Journal d'accès aux PII (art. 30, auditabilité)

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

Un **sink persistant est fourni** : `PrismaPiiAccessLogSink`
(`@kengela/adapter-persistence-prisma`) implémente `PiiAccessLogSink` en insérant une ligne
d'audit par accès (RGPD art. 30). Son constructeur prend le délégué Prisma de la table de
journal ; `actorId` absent est stocké `null` (accès système), et `at` (epoch ms) est
converti en `Date`.

```ts
import { PrismaPiiAccessLogSink } from '@kengela/adapter-persistence-prisma';

// `prisma.piiAccessLog` est le délégué Prisma de ta table d'audit (create).
const audit = new PrismaPiiAccessLogSink(prisma.piiAccessLog); // PiiAccessLogSink
```

À **chaque lecture/export de PII**, journaliser : qui (`actorId`), quel sujet
(`subjectId`), quels champs (`fields`), pour quelle finalité (`purpose`), et quand
(`at`). Ne journaliser **que les noms de champs**, jamais leurs valeurs.

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

Points clés :

- Émettre l'entrée **après** un déchiffrement réussi (pas de log d'accès pour une
  lecture qui a échoué en `null` après shredding - ou alors avec une finalité distincte).
- `actorId` omis pour un accès purement système (batch, synchro).
- Utiliser `redactProfile` si le journal capture aussi un aperçu - jamais de valeur PII
  en clair dans le sink.

---

## Exemple complet (copier-coller)

Un seul module assemblant tout le code fonctionnel de la recette : câblage (chiffrement de
champ par tenant en contexte HKDF **dédié**, store de clé par sujet **wrappé at-rest**,
crypto-shredder, journal d'accès), puis les chemins écriture / lecture tracée / effacement /
purge par rétention, et minimisation / redaction. Les `prisma.*` sont **tes** délégués
Prisma (tables à définir, voir §8) ; `masterKey` vient du coffre.

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

## 8. Fourni vs. à écrire

### Fourni (prêt à l'emploi, symboles réels)

- **Classification** - `classify`, `isPii`, `PII_FIELDS`, `PiiSensitivity`
  (`@kengela/pii`). Registre complet identité + coordonnées + org.
- **Chiffrement at-rest par tenant** - `AesGcmKeyManagement` (HKDF-SHA256 par tenant,
  `KeyManagementPort`) + `AesGcmFieldCipher` (`FieldCipherPort`, base64)
  (`@kengela/adapter-authn-native`).
- **Chiffrement par sujet** - `SubjectFieldCipher` (`encryptFor` / `decryptFor` →
  `null` si clé détruite).
- **`SubjectKeyStore` persistant (Prisma)** - `PrismaSubjectKeyStore`
  (`@kengela/adapter-persistence-prisma`), options `{ keyManagement?, keyBytes? }` : clé de
  sujet **wrappée at-rest** si un `KeyManagementPort` est injecté, `getOrCreateKey`
  idempotent, `deleteKey` réellement destructif.
- **`PiiAccessLogSink` persistant (Prisma)** - `PrismaPiiAccessLogSink`
  (`@kengela/adapter-persistence-prisma`) : une ligne d'audit par accès.
- **Crypto-shredding** - `SubjectCryptoShredder` (`ErasurePort.eraseSubject`).
- **Minimisation / redaction** - `minimizeProfile`, `redactProfile` (`@kengela/pii`).
- **Rétention** - `retentionExpired`, `DEFAULT_RETENTION`, `RetentionPolicy`
  (`@kengela/pii`).
- **Contrats de ports** - `FieldCipherPort`, `KeyManagementPort`, `SubjectKeyStore`,
  `ErasurePort`, `PiiAccessLogSink` (`@kengela/contracts`).

### À écrire côté application (non fourni)

- **Schéma Prisma + migration** - `PrismaSubjectKeyStore` et `PrismaPiiAccessLogSink` sont
  fournis, mais **la table Prisma** (modèle `SubjectKey` avec clé unique
  `(tenantId, subjectId)` + colonne `key`, modèle d'audit `PiiAccessLog`) et sa migration
  sont à définir dans **ton** `schema.prisma`. Injecte un `KeyManagementPort` dans
  `PrismaSubjectKeyStore` (option `keyManagement`) pour ne jamais stocker la clé en clair ;
  la propagation destructive aux réplicas/backups reste un choix d'exploitation (expiration).
- **Déclencheurs de purge** - cron/job qui parcourt les enregistrements, calcule
  l'ancienneté, applique `retentionExpired(classify(field), ageMs)` puis appelle
  `ErasurePort.eraseSubject`. La décision est fournie (fonction pure), l'ordonnancement
  non.
- **Câblage ORM / persistance** - brancher `encryptField` / `decryptField` (ou
  `SubjectFieldCipher`) dans les hooks de lecture/écriture (Prisma middleware / repos),
  décider colonne par colonne « clair vs chiffré tenant vs chiffré sujet » à partir de
  `classify`, et invoquer `PiiAccessLogSink.record` sur chaque chemin de lecture PII.
- **Chargement de la clé maître / des politiques** - `masterKey` d'`AesGcmKeyManagement`
  provient du coffre (`SecretsPort` / Vault) ; les durées de `RetentionPolicy` sont un
  choix métier par app. Rien n'est en dur.

> Invariant : le noyau ne connaît que les **ports** (`@kengela/contracts`) et les
> **fonctions pures** (`@kengela/pii`). Tout ce qui touche le disque (clés, journal,
> ORM, cron) est un adaptateur applicatif - c'est là que se concentre le travail à
> écrire.
