# 06 - Conformité & données personnelles (PII)

La conformité RGPD est **intégrée par conception**, pas ajoutée après coup. `@kengela/pii` (cœur, pur)
couvre classification, minimisation et redaction ; les ports de `@kengela/contracts` couvrent le
chiffrement de champ, le journal d'accès et l'effacement ; `@kengela/adapter-authn-native` fournit le
crypto-shredding concret (voir aussi [03-authentication.md](./03-authentication.md)).

> Les fonctions de `@kengela/pii` opèrent sur le `DirectoryProfile` **riche** de
> `@kengela/iam-mapping`.

## Classification

`classify(field)` renvoie la sensibilité d'un champ, sur trois niveaux :

| Sensibilité | Signification                                           | Exemples                                                                                      |
| ----------- | ------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `none`      | non personnel (identifiant technique, rattachement org) | `externalId`, `department`, `title`, `costCenter`, `locale`                                   |
| `pii`       | donnée personnelle (identifiabilité directe/indirecte)  | `email`, `firstName`, `lastName`, `phoneNumber`, `streetAddress`, `employeeNumber`, `manager` |
| `sensitive` | catégorie particulière (RGPD art. 9 : santé, biométrie) | _(aucune dans un annuaire standard ; prévu pour extension)_                                   |

```ts
import { classify, isPii, PII_FIELDS } from '@kengela/pii';

classify('email'); // 'pii'
classify('department'); // 'none'
isPii('phoneNumber'); // true
PII_FIELDS; // liste des champs classés personnels
```

Le registre est la source de vérité : un champ inconnu retombe sur `none`.

## Minimisation (art. 5.1.c)

`minimizeProfile(profile, allowedFields)` ne conserve **que** les attributs explicitement autorisés
pour la finalité de l'app. Les `claims` bruts sont supprimés ; les champs d'identité non autorisés
sont neutralisés (`null`).

```ts
import { minimizeProfile } from '@kengela/pii';

const minimal = minimizeProfile(profile, ['email', 'firstName', 'department']);
// firstName conservé ; lastName/displayName → null ; attributs limités à department ; claims vidés
```

C'est le pendant « données » du principe Kengela « chaque app pioche son sous-ensemble » : on ne
transporte pas les attributs dont on n'a pas besoin.

## Redaction / masquage (journaux & affichage)

`redactProfile(profile)` masque les données personnelles sans les exposer en clair, pour les
journaux ou l'affichage partiel. L'e-mail est masqué en gardant le domaine ; les champs `pii` sont
réduits à leur initiale ; les champs non personnels restent intacts.

```ts
import { redactProfile } from '@kengela/pii';

const safe = redactProfile(profile);
// email 'alice@corp.example' → 'a***@corp.example' ; firstName 'Alice' → 'A***' ; department inchangé
```

## Rétention (art. 5.1.e)

`retentionExpired(sensitivity, ageMs, policy?)` dit si une donnée a dépassé sa durée de conservation.
La politique par défaut est **prudente** :

| Sensibilité | Durée par défaut (`DEFAULT_RETENTION`) |
| ----------- | -------------------------------------- |
| `none`      | illimité (`null`)                      |
| `pii`       | 2 ans (730 jours)                      |
| `sensitive` | 6 mois (182 jours)                     |

```ts
import { retentionExpired, DEFAULT_RETENTION, type RetentionPolicy } from '@kengela/pii';

const ageMs = Date.now() - createdAt.getTime();
if (retentionExpired('pii', ageMs)) {
  // au-delà de la rétention → purge / anonymisation
}

// Une app peut fixer ses propres durées :
const myPolicy: RetentionPolicy = {
  none: null,
  pii: 365 * 24 * 3600 * 1000,
  sensitive: 90 * 24 * 3600 * 1000,
};
retentionExpired('pii', ageMs, myPolicy);
```

## Chiffrement at-rest des PII (`FieldCipherPort`)

Les PII stockées sont chiffrées au **niveau champ**, avec isolation cryptographique **par tenant**.
Le port :

```ts
interface FieldCipherPort {
  encryptField(tenantId: TenantId, plaintext: string): Promise<string>; // → base64 stockable
  decryptField(tenantId: TenantId, ciphertext: string): Promise<string>;
}
```

Implémentation : `AesGcmFieldCipher` (AES-256-GCM, clé dérivée par tenant). Voir
[03-authentication.md](./03-authentication.md#chiffrement-de-champ--crypto-shredding).

## Effacement / droit à l'oubli (art. 17) — crypto-shredding

L'effacement recommandé est le **crypto-shredding** : chaque personne concernée (`subjectId`) a sa
propre clé (`SubjectKeyStore`) ; détruire la clé rend toutes ses PII chiffrées **définitivement
illisibles**, sans balayer chaque table.

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

`SubjectFieldCipher` chiffre/déchiffre par sujet (retourne `null` si la clé a été détruite),
`SubjectCryptoShredder` implémente `ErasurePort` :

```ts
import { SubjectFieldCipher, SubjectCryptoShredder } from '@kengela/adapter-authn-native';

const cipher = new SubjectFieldCipher(subjectKeyStore);
const shredder = new SubjectCryptoShredder(subjectKeyStore);

await shredder.eraseSubject('t1', 'subject-42');
await cipher.decryptFor('t1', 'subject-42', enc); // null : donnée « shreddée »
```

Contrôles prouvés : après effacement, la PII est illisible ; la clé d'un autre sujet ne déchiffre
pas. C'est un effacement RGPD _effectif_ qui ne dépend pas d'un balayage exhaustif des tables.

## Journal d'accès aux PII (art. 30) — `PiiAccessLogSink`

Chaque **lecture/export** de données personnelles doit être traçable : qui, quel sujet, quels champs,
quelle finalité. Le port :

```ts
interface PiiAccessLogSink {
  record(entry: {
    readonly tenantId: TenantId;
    readonly subjectId: string; // personne concernée
    readonly actorId?: UserId; // absent = système
    readonly fields: readonly string[];
    readonly purpose: string; // finalité du traitement
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

// À chaque accès PII :
piiLog.record({
  tenantId: 't1',
  subjectId: 'subject-42',
  actorId: currentUser.id,
  fields: ['email', 'phoneNumber'],
  purpose: 'support_ticket_resolution',
  at: Date.now(),
});
```

L'implémentation (destination du journal) appartient à l'application ; le port garantit que la
traçabilité fait partie du contrat, pas d'un ajout optionnel.

## Récapitulatif RGPD → outil Kengela

| Exigence RGPD                          | Outil                                                                                  |
| -------------------------------------- | -------------------------------------------------------------------------------------- |
| Minimisation (art. 5.1.c)              | `minimizeProfile`                                                                      |
| Rétention (art. 5.1.e)                 | `retentionExpired`, `DEFAULT_RETENTION`                                                |
| Chiffrement at-rest                    | `FieldCipherPort` / `AesGcmFieldCipher` (par tenant), `SubjectFieldCipher` (par sujet) |
| Effacement / droit à l'oubli (art. 17) | `ErasurePort` / `SubjectCryptoShredder` (crypto-shredding)                             |
| Journal d'accès (art. 30)              | `PiiAccessLogSink`                                                                     |
| Masquage journaux/affichage            | `redactProfile`                                                                        |
| Classification                         | `classify`, `isPii`, `PII_FIELDS`                                                      |

</content>
