# Recette 12 — Provisioning Microsoft Entra ID (Azure AD) via SCIM 2.0

Provisionner automatiquement les comptes et groupes depuis **Microsoft Entra ID** vers
votre application, sans écrire de code de synchronisation. Entra pousse les changements
(création, mise à jour, désactivation) en appelant un endpoint **SCIM 2.0** que vous
exposez ; Kengela fournit les handlers, la validation, la sérialisation et le mapping vers
le modèle interne. Vous, vous branchez la persistance et l'authentification du jeton.

---

## 1. Le flux, et qui fournit quoi

```
Microsoft Entra ID  ──HTTP(S) SCIM 2.0──▶  Votre endpoint /scim/v2/*
(Enterprise App,                              │
 Provisioning "Automatic")                    ▼
                                    @kengela/scim-server (handlers PURS)
                                    handleUsersPost / handleUsersPatch / …
                                    handleGroupsPost / handleGroupsPatch / …
                                    handleServiceProviderConfig / handleSchemas / …
                                              │
                            ┌─────────────────┴──────────────────┐
                            ▼                                     ▼
                    ScimStore (votre                    @kengela/iam-mapping
                    adapter Prisma)                     profileFromScim → DirectoryProfile
                            │                            evaluateMappings → rôles + unité
                            ▼
                    Base de l'application
```

Entra parle SCIM. Le cœur `@kengela/scim-server` traduit chaque requête SCIM en un appel de
**port de persistance** et renvoie une réponse SCIM conforme. Le mapping des rôles internes
est un second temps, alimenté par `@kengela/iam-mapping`.

### Ce que Kengela fournit (aucun HTTP, aucune base)

- **Handlers Users** — `handleUsersPost`, `handleUsersPostStrict`, `handleUsersGet`,
  `handleUsersList`, `handleUsersPatch`, `handleUsersPut`, `handleUsersDelete`.
- **Handlers Groups** — `handleGroupsPost`, `handleGroupsGet`, `handleGroupsList`,
  `handleGroupsPatch`, `handleGroupsPut`, `handleGroupsDelete`.
- **Découverte (auto-description)** — `handleServiceProviderConfig`, `handleResourceTypes`,
  `handleSchemas` (+ leurs générateurs purs `serviceProviderConfig()`, `resourceTypes()`,
  `schemaDefinitions()`).
- **Validation** — `validateScimUser`, `validateScimGroup` → `ScimValidationResult`.
- **Sérialisation / parsing** — `toScimUser`, `toScimGroup`, `userListResponse`,
  `groupListResponse`, `scimError`, `parseUserPatch`, `parseGroupMemberPatch`,
  `parseUserNameFilter`, `parseExternalIdFilter`, `parseDisplayNameFilter`,
  `parsePagination`, et les extracteurs de corps `emailOf` / `givenNameOf` / `familyNameOf`
  / `displayNameOf` / `groupDisplayNameOf` / `externalIdOf` / `activeOf` / `memberIdsOf`.
- **Mapping** — `profileFromScim`, `evaluateMappings` (dans `@kengela/iam-mapping`).

### Ce que l'application fournit

- **L'implémentation du port `ScimStore`** (la vraie persistance Prisma/SQL).
- **Le montage HTTP** : un routeur Express ou un contrôleur NestJS qui parse la requête,
  résout le `tenantId`, appelle le handler et sérialise la `ScimResponse`.
- **L'authentification du Bearer token** que Entra envoie dans `Authorization`.

> Les handlers sont **purs** : `(store, ScimRequest) => Promise<ScimResponse>`. Aucune
> dépendance à Express/Nest, aucune I/O directe. Ils sont testables sans réseau ni base.

---

## 2. Installation

```bash
npm install @kengela/scim-server @kengela/iam-mapping @kengela/contracts
```

ESM only (`"type": "module"`), TypeScript strict. Les imports internes sont en `.js`
(NodeNext).

---

## 3. Implémenter la persistance : le port `ScimStore`

**Attention à la nomenclature — deux ports coexistent :**

| Port             | Paquet                 | Rôle                                                                                                                                                         |
| ---------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ScimStore`      | `@kengela/scim-server` | Port NARROW **consommé par les handlers**. CRUD SCIM complet Users + Groups. **C'est celui que vous implémentez pour cette recette.**                        |
| `ScimRepository` | `@kengela/contracts`   | Port ATRIUM historique à 2 méthodes (`upsertUserByEmail`, `deactivateUser`). Orienté « pull/upsert par profil », pas CRUD SCIM. Non requis par les handlers. |

Les handlers SCIM de cette recette parlent à **`ScimStore`**. `ScimRepository` (contracts)
reste utile pour un flux d'import « pull » (Graph/OIDC) qui écrit directement un
`DirectoryProfile` ; il n'est pas le port du serveur SCIM « push ». Voir §5 pour le lien.

### Interface réelle (`@kengela/scim-server`)

```ts
import type { TenantId } from '@kengela/contracts';

export interface ScimStore {
  getUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null>;
  findUserByEmail(tenantId: TenantId, email: string): Promise<ScimUserRow | null>;
  listUsers(tenantId: TenantId, options: ScimUserListOptions): Promise<ScimListPage<ScimUserRow>>;
  createUser(tenantId: TenantId, input: ScimUserWriteInput): Promise<ScimUserRow>;
  replaceUser(
    tenantId: TenantId,
    id: string,
    input: ScimUserWriteInput,
  ): Promise<ScimUserRow | null>;
  patchUser(tenantId: TenantId, id: string, patch: ScimUserPatch): Promise<ScimUserRow | null>;
  deactivateUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null>;

  getGroup(tenantId: TenantId, id: string): Promise<ScimGroupRow | null>;
  listGroups(
    tenantId: TenantId,
    options: ScimGroupListOptions,
  ): Promise<ScimListPage<ScimGroupRow>>;
  createGroup(tenantId: TenantId, input: ScimGroupWriteInput): Promise<ScimGroupRow>;
  replaceGroup(
    tenantId: TenantId,
    id: string,
    input: ScimGroupWriteInput,
  ): Promise<ScimGroupRow | null>;
  patchGroup(
    tenantId: TenantId,
    id: string,
    ops: readonly GroupMemberPatch[],
  ): Promise<ScimGroupRow | null>;
  deleteGroup(tenantId: TenantId, id: string): Promise<boolean>;
}
```

Invariants exigés par le contrat (`types.ts`) :

- `findUserByEmail` : réconciliation **insensible à la casse** (idempotence du provisioning ;
  `handleUsersPost` s'en sert pour ne jamais créer de doublon).
- `deactivateUser` : **désactive** (`active=false`), ne supprime **jamais** physiquement
  (déprovisionnement RGPD-safe). `handleUsersDelete` appelle cette méthode.
- `listUsers`/`listGroups` : `totalResults` = total filtré **avant** pagination.

### Formes des lignes et des entrées

```ts
interface ScimUserRow {
  readonly id: string;
  readonly userName: string; // porte l'e-mail (clé de réconciliation)
  readonly externalId: string | null;
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly active: boolean;
  readonly createdAt: string; // ISO 8601
  readonly lastModified: string; // ISO 8601
}
interface ScimUserWriteInput {
  // POST + PUT
  readonly userName: string;
  readonly externalId: string | null;
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly active: boolean;
}
interface ScimUserPatch {
  // PATCH normalisé
  readonly active: boolean | null; // null = non touché
  readonly identity: {
    // undefined = non touché ; null = effacé
    readonly firstName?: string | null;
    readonly lastName?: string | null;
    readonly displayName?: string | null;
  };
}
type GroupMemberPatch =
  | { readonly kind: 'add'; readonly members: readonly string[] }
  | { readonly kind: 'remove'; readonly members: readonly string[] }
  | { readonly kind: 'replace'; readonly members: readonly string[] };
```

### Exemple d'adapter Prisma minimal

```ts
import type {
  ScimStore,
  ScimUserRow,
  ScimGroupRow,
  ScimUserWriteInput,
  ScimUserPatch,
  ScimGroupWriteInput,
  GroupMemberPatch,
  ScimUserListOptions,
  ScimGroupListOptions,
  ScimListPage,
} from '@kengela/scim-server';
import type { TenantId } from '@kengela/contracts';
import type { PrismaClient } from '@prisma/client';

const iso = (d: Date) => d.toISOString();

function toUserRow(u: {
  id: string;
  userName: string;
  externalId: string | null;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}): ScimUserRow {
  return {
    id: u.id,
    userName: u.userName,
    externalId: u.externalId,
    firstName: u.firstName,
    lastName: u.lastName,
    displayName: u.displayName,
    active: u.active,
    createdAt: iso(u.createdAt),
    lastModified: iso(u.updatedAt),
  };
}

export class PrismaScimStore implements ScimStore {
  constructor(private readonly db: PrismaClient) {}

  async getUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null> {
    const u = await this.db.scimUser.findFirst({ where: { id, tenantId } });
    return u ? toUserRow(u) : null;
  }

  async findUserByEmail(tenantId: TenantId, email: string): Promise<ScimUserRow | null> {
    const u = await this.db.scimUser.findFirst({
      where: { tenantId, userName: { equals: email, mode: 'insensitive' } }, // insensible à la casse
    });
    return u ? toUserRow(u) : null;
  }

  async listUsers(tenantId: TenantId, o: ScimUserListOptions): Promise<ScimListPage<ScimUserRow>> {
    const where = {
      tenantId,
      ...(o.userName ? { userName: { equals: o.userName, mode: 'insensitive' as const } } : {}),
      ...(o.externalId ? { externalId: o.externalId } : {}), // caseExact
    };
    const [total, rows] = await this.db.$transaction([
      this.db.scimUser.count({ where }),
      this.db.scimUser.findMany({
        where,
        skip: o.startIndex - 1,
        take: o.count,
        orderBy: { createdAt: 'asc' },
      }),
    ]);
    return {
      resources: rows.map(toUserRow),
      totalResults: total,
      startIndex: o.startIndex,
      itemsPerPage: rows.length,
    };
  }

  async createUser(tenantId: TenantId, i: ScimUserWriteInput): Promise<ScimUserRow> {
    return toUserRow(await this.db.scimUser.create({ data: { tenantId, ...i } }));
  }

  async replaceUser(
    tenantId: TenantId,
    id: string,
    i: ScimUserWriteInput,
  ): Promise<ScimUserRow | null> {
    const found = await this.db.scimUser.findFirst({ where: { id, tenantId } });
    if (!found) return null;
    return toUserRow(await this.db.scimUser.update({ where: { id }, data: { ...i } }));
  }

  async patchUser(tenantId: TenantId, id: string, p: ScimUserPatch): Promise<ScimUserRow | null> {
    const found = await this.db.scimUser.findFirst({ where: { id, tenantId } });
    if (!found) return null;
    const data: Record<string, unknown> = {};
    if (p.active !== null) data['active'] = p.active;
    if (p.identity.firstName !== undefined) data['firstName'] = p.identity.firstName; // null = effacé
    if (p.identity.lastName !== undefined) data['lastName'] = p.identity.lastName;
    if (p.identity.displayName !== undefined) data['displayName'] = p.identity.displayName;
    return toUserRow(await this.db.scimUser.update({ where: { id }, data }));
  }

  async deactivateUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null> {
    const found = await this.db.scimUser.findFirst({ where: { id, tenantId } });
    if (!found) return null;
    return toUserRow(await this.db.scimUser.update({ where: { id }, data: { active: false } }));
  }

  // ── Groups ────────────────────────────────────────────────────────────────
  async getGroup(tenantId: TenantId, id: string): Promise<ScimGroupRow | null> {
    /* … */ return null;
  }
  async listGroups(
    tenantId: TenantId,
    o: ScimGroupListOptions,
  ): Promise<ScimListPage<ScimGroupRow>> {
    /* même schéma que listUsers, filtre displayName eq */ return {
      resources: [],
      totalResults: 0,
      startIndex: o.startIndex,
      itemsPerPage: 0,
    };
  }
  async createGroup(tenantId: TenantId, i: ScimGroupWriteInput): Promise<ScimGroupRow> {
    /* … */ throw new Error('impl');
  }
  async replaceGroup(
    tenantId: TenantId,
    id: string,
    i: ScimGroupWriteInput,
  ): Promise<ScimGroupRow | null> {
    return null;
  }
  async patchGroup(
    tenantId: TenantId,
    id: string,
    ops: readonly GroupMemberPatch[],
  ): Promise<ScimGroupRow | null> {
    // appliquer add/remove/replace sur la table de jointure membre↔groupe, borné au tenant
    return null;
  }
  async deleteGroup(tenantId: TenantId, id: string): Promise<boolean> {
    return false;
  }
}
```

---

## 4. Monter l'endpoint SCIM

L'adapter fait **quatre choses** : (1) authentifie le Bearer token, (2) résout le
`tenantId`, (3) construit un `ScimRequest`, (4) appelle le handler et sérialise la
`ScimResponse` en `application/scim+json`.

```ts
export interface ScimRequest {
  readonly tenantId: TenantId;
  readonly pathId?: string; // segment /:id
  readonly query?: {
    readonly filter?: string;
    readonly startIndex?: string | number;
    readonly count?: string | number;
  };
  readonly body?: unknown; // JSON déjà désérialisé
}
export interface ScimResponse {
  readonly status: number;
  readonly body?: Readonly<Record<string, unknown>>;
}
```

### Variante Express

```ts
import express from 'express';
import {
  handleUsersPost,
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
  handleServiceProviderConfig,
  handleResourceTypes,
  handleSchemas,
  validateScimUser,
  validateScimGroup,
  scimError,
} from '@kengela/scim-server';

export function scimRouter(store: ScimStore, resolveTenant: (req: express.Request) => TenantId) {
  const r = express.Router();
  r.use(express.json({ type: ['application/json', 'application/scim+json'] }));

  // (1) Auth du Bearer token — voir §8
  r.use((req, res, next) => {
    if (!isValidBearer(req.header('authorization'))) {
      return res
        .status(401)
        .type('application/scim+json')
        .json(scimError(401, 'Jeton porteur invalide.', 'invalidCredentials'));
    }
    next();
  });

  const send = (res: express.Response, out: { status: number; body?: object }) =>
    out.body === undefined
      ? res.status(out.status).end()
      : res.status(out.status).type('application/scim+json').json(out.body);

  const reqOf = (req: express.Request): ScimRequest => ({
    tenantId: resolveTenant(req),
    pathId: req.params['id'],
    query: {
      filter: req.query['filter'] as string | undefined,
      startIndex: req.query['startIndex'] as string | undefined,
      count: req.query['count'] as string | undefined,
    },
    body: req.body,
  });

  // ── Découverte (aucun store) ──────────────────────────────────────────────
  r.get('/ServiceProviderConfig', (_req, res) => send(res, handleServiceProviderConfig()));
  r.get('/ResourceTypes/:id?', (req, res) => send(res, handleResourceTypes(req.params['id'])));
  r.get('/Schemas/:id?', (req, res) => send(res, handleSchemas(req.params['id'])));

  // ── Users ─────────────────────────────────────────────────────────────────
  r.post('/Users', async (req, res) => {
    const v = validateScimUser(req.body); // validation d'entrée
    if (!v.valid)
      return send(res, { status: 400, body: scimError(400, v.errors.join(' '), 'invalidValue') });
    send(res, await handleUsersPost(store, reqOf(req)));
  });
  r.get('/Users', async (req, res) => send(res, await handleUsersList(store, reqOf(req))));
  r.get('/Users/:id', async (req, res) => send(res, await handleUsersGet(store, reqOf(req))));
  r.put('/Users/:id', async (req, res) => {
    const v = validateScimUser(req.body);
    if (!v.valid)
      return send(res, { status: 400, body: scimError(400, v.errors.join(' '), 'invalidValue') });
    send(res, await handleUsersPut(store, reqOf(req)));
  });
  r.patch('/Users/:id', async (req, res) => send(res, await handleUsersPatch(store, reqOf(req))));
  r.delete('/Users/:id', async (req, res) => send(res, await handleUsersDelete(store, reqOf(req))));

  // ── Groups ──────────────────────────────────────────────────────────────── (mêmes 6 verbes,
  // valider avec validateScimGroup sur POST/PUT)
  r.post('/Groups', async (req, res) => {
    const v = validateScimGroup(req.body);
    if (!v.valid)
      return send(res, { status: 400, body: scimError(400, v.errors.join(' '), 'invalidValue') });
    send(res, await handleGroupsPost(store, reqOf(req)));
  });
  r.get('/Groups', async (req, res) => send(res, await handleGroupsList(store, reqOf(req))));
  r.get('/Groups/:id', async (req, res) => send(res, await handleGroupsGet(store, reqOf(req))));
  r.put('/Groups/:id', async (req, res) => send(res, await handleGroupsPut(store, reqOf(req))));
  r.patch('/Groups/:id', async (req, res) => send(res, await handleGroupsPatch(store, reqOf(req))));
  r.delete('/Groups/:id', async (req, res) =>
    send(res, await handleGroupsDelete(store, reqOf(req))),
  );
  return r;
}
```

Montage : `app.use('/scim/v2', scimRouter(store, resolveTenant))`.

### Variante NestJS (esquisse)

Un `@Controller('scim/v2')` reproduit exactement le même câblage : une méthode par
verbe/ressource, un `ScimAuthGuard` pour le Bearer, un helper qui transforme le résultat en
réponse `application/scim+json`. Les handlers restant purs, le contrôleur ne contient que du
transport.

> **Point d'attention Kengela** : ne PAS décorer avec `@Controller({ version })` sans avoir
> activé `enableVersioning`, sinon 404. Le versionnage SCIM (`/v2`) se fait dans le chemin,
> pas via l'URI versioning Nest.

### Note sur la validation

`validateScimUser` / `validateScimGroup` renvoient `{ valid: boolean; errors: readonly string[] }`.
Contrôles : `schemas` présent/non vide/URNs reconnues ; attribut requis présent (`userName`
pour User, `displayName` pour Group) ; types scalaires ; multi-valués bien formés. C'est une
validation **fail-closed** de VOTRE schéma, à l'entrée comme en sortie (round-trip :
`toScimUser(row)` repasse `validateScimUser`). Les filtres et la pagination sont parsés par
les handlers eux-mêmes via `parseUserNameFilter`/`parseExternalIdFilter`/`parsePagination` ;
inutile de les traiter dans l'adapter.

---

## 5. Mapping vers `DirectoryProfile` puis rôles internes

Deux temps distincts : la **persistance SCIM** (§3-4) accepte le flux Entra, puis un job de
**mapping** projette ces données vers les rôles applicatifs.

### `profileFromScim` → `DirectoryProfile` (variante riche)

```ts
import { profileFromScim, evaluateMappings } from '@kengela/iam-mapping';

const profile = profileFromScim(scimBody); // scimBody = corps SCIM brut poussé par Entra
// → DirectoryProfile (variante iam-mapping) :
//   { email, externalId, firstName, lastName, displayName, attributes, groups, claims }
```

**Deux `DirectoryProfile` cohabitent — ne pas les confondre :**

|                     | `@kengela/iam-mapping` (riche)           | `@kengela/contracts` (minimal) |
| ------------------- | ---------------------------------------- | ------------------------------ |
| Retourné par        | `profileFromScim`, `profileFromGraph`, … | port `DirectorySourcePort`     |
| `email`             | `string` (obligatoire, lowercasé)        | `email?: string`               |
| `externalId`        | `string \| null`                         | `string` (obligatoire)         |
| Identité            | `firstName`/`lastName`/`displayName`     | `displayName?` seul            |
| `attributes`        | `DirectoryAttributes` typé               | `Record<string, unknown>`      |
| `active` / `source` | absents                                  | présents                       |
| `claims`            | présent (règles avancées)                | absent                         |

`profileFromScim` produit la **variante riche**. C'est elle que le moteur de règles consomme.
Si vous devez alimenter le port `ScimRepository`/`DirectorySourcePort` de `contracts`
(variante minimale), projetez explicitement (l'`active` vient de `activeOf(body)`, la
`source` vaut `'scim'`).

`profileFromScim` accepte un `ScimAttributeMap` optionnel (config tenant) pour surcharger les
chemins lus, champ par champ. Défauts (`SCIM_DEFAULT_ATTRIBUTE_KEYS`) : `email` =
`userName` puis `emails[primary]`, `firstName` = `name.givenName`, `department` =
`enterprise.department`, etc. L'extension enterprise est lue sous l'URN
`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`.

### `evaluateMappings` → rôles + unité d'organigramme

```ts
import type { IdpMappingRule } from '@kengela/iam-mapping';

const rules: IdpMappingRule[] = [
  {
    id: 'admins',
    priority: 0,
    stopOnMatch: true,
    any: [{ source: 'GROUP', op: 'iequals', value: 'Kengela-Admins' }],
    assignRoleKeys: ['ADM'],
  },
  {
    id: 'compta',
    priority: 10,
    all: [{ source: 'ATTRIBUTE', key: 'department', op: 'iequals', value: 'Finance' }],
    assignRoleKeys: ['VAL'],
    orgUnit: { by: 'name', fromAttribute: 'department' },
  },
];

const result = evaluateMappings(profile, rules);
// → { roleKeys, orgUnitDirectives, matchedRuleIds }
```

Le moteur est **déterministe** (tri par `priority` puis `id`), accumule les rôles en union,
respecte `stopOnMatch`. Les règles sont **configurables par tenant** (jamais en dur). Les
conditions testent les `groups`, les `claims` OIDC ou les `attributes` SCIM, avec les
opérateurs `equals`/`iequals`/`contains`/`matches`/`in`/`present`. `matches` compile une
regex **bornée anti-ReDoS** (`safeRegexTest`, fail-closed).

Le pipeline complet côté app : `profileFromScim(body)` → `evaluateMappings(profile, rules)`
→ appliquer `roleKeys` + `orgUnitDirectives` via vos repos (grants + rattachement).

---

## 6. Configurer Microsoft Entra ID

Dans le portail Entra : **Entreprise applications → (votre app) → Provisioning**, mode
**Automatic**. Section **Admin Credentials** :

- **Tenant URL** = l'URL publique de votre endpoint, terminant par le point de montage SCIM,
  p. ex. `https://app.exemple.com/scim/v2`. Entra ajoute lui-même `/Users`, `/Groups`, etc.
- **Secret Token** = le Bearer token que vous générez et que votre app validera (§8). Entra
  l'enverra dans l'en-tête `Authorization: Bearer <token>` de chaque requête.
- Bouton **Test Connection** : Entra appelle `GET /ServiceProviderConfig`, `GET /Schemas`,
  `GET /ResourceTypes`, puis un `GET /Users?filter=userName eq "..."` et un
  `GET /Users?filter=externalId eq "..."`. Les deux filtres sont supportés par
  `handleUsersList` — indispensable pour que le test passe.

**Attribute Mappings** (section Mappings) : conserver les mappings SCIM standard d'Entra.
Les défauts d'Entra correspondent aux chemins lus par `profileFromScim` :

| Attribut Entra            | Chemin SCIM émis               | Lu par                        |
| ------------------------- | ------------------------------ | ----------------------------- |
| `userPrincipalName`       | `userName`                     | `emailOf` / `email`           |
| `mail`                    | `emails[type eq "work"].value` | `emailOf` (repli)             |
| `givenName`               | `name.givenName`               | `givenNameOf`                 |
| `surname`                 | `name.familyName`              | `familyNameOf`                |
| `displayName`             | `displayName`                  | `displayNameOf`               |
| `objectId`                | `externalId`                   | `externalIdOf`                |
| `isSoftDeleted` (inversé) | `active`                       | `activeOf`                    |
| `department`              | `enterprise:department`        | `profileFromScim` (attributs) |

Pour provisionner aussi les **groupes**, activer « Provision Microsoft Entra ID Groups » et
assigner les groupes à l'application. Entra crée alors les groupes via `POST /Groups` et gère
les membres via `PATCH /Groups/:id` (`members[value eq "<id>"]` pour les retraits ciblés,
géré par `parseGroupMemberPatch`).

---

## 7. Test de conformité

Microsoft fournit un **validateur SCIM** (« Test the SCIM endpoint compatibility », module
PowerShell / Postman collection publiée par Microsoft) qui rejoue la suite d'appels attendue
par Entra. À défaut, le bouton **Test Connection** du portail exerce le chemin critique.

Endpoints obligatoires SCIM 2.0 et leur couverture :

| Endpoint                                            | Fournisseur Kengela                            | Statut     |
| --------------------------------------------------- | ---------------------------------------------- | ---------- |
| `/Users` (POST/GET/PUT/PATCH/DELETE + list+filter)  | handlers `users.ts`                            | ✅ couvert |
| `/Groups` (POST/GET/PUT/PATCH/DELETE + list+filter) | handlers `groups.ts`                           | ✅ couvert |
| `/ServiceProviderConfig`                            | `handleServiceProviderConfig` (`discovery.ts`) | ✅ couvert |
| `/Schemas` (+ `/Schemas/:urn`)                      | `handleSchemas` (`discovery.ts`)               | ✅ couvert |
| `/ResourceTypes` (+ `/ResourceTypes/:id`)           | `handleResourceTypes` (`discovery.ts`)         | ✅ couvert |

`discovery.ts` couvre **les trois endpoints de découverte**. `serviceProviderConfig()` déclare
les capacités réelles du cœur : `patch` supporté, `filter` supporté (borné à `MAX_PAGE_SIZE`),
`bulk`/`sort`/`etag`/`changePassword` **non** supportés, schéma d'authentification
`oauthbearertoken`. `schemaDefinitions()` décrit core User (RFC 7643 §4.1), extension
enterprise (§4.3) et Group (§4.2) — exactement ce que `toScimUser`/`toScimGroup` savent
porter, et ce que `validateScimUser` vérifie (round-trip garanti).

Points que le validateur Entra contrôle et qui sont déjà gérés :

- **Idempotence** : un `POST /Users` d'un e-mail existant renvoie 200 sans doublon
  (`handleUsersPost` réconcilie via `findUserByEmail`). Si l'IdP attend un rejet strict de
  doublon (409 `uniqueness`), câbler `handleUsersPostStrict` à la place.
- **Filtre par `externalId`** : `GET /Users?filter=externalId eq "..."` supporté.
- **Déprovisionnement** : `DELETE /Users/:id` désactive (204), ne supprime pas.
- **Erreurs SCIM** : `scimError` produit l'enveloppe RFC 7644 §3.12 (`status` en chaîne +
  `scimType` + `detail`).

---

## 8. Encadré — fourni vs à écrire

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ FOURNI PAR KENGELA (aucune ligne à écrire)                                     │
│  • Handlers Users + Groups (CRUD SCIM, réconciliation, désactivation)          │
│  • Découverte : ServiceProviderConfig / Schemas / ResourceTypes (discovery.ts) │
│  • Validation : validateScimUser / validateScimGroup                           │
│  • Sérialisation/parsing : toScimUser, parseUserPatch, parseGroupMemberPatch,  │
│    filtres eq bornés, pagination, scimError                                    │
│  • Mapping : profileFromScim → DirectoryProfile, evaluateMappings → rôles      │
├──────────────────────────────────────────────────────────────────────────────┤
│ À ÉCRIRE PAR L'APPLICATION                                                      │
│  • ScimStore : l'implémentation Prisma/SQL réelle (§3)                          │
│    – insensibilité à la casse sur findUserByEmail                              │
│    – désactivation ≠ suppression                                              │
│    – totalResults avant pagination                                            │
│  • Montage de l'endpoint : routeur Express OU contrôleur NestJS (§4)            │
│    – parse corps + query, résolution tenantId, sérialisation scim+json        │
│  • Authentification du Bearer token (§6) :                                     │
│    – comparer le jeton Entra en TEMPS CONSTANT (timing-safe)                   │
│    – stocker le secret hors code (Vault/env), rotation possible               │
│    – 401 + scimError('invalidCredentials') si absent/invalide                 │
│  • Application des résultats de mapping (grants + rattachement org)             │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Sécurité du Bearer** : Entra n'utilise pas OAuth2 côté client par défaut mais un jeton
long-vécu ; traitez-le comme un secret de premier plan. Comparaison à temps constant
(`crypto.timingSafeEqual`), jamais de log du jeton, HTTPS obligatoire, et idéalement une
allow-list d'IP Entra en amont. C'est le **seul** verrou d'accès à un endpoint qui écrit dans
votre annuaire : ne le sous-traitez pas à un middleware générique sans le vérifier.
