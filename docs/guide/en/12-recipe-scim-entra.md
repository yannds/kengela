# Recipe 12 - Provisioning Microsoft Entra ID (Azure AD) via SCIM 2.0

Automatically provision accounts and groups from **Microsoft Entra ID** into your
application, without writing any synchronization code. Entra pushes changes (creation,
update, deactivation) by calling a **SCIM 2.0** endpoint that you expose; Kengela provides
the handlers, validation, serialization and mapping to the internal model. You wire in
persistence and token authentication.

---

## 1. The flow, and who provides what

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

Entra speaks SCIM. The `@kengela/scim-server` core translates each SCIM request into a call
to a **persistence port** and returns a compliant SCIM response. Mapping to internal roles is
a second stage, powered by `@kengela/iam-mapping`.

### What Kengela provides (no HTTP, no database)

- **Users handlers** - `handleUsersPost`, `handleUsersPostStrict`, `handleUsersGet`,
  `handleUsersList`, `handleUsersPatch`, `handleUsersPut`, `handleUsersDelete`.
- **Groups handlers** - `handleGroupsPost`, `handleGroupsGet`, `handleGroupsList`,
  `handleGroupsPatch`, `handleGroupsPut`, `handleGroupsDelete`.
- **Discovery (self-description)** - `handleServiceProviderConfig`, `handleResourceTypes`,
  `handleSchemas` (+ their pure generators `serviceProviderConfig()`, `resourceTypes()`,
  `schemaDefinitions()`).
- **Validation** - `validateScimUser`, `validateScimGroup` → `ScimValidationResult`.
- **Serialization / parsing** - `toScimUser`, `toScimGroup`, `userListResponse`,
  `groupListResponse`, `scimError`, `parseUserPatch`, `parseGroupMemberPatch`,
  `parseUserNameFilter`, `parseExternalIdFilter`, `parseDisplayNameFilter`,
  `parsePagination`, and the body extractors `emailOf` / `givenNameOf` / `familyNameOf`
  / `displayNameOf` / `groupDisplayNameOf` / `externalIdOf` / `activeOf` / `memberIdsOf`.
- **Mapping** - `profileFromScim`, `evaluateMappings` (in `@kengela/iam-mapping`).

### What the application provides

- **The `ScimStore` port implementation** (the real Prisma/SQL persistence).
- **The HTTP mount**: an Express router or a NestJS controller that parses the request,
  resolves the `tenantId`, calls the handler and serializes the `ScimResponse`.
- **Authentication of the Bearer token** that Entra sends in `Authorization`.

> The handlers are **pure**: `(store, ScimRequest) => Promise<ScimResponse>`. No dependency on
> Express/Nest, no direct I/O. They are testable without network or database.

---

## 2. Installation

```bash
npm install @kengela/scim-server @kengela/iam-mapping @kengela/contracts
```

ESM only (`"type": "module"`), strict TypeScript. Internal imports use `.js` (NodeNext).

---

## 3. Implementing persistence: the `ScimStore` port

**Watch the naming - two ports coexist:**

| Port             | Package                | Role                                                                                                                                                                       |
| ---------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ScimStore`      | `@kengela/scim-server` | NARROW port **consumed by the handlers**. Full SCIM CRUD for Users + Groups. **This is the one you implement for this recipe.**                                            |
| `ScimRepository` | `@kengela/contracts`   | Historical APPLICATIVE port with 2 methods (`upsertUserByEmail`, `deactivateUser`). Oriented toward "pull/upsert by profile", not SCIM CRUD. Not required by the handlers. |

The SCIM handlers in this recipe talk to **`ScimStore`** (a rich CRUD port, `ScimUserRow`
rows…). `ScimRepository` (contracts) is a MINIMAL federation port oriented toward
reconciliation - exactly **two** methods, verified in `contracts/src/index.ts`:

```ts
// @kengela/contracts
export interface ScimRepository {
  upsertUserByEmail(
    tenantId: TenantId,
    profile: DirectoryProfile, // variante contracts (minimale)
  ): Promise<{ readonly id: string; readonly created: boolean }>;
  deactivateUser(tenantId: TenantId, id: string): Promise<void>;
}
```

The two ports **are not interchangeable**: `ScimRepository` is a synchronization VIEW on top
of `ScimStore`. The `ScimStore → ScimRepository` bridge is **not** shipped by the core, BY
DESIGN (documented in `contracts-projection.ts`): it would have to depend on both
`@kengela/scim-server` and `@kengela/contracts`, yet `iam-mapping` is a CORE package that
`scim-server` already depends on - the reverse would create a cycle. Its place is therefore a
composition adapter on the app side. The real hard part - projecting any IdP source into a
common shape - is solved by `toContractsProfile` (§5). Once the contracts profile is
obtained, the call is direct:

```ts
const profile = toContractsProfile(profileFromScim(body), { source: 'scim', active });
await scimRepository.upsertUserByEmail(tenantId, profile);
```

### Real interface (`@kengela/scim-server`)

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

Invariants required by the contract (`types.ts`):

- `findUserByEmail`: **case-insensitive** reconciliation (provisioning idempotence;
  `handleUsersPost` uses it to never create a duplicate).
- `deactivateUser`: **deactivates** (`active=false`), **never** physically deletes
  (GDPR-safe deprovisioning). `handleUsersDelete` calls this method.
- `listUsers`/`listGroups`: `totalResults` = filtered total **before** pagination.

### Shapes of rows and inputs

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

### Minimal Prisma adapter example

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

## 4. Mounting the SCIM endpoint

The adapter does **four things**: (1) authenticates the Bearer token, (2) resolves the
`tenantId`, (3) builds a `ScimRequest`, (4) calls the handler and serializes the
`ScimResponse` as `application/scim+json`.

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

### Express variant

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

  // (1) Auth du Bearer token - voir §8
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

Mount: `app.use('/scim/v2', scimRouter(store, resolveTenant))`.

### NestJS variant (sketch)

A `@Controller('scim/v2')` reproduces exactly the same wiring: one method per
verb/resource, a `ScimAuthGuard` for the Bearer, a helper that turns the result into an
`application/scim+json` response. Since the handlers stay pure, the controller contains only
transport.

> **Kengela caveat**: do NOT decorate with `@Controller({ version })` without having enabled
> `enableVersioning`, otherwise 404. SCIM versioning (`/v2`) is done in the path, not via Nest
> URI versioning.

### Note on validation

`validateScimUser` / `validateScimGroup` return `{ valid: boolean; errors: readonly string[] }`.
Checks: `schemas` present/non-empty/recognized URNs; required attribute present (`userName`
for User, `displayName` for Group); scalar types; well-formed multi-valued fields. This is a
**fail-closed** validation of YOUR schema, on input as well as output (round-trip:
`toScimUser(row)` re-runs `validateScimUser`). Filters and pagination are parsed by the
handlers themselves via `parseUserNameFilter`/`parseExternalIdFilter`/`parsePagination`; no
need to handle them in the adapter.

---

## 5. Mapping to `DirectoryProfile` then internal roles

Two distinct stages: **SCIM persistence** (§3-4) accepts the Entra flow, then a **mapping**
job projects that data toward the application roles.

### `profileFromScim` → `DirectoryProfile` (rich variant)

```ts
import { profileFromScim, evaluateMappings } from '@kengela/iam-mapping';

const profile = profileFromScim(scimBody); // scimBody = corps SCIM brut poussé par Entra
// → DirectoryProfile (variante iam-mapping) :
//   { email, externalId, firstName, lastName, displayName, attributes, groups, claims }
```

**Two `DirectoryProfile` types coexist - do not confuse them:**

|                     | `@kengela/iam-mapping` (rich)            | `@kengela/contracts` (minimal) |
| ------------------- | ---------------------------------------- | ------------------------------ |
| Returned by         | `profileFromScim`, `profileFromGraph`, … | port `DirectorySourcePort`     |
| `email`             | `string` (required, lowercased)          | `email?: string`               |
| `externalId`        | `string \| null`                         | `string` (required)            |
| Identity            | `firstName`/`lastName`/`displayName`     | `displayName?` only            |
| `attributes`        | typed `DirectoryAttributes`              | `Record<string, unknown>`      |
| `active` / `source` | absent                                   | present                        |
| `claims`            | present (advanced rules)                 | absent                         |

`profileFromScim` produces the **rich variant**. That is what the rule engine consumes.

To feed the `ScimRepository` / `DirectorySourcePort` port of `contracts` (minimal variant),
do **not** write the projection by hand: `@kengela/iam-mapping` exports the PURE function
**`toContractsProfile(rich, { source, active })`** which projects the rich `DirectoryProfile`
into the minimal shape of `contracts`. The two fields absent from the rich profile (`active`,
`source`) are supplied explicitly by the caller:

```ts
import { profileFromScim, toContractsProfile } from '@kengela/iam-mapping';
import { activeOf } from '@kengela/scim-server';

// scimBody = corps SCIM brut poussé par Entra
const rich = profileFromScim(scimBody); // DirectoryProfile riche (iam-mapping)
const active = activeOf(scimBody); // état d'activation lu du corps SCIM
const profile = toContractsProfile(rich, { source: 'scim', active });
// → DirectoryProfile MINIMAL (contracts) : { externalId, email?, displayName?,
//   groups, attributes, active, source }
```

What `toContractsProfile` guarantees, per reading of `contracts-projection.ts`:

- **`externalId` non-null**: `rich.externalId`, falling back to the email (stable fallback);
  never `undefined` on the contracts side.
- **`email` / `displayName`**: omitted (not `undefined`) when empty - honors
  `exactOptionalPropertyTypes`.
- **`firstName` / `lastName`**: folded back into `attributes` (the contracts profile has no
  dedicated name field) - nothing is lost.
- **Raw `claims` NOT carried over**: volume + potential PII.

`profileFromScim` accepts an optional `ScimAttributeMap` (tenant config) to override the read
paths, field by field. Defaults (`SCIM_DEFAULT_ATTRIBUTE_KEYS`): `email` = `userName` then
`emails[primary]`, `firstName` = `name.givenName`, `department` = `enterprise.department`,
etc. The enterprise extension is read under the URN
`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`.

### `evaluateMappings` → roles + org-chart unit

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

The engine is **deterministic** (sorted by `priority` then `id`), accumulates roles as a
union, honors `stopOnMatch`. The rules are **tenant-configurable** (never hard-coded). The
conditions test the `groups`, the OIDC `claims` or the SCIM `attributes`, with the operators
`equals`/`iequals`/`contains`/`matches`/`in`/`present`. `matches` compiles a **ReDoS-bounded**
regex (`safeRegexTest`, fail-closed).

The full app-side pipeline: `profileFromScim(body)` → `evaluateMappings(profile, rules)` →
apply `roleKeys` + `orgUnitDirectives` via your repos (grants + attachment).

---

## 6. Configuring Microsoft Entra ID

In the Entra portal: **Enterprise applications → (your app) → Provisioning**, mode
**Automatic**. **Admin Credentials** section:

- **Tenant URL** = the public URL of your endpoint, ending at the SCIM mount point, e.g.
  `https://app.exemple.com/scim/v2`. Entra itself appends `/Users`, `/Groups`, etc.
- **Secret Token** = the Bearer token you generate and that your app will validate (§8). Entra
  will send it in the `Authorization: Bearer <token>` header of every request.
- **Test Connection** button: Entra calls `GET /ServiceProviderConfig`, `GET /Schemas`,
  `GET /ResourceTypes`, then a `GET /Users?filter=userName eq "..."` and a
  `GET /Users?filter=externalId eq "..."`. Both filters are supported by `handleUsersList` -
  indispensable for the test to pass.

**Attribute Mappings** (Mappings section): keep Entra's standard SCIM mappings. Entra's
defaults match the paths read by `profileFromScim`:

| Entra attribute           | Emitted SCIM path              | Read by                        |
| ------------------------- | ------------------------------ | ------------------------------ |
| `userPrincipalName`       | `userName`                     | `emailOf` / `email`            |
| `mail`                    | `emails[type eq "work"].value` | `emailOf` (fallback)           |
| `givenName`               | `name.givenName`               | `givenNameOf`                  |
| `surname`                 | `name.familyName`              | `familyNameOf`                 |
| `displayName`             | `displayName`                  | `displayNameOf`                |
| `objectId`                | `externalId`                   | `externalIdOf`                 |
| `isSoftDeleted` (negated) | `active`                       | `activeOf`                     |
| `department`              | `enterprise:department`        | `profileFromScim` (attributes) |

To provision **groups** as well, enable "Provision Microsoft Entra ID Groups" and assign the
groups to the application. Entra then creates the groups via `POST /Groups` and manages the
members via `PATCH /Groups/:id` (`members[value eq "<id>"]` for targeted removals, handled by
`parseGroupMemberPatch`).

---

## 7. Conformance test

Microsoft provides a **SCIM validator** ("Test the SCIM endpoint compatibility", PowerShell
module / Postman collection published by Microsoft) that replays the call sequence expected by
Entra. Failing that, the portal's **Test Connection** button exercises the critical path.

Mandatory SCIM 2.0 endpoints and their coverage:

| Endpoint                                            | Kengela provider                               | Status     |
| --------------------------------------------------- | ---------------------------------------------- | ---------- |
| `/Users` (POST/GET/PUT/PATCH/DELETE + list+filter)  | handlers `users.ts`                            | ✅ covered |
| `/Groups` (POST/GET/PUT/PATCH/DELETE + list+filter) | handlers `groups.ts`                           | ✅ covered |
| `/ServiceProviderConfig`                            | `handleServiceProviderConfig` (`discovery.ts`) | ✅ covered |
| `/Schemas` (+ `/Schemas/:urn`)                      | `handleSchemas` (`discovery.ts`)               | ✅ covered |
| `/ResourceTypes` (+ `/ResourceTypes/:id`)           | `handleResourceTypes` (`discovery.ts`)         | ✅ covered |

`discovery.ts` covers **the three discovery endpoints**. `serviceProviderConfig()` declares
the core's real capabilities: `patch` supported, `filter` supported (bounded to
`MAX_PAGE_SIZE`), `bulk`/`sort`/`etag`/`changePassword` **not** supported, authentication
scheme `oauthbearertoken`. `schemaDefinitions()` describes core User (RFC 7643 §4.1),
enterprise extension (§4.3) and Group (§4.2) - exactly what `toScimUser`/`toScimGroup` can
carry, and what `validateScimUser` checks (round-trip guaranteed).

Points the Entra validator checks that are already handled:

- **Idempotence**: a `POST /Users` of an existing email returns 200 with no duplicate
  (`handleUsersPost` reconciles via `findUserByEmail`). If the IdP expects a strict duplicate
  rejection (409 `uniqueness`), wire `handleUsersPostStrict` instead.
- **Filter by `externalId`**: `GET /Users?filter=externalId eq "..."` supported.
- **Deprovisioning**: `DELETE /Users/:id` deactivates (204), does not delete.
- **SCIM errors**: `scimError` produces the RFC 7644 §3.12 envelope (`status` as a string +
  `scimType` + `detail`).

---

## 8. Sidebar - provided vs to write

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

**Bearer security**: Entra does not use client-side OAuth2 by default but a long-lived token;
treat it as a first-class secret. Constant-time comparison (`crypto.timingSafeEqual`), never
log the token, HTTPS mandatory, and ideally an allow-list of Entra IPs upstream. It is the
**only** access lock on an endpoint that writes into your directory: do not delegate it to a
generic middleware without verifying it.

---

## Complete example (copy-paste)

A single file that assembles all the functional code of the page: the Prisma `ScimStore`
adapter, constant-time Bearer authentication, the Express router (discovery + Users +
Groups) and the SCIM → roles → `ScimRepository` mapping pipeline.

```ts
import { timingSafeEqual } from 'node:crypto';
import express from 'express';
import type { PrismaClient } from '@prisma/client';
import type { TenantId } from '@kengela/contracts';
import type { ScimRepository } from '@kengela/contracts';
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
  activeOf,
  type ScimStore,
  type ScimUserRow,
  type ScimGroupRow,
  type ScimUserWriteInput,
  type ScimUserPatch,
  type ScimGroupWriteInput,
  type GroupMemberPatch,
  type ScimUserListOptions,
  type ScimGroupListOptions,
  type ScimListPage,
  type ScimRequest,
} from '@kengela/scim-server';
import {
  profileFromScim,
  toContractsProfile,
  evaluateMappings,
  type IdpMappingRule,
} from '@kengela/iam-mapping';

// ── 1. Adapter de persistance : ScimStore (Prisma) ──────────────────────────
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
      totalResults: total, // total filtré AVANT pagination
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
    if (!found) return null; // désactive, ne supprime JAMAIS
    return toUserRow(await this.db.scimUser.update({ where: { id }, data: { active: false } }));
  }

  // Groups : même schéma, filtre displayName eq, patch add/remove/replace borné au tenant.
  async getGroup(_tenantId: TenantId, _id: string): Promise<ScimGroupRow | null> {
    return null;
  }
  async listGroups(
    _tenantId: TenantId,
    o: ScimGroupListOptions,
  ): Promise<ScimListPage<ScimGroupRow>> {
    return { resources: [], totalResults: 0, startIndex: o.startIndex, itemsPerPage: 0 };
  }
  async createGroup(_tenantId: TenantId, _i: ScimGroupWriteInput): Promise<ScimGroupRow> {
    throw new Error('impl');
  }
  async replaceGroup(
    _tenantId: TenantId,
    _id: string,
    _i: ScimGroupWriteInput,
  ): Promise<ScimGroupRow | null> {
    return null;
  }
  async patchGroup(
    _tenantId: TenantId,
    _id: string,
    _ops: readonly GroupMemberPatch[],
  ): Promise<ScimGroupRow | null> {
    return null;
  }
  async deleteGroup(_tenantId: TenantId, _id: string): Promise<boolean> {
    return false;
  }
}

// ── 2. Auth Bearer à temps constant (secret hors code) ──────────────────────
function isValidBearer(header: string | undefined): boolean {
  const expected = process.env.SCIM_BEARER_TOKEN ?? '';
  if (!header?.startsWith('Bearer ') || expected === '') return false;
  const provided = header.slice('Bearer '.length);
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b); // comparaison timing-safe
}

// ── 3. Routeur Express (découverte + Users + Groups) ────────────────────────
export function scimRouter(store: ScimStore, resolveTenant: (req: express.Request) => TenantId) {
  const r = express.Router();
  r.use(express.json({ type: ['application/json', 'application/scim+json'] }));

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

  // Découverte (aucun store) - les trois endpoints de discovery.ts.
  r.get('/ServiceProviderConfig', (_req, res) => send(res, handleServiceProviderConfig()));
  r.get('/ResourceTypes/:id?', (req, res) => send(res, handleResourceTypes(req.params['id'])));
  r.get('/Schemas/:id?', (req, res) => send(res, handleSchemas(req.params['id'])));

  // Users.
  r.post('/Users', async (req, res) => {
    const v = validateScimUser(req.body);
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

  // Groups.
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

// ── 4. Pipeline mapping SCIM → rôles + projection contracts ─────────────────
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

export async function onScimUserPushed(
  tenantId: TenantId,
  scimBody: Record<string, unknown>,
  scimRepository: ScimRepository,
): Promise<void> {
  const rich = profileFromScim(scimBody); // DirectoryProfile riche
  const result = evaluateMappings(rich, rules); // { roleKeys, orgUnitDirectives, matchedRuleIds }

  // Projection RICHE → MINIMAL (contracts), puis réconciliation.
  const profile = toContractsProfile(rich, { source: 'scim', active: activeOf(scimBody) });
  await scimRepository.upsertUserByEmail(tenantId, profile);

  // … appliquer result.roleKeys + result.orgUnitDirectives via vos repos (grants + rattachement).
  void result;
}

// ── 5. Montage ──────────────────────────────────────────────────────────────
// const store = new PrismaScimStore(prisma);
// app.use('/scim/v2', scimRouter(store, (req) => resolveTenantId(req)));
```
