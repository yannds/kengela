/**
 * Suite « Microsoft Entra (Azure AD) SCIM validator » — reproduit la séquence type du
 * validateur de provisioning : découverte, cycle de vie utilisateur (create/uniqueness/
 * filtres/activation/désactivation) et gestion de groupes, plus l'auto-vérification du
 * schéma sur chaque réponse.
 */
import { describe, expect, it } from 'vitest';
import {
  handleGroupsList,
  handleGroupsPatch,
  handleGroupsPost,
  handleResourceTypes,
  handleSchemas,
  handleServiceProviderConfig,
  handleUsersDelete,
  handleUsersGet,
  handleUsersList,
  handleUsersPatch,
  handleUsersPostStrict,
  handleUsersPut,
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  validateScimGroup,
  validateScimUser,
  type ScimResponse,
} from '../src/index.js';
import { FakeScimStore } from './fake-store.js';

const TENANT = 'entra-tenant';

function idOf(res: ScimResponse): string {
  const value = res.body?.['id'];
  return typeof value === 'string' ? value : '';
}

function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? (value as Record<string, unknown>[]) : [];
}

describe('Entra validator — phase de découverte', () => {
  it('GET /ServiceProviderConfig renvoie les capacités attendues', () => {
    const res = handleServiceProviderConfig();
    expect(res.status).toBe(200);
    expect((res.body?.['patch'] as Record<string, unknown>)['supported']).toBe(true);
    expect((res.body?.['filter'] as Record<string, unknown>)['supported']).toBe(true);
  });

  it('GET /ResourceTypes déclare User + Group', () => {
    const ids = records(handleResourceTypes().body?.['Resources']).map((r) => r['id']);
    expect(ids).toContain('User');
    expect(ids).toContain('Group');
  });

  it('GET /Schemas déclare core User + extension enterprise', () => {
    const ids = records(handleSchemas().body?.['Resources']).map((s) => s['id']);
    expect(ids).toContain(SCIM_SCHEMA_CORE_USER);
    expect(ids).toContain(SCIM_SCHEMA_ENTERPRISE_USER);
  });
});

describe('Entra validator — cycle de vie utilisateur', () => {
  it('POST crée (201) avec schemas + meta, re-POST même userName ⇒ 409 uniqueness', async () => {
    const store = new FakeScimStore();
    const created = await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: {
        schemas: [SCIM_SCHEMA_CORE_USER],
        userName: 'grace@example.com',
        externalId: 'entra-ext-42',
        name: { givenName: 'Grace', familyName: 'Hopper' },
      },
    });

    expect(created.status).toBe(201);
    expect(created.body?.['schemas']).toEqual([SCIM_SCHEMA_CORE_USER]);
    expect(typeof created.body?.['id']).toBe('string');
    expect(created.body?.['externalId']).toBe('entra-ext-42');
    expect(created.body?.['active']).toBe(true);
    const meta = created.body?.['meta'] as Record<string, unknown>;
    expect(meta['resourceType']).toBe('User');
    expect(typeof meta['location']).toBe('string');
    expect(typeof meta['created']).toBe('string');
    expect(typeof meta['lastModified']).toBe('string');

    const dup = await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { schemas: [SCIM_SCHEMA_CORE_USER], userName: 'GRACE@example.com' },
    });
    expect(dup.status).toBe(409);
    expect(dup.body?.['scimType']).toBe('uniqueness');
    expect(dup.body?.['status']).toBe('409');
  });

  it('GET /Users?filter=userName eq (insensible à la casse) retrouve la ressource', async () => {
    const store = new FakeScimStore();
    await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com' },
    });

    const res = await handleUsersList(store, {
      tenantId: TENANT,
      query: { filter: 'userName eq "GRACE@example.com"' },
    });
    expect(res.body?.['totalResults']).toBe(1);
    expect(records(res.body?.['Resources'])[0]?.['userName']).toBe('grace@example.com');
  });

  it('GET /Users?filter=externalId eq retrouve la ressource', async () => {
    const store = new FakeScimStore();
    await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com', externalId: 'entra-ext-42' },
    });

    const res = await handleUsersList(store, {
      tenantId: TENANT,
      query: { filter: 'externalId eq "entra-ext-42"' },
    });
    expect(res.body?.['totalResults']).toBe(1);
    expect(records(res.body?.['Resources'])[0]?.['externalId']).toBe('entra-ext-42');
  });

  it('GET /Users?filter=externalId eq inconnu ⇒ liste vide (0)', async () => {
    const store = new FakeScimStore();
    await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com', externalId: 'entra-ext-42' },
    });
    const res = await handleUsersList(store, {
      tenantId: TENANT,
      query: { filter: 'externalId eq "nope"' },
    });
    expect(res.body?.['totalResults']).toBe(0);
  });

  it('PATCH replace active=false déprovisionne (utilisateur désactivé)', async () => {
    const store = new FakeScimStore();
    const created = await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com' },
    });
    const id = idOf(created);

    const patched = await handleUsersPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [{ op: 'replace', path: 'active', value: false }],
      },
    });
    expect(patched.status).toBe(200);
    expect(patched.body?.['active']).toBe(false);
  });

  it("PATCH replace name.givenName met à jour l'attribut complexe", async () => {
    const store = new FakeScimStore();
    const created = await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com', name: { givenName: 'Grace', familyName: 'Hopper' } },
    });
    const id = idOf(created);

    const patched = await handleUsersPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'replace', path: 'name.givenName', value: 'Grace B.' }] },
    });
    expect(patched.status).toBe(200);
    expect((patched.body?.['name'] as Record<string, unknown>)['givenName']).toBe('Grace B.');
  });

  it('PATCH sans path (forme value partielle) désactive aussi', async () => {
    const store = new FakeScimStore();
    const created = await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com' },
    });
    const patched = await handleUsersPatch(store, {
      tenantId: TENANT,
      pathId: idOf(created),
      body: { Operations: [{ op: 'replace', value: { active: false } }] },
    });
    expect(patched.body?.['active']).toBe(false);
  });

  it('PUT remplace la ressource et peut réactiver', async () => {
    const store = new FakeScimStore();
    const created = await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com', active: false },
    });
    const put = await handleUsersPut(store, {
      tenantId: TENANT,
      pathId: idOf(created),
      body: { schemas: [SCIM_SCHEMA_CORE_USER], userName: 'grace@example.com', active: true },
    });
    expect(put.status).toBe(200);
    expect(put.body?.['active']).toBe(true);
  });

  it('DELETE ⇒ 204 et ressource désactivée (pas supprimée)', async () => {
    const store = new FakeScimStore();
    const created = await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com' },
    });
    const id = idOf(created);

    const del = await handleUsersDelete(store, { tenantId: TENANT, pathId: id });
    expect(del.status).toBe(204);
    expect(del.body).toBeUndefined();

    const after = await handleUsersGet(store, { tenantId: TENANT, pathId: id });
    expect(after.status).toBe(200);
    expect(after.body?.['active']).toBe(false);
  });

  it("GET /Users/:id inconnu ⇒ 404 avec enveloppe d'erreur SCIM", async () => {
    const store = new FakeScimStore();
    const res = await handleUsersGet(store, { tenantId: TENANT, pathId: 'ghost' });
    expect(res.status).toBe(404);
    expect(res.body?.['status']).toBe('404');
  });

  it('chaque réponse utilisateur reste conforme au schéma (validateScimUser)', async () => {
    const store = new FakeScimStore();
    const created = await handleUsersPostStrict(store, {
      tenantId: TENANT,
      body: { userName: 'grace@example.com', externalId: 'entra-ext-42' },
    });
    expect(validateScimUser(created.body).valid).toBe(true);

    const got = await handleUsersGet(store, { tenantId: TENANT, pathId: idOf(created) });
    expect(validateScimUser(got.body).valid).toBe(true);
  });
});

describe('Entra validator — cycle de vie groupe', () => {
  it('create, patch membres add/remove, list filter displayName eq', async () => {
    const store = new FakeScimStore();
    const created = await handleGroupsPost(store, {
      tenantId: TENANT,
      body: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'], displayName: 'Sales' },
    });
    expect(created.status).toBe(201);
    expect(validateScimGroup(created.body).valid).toBe(true);
    const id = idOf(created);

    const added = await handleGroupsPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'add', path: 'members', value: [{ value: 'u1' }] }] },
    });
    expect(records(added.body?.['members'])).toHaveLength(1);

    const removed = await handleGroupsPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'remove', path: 'members[value eq "u1"]' }] },
    });
    expect(records(removed.body?.['members'])).toHaveLength(0);

    const list = await handleGroupsList(store, {
      tenantId: TENANT,
      query: { filter: 'displayName eq "Sales"' },
    });
    expect(list.body?.['totalResults']).toBe(1);
  });
});
