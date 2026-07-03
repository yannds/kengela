import { describe, expect, it } from 'vitest';
import {
  handleUsersDelete,
  handleUsersGet,
  handleUsersList,
  handleUsersPatch,
  handleUsersPost,
  handleUsersPut,
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ERROR,
  SCIM_SCHEMA_LIST_RESPONSE,
  type ScimResponse,
} from '../src/index.js';
import { FakeScimStore } from './fake-store.js';

const TENANT = 't1';

function idOf(res: ScimResponse): string {
  const value = res.body?.['id'];
  return typeof value === 'string' ? value : '';
}

async function seedUser(store: FakeScimStore, body: Record<string, unknown>): Promise<string> {
  const res = await handleUsersPost(store, { tenantId: TENANT, body });
  return idOf(res);
}

describe('handleUsersPost', () => {
  it('crée un utilisateur (201) avec la ressource SCIM sérialisée', async () => {
    const store = new FakeScimStore();
    const res = await handleUsersPost(store, {
      tenantId: TENANT,
      body: { userName: 'ada@example.com', name: { givenName: 'Ada', familyName: 'Lovelace' } },
    });

    expect(res.status).toBe(201);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_CORE_USER]);
    expect(res.body?.['userName']).toBe('ada@example.com');
    expect(res.body?.['active']).toBe(true);
    expect(res.body?.['name']).toEqual({ givenName: 'Ada', familyName: 'Lovelace' });
    expect(idOf(res)).not.toBe('');
  });

  it('réconcilie par e-mail (insensible à la casse) sans doublon (200)', async () => {
    const store = new FakeScimStore();
    const first = await handleUsersPost(store, {
      tenantId: TENANT,
      body: { userName: 'ada@example.com' },
    });
    const again = await handleUsersPost(store, {
      tenantId: TENANT,
      body: { userName: 'ADA@example.com' },
    });

    expect(first.status).toBe(201);
    expect(again.status).toBe(200);
    expect(idOf(again)).toBe(idOf(first));

    const list = await handleUsersList(store, { tenantId: TENANT });
    expect(list.body?.['totalResults']).toBe(1);
  });

  it('rejette (400 SCIM) un corps sans userName ni e-mail', async () => {
    const store = new FakeScimStore();
    const res = await handleUsersPost(store, { tenantId: TENANT, body: { displayName: 'x' } });

    expect(res.status).toBe(400);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_ERROR]);
    expect(res.body?.['scimType']).toBe('invalidValue');
  });

  it("lit l'e-mail depuis emails[primary] quand userName est absent", async () => {
    const store = new FakeScimStore();
    const res = await handleUsersPost(store, {
      tenantId: TENANT,
      body: { emails: [{ value: 'grace@example.com', primary: true }] },
    });

    expect(res.status).toBe(201);
    expect(res.body?.['userName']).toBe('grace@example.com');
  });
});

describe('handleUsersGet', () => {
  it('renvoie la ressource (200) par id', async () => {
    const store = new FakeScimStore();
    const id = await seedUser(store, { userName: 'ada@example.com' });

    const res = await handleUsersGet(store, { tenantId: TENANT, pathId: id });
    expect(res.status).toBe(200);
    expect(idOf(res)).toBe(id);
  });

  it('renvoie 404 SCIM pour un id inconnu', async () => {
    const store = new FakeScimStore();
    const res = await handleUsersGet(store, { tenantId: TENANT, pathId: 'ghost' });

    expect(res.status).toBe(404);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_ERROR]);
    expect(res.body?.['status']).toBe('404');
  });
});

describe('handleUsersList', () => {
  it('filtre par userName eq et renvoie un ListResponse conforme', async () => {
    const store = new FakeScimStore();
    await seedUser(store, { userName: 'ada@example.com' });
    await seedUser(store, { userName: 'grace@example.com' });

    const res = await handleUsersList(store, {
      tenantId: TENANT,
      query: { filter: 'userName eq "grace@example.com"' },
    });

    expect(res.status).toBe(200);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_LIST_RESPONSE]);
    expect(res.body?.['totalResults']).toBe(1);
    const resources = res.body?.['Resources'];
    expect(Array.isArray(resources)).toBe(true);
    expect((resources as Record<string, unknown>[])[0]?.['userName']).toBe('grace@example.com');
  });

  it('pagine via startIndex/count (itemsPerPage = taille de la tranche)', async () => {
    const store = new FakeScimStore();
    await seedUser(store, { userName: 'a@example.com' });
    await seedUser(store, { userName: 'b@example.com' });
    await seedUser(store, { userName: 'c@example.com' });

    const res = await handleUsersList(store, {
      tenantId: TENANT,
      query: { startIndex: 2, count: 1 },
    });

    expect(res.body?.['totalResults']).toBe(3);
    expect(res.body?.['startIndex']).toBe(2);
    expect(res.body?.['itemsPerPage']).toBe(1);
  });

  it('renvoie une liste vide pour un filtre non supporté', async () => {
    const store = new FakeScimStore();
    await seedUser(store, { userName: 'a@example.com' });

    const res = await handleUsersList(store, {
      tenantId: TENANT,
      query: { filter: 'active eq true' },
    });

    expect(res.status).toBe(200);
    expect(res.body?.['totalResults']).toBe(0);
  });
});

describe('handleUsersPatch', () => {
  it('désactive puis réactive via replace active', async () => {
    const store = new FakeScimStore();
    const id = await seedUser(store, { userName: 'ada@example.com' });

    const off = await handleUsersPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'replace', path: 'active', value: false }] },
    });
    expect(off.body?.['active']).toBe(false);

    const on = await handleUsersPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'replace', path: 'active', value: true }] },
    });
    expect(on.body?.['active']).toBe(true);
  });

  it("remplace un attribut d'identité (displayName)", async () => {
    const store = new FakeScimStore();
    const id = await seedUser(store, { userName: 'ada@example.com', displayName: 'Ada' });

    const res = await handleUsersPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'replace', path: 'displayName', value: 'Ada L.' }] },
    });

    expect(res.status).toBe(200);
    expect(res.body?.['displayName']).toBe('Ada L.');
  });

  it('renvoie 404 pour un id inconnu', async () => {
    const store = new FakeScimStore();
    const res = await handleUsersPatch(store, {
      tenantId: TENANT,
      pathId: 'ghost',
      body: { Operations: [] },
    });
    expect(res.status).toBe(404);
  });
});

describe('handleUsersPut', () => {
  it('remplace la ressource (identité + active)', async () => {
    const store = new FakeScimStore();
    const id = await seedUser(store, { userName: 'ada@example.com', displayName: 'Ada' });

    const res = await handleUsersPut(store, {
      tenantId: TENANT,
      pathId: id,
      body: {
        userName: 'ada@example.com',
        name: { givenName: 'Ada', familyName: 'King' },
        active: false,
      },
    });

    expect(res.status).toBe(200);
    expect(res.body?.['name']).toEqual({ givenName: 'Ada', familyName: 'King' });
    expect(res.body?.['active']).toBe(false);
  });
});

describe('handleUsersDelete', () => {
  it("désactive (204) sans supprimer : l'utilisateur reste lisible, inactif", async () => {
    const store = new FakeScimStore();
    const id = await seedUser(store, { userName: 'ada@example.com' });

    const del = await handleUsersDelete(store, { tenantId: TENANT, pathId: id });
    expect(del.status).toBe(204);
    expect(del.body).toBeUndefined();

    const after = await handleUsersGet(store, { tenantId: TENANT, pathId: id });
    expect(after.status).toBe(200);
    expect(after.body?.['active']).toBe(false);
  });

  it('renvoie 404 pour un id inconnu', async () => {
    const store = new FakeScimStore();
    const res = await handleUsersDelete(store, { tenantId: TENANT, pathId: 'ghost' });
    expect(res.status).toBe(404);
  });
});
