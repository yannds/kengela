import { describe, expect, it } from 'vitest';
import {
  handleGroupsDelete,
  handleGroupsGet,
  handleGroupsList,
  handleGroupsPatch,
  handleGroupsPost,
  handleGroupsPut,
  SCIM_SCHEMA_ERROR,
  SCIM_SCHEMA_GROUP,
  SCIM_SCHEMA_LIST_RESPONSE,
  type ScimResponse,
} from '../src/index.js';
import { FakeScimStore } from './fake-store.js';

const TENANT = 't1';

function idOf(res: ScimResponse): string {
  const value = res.body?.['id'];
  return typeof value === 'string' ? value : '';
}

function memberValues(res: ScimResponse): string[] {
  const members = res.body?.['members'];
  if (!Array.isArray(members)) {
    return [];
  }
  const list: readonly unknown[] = members;
  const out: string[] = [];
  for (const m of list) {
    if (typeof m === 'object' && m !== null) {
      const value = (m as Record<string, unknown>)['value'];
      if (typeof value === 'string') {
        out.push(value);
      }
    }
  }
  return out;
}

async function seedGroup(store: FakeScimStore, body: Record<string, unknown>): Promise<string> {
  const res = await handleGroupsPost(store, { tenantId: TENANT, body });
  return idOf(res);
}

describe('handleGroupsPost', () => {
  it('crée un groupe (201) avec membres et schéma SCIM', async () => {
    const store = new FakeScimStore();
    const res = await handleGroupsPost(store, {
      tenantId: TENANT,
      body: { displayName: 'Engineering', members: [{ value: 'u1' }, { value: 'u2' }] },
    });

    expect(res.status).toBe(201);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_GROUP]);
    expect(res.body?.['displayName']).toBe('Engineering');
    expect(memberValues(res)).toEqual(['u1', 'u2']);
  });

  it('rejette (400 SCIM) un groupe sans displayName', async () => {
    const store = new FakeScimStore();
    const res = await handleGroupsPost(store, { tenantId: TENANT, body: {} });

    expect(res.status).toBe(400);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_ERROR]);
  });
});

describe('handleGroupsGet', () => {
  it('renvoie le groupe (200) et 404 pour un id inconnu', async () => {
    const store = new FakeScimStore();
    const id = await seedGroup(store, { displayName: 'Ops' });

    const ok = await handleGroupsGet(store, { tenantId: TENANT, pathId: id });
    expect(ok.status).toBe(200);
    expect(idOf(ok)).toBe(id);

    const missing = await handleGroupsGet(store, { tenantId: TENANT, pathId: 'ghost' });
    expect(missing.status).toBe(404);
    expect(missing.body?.['schemas']).toEqual([SCIM_SCHEMA_ERROR]);
  });
});

describe('handleGroupsList', () => {
  it('liste tous les groupes (ListResponse conforme)', async () => {
    const store = new FakeScimStore();
    await seedGroup(store, { displayName: 'Ops' });
    await seedGroup(store, { displayName: 'Eng' });

    const res = await handleGroupsList(store, { tenantId: TENANT });
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_LIST_RESPONSE]);
    expect(res.body?.['totalResults']).toBe(2);
  });

  it('filtre par displayName eq', async () => {
    const store = new FakeScimStore();
    await seedGroup(store, { displayName: 'Ops' });
    await seedGroup(store, { displayName: 'Eng' });

    const res = await handleGroupsList(store, {
      tenantId: TENANT,
      query: { filter: 'displayName eq "Eng"' },
    });
    expect(res.body?.['totalResults']).toBe(1);
  });
});

describe('handleGroupsPatch', () => {
  it('ajoute des membres', async () => {
    const store = new FakeScimStore();
    const id = await seedGroup(store, { displayName: 'Eng', members: [{ value: 'u1' }] });

    const res = await handleGroupsPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'add', path: 'members', value: [{ value: 'u2' }] }] },
    });
    expect(memberValues(res)).toEqual(['u1', 'u2']);
  });

  it('retire un membre ciblé (members[value eq "..."])', async () => {
    const store = new FakeScimStore();
    const id = await seedGroup(store, {
      displayName: 'Eng',
      members: [{ value: 'u1' }, { value: 'u2' }],
    });

    const res = await handleGroupsPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'remove', path: 'members[value eq "u1"]' }] },
    });
    expect(memberValues(res)).toEqual(['u2']);
  });

  it("remplace l'ensemble des membres", async () => {
    const store = new FakeScimStore();
    const id = await seedGroup(store, { displayName: 'Eng', members: [{ value: 'u1' }] });

    const res = await handleGroupsPatch(store, {
      tenantId: TENANT,
      pathId: id,
      body: { Operations: [{ op: 'replace', path: 'members', value: [{ value: 'u9' }] }] },
    });
    expect(memberValues(res)).toEqual(['u9']);
  });

  it('renvoie 404 pour un groupe inconnu', async () => {
    const store = new FakeScimStore();
    const res = await handleGroupsPatch(store, {
      tenantId: TENANT,
      pathId: 'ghost',
      body: { Operations: [] },
    });
    expect(res.status).toBe(404);
  });
});

describe('handleGroupsPut', () => {
  it('remplace displayName + membres', async () => {
    const store = new FakeScimStore();
    const id = await seedGroup(store, { displayName: 'Eng', members: [{ value: 'u1' }] });

    const res = await handleGroupsPut(store, {
      tenantId: TENANT,
      pathId: id,
      body: { displayName: 'Engineering', members: [{ value: 'u2' }, { value: 'u3' }] },
    });

    expect(res.status).toBe(200);
    expect(res.body?.['displayName']).toBe('Engineering');
    expect(memberValues(res)).toEqual(['u2', 'u3']);
  });
});

describe('handleGroupsDelete', () => {
  it('supprime le groupe (204) puis 404 au relecture', async () => {
    const store = new FakeScimStore();
    const id = await seedGroup(store, { displayName: 'Eng' });

    const del = await handleGroupsDelete(store, { tenantId: TENANT, pathId: id });
    expect(del.status).toBe(204);
    expect(del.body).toBeUndefined();

    const after = await handleGroupsGet(store, { tenantId: TENANT, pathId: id });
    expect(after.status).toBe(404);
  });

  it('renvoie 404 pour un id inconnu', async () => {
    const store = new FakeScimStore();
    const res = await handleGroupsDelete(store, { tenantId: TENANT, pathId: 'ghost' });
    expect(res.status).toBe(404);
  });
});
