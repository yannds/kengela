/**
 * RED TEAM — SCIM 2.0 (@kengela/scim-server).
 *
 * Injection de filtre, ReDoS, PATCH malveillant, contournement d'unicite, isolation tenant,
 * validation de schema. Handlers PURS + FakeScimStore en memoire (aucun HTTP/DB).
 */
import { describe, expect, it } from 'vitest';
import type { ScimRequest } from '../src/index.js';
import {
  handleUsersDelete,
  handleUsersGet,
  handleUsersList,
  handleUsersPostStrict,
  parseGroupMemberPatch,
  parseUserNameFilter,
  parseUserPatch,
  validateScimGroup,
  validateScimUser,
} from '../src/index.js';
import { FakeScimStore } from './fake-store.js';

const req = (over: Partial<ScimRequest> & { tenantId: string }): ScimRequest => ({ ...over });

describe('RED — SCIM : filtres (injection & ReDoS)', () => {
  it('un filtre borne rejette une entree gigantesque sans exploser (pas de ReDoS)', () => {
    const huge = `userName eq "${'a'.repeat(200_000)}`; // pas de guillemet fermant : ne matche pas
    const started = Date.now();
    expect(parseUserNameFilter(huge)).toBeNull();
    expect(Date.now() - started).toBeLessThan(500);
  });

  it('une tentative d’injection dans le filtre n’est pas interpretee (retour null)', () => {
    expect(parseUserNameFilter('userName eq "a" or "1" eq "1"')).toBeNull();
    expect(parseUserNameFilter('userName sw "a"')).toBeNull();
    expect(parseUserNameFilter('userName eq "a"; DROP TABLE users')).toBeNull();
  });

  it('un filtre non supporte renvoie une liste VIDE, jamais une erreur ni tout le tenant', async () => {
    const store = new FakeScimStore();
    await store.createUser('t1', {
      userName: 'a@x.io',
      externalId: null,
      firstName: null,
      lastName: null,
      displayName: null,
      active: true,
    });
    const res = await handleUsersList(
      store,
      req({ tenantId: 't1', query: { filter: 'userName co "a"' } }),
    );
    expect(res.status).toBe(200);
    const body = res.body as { totalResults: number; Resources: readonly unknown[] };
    expect(body.totalResults).toBe(0);
    expect(body.Resources).toHaveLength(0);
  });
});

describe('RED — SCIM : PATCH malveillant', () => {
  it('une operation inconnue est ignoree (fail-closed, pas de mutation)', () => {
    const patch = parseUserPatch({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'destroy', path: 'active', value: true }],
    });
    expect(patch.active).toBeNull();
    expect(patch.identity).toEqual({});
  });

  it('un `path` forge sur les membres n’extrait qu’un id borne (ou rien)', () => {
    const forged = parseGroupMemberPatch({
      Operations: [{ op: 'remove', path: `members[value eq "${'x'.repeat(5000)}"]` }],
    });
    // Extraction bornee a 256 : soit un id tronque, soit vide ; jamais une explosion.
    expect(forged.length).toBeLessThanOrEqual(1);
  });

  it('remove ciblé `members[value eq "id"]` est correctement normalisé', () => {
    const ops = parseGroupMemberPatch({
      Operations: [{ op: 'remove', path: 'members[value eq "u-42"]' }],
    });
    expect(ops).toEqual([{ kind: 'remove', members: ['u-42'] }]);
  });
});

describe('RED — SCIM : unicite & deprovisionnement', () => {
  it('POST strict : un userName deja present => 409 uniqueness (pas de doublon)', async () => {
    const store = new FakeScimStore();
    const body = { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: 'dup@x.io' };
    const first = await handleUsersPostStrict(store, req({ tenantId: 't1', body }));
    expect(first.status).toBe(201);
    // Meme email, casse differente => toujours 409 (insensible a la casse).
    const second = await handleUsersPostStrict(
      store,
      req({ tenantId: 't1', body: { ...body, userName: 'DUP@X.IO' } }),
    );
    expect(second.status).toBe(409);
    const err = second.body as { scimType?: string };
    expect(err.scimType).toBe('uniqueness');
  });

  it('DELETE = DESACTIVATION (jamais de suppression physique)', async () => {
    const store = new FakeScimStore();
    const created = await store.createUser('t1', {
      userName: 'a@x.io',
      externalId: null,
      firstName: null,
      lastName: null,
      displayName: null,
      active: true,
    });
    const del = await handleUsersDelete(store, req({ tenantId: 't1', pathId: created.id }));
    expect(del.status).toBe(204);
    // L'utilisateur existe toujours mais desactive.
    const still = await store.getUser('t1', created.id);
    expect(still?.active).toBe(false);
  });
});

describe('RED — SCIM : isolation multi-tenant', () => {
  it('un utilisateur du tenant A est introuvable via le tenant B (404)', async () => {
    const store = new FakeScimStore();
    const created = await store.createUser('tenant-A', {
      userName: 'a@x.io',
      externalId: null,
      firstName: null,
      lastName: null,
      displayName: null,
      active: true,
    });
    const cross = await handleUsersGet(store, req({ tenantId: 'tenant-B', pathId: created.id }));
    expect(cross.status).toBe(404);
    const same = await handleUsersGet(store, req({ tenantId: 'tenant-A', pathId: created.id }));
    expect(same.status).toBe(200);
  });
});

describe('RED — SCIM : validation de schema (bypass)', () => {
  it('rejette un corps sans `schemas`', () => {
    expect(validateScimUser({ userName: 'a@x.io' }).valid).toBe(false);
  });

  it('rejette un schema non reconnu (URN forgee)', () => {
    const res = validateScimUser({
      schemas: ['urn:evil:custom'],
      userName: 'a@x.io',
    });
    expect(res.valid).toBe(false);
  });

  it('rejette un userName de mauvais type (injection de type)', () => {
    const res = validateScimUser({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: { $ne: null },
    });
    expect(res.valid).toBe(false);
  });

  it('rejette un multi-valued mal forme (emails[].value non chaine)', () => {
    const res = validateScimUser({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'a@x.io',
      emails: [{ value: { nested: true } }],
    });
    expect(res.valid).toBe(false);
  });

  it('un groupe sans displayName est rejete', () => {
    expect(
      validateScimGroup({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'] }).valid,
    ).toBe(false);
  });
});
