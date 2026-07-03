import { describe, expect, it } from 'vitest';
import {
  handleUsersPost,
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  SCIM_SCHEMA_GROUP,
  validateScimGroup,
  validateScimUser,
  type KengelaScimUser,
} from '../src/index.js';
import { FakeScimStore } from './fake-store.js';

describe('validateScimUser', () => {
  it('accepte un KengelaScimUser valide (schemas + userName + types corrects)', () => {
    const user: KengelaScimUser = {
      schemas: [SCIM_SCHEMA_CORE_USER, SCIM_SCHEMA_ENTERPRISE_USER],
      userName: 'ada@example.com',
      name: { givenName: 'Ada', familyName: 'Lovelace' },
      displayName: 'Ada Lovelace',
      active: true,
      emails: [{ value: 'ada@example.com', primary: true }],
    };
    const result = validateScimUser(user);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('rejette une ressource sans `schemas`', () => {
    const result = validateScimUser({ userName: 'ada@example.com' });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('schemas'))).toBe(true);
  });

  it('rejette une ressource sans `userName`', () => {
    const result = validateScimUser({ schemas: [SCIM_SCHEMA_CORE_USER] });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('userName'))).toBe(true);
  });

  it('rejette un type invalide (active non booléen)', () => {
    const result = validateScimUser({
      schemas: [SCIM_SCHEMA_CORE_USER],
      userName: 'ada@example.com',
      active: 'yes',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('active'))).toBe(true);
  });

  it('rejette un attribut multi-valué mal formé (emails non tableau)', () => {
    const result = validateScimUser({
      schemas: [SCIM_SCHEMA_CORE_USER],
      userName: 'ada@example.com',
      emails: 'ada@example.com',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('emails'))).toBe(true);
  });

  it('rejette un schéma déclaré non reconnu', () => {
    const result = validateScimUser({
      schemas: [SCIM_SCHEMA_CORE_USER, 'urn:acme:custom:1.0:Thing'],
      userName: 'ada@example.com',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('non reconnu'))).toBe(true);
  });

  it('rejette un `schemas` vide', () => {
    const result = validateScimUser({ schemas: [], userName: 'ada@example.com' });
    expect(result.valid).toBe(false);
  });

  it('rejette une entrée non-objet', () => {
    expect(validateScimUser(null).valid).toBe(false);
    expect(validateScimUser('x').valid).toBe(false);
  });

  it('rejette name non objet et name.givenName non chaîne', () => {
    const bad = validateScimUser({
      schemas: [SCIM_SCHEMA_CORE_USER],
      userName: 'ada@example.com',
      name: { givenName: 42 },
    });
    expect(bad.valid).toBe(false);
    expect(bad.errors.some((e) => e.includes('givenName'))).toBe(true);
  });
});

describe('validateScimGroup', () => {
  it('accepte un groupe valide (schemas + displayName + members)', () => {
    const result = validateScimGroup({
      schemas: [SCIM_SCHEMA_GROUP],
      displayName: 'Engineering',
      members: [{ value: 'u1' }, { value: 'u2' }],
    });
    expect(result.valid).toBe(true);
  });

  it('rejette un groupe sans displayName', () => {
    const result = validateScimGroup({ schemas: [SCIM_SCHEMA_GROUP] });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('displayName'))).toBe(true);
  });

  it('rejette des membres mal formés', () => {
    const result = validateScimGroup({
      schemas: [SCIM_SCHEMA_GROUP],
      displayName: 'Eng',
      members: [{ value: 42 }],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('members'))).toBe(true);
  });
});

describe('round-trip (in == out conforme)', () => {
  it("la sortie sérialisée d'un user créé PASSE validateScimUser", async () => {
    const store = new FakeScimStore();
    const res = await handleUsersPost(store, {
      tenantId: 't1',
      body: {
        userName: 'ada@example.com',
        externalId: 'ext-1',
        name: { givenName: 'Ada', familyName: 'Lovelace' },
        displayName: 'Ada Lovelace',
      },
    });
    expect(res.status).toBe(201);
    const result = validateScimUser(res.body);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });
});
