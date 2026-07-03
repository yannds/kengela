import { describe, expect, it } from 'vitest';
import {
  KENGELA_SCIM_ATTRIBUTE_PATHS,
  SCIM_SCHEMA_ENTERPRISE_USER,
  projectScimUser,
  type KengelaScimUser,
} from '../src/scim-schema.js';

/** Utilisateur riche facon Okta/Entra (bien au-dela des 7 attributs d'origine). */
const RICH_USER: KengelaScimUser = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User', SCIM_SCHEMA_ENTERPRISE_USER],
  userName: 'alice@acme.io',
  externalId: 'ext-123',
  name: { givenName: 'Alice', familyName: 'Martin', formatted: 'Alice Martin' },
  displayName: 'Alice Martin',
  title: 'Directrice',
  userType: 'Employee',
  preferredLanguage: 'fr-FR',
  locale: 'fr-FR',
  timezone: 'Africa/Brazzaville',
  active: true,
  emails: [
    { value: 'old@acme.io', primary: false },
    { value: 'alice@acme.io', primary: true },
  ],
  phoneNumbers: [{ value: '+242060000000', type: 'work', primary: true }],
  addresses: [
    {
      streetAddress: '12 av. de la Paix',
      locality: 'Brazzaville',
      region: 'Brazzaville',
      postalCode: 'BZV',
      country: 'CG',
      primary: true,
    },
  ],
  groups: [{ display: 'Finance', value: 'grp-1' }, { value: 'grp-2' }],
  enterprise: {
    employeeNumber: 'E-42',
    costCenter: 'CC-9',
    organization: 'ACME',
    division: 'Ops',
    department: 'Comptabilite',
    manager: { value: 'bob@acme.io', displayName: 'Bob' },
  },
  extensions: { 'urn:okta:custom': { badgeId: 'B-7' } },
};

describe('projectScimUser', () => {
  const profile = projectScimUser(RICH_USER);

  it('projette identite + email primaire', () => {
    expect(profile.email).toBe('alice@acme.io');
    expect(profile.externalId).toBe('ext-123');
    expect(profile.firstName).toBe('Alice');
    expect(profile.lastName).toBe('Martin');
    expect(profile.displayName).toBe('Alice Martin');
  });

  it('projette les attributs riches (enterprise, adresse, telephone, locale)', () => {
    const a = profile.attributes;
    expect(a.department).toBe('Comptabilite');
    expect(a.employeeNumber).toBe('E-42');
    expect(a.costCenter).toBe('CC-9');
    expect(a.organization).toBe('ACME');
    expect(a.manager).toBe('bob@acme.io');
    expect(a.title).toBe('Directrice');
    expect(a.phoneNumber).toBe('+242060000000');
    expect(a.city).toBe('Brazzaville');
    expect(a.country).toBe('CG');
    expect(a.timezone).toBe('Africa/Brazzaville');
    expect(a.preferredLanguage).toBe('fr-FR');
  });

  it('preserve les extensions custom (Okta/Entra) sans les figer', () => {
    expect(profile.attributes.extensions).toEqual({ 'urn:okta:custom': { badgeId: 'B-7' } });
    expect(profile.claims['enterprise']).toBeDefined();
  });

  it('extrait les groupes (display prioritaire, sinon value)', () => {
    expect(profile.groups).toEqual(['Finance', 'grp-2']);
  });

  it('tombe sur userName si aucun email primaire', () => {
    const p = projectScimUser({ userName: 'bob@acme.io' });
    expect(p.email).toBe('bob@acme.io');
  });
});

describe("registre d'attributs SCIM", () => {
  it('inclut les chemins enterprise', () => {
    expect(KENGELA_SCIM_ATTRIBUTE_PATHS).toContain(`${SCIM_SCHEMA_ENTERPRISE_USER}:employeeNumber`);
    expect(KENGELA_SCIM_ATTRIBUTE_PATHS).toContain('emails');
    expect(KENGELA_SCIM_ATTRIBUTE_PATHS).toContain('name.givenName');
  });
});
