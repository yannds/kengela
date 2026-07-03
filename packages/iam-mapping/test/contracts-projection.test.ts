import { describe, expect, it } from 'vitest';
import type { DirectoryProfile } from '../src/profile.js';
import { toContractsProfile } from '../src/contracts-projection.js';

const rich = (over: Partial<DirectoryProfile> = {}): DirectoryProfile => ({
  email: 'alice@acme.io',
  externalId: 'ext-1',
  firstName: 'Alice',
  lastName: 'Martin',
  displayName: 'Alice Martin',
  attributes: { department: 'Ops', title: 'Manager' },
  groups: ['g1', 'g2'],
  claims: { sub: 'ext-1', secret: 'ne-doit-pas-fuiter' },
  ...over,
});

describe('toContractsProfile', () => {
  it('projette identité + attributs + firstName/lastName reversés', () => {
    const out = toContractsProfile(rich(), { source: 'scim', active: true });
    expect(out).toEqual({
      externalId: 'ext-1',
      email: 'alice@acme.io',
      displayName: 'Alice Martin',
      groups: ['g1', 'g2'],
      attributes: {
        department: 'Ops',
        title: 'Manager',
        firstName: 'Alice',
        lastName: 'Martin',
      },
      active: true,
      source: 'scim',
    });
  });

  it('ne reporte PAS les claims bruts (volume + PII)', () => {
    const out = toContractsProfile(rich(), { source: 'oidc', active: true });
    expect(out.attributes).not.toHaveProperty('secret');
  });

  it('externalId null -> repli sur email', () => {
    const out = toContractsProfile(rich({ externalId: null }), { source: 'saml', active: true });
    expect(out.externalId).toBe('alice@acme.io');
  });

  it('email absent -> propriété OMISE (exactOptionalPropertyTypes)', () => {
    const out = toContractsProfile(rich({ email: '' }), { source: 'ldap', active: false });
    expect('email' in out).toBe(false);
  });

  it('displayName null -> propriété omise', () => {
    const out = toContractsProfile(rich({ displayName: null }), { source: 'graph', active: true });
    expect('displayName' in out).toBe(false);
  });

  it('firstName/lastName absents -> non ajoutés aux attributs', () => {
    const out = toContractsProfile(
      rich({ firstName: null, lastName: null, attributes: { department: 'Ops' } }),
      { source: 'google', active: true },
    );
    expect(out.attributes).toEqual({ department: 'Ops' });
  });

  it('active et source proviennent des métadonnées', () => {
    const out = toContractsProfile(rich(), { source: 'ldap', active: false });
    expect(out.active).toBe(false);
    expect(out.source).toBe('ldap');
  });

  it('groups copié (nouvelle référence de tableau)', () => {
    const source = rich();
    const out = toContractsProfile(source, { source: 'scim', active: true });
    expect(out.groups).toEqual(source.groups);
    expect(out.groups).not.toBe(source.groups);
  });
});
