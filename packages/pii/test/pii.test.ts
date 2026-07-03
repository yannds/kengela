import type { DirectoryProfile } from '@kengela/iam-mapping';
import { describe, expect, it } from 'vitest';
import { classify, isPii, PII_FIELDS } from '../src/classification.js';
import { minimizeProfile } from '../src/minimize.js';
import { redactProfile } from '../src/redact.js';

const profile = (): DirectoryProfile => ({
  email: 'alice@acme.io',
  externalId: 'ext-1',
  firstName: 'Alice',
  lastName: 'Martin',
  displayName: 'Alice Martin',
  attributes: { department: 'Ops', phoneNumber: '+242060000000', city: 'Brazzaville' },
  groups: ['Finance'],
  claims: { raw: { a: 1 } },
});

describe('classification', () => {
  it('classe PII vs non-PII', () => {
    expect(classify('email')).toBe('pii');
    expect(classify('phoneNumber')).toBe('pii');
    expect(classify('department')).toBe('none');
    expect(classify('inconnu')).toBe('none');
    expect(isPii('city')).toBe(true);
    expect(isPii('title')).toBe(false);
  });

  it('PII_FIELDS contient les champs personnels, pas les autres', () => {
    expect(PII_FIELDS).toContain('email');
    expect(PII_FIELDS).toContain('phoneNumber');
    expect(PII_FIELDS).not.toContain('department');
  });
});

describe('minimizeProfile', () => {
  it('ne garde que les attributs autorises + neutralise l identite non autorisee', () => {
    const m = minimizeProfile(profile(), ['department']);
    expect(m.attributes.department).toBe('Ops');
    expect(m.attributes.phoneNumber).toBeUndefined();
    expect(m.attributes.city).toBeUndefined();
    expect(m.firstName).toBeNull();
    expect(m.claims).toEqual({});
    expect(m.email).toBe('alice@acme.io');
  });

  it('conserve l identite et les attributs autorises', () => {
    const m = minimizeProfile(profile(), ['firstName', 'phoneNumber']);
    expect(m.firstName).toBe('Alice');
    expect(m.lastName).toBeNull();
    expect(m.attributes.phoneNumber).toBe('+242060000000');
  });
});

describe('redactProfile', () => {
  it('masque email et noms', () => {
    const r = redactProfile(profile());
    expect(r.email).toBe('a***@acme.io');
    expect(r.firstName).toBe('A***');
    expect(r.displayName).toBe('A***');
  });
});
