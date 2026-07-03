import { describe, expect, it } from 'vitest';
import { toAuthContext, toObligation } from '../src/mapping.js';

describe('toAuthContext', () => {
  it('reconstitue les sous-objets geo/device et omet les champs absents', () => {
    const ctx = toAuthContext({
      authTime: 42,
      ip: '1.2.3.4',
      geo: { country: 'CG', lat: 1.5 },
      device: { trusted: true },
    });

    expect(ctx).toEqual({
      authTime: 42,
      ip: '1.2.3.4',
      geo: { country: 'CG', lat: 1.5 },
      device: { trusted: true },
    });
  });

  it('fail-closed : entree non-objet -> authTime 0', () => {
    expect(toAuthContext('corrompu')).toEqual({ authTime: 0 });
    expect(toAuthContext(null)).toEqual({ authTime: 0 });
  });

  it('ecarte les sous-objets entierement vides ou illisibles', () => {
    const ctx = toAuthContext({ authTime: 7, geo: {}, device: 'nope' });
    expect(ctx).toEqual({ authTime: 7 });
  });
});

describe('toObligation', () => {
  it('retourne null sur un type inconnu', () => {
    expect(toObligation({ type: 'teleport' })).toBeNull();
  });

  it('retourne null sur une entree non-objet', () => {
    expect(toObligation(42)).toBeNull();
  });

  it('mappe un type valide avec params', () => {
    expect(toObligation({ type: 'reauthenticate', params: { within: 300 } })).toEqual({
      type: 'reauthenticate',
      params: { within: 300 },
    });
  });
});
