import type { Grant } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { activeGrants, grantCovers, isAuthorized } from '../src/engine.js';
import { assertPermissionSyntax, permissionCovers, PermissionSyntaxError } from '../src/grant.js';
import { relationRank, scopeCoversRelation, SCOPE_RANK } from '../src/scope.js';

const grant = (permission: string, scope: Grant['scope'], extra: Partial<Grant> = {}): Grant => ({
  permission,
  scope,
  source: 'MANUAL',
  ...extra,
});

describe('permissionCovers', () => {
  it('couvre par egalite stricte', () => {
    expect(permissionCovers('data.cashier.read', 'data.cashier.read')).toBe(true);
    expect(permissionCovers('data.cashier.read', 'data.cashier.write')).toBe(false);
  });

  it('joker terminal = prefixe', () => {
    expect(permissionCovers('data.cashier.*', 'data.cashier.register.read')).toBe(true);
    expect(permissionCovers('data.*', 'data.anything.deep.enough')).toBe(true);
    expect(permissionCovers('data.cashier.*', 'control.cashier.read')).toBe(false);
  });

  it('joker simple couvre exactement un segment', () => {
    expect(permissionCovers('data.*.read', 'data.orders.read')).toBe(true);
    expect(permissionCovers('data.*.read', 'data.a.b.read')).toBe(false);
  });

  it('rejette une longueur differente sans joker terminal', () => {
    expect(permissionCovers('data.cashier.read', 'data.cashier.read.own')).toBe(false);
    expect(permissionCovers('data.cashier.read.own', 'data.cashier.read')).toBe(false);
  });
});

describe('assertPermissionSyntax', () => {
  it('accepte une permission valide', () => {
    expect(() => {
      assertPermissionSyntax('data.cashier.register.read');
    }).not.toThrow();
  });

  it('rejette segments invalides ou trop courts', () => {
    expect(() => {
      assertPermissionSyntax('data');
    }).toThrow(PermissionSyntaxError);
    expect(() => {
      assertPermissionSyntax('data.Cashier.read');
    }).toThrow(PermissionSyntaxError);
  });
});

describe('scope / relation', () => {
  it('ordonne les portees', () => {
    expect(SCOPE_RANK.own).toBeLessThan(SCOPE_RANK.global);
  });

  it('global couvre toute relation, own seulement self', () => {
    expect(scopeCoversRelation('global', 'tenant')).toBe(true);
    expect(scopeCoversRelation('own', 'self')).toBe(true);
    expect(scopeCoversRelation('own', 'unit')).toBe(false);
  });

  it('relation none exige un grant global', () => {
    expect(relationRank('none')).toBe(SCOPE_RANK.global);
    expect(scopeCoversRelation('tenant', 'none')).toBe(false);
    expect(scopeCoversRelation('global', 'none')).toBe(true);
  });
});

describe('grantCovers / isAuthorized', () => {
  it('combine motif et portee', () => {
    const held = grant('data.cashier.register.read', 'unit');
    expect(grantCovers(held, 'data.cashier.register.read', 'self')).toBe(true);
    expect(grantCovers(held, 'data.cashier.register.read', 'tenant')).toBe(false);
    expect(grantCovers(held, 'data.cashier.register.write', 'self')).toBe(false);
  });

  it('deny-by-default sans grant couvrant', () => {
    expect(isAuthorized([], 'data.cashier.read', 'self', 0)).toBe(false);
    const held = [grant('data.orders.read', 'tenant')];
    expect(isAuthorized(held, 'data.cashier.read', 'self', 0)).toBe(false);
  });

  it('autorise via un grant plus large', () => {
    const held = [grant('data.cashier.*', 'tenant')];
    expect(isAuthorized(held, 'data.cashier.register.read', 'subtree', 0)).toBe(true);
  });
});

describe('activeGrants', () => {
  it('exclut les grants expires', () => {
    const held = [
      grant('data.a.read', 'tenant', { expiresAt: new Date(500) }),
      grant('data.b.read', 'tenant', { expiresAt: new Date(5000) }),
      grant('data.c.read', 'tenant'),
    ];
    const active = activeGrants(held, 1000);
    expect(active.map((g) => g.permission)).toEqual(['data.b.read', 'data.c.read']);
  });
});
