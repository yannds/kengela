import type { Principal, ResourceRef } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { PrincipalRelationResolver } from '../src/relation-resolver.js';

const principal = (over: Partial<Principal> = {}): Principal => ({
  userId: 'u1',
  tenantId: 't1',
  roles: ['cashier'],
  orgUnitId: 'unit-A',
  agencyId: 'agency-1',
  coverageUnits: ['unit-B', 'unit-C'],
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: 0 },
  ...over,
});

const resource = (over: Partial<ResourceRef> = {}): ResourceRef => ({
  type: 'invoice',
  tenantId: 't1',
  ...over,
});

describe('PrincipalRelationResolver', () => {
  const resolver = new PrincipalRelationResolver();

  it('cross-tenant => none (defense en profondeur)', async () => {
    expect(await resolver.resolveRelation(principal(), resource({ tenantId: 't2' }))).toBe('none');
  });

  it('proprietaire prouve (attributs.ownerId === userId) => self', async () => {
    const rel = await resolver.resolveRelation(
      principal(),
      resource({ attributes: { ownerId: 'u1' } }),
    );
    expect(rel).toBe('self');
  });

  it('la ressource EST le sujet (resource.id === userId) => self', async () => {
    const rel = await resolver.resolveRelation(principal(), resource({ type: 'user', id: 'u1' }));
    expect(rel).toBe('self');
  });

  it('meme unite directe (attributs.unitId === orgUnitId) => unit', async () => {
    const rel = await resolver.resolveRelation(
      principal(),
      resource({ attributes: { unitId: 'unit-A' } }),
    );
    expect(rel).toBe('unit');
  });

  it('meme agence (attributs.agencyId === agencyId) => unit', async () => {
    const rel = await resolver.resolveRelation(
      principal(),
      resource({ attributes: { agencyId: 'agency-1' } }),
    );
    expect(rel).toBe('unit');
  });

  it('unite couverte (coverageUnits) => subtree', async () => {
    const rel = await resolver.resolveRelation(
      principal(),
      resource({ attributes: { unitId: 'unit-B' } }),
    );
    expect(rel).toBe('subtree');
  });

  it('self prime sur unit quand les deux sont prouvables', async () => {
    const rel = await resolver.resolveRelation(
      principal(),
      resource({ attributes: { ownerId: 'u1', unitId: 'unit-A' } }),
    );
    expect(rel).toBe('self');
  });

  it('unit prime sur subtree (unite directe ET couverte)', async () => {
    // unit-A est l'unite directe ; on la met AUSSI en couverture : la relation la
    // plus etroite prouvable (unit) l'emporte.
    const rel = await resolver.resolveRelation(
      principal({ coverageUnits: ['unit-A'] }),
      resource({ attributes: { unitId: 'unit-A' } }),
    );
    expect(rel).toBe('unit');
  });

  it('meme tenant sans lien plus etroit prouvable => tenant (deny-by-default)', async () => {
    expect(await resolver.resolveRelation(principal(), resource())).toBe('tenant');
  });

  it('unite inconnue du principal (ni directe ni couverte) => tenant', async () => {
    const rel = await resolver.resolveRelation(
      principal(),
      resource({ attributes: { unitId: 'unit-Z' } }),
    );
    expect(rel).toBe('tenant');
  });

  it('proprietaire tiers (ownerId !== userId) ne donne PAS self', async () => {
    const rel = await resolver.resolveRelation(
      principal(),
      resource({ attributes: { ownerId: 'u2' } }),
    );
    expect(rel).toBe('tenant');
  });

  it('attribut owner non-string ignore (fail-closed) => tenant', async () => {
    const rel = await resolver.resolveRelation(
      principal(),
      resource({ attributes: { ownerId: 42 } }),
    );
    expect(rel).toBe('tenant');
  });

  it("cles d'attributs configurables (ownerAttributeKeys / unitAttributeKeys)", async () => {
    const custom = new PrincipalRelationResolver({
      ownerAttributeKeys: ['createdBy'],
      unitAttributeKeys: ['stationId'],
    });
    expect(
      await custom.resolveRelation(principal(), resource({ attributes: { createdBy: 'u1' } })),
    ).toBe('self');
    expect(
      await custom.resolveRelation(principal(), resource({ attributes: { stationId: 'unit-A' } })),
    ).toBe('unit');
    // `ownerId` par defaut n'est plus lu avec une carte personnalisee.
    expect(
      await custom.resolveRelation(principal(), resource({ attributes: { ownerId: 'u1' } })),
    ).toBe('tenant');
  });
});
