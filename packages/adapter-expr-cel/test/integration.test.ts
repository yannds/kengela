/**
 * Preuve bout-en-bout : le vrai moteur CEL branche dans le PDP en couches
 * d'authz-core. Le scoping declaratif et le conditional access sont evalues
 * par CEL reel, pas un stub.
 */
import type {
  AccessRequest,
  AuthorizationRepository,
  Grant,
  Policy,
  Principal,
  RelationResolver,
} from '@kengela/contracts';
import { LayeredDecisionPoint } from '@kengela/authz-core';
import { describe, expect, it } from 'vitest';
import { CelExpressionEngine } from '../src/cel-expression-engine.js';

const GRANT: Grant = {
  permission: 'data.cashier.register.read',
  scope: 'tenant',
  source: 'MANUAL',
};

const repo: AuthorizationRepository = {
  loadGrantsForUser: () => Promise.resolve([GRANT]),
  loadRole: () => Promise.resolve(null),
};
const relations: RelationResolver = { resolveRelation: () => Promise.resolve('self') };

const principal = (agency: string): Principal => ({
  userId: 'u1',
  tenantId: 't1',
  roles: ['cashier'],
  agencyId: agency,
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: 0 },
});

const request = (agency: string, resourceAgency: string, riskScore: number): AccessRequest => ({
  principal: principal(agency),
  action: 'read',
  resource: {
    type: 'data.cashier.register',
    tenantId: 't1',
    attributes: { agencyId: resourceAgency },
  },
  env: { riskScore },
});

const pdp = (policies: readonly Policy[]): LayeredDecisionPoint =>
  new LayeredDecisionPoint({
    grants: repo,
    relations,
    policies: { loadPolicies: () => Promise.resolve(policies) },
    expr: new CelExpressionEngine(),
    clock: { now: () => 1000 },
  });

const SCOPING: Policy = {
  resource: 'data.cashier.register',
  action: 'read',
  rules: [{ effect: 'allow', when: 'resource.attributes.agencyId == principal.agencyId' }],
};
const RISK_DENY: Policy = {
  resource: 'data.cashier.register',
  action: 'read',
  rules: [{ effect: 'deny', when: 'env.riskScore > 50', reason: 'high_risk' }],
};

describe('CEL reel dans le LayeredDecisionPoint', () => {
  it("scoping ABAC : allow quand l'agence de la ressource correspond", async () => {
    const d = await pdp([SCOPING]).check(request('A1', 'A1', 0));
    expect(d.effect).toBe('allow');
  });

  it('scoping ABAC : deny quand elle differe', async () => {
    const d = await pdp([SCOPING]).check(request('A1', 'A2', 0));
    expect(d.effect).toBe('deny');
    expect(d.reason).toBe('no_matching_allow');
  });

  it('conditional access : deny sur risque eleve', async () => {
    const d = await pdp([RISK_DENY]).check(request('A1', 'A1', 80));
    expect(d.effect).toBe('deny');
    expect(d.reason).toBe('high_risk');
  });

  it('conditional access : allow sur risque faible', async () => {
    const d = await pdp([RISK_DENY]).check(request('A1', 'A1', 10));
    expect(d.effect).toBe('allow');
  });
});
