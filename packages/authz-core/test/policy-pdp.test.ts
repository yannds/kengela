import type {
  AuthContext,
  AuthorizationRepository,
  Clock,
  Decision,
  DecisionLogSink,
  ExpressionContext,
  ExpressionEnginePort,
  Grant,
  OrgRelation,
  Policy,
  Principal,
  RelationResolver,
} from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { LayeredDecisionPoint } from '../src/policy-pdp.js';

const CLOCK: Clock = { now: () => 1000 };

/** Stub d'evaluateur : le vrai CEL est un adapter ; ici on interprete 2 jetons. */
const EXPR: ExpressionEnginePort = {
  evaluateBoolean: (expression: string, ctx: ExpressionContext): boolean => {
    if (expression === 'agency_match') {
      return ctx.resource.attributes?.['agencyId'] === ctx.principal.agencyId;
    }
    if (expression === 'high_risk') {
      return (ctx.env.riskScore ?? 0) > 50;
    }
    return false;
  },
};

const grant = (permission: string, scope: Grant['scope']): Grant => ({
  permission,
  scope,
  source: 'MANUAL',
});

const repoWith = (grants: readonly Grant[]): AuthorizationRepository => ({
  loadGrantsForUser: () => Promise.resolve(grants),
  loadRole: () => Promise.resolve(null),
});

const relationOf = (relation: OrgRelation): RelationResolver => ({
  resolveRelation: () => Promise.resolve(relation),
});

const store = (
  policies: readonly Policy[],
): { loadPolicies: () => Promise<readonly Policy[]> } => ({
  loadPolicies: () => Promise.resolve(policies),
});

const principal = (agencyId: string): Principal => ({
  userId: 'u1',
  tenantId: 't1',
  roles: ['cashier'],
  agencyId,
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: 0 },
});

const request = (agencyId: string, resourceAgency: string, env: Partial<AuthContext> = {}) => ({
  principal: principal(agencyId),
  action: 'read',
  resource: {
    type: 'data.cashier.register',
    tenantId: 't1',
    attributes: { agencyId: resourceAgency },
  },
  env,
});

const GRANT = grant('data.cashier.register.read', 'tenant');

const ALLOW_SCOPING: Policy = {
  resource: 'data.cashier.register',
  action: 'read',
  rules: [{ effect: 'allow', when: 'agency_match' }],
};
const DENY_RISK: Policy = {
  resource: 'data.cashier.register',
  action: 'read',
  rules: [{ effect: 'deny', when: 'high_risk', reason: 'high_risk_blocked' }],
};
const STEPUP_RISK: Policy = {
  resource: 'data.cashier.register',
  action: 'read',
  rules: [{ effect: 'step_up', when: 'high_risk', obligations: [{ type: 'require_passkey' }] }],
};

const pdp = (grants: readonly Grant[], policies: readonly Policy[], log?: DecisionLogSink) =>
  new LayeredDecisionPoint({
    grants: repoWith(grants),
    relations: relationOf('self'),
    policies: store(policies),
    expr: EXPR,
    clock: CLOCK,
    ...(log ? { log } : {}),
  });

describe('LayeredDecisionPoint', () => {
  it('RBAC seul gouverne sans policy', async () => {
    const d = await pdp([GRANT], []).check(request('A1', 'A1'));
    expect(d.effect).toBe('allow');
    expect(d.reason).toBe('rbac_grant');
  });

  it('plancher RBAC : deny sans grant meme avec policy allow', async () => {
    const d = await pdp([], [ALLOW_SCOPING]).check(request('A1', 'A1'));
    expect(d.effect).toBe('deny');
    expect(d.reason).toBe('no_grant');
  });

  it('scoping ABAC : allow si la condition matche (meme agence)', async () => {
    const d = await pdp([GRANT], [ALLOW_SCOPING]).check(request('A1', 'A1'));
    expect(d.effect).toBe('allow');
  });

  it('scoping ABAC : deny no_matching_allow si condition non satisfaite', async () => {
    const d = await pdp([GRANT], [ALLOW_SCOPING]).check(request('A1', 'A2'));
    expect(d.effect).toBe('deny');
    expect(d.reason).toBe('no_matching_allow');
  });

  it("deny explicite l'emporte (deny-wins)", async () => {
    const d = await pdp([GRANT], [ALLOW_SCOPING, DENY_RISK]).check(
      request('A1', 'A1', { riskScore: 80 }),
    );
    expect(d.effect).toBe('deny');
    expect(d.reason).toBe('high_risk_blocked');
  });

  it('step-up : impose une obligation (passkey) sur risque eleve', async () => {
    const d = await pdp([GRANT], [ALLOW_SCOPING, STEPUP_RISK]).check(
      request('A1', 'A1', { riskScore: 80 }),
    );
    expect(d.effect).toBe('step_up');
    expect(d.obligations?.[0]?.type).toBe('require_passkey');
  });

  it('emet un decision log', async () => {
    const records: Decision[] = [];
    const log: DecisionLogSink = {
      record: (entry) => {
        records.push(entry.decision);
      },
    };
    await pdp([GRANT], [], log).check(request('A1', 'A1'));
    expect(records).toHaveLength(1);
    expect(records[0]?.effect).toBe('allow');
  });
});
