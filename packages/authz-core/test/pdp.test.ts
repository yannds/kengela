import type {
  AuthorizationRepository,
  Clock,
  Decision,
  DecisionLogSink,
  Grant,
  OrgRelation,
  Principal,
  RelationResolver,
} from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { RbacDecisionPoint } from '../src/pdp.js';

const FIXED_CLOCK: Clock = { now: () => 1000 };

const principal = (): Principal => ({
  userId: 'u1',
  tenantId: 't1',
  roles: ['cashier'],
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: 0 },
});

const repoWith = (grants: readonly Grant[]): AuthorizationRepository => ({
  loadGrantsForUser: () => Promise.resolve(grants),
  loadRole: () => Promise.resolve(null),
});

const relationOf = (relation: OrgRelation): RelationResolver => ({
  resolveRelation: () => Promise.resolve(relation),
});

const grant = (permission: string, scope: Grant['scope']): Grant => ({
  permission,
  scope,
  source: 'MANUAL',
});

const request = (type: string, action: string) => ({
  principal: principal(),
  action,
  resource: { type, tenantId: 't1' },
});

describe('RbacDecisionPoint', () => {
  it('autorise quand un grant couvre a la relation', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: relationOf('subtree'),
      clock: FIXED_CLOCK,
    });
    const decision = await pdp.check(request('data.cashier.register', 'read'));
    expect(decision.effect).toBe('allow');
    expect(decision.reason).toBe('rbac_grant');
    expect(decision.matchedPolicy).toBe('data.cashier.register.read');
  });

  it('refuse par defaut sans grant (deny-by-default)', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.orders.read', 'tenant')]),
      relations: relationOf('self'),
      clock: FIXED_CLOCK,
    });
    const decision = await pdp.check(request('data.cashier.register', 'read'));
    expect(decision.effect).toBe('deny');
    expect(decision.reason).toBe('no_grant');
  });

  it('refuse quand la portee est insuffisante pour la relation', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'own')]),
      relations: relationOf('tenant'),
      clock: FIXED_CLOCK,
    });
    const decision = await pdp.check(request('data.cashier.register', 'read'));
    expect(decision.effect).toBe('deny');
  });

  it('emet un decision log a chaque check', async () => {
    const records: { decision: Decision; at: number }[] = [];
    const log: DecisionLogSink = {
      record: (entry) => {
        records.push({ decision: entry.decision, at: entry.at });
      },
    };
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: relationOf('self'),
      log,
      clock: FIXED_CLOCK,
    });
    await pdp.check(request('data.cashier.register', 'read'));
    expect(records).toHaveLength(1);
    expect(records[0]?.at).toBe(1000);
    expect(records[0]?.decision.effect).toBe('allow');
  });

  it('checkMany traite un lot', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.cashier.*', 'tenant')]),
      relations: relationOf('self'),
      clock: FIXED_CLOCK,
    });
    const decisions = await pdp.checkMany([
      request('data.cashier.register', 'read'),
      request('data.orders', 'read'),
    ]);
    expect(decisions.map((d) => d.effect)).toEqual(['allow', 'deny']);
  });
});
