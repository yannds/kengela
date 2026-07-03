import type { PolicyRow, PolicyRuleRow } from '../src/prisma-like.js';
import { describe, expect, it } from 'vitest';
import { PrismaPolicyStore } from '../src/policy-store.js';
import { FakePrisma } from './fake-prisma.js';

const ruleRow = (over: Partial<PolicyRuleRow>): PolicyRuleRow => ({
  effect: 'allow',
  scope: null,
  when: null,
  obligations: null,
  reason: null,
  ...over,
});

const policyRow = (rules: readonly PolicyRuleRow[]): PolicyRow => ({
  resource: 'data.cashier.register',
  action: 'read',
  tenantId: 't1',
  rules,
});

describe('PrismaPolicyStore.loadPolicies', () => {
  it('mappe une policy avec sa regle et ses champs optionnels', async () => {
    const prisma = new FakePrisma();
    prisma.seedPolicy(
      policyRow([
        ruleRow({
          effect: 'allow',
          scope: 'tenant',
          when: 'resource.attributes.agencyId == principal.agencyId',
          reason: 'same_agency',
        }),
      ]),
    );
    const store = new PrismaPolicyStore(prisma);

    const policies = await store.loadPolicies('t1');

    expect(policies).toEqual([
      {
        resource: 'data.cashier.register',
        action: 'read',
        rules: [
          {
            effect: 'allow',
            scope: 'tenant',
            when: 'resource.attributes.agencyId == principal.agencyId',
            reason: 'same_agency',
          },
        ],
      },
    ]);
  });

  it('fail-closed : ecarte une regle a l effet inconnu', async () => {
    const prisma = new FakePrisma();
    const warnings: string[] = [];
    prisma.seedPolicy(policyRow([ruleRow({ effect: 'maybe' }), ruleRow({ effect: 'deny' })]));
    const store = new PrismaPolicyStore(prisma, { logger: { warn: (m) => warnings.push(m) } });

    const policies = await store.loadPolicies('t1');

    expect(policies[0]?.rules).toEqual([{ effect: 'deny' }]);
    expect(warnings).toHaveLength(1);
  });

  it('fail-closed : ecarte une regle au scope present mais invalide', async () => {
    const prisma = new FakePrisma();
    prisma.seedPolicy(policyRow([ruleRow({ effect: 'allow', scope: 'universe' })]));
    const store = new PrismaPolicyStore(prisma);

    const policies = await store.loadPolicies('t1');

    expect(policies[0]?.rules).toHaveLength(0);
  });

  it('mappe les obligations valides et ecarte les types inconnus', async () => {
    const prisma = new FakePrisma();
    prisma.seedPolicy(
      policyRow([
        ruleRow({
          effect: 'step_up',
          obligations: [
            { type: 'require_mfa' },
            { type: 'teleport' },
            { type: 'notify', params: { channel: 'sms' } },
          ],
        }),
      ]),
    );
    const store = new PrismaPolicyStore(prisma);

    const policies = await store.loadPolicies('t1');

    expect(policies[0]?.rules[0]?.obligations).toEqual([
      { type: 'require_mfa' },
      { type: 'notify', params: { channel: 'sms' } },
    ]);
  });

  it('isole les policies par tenant', async () => {
    const prisma = new FakePrisma();
    prisma.seedPolicy(policyRow([ruleRow({})]));
    prisma.seedPolicy({ ...policyRow([ruleRow({})]), tenantId: 't2' });
    const store = new PrismaPolicyStore(prisma);

    expect(await store.loadPolicies('t1')).toHaveLength(1);
  });
});
