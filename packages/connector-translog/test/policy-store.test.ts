import type { PolicyStore } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { TranslogPolicyStore } from '../src/policy-store.js';

describe('TranslogPolicyStore.loadPolicies', () => {
  it('retourne toujours [] (TransLog n a pas de table policy)', async () => {
    // Type via le port : le consommateur appelle loadPolicies(tenantId).
    const store: PolicyStore = new TranslogPolicyStore();
    expect(await store.loadPolicies('t1')).toEqual([]);
  });
});
