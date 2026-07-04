/**
 * TranslogPolicyStore - implements PolicyStore on TranslogPrismaLike.
 *
 * TransLog has NO declarative policy table for now: authorization relies on RBAC alone
 * (grants from RolePermission). We therefore return `[]` honestly rather than inventing
 * policies. See DEBT.md for the target (policy table + tenant overrides).
 */
import type { Policy, PolicyStore } from '@kengela/contracts';

export class TranslogPolicyStore implements PolicyStore {
  // Signature without parameter: conforms to `PolicyStore.loadPolicies(tenantId)`
  // (an implementation may ignore trailing parameters). TransLog has no policy
  // table -> honest `[]`.
  public loadPolicies(): Promise<readonly Policy[]> {
    return Promise.resolve([]);
  }
}
