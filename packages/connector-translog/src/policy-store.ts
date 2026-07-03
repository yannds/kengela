/**
 * TranslogPolicyStore — implemente PolicyStore sur TranslogPrismaLike.
 *
 * TransLog n'a PAS de table de policies declaratives pour l'instant : l'autorisation
 * repose sur le RBAC seul (grants issus de RolePermission). On retourne donc `[]`
 * de maniere honnete plutot que d'inventer des policies. Voir DEBT.md pour la cible
 * (table policy + overrides tenant).
 */
import type { Policy, PolicyStore } from '@kengela/contracts';

export class TranslogPolicyStore implements PolicyStore {
  // Signature sans parametre : conforme a `PolicyStore.loadPolicies(tenantId)`
  // (une implementation peut ignorer des parametres de fin). TransLog n'a pas de
  // table policy -> `[]` honnete.
  public loadPolicies(): Promise<readonly Policy[]> {
    return Promise.resolve([]);
  }
}
