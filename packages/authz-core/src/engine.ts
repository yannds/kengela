/**
 * Coeur de decision RBAC, deny-by-default. PUR : aucune dependance infra ni vendor.
 * Un grant couvre une permission requise a une relation donnee ssi son motif couvre
 * la permission ET sa portee couvre la relation.
 */
import type { Grant, OrgRelation } from '@kengela/contracts';
import { permissionCovers } from './grant.js';
import { scopeCoversRelation } from './scope.js';

/** Un grant couvre-t-il la permission requise a cette relation ? */
export function grantCovers(grant: Grant, required: string, relation: OrgRelation): boolean {
  return permissionCovers(grant.permission, required) && scopeCoversRelation(grant.scope, relation);
}

/** Grants encore actifs a l'instant `now` (exclut les grants expires). */
export function activeGrants(grants: readonly Grant[], now: number): readonly Grant[] {
  return grants.filter((g) => g.expiresAt === undefined || g.expiresAt.getTime() > now);
}

/**
 * Autorise ssi un grant actif couvre la permission a une portee >= relation.
 * Deny-by-default : aucun grant couvrant => refus.
 */
export function isAuthorized(
  grants: readonly Grant[],
  required: string,
  relation: OrgRelation,
  now: number,
): boolean {
  return activeGrants(grants, now).some((g) => grantCovers(g, required, relation));
}
