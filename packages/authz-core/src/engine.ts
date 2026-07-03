/**
 * Coeur de decision RBAC, deny-by-default. PUR : aucune dependance infra ni vendor.
 * Un grant couvre une permission requise a une relation donnee ssi son motif couvre
 * la permission ET sa portee couvre la relation.
 */
import type { Grant, OrgRelation, TenantId } from '@kengela/contracts';
import { permissionCovers } from './grant.js';
import { scopeCoversRelation } from './scope.js';

/** Un grant couvre-t-il la permission requise a cette relation ? */
export function grantCovers(grant: Grant, required: string, relation: OrgRelation): boolean {
  return permissionCovers(grant.permission, required) && scopeCoversRelation(grant.scope, relation);
}

/**
 * Isolation multi-tenant, defense-en-profondeur (fail-closed).
 *
 * Si la ressource visee n'appartient PAS au tenant du principal, la relation
 * organisationnelle resolue est RAMENEE a `none` : seul un grant de portee `global`
 * (plan plateforme) peut alors couvrir. Cela ferme tout franchissement cross-tenant
 * meme si le `RelationResolver` injecte se trompe et renvoie une relation trop large
 * (ex. `tenant`) pour une ressource d'un autre tenant. Le PDP n'accorde jamais sa
 * confiance aveugle a l'organigramme pour l'isolation : l'egalite de tenant prime.
 */
export function tenantScopedRelation(
  principalTenantId: TenantId,
  resourceTenantId: TenantId,
  resolved: OrgRelation,
): OrgRelation {
  return principalTenantId === resourceTenantId ? resolved : 'none';
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
