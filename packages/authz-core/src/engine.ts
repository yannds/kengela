/**
 * RBAC decision core, deny-by-default. PURE: no infra or vendor dependency.
 * A grant covers a required permission at a given relation iff its pattern covers
 * the permission AND its scope covers the relation.
 */
import type { Grant, OrgRelation, TenantId } from '@kengela/contracts';
import { permissionCovers } from './grant.js';
import { scopeCoversRelation } from './scope.js';

/** Does a grant cover the required permission at this relation? */
export function grantCovers(grant: Grant, required: string, relation: OrgRelation): boolean {
  return permissionCovers(grant.permission, required) && scopeCoversRelation(grant.scope, relation);
}

/**
 * Multi-tenant isolation, defense-in-depth (fail-closed).
 *
 * If the target resource does NOT belong to the principal's tenant, the resolved
 * organizational relation is DOWNGRADED to `none`: only a `global` scope grant
 * (platform plane) can then cover. This closes any cross-tenant crossing even if
 * the injected `RelationResolver` is wrong and returns a relation that is too broad
 * (e.g. `tenant`) for a resource in another tenant. The PDP never blindly trusts
 * the org chart for isolation: tenant equality prevails.
 */
export function tenantScopedRelation(
  principalTenantId: TenantId,
  resourceTenantId: TenantId,
  resolved: OrgRelation,
): OrgRelation {
  return principalTenantId === resourceTenantId ? resolved : 'none';
}

/** Grants still active at instant `now` (excludes expired grants). */
export function activeGrants(grants: readonly Grant[], now: number): readonly Grant[] {
  return grants.filter((g) => g.expiresAt === undefined || g.expiresAt.getTime() > now);
}

/**
 * Authorizes iff an active grant covers the permission at a scope >= relation.
 * Deny-by-default: no covering grant => deny.
 */
export function isAuthorized(
  grants: readonly Grant[],
  required: string,
  relation: OrgRelation,
  now: number,
): boolean {
  return activeGrants(grants, now).some((g) => grantCovers(g, required, relation));
}
