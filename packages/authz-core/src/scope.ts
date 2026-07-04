/**
 * Organizational scopes and relations.
 *
 * A right granted at a scope covers all narrower scopes:
 *   own subset unit subset subtree subset tenant subset global
 *
 * The *relation* is the position of the resource relative to the actor, resolved
 * upstream against the org chart (RelationResolver). We convert it into the
 * minimal scope rank required to cover the resource.
 */
import type { OrgRelation, Scope } from '@kengela/contracts';

/** Scopes from the narrowest (0) to the broadest (4). */
export const SCOPE_RANK: Readonly<Record<Scope, number>> = {
  own: 0,
  unit: 1,
  subtree: 2,
  tenant: 3,
  global: 4,
};

/** Minimal scope rank a grant must have to cover this relation. */
export function relationRank(relation: OrgRelation): number {
  switch (relation) {
    case 'self':
      return SCOPE_RANK.own;
    case 'unit':
      return SCOPE_RANK.unit;
    case 'subtree':
      return SCOPE_RANK.subtree;
    case 'tenant':
      return SCOPE_RANK.tenant;
    case 'none':
      // No organizational link: only a `global` grant can cover.
      return SCOPE_RANK.global;
  }
}

/** Does a grant's scope cover the requested relation? */
export function scopeCoversRelation(grantScope: Scope, relation: OrgRelation): boolean {
  return SCOPE_RANK[grantScope] >= relationRank(relation);
}
