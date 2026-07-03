/**
 * Portees et relations organisationnelles.
 *
 * Un droit accorde a une portee couvre toutes les portees plus etroites :
 *   own subset unit subset subtree subset tenant subset global
 *
 * La *relation* est la position de la ressource par rapport a l'acteur, resolue
 * en amont sur l'organigramme (RelationResolver). On la convertit en rang de
 * portee minimal requis pour couvrir la ressource.
 */
import type { OrgRelation, Scope } from '@kengela/contracts';

/** Portees de la plus etroite (0) a la plus large (4). */
export const SCOPE_RANK: Readonly<Record<Scope, number>> = {
  own: 0,
  unit: 1,
  subtree: 2,
  tenant: 3,
  global: 4,
};

/** Rang de portee minimal qu'un grant doit avoir pour couvrir cette relation. */
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
      // Aucun lien organisationnel : seul un grant `global` peut couvrir.
      return SCOPE_RANK.global;
  }
}

/** La portee d'un grant couvre-t-elle la relation demandee ? */
export function scopeCoversRelation(grantScope: Scope, relation: OrgRelation): boolean {
  return SCOPE_RANK[grantScope] >= relationRank(relation);
}
