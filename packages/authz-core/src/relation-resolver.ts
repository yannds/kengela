/**
 * RelationResolver par defaut, PUR (aucun vendor, aucune DB).
 *
 * Les deux PDP (`RbacDecisionPoint`, `PolicyDecisionPoint`) EXIGENT un
 * `RelationResolver` en dependance, mais aucun n'etait livre : chaque app devait
 * ecrire le sien. Ce resolver comble le cas le plus courant en calculant la
 * relation organisationnelle DIRECTEMENT depuis les champs org deja portes par le
 * `Principal` (`orgUnitId`, `agencyId`, `coverageUnits`) confrontes a la
 * `ResourceRef` (`id` + `attributes.ownerId` / `attributes.unitId`...).
 *
 * DOCTRINE deny-by-default : on ne CLASSE une relation plus etroite (self > unit >
 * subtree) que si elle est PROUVABLE par les donnees fournies. A defaut de preuve,
 * on retombe sur la relation la plus faible defendable — `tenant` si la ressource
 * appartient au meme tenant, sinon `none`. Une relation plus etroite exige un grant
 * de portee plus NARROW (self=own) : ne la rendre que sur preuve evite d'ouvrir un
 * acces qu'un simple grant `own` couvrirait a tort.
 *
 * LIMITE (par conception) : la couverture organisationnelle se limite aux unites
 * DEJA presentes dans le `Principal` (`coverageUnits`). Un vrai sous-arbre calcule
 * hors du jeton (traversee de l'organigramme en base) reste du ressort d'un
 * `RelationResolver` cote app, adosse a la persistance — ce resolver-ci ne fait
 * AUCUN acces I/O et reste donc composable/testable sans infra.
 */
import type { OrgRelation, Principal, RelationResolver, ResourceRef } from '@kengela/contracts';

/**
 * Options du resolver : noms d'attributs de ressource a lire (config-driven, jamais
 * en dur cote app). Les defauts couvrent les conventions usuelles.
 */
export interface PrincipalRelationResolverOptions {
  /** Attributs portant le proprietaire de la ressource (essayes dans l'ordre). Defaut : `ownerId`. */
  readonly ownerAttributeKeys?: readonly string[];
  /** Attributs portant l'unite organisationnelle de la ressource. Defaut : `unitId`, `orgUnitId`, `agencyId`. */
  readonly unitAttributeKeys?: readonly string[];
}

const DEFAULT_OWNER_KEYS: readonly string[] = ['ownerId'];
const DEFAULT_UNIT_KEYS: readonly string[] = ['unitId', 'orgUnitId', 'agencyId'];

/** Chaine non vide, ou `undefined` (fail-closed sur toute autre forme). */
function asId(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** Premiere valeur d'identifiant non vide parmi les cles candidates. */
function firstAttr(
  attributes: Readonly<Record<string, unknown>> | undefined,
  keys: readonly string[],
): string | undefined {
  if (attributes === undefined) {
    return undefined;
  }
  for (const key of keys) {
    const value = asId(attributes[key]);
    if (value !== undefined) {
      return value;
    }
  }
  return undefined;
}

/** Unites organisationnelles propres au principal (unite directe + agence). */
function principalUnitIds(principal: Principal): ReadonlySet<string> {
  const ids = new Set<string>();
  if (principal.orgUnitId !== undefined) {
    ids.add(principal.orgUnitId);
  }
  if (principal.agencyId !== undefined) {
    ids.add(principal.agencyId);
  }
  return ids;
}

export class PrincipalRelationResolver implements RelationResolver {
  readonly #ownerKeys: readonly string[];
  readonly #unitKeys: readonly string[];

  public constructor(options: PrincipalRelationResolverOptions = {}) {
    this.#ownerKeys = options.ownerAttributeKeys ?? DEFAULT_OWNER_KEYS;
    this.#unitKeys = options.unitAttributeKeys ?? DEFAULT_UNIT_KEYS;
  }

  public resolveRelation(principal: Principal, resource: ResourceRef): Promise<OrgRelation> {
    return Promise.resolve(this.#relate(principal, resource));
  }

  #relate(principal: Principal, resource: ResourceRef): OrgRelation {
    // Isolation multi-tenant, defense-en-profondeur : cross-tenant => aucun lien.
    if (resource.tenantId !== principal.tenantId) {
      return 'none';
    }

    const attributes = resource.attributes;

    // 1. self : proprietaire PROUVE (attribut owner === userId), ou la ressource
    //    EST le sujet lui-meme (`resource.id === userId`, cas d'un profil `user`).
    const ownerId = firstAttr(attributes, this.#ownerKeys);
    if (ownerId === principal.userId || asId(resource.id) === principal.userId) {
      return 'self';
    }

    // 2/3. unite : l'unite de la ressource est-elle celle du principal (unit) ou
    //       une unite qu'il couvre (subtree) ? Sans unite lisible => on n'affirme rien.
    const resourceUnitId = firstAttr(attributes, this.#unitKeys);
    if (resourceUnitId !== undefined) {
      if (principalUnitIds(principal).has(resourceUnitId)) {
        return 'unit';
      }
      if (principal.coverageUnits?.includes(resourceUnitId) === true) {
        return 'subtree';
      }
    }

    // 4. meme tenant, aucun lien plus etroit prouvable => la relation la plus faible
    //    defendable est `tenant` (exige un grant de portee tenant pour couvrir).
    return 'tenant';
  }
}
