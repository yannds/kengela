/**
 * Default RelationResolver, PURE (no vendor, no DB).
 *
 * Both PDPs (`RbacDecisionPoint`, `PolicyDecisionPoint`) REQUIRE a
 * `RelationResolver` as a dependency, but none was shipped: every app had to
 * write its own. This resolver covers the most common case by computing the
 * organizational relation DIRECTLY from the org fields already carried by the
 * `Principal` (`orgUnitId`, `agencyId`, `coverageUnits`) matched against the
 * `ResourceRef` (`id` + `attributes.ownerId` / `attributes.unitId`...).
 *
 * deny-by-default DOCTRINE: we only CLASSIFY a narrower relation (self > unit >
 * subtree) if it is PROVABLE from the supplied data. Without proof, we fall back
 * to the weakest defensible relation - `tenant` if the resource belongs to the
 * same tenant, otherwise `none`. A narrower relation requires a NARROWER scope
 * grant (self=own): only returning it on proof avoids opening an access that a
 * plain `own` grant would wrongly cover.
 *
 * LIMIT (by design): organizational coverage is limited to the units ALREADY
 * present in the `Principal` (`coverageUnits`). A true subtree computed outside
 * the token (org chart traversal in the database) remains the responsibility of
 * an app-side `RelationResolver` backed by persistence - this resolver does NO
 * I/O access and thus stays composable/testable without infra.
 */
import type { OrgRelation, Principal, RelationResolver, ResourceRef } from '@kengela/contracts';

/**
 * Resolver options: names of resource attributes to read (config-driven, never
 * hardcoded app-side). The defaults cover the usual conventions.
 */
export interface PrincipalRelationResolverOptions {
  /** Attributes carrying the resource owner (tried in order). Default: `ownerId`. */
  readonly ownerAttributeKeys?: readonly string[];
  /** Attributes carrying the resource's organizational unit. Default: `unitId`, `orgUnitId`, `agencyId`. */
  readonly unitAttributeKeys?: readonly string[];
}

const DEFAULT_OWNER_KEYS: readonly string[] = ['ownerId'];
const DEFAULT_UNIT_KEYS: readonly string[] = ['unitId', 'orgUnitId', 'agencyId'];

/** Non-empty string, or `undefined` (fail-closed on any other shape). */
function asId(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** First non-empty id value among the candidate keys. */
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

/** Organizational units owned by the principal (direct unit + agency). */
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
    // Multi-tenant isolation, defense-in-depth: cross-tenant => no link.
    if (resource.tenantId !== principal.tenantId) {
      return 'none';
    }

    const attributes = resource.attributes;

    // 1. self: PROVEN owner (owner attribute === userId), or the resource
    //    IS the subject itself (`resource.id === userId`, case of a `user` profile).
    const ownerId = firstAttr(attributes, this.#ownerKeys);
    if (ownerId === principal.userId || asId(resource.id) === principal.userId) {
      return 'self';
    }

    // 2/3. unit: is the resource's unit the principal's own (unit) or a unit it
    //       covers (subtree)? Without a readable unit => we assert nothing.
    const resourceUnitId = firstAttr(attributes, this.#unitKeys);
    if (resourceUnitId !== undefined) {
      if (principalUnitIds(principal).has(resourceUnitId)) {
        return 'unit';
      }
      if (principal.coverageUnits?.includes(resourceUnitId) === true) {
        return 'subtree';
      }
    }

    // 4. same tenant, no narrower link provable => the weakest defensible
    //    relation is `tenant` (requires a tenant scope grant to cover).
    return 'tenant';
  }
}
