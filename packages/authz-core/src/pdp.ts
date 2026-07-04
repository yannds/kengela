/**
 * Policy Decision Point (PDP) - RBAC layer.
 *
 * Deny-by-default, evaluated PER REQUEST (Zero Trust). Grants are reloaded on
 * every check via the AuthorizationRepository (anti-staleness: a revoked right
 * stops acting immediately, we do not trust the cached Principal.roles).
 *
 * The ABAC layers (CEL conditions) and conditional access (geo/time/risk) are
 * grafted on top in later packages; this PDP only decides RBAC.
 */
import type {
  AccessRequest,
  AuthorizationRepository,
  Clock,
  Decision,
  DecisionLogSink,
  PolicyDecisionPoint,
  RelationResolver,
} from '@kengela/contracts';
import { activeGrants, grantCovers, tenantScopedRelation } from './engine.js';

export interface RbacDecisionPointDeps {
  readonly grants: AuthorizationRepository;
  readonly relations: RelationResolver;
  readonly log?: DecisionLogSink;
  readonly clock?: Clock;
}

const SYSTEM_CLOCK: Clock = { now: () => Date.now() };

export class RbacDecisionPoint implements PolicyDecisionPoint {
  readonly #deps: RbacDecisionPointDeps;

  public constructor(deps: RbacDecisionPointDeps) {
    this.#deps = deps;
  }

  public async check(request: AccessRequest): Promise<Decision> {
    const now = (this.#deps.clock ?? SYSTEM_CLOCK).now();
    const resolved = await this.#deps.relations.resolveRelation(
      request.principal,
      request.resource,
    );
    // Multi-tenant isolation, defense-in-depth: cross-tenant => relation `none`.
    const relation = tenantScopedRelation(
      request.principal.tenantId,
      request.resource.tenantId,
      resolved,
    );
    const required = `${request.resource.type}.${request.action}`;
    const held = await this.#deps.grants.loadGrantsForUser(
      request.principal.userId,
      request.principal.tenantId,
    );
    const allowed = activeGrants(held, now).some((g) => grantCovers(g, required, relation));

    const crossTenant = request.principal.tenantId !== request.resource.tenantId;
    const signals = { relation, ...(crossTenant ? { crossTenant: true } : {}) };
    const decision: Decision = allowed
      ? { effect: 'allow', reason: 'rbac_grant', matchedPolicy: required, signals }
      : { effect: 'deny', reason: 'no_grant', signals };

    await this.#deps.log?.record({ request, decision, at: now });
    return decision;
  }

  public checkMany(requests: readonly AccessRequest[]): Promise<readonly Decision[]> {
    return Promise.all(requests.map((r) => this.check(r)));
  }
}
