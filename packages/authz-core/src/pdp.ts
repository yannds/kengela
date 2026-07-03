/**
 * Point de decision (PDP) — couche RBAC.
 *
 * Deny-by-default, evalue PAR REQUETE (Zero Trust). Les grants sont recharges a
 * chaque check via l'AuthorizationRepository (anti-staleness : un droit revoque
 * cesse d'agir immediatement, on ne fait pas confiance au Principal.roles cache).
 *
 * Les couches ABAC (conditions CEL) et conditional access (geo/heure/risque) se
 * greffent au-dessus dans des paquets ulterieurs ; ce PDP-ci ne tranche que le RBAC.
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
import { activeGrants, grantCovers } from './engine.js';

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
    const relation = await this.#deps.relations.resolveRelation(
      request.principal,
      request.resource,
    );
    const required = `${request.resource.type}.${request.action}`;
    const held = await this.#deps.grants.loadGrantsForUser(
      request.principal.userId,
      request.principal.tenantId,
    );
    const allowed = activeGrants(held, now).some((g) => grantCovers(g, required, relation));

    const decision: Decision = allowed
      ? { effect: 'allow', reason: 'rbac_grant', matchedPolicy: required, signals: { relation } }
      : { effect: 'deny', reason: 'no_grant', signals: { relation } };

    await this.#deps.log?.record({ request, decision, at: now });
    return decision;
  }

  public checkMany(requests: readonly AccessRequest[]): Promise<readonly Decision[]> {
    return Promise.all(requests.map((r) => this.check(r)));
  }
}
