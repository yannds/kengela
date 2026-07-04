/**
 * Layered PDP - RBAC (floor) + ABAC (conditions) + conditional access.
 *
 * Zero Trust, deny-by-default, evaluated PER REQUEST. Decision order:
 *  1. RBAC floor: without an active grant covering the permission at the relation, DENY.
 *  2. Policies applicable to (resource, action): evaluated against {principal, resource, env}
 *     via the ExpressionEnginePort (CEL provided by an adapter; here we only delegate).
 *  3. An explicit DENY wins (deny-wins).
 *  4. Positive ABAC gate: if `allow` rules exist, at least one must match
 *     (otherwise DENY `no_matching_allow`) - this is declarative scoping (e.g. same agency).
 *  5. STEP_UP: matched `step_up` rules impose obligations (e.g. passkey).
 *  6. Otherwise ALLOW.
 *
 * PURE: no vendor dependency. The concrete CEL engine is injected (adapter).
 */
import type {
  AccessRequest,
  AuthorizationRepository,
  Clock,
  Decision,
  DecisionLogSink,
  ExpressionContext,
  ExpressionEnginePort,
  Obligation,
  OrgRelation,
  Policy,
  PolicyDecisionPoint,
  PolicyRule,
  PolicyStore,
  RelationResolver,
} from '@kengela/contracts';
import { activeGrants, grantCovers, tenantScopedRelation } from './engine.js';
import { scopeCoversRelation } from './scope.js';

export interface LayeredDecisionPointDeps {
  readonly grants: AuthorizationRepository;
  readonly relations: RelationResolver;
  readonly policies: PolicyStore;
  readonly expr: ExpressionEnginePort;
  readonly log?: DecisionLogSink;
  readonly clock?: Clock;
}

const SYSTEM_CLOCK: Clock = { now: () => Date.now() };

function policyMatchesRequest(policy: Policy, resourceType: string, action: string): boolean {
  const resourceOk = policy.resource === '*' || policy.resource === resourceType;
  const actionOk = policy.action === '*' || policy.action === action;
  return resourceOk && actionOk;
}

export class LayeredDecisionPoint implements PolicyDecisionPoint {
  readonly #deps: LayeredDecisionPointDeps;

  public constructor(deps: LayeredDecisionPointDeps) {
    this.#deps = deps;
  }

  public async check(request: AccessRequest): Promise<Decision> {
    const now = (this.#deps.clock ?? SYSTEM_CLOCK).now();
    const { principal, resource, action } = request;
    const resolved = await this.#deps.relations.resolveRelation(principal, resource);
    // Multi-tenant isolation, defense-in-depth: cross-tenant => relation `none`
    // (only a `global` grant from the platform plane can cover).
    const relation = tenantScopedRelation(principal.tenantId, resource.tenantId, resolved);
    const required = `${resource.type}.${action}`;

    // 1. RBAC floor.
    const held = await this.#deps.grants.loadGrantsForUser(principal.userId, principal.tenantId);
    const rbacOk = activeGrants(held, now).some((g) => grantCovers(g, required, relation));
    if (!rbacOk) {
      return this.#emit(
        request,
        { effect: 'deny', reason: 'no_grant', signals: { relation } },
        now,
      );
    }

    // 2. Applicable policies.
    const all = await this.#deps.policies.loadPolicies(principal.tenantId);
    const rules = all
      .filter((p) => policyMatchesRequest(p, resource.type, action))
      .flatMap((p) => p.rules);

    if (rules.length === 0) {
      return this.#emit(
        request,
        { effect: 'allow', reason: 'rbac_grant', matchedPolicy: required, signals: { relation } },
        now,
      );
    }

    const ctx: ExpressionContext = {
      principal,
      resource,
      env: { ...principal.ctx, ...request.env, now },
    };
    // FAIL-CLOSED (Zero Trust): if a condition cannot be evaluated
    // (missing variable, invalid expression...), we REFUSE the request.
    let matched: PolicyRule[];
    try {
      matched = rules.filter((r) => this.#ruleApplies(r, relation, ctx));
    } catch {
      return this.#emit(
        request,
        { effect: 'deny', reason: 'condition_error', signals: { relation } },
        now,
      );
    }

    // 3. Explicit deny takes precedence.
    const deny = matched.find((r) => r.effect === 'deny');
    if (deny) {
      return this.#emit(
        request,
        { effect: 'deny', reason: deny.reason ?? 'policy_deny', signals: { relation } },
        now,
      );
    }

    // 4. Positive ABAC gate.
    const hasAllowRules = rules.some((r) => r.effect === 'allow');
    const hasMatchedAllow = matched.some((r) => r.effect === 'allow');
    if (hasAllowRules && !hasMatchedAllow) {
      return this.#emit(
        request,
        { effect: 'deny', reason: 'no_matching_allow', signals: { relation } },
        now,
      );
    }

    // 5. Step-up.
    const obligations: Obligation[] = matched
      .filter((r) => r.effect === 'step_up')
      .flatMap((r) => r.obligations ?? []);
    if (obligations.length > 0) {
      return this.#emit(
        request,
        { effect: 'step_up', reason: 'step_up_required', obligations, signals: { relation } },
        now,
      );
    }

    // 6. Authorized.
    return this.#emit(
      request,
      { effect: 'allow', reason: 'rbac_grant', matchedPolicy: required, signals: { relation } },
      now,
    );
  }

  public checkMany(requests: readonly AccessRequest[]): Promise<readonly Decision[]> {
    return Promise.all(requests.map((r) => this.check(r)));
  }

  #ruleApplies(rule: PolicyRule, relation: OrgRelation, ctx: ExpressionContext): boolean {
    if (rule.scope !== undefined && !scopeCoversRelation(rule.scope, relation)) {
      return false;
    }
    return rule.when === undefined || this.#deps.expr.evaluateBoolean(rule.when, ctx);
  }

  async #emit(request: AccessRequest, decision: Decision, at: number): Promise<Decision> {
    await this.#deps.log?.record({ request, decision, at });
    return decision;
  }
}
