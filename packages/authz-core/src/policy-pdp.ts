/**
 * PDP en couches — RBAC (plancher) + ABAC (conditions) + conditional access.
 *
 * Zero Trust, deny-by-default, evalue PAR REQUETE. Ordre de decision :
 *  1. Plancher RBAC : sans grant actif couvrant la permission a la relation, DENY.
 *  2. Policies applicables a (resource, action) : evaluees contre {principal, resource, env}
 *     via l'ExpressionEnginePort (CEL fourni par un adapter ; ici on ne fait que deleguer).
 *  3. Un DENY explicite l'emporte (deny-wins).
 *  4. Gate ABAC positif : si des regles `allow` existent, au moins une doit matcher
 *     (sinon DENY `no_matching_allow`) — c'est le scoping declaratif (ex. meme agence).
 *  5. STEP_UP : les regles `step_up` matchees imposent des obligations (ex. passkey).
 *  6. Sinon ALLOW.
 *
 * PUR : aucune dependance vendor. Le moteur CEL concret est injecte (adapter).
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
    // Isolation multi-tenant, defense-en-profondeur : cross-tenant => relation `none`
    // (seul un grant `global` du plan plateforme peut couvrir).
    const relation = tenantScopedRelation(principal.tenantId, resource.tenantId, resolved);
    const required = `${resource.type}.${action}`;

    // 1. Plancher RBAC.
    const held = await this.#deps.grants.loadGrantsForUser(principal.userId, principal.tenantId);
    const rbacOk = activeGrants(held, now).some((g) => grantCovers(g, required, relation));
    if (!rbacOk) {
      return this.#emit(
        request,
        { effect: 'deny', reason: 'no_grant', signals: { relation } },
        now,
      );
    }

    // 2. Policies applicables.
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
    // FAIL-CLOSED (Zero Trust) : si une condition ne peut pas etre evaluee
    // (variable absente, expression invalide...), on REFUSE la requete.
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

    // 3. Deny explicite prioritaire.
    const deny = matched.find((r) => r.effect === 'deny');
    if (deny) {
      return this.#emit(
        request,
        { effect: 'deny', reason: deny.reason ?? 'policy_deny', signals: { relation } },
        now,
      );
    }

    // 4. Gate ABAC positif.
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

    // 6. Autorise.
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
