/**
 * Adapter CEL — implémente ExpressionEnginePort à l'aide de @marcbachmann/cel-js.
 *
 * Le vendor vit ICI (paquet adapter). Sandboxé, lecture seule, compilations mises
 * en cache. Le contexte {principal, resource, env, tenant} est exposé tel quel aux
 * expressions ; une expression doit retourner un booléen (sinon erreur explicite).
 *
 * Fonctions de dates injectées (déterministes via Clock) : `now()`, `daysUntil(x)`,
 * `businessDaysBetween(a, b)` — pour des conditions temporelles (échéance, business-hours).
 *
 * Dette connue (voir DEBT.md) : une erreur d'évaluation (variable absente, non-booléen)
 * est LEVÉE ; le PDP (LayeredDecisionPoint) la rattrape en fail-closed (deny).
 */
import { Environment } from '@marcbachmann/cel-js';
import type { Clock, ExpressionContext, ExpressionEnginePort } from '@kengela/contracts';
import { businessDaysBetween, daysBetween, toEpochMs } from './dates.js';

type CompiledExpression = (context: Record<string, unknown>) => unknown;

const SYSTEM_CLOCK: Clock = { now: () => Date.now() };

export class CelEvaluationError extends Error {
  public override readonly name = 'CelEvaluationError';
}

export class CelExpressionEngine implements ExpressionEnginePort {
  readonly #env: Environment;
  readonly #cache = new Map<string, CompiledExpression>();

  public constructor(options: { readonly clock?: Clock } = {}) {
    const clock = options.clock ?? SYSTEM_CLOCK;
    this.#env = new Environment()
      // Variables de contexte exposées aux policies (accès dynamique).
      .registerVariable('principal', 'dyn')
      .registerVariable('resource', 'dyn')
      .registerVariable('env', 'dyn')
      .registerVariable('tenant', 'dyn')
      .registerFunction('now(): int', (): bigint => BigInt(clock.now()))
      .registerFunction('daysUntil(dyn): int', (target: unknown): bigint =>
        BigInt(daysBetween(clock.now(), toEpochMs(target))),
      )
      .registerFunction('businessDaysBetween(dyn, dyn): int', (a: unknown, b: unknown): bigint =>
        BigInt(businessDaysBetween(toEpochMs(a), toEpochMs(b))),
      );
  }

  public evaluateBoolean(expression: string, ctx: ExpressionContext): boolean {
    const compiled = this.#compile(expression);
    let result: unknown;
    try {
      result = compiled(ctx as unknown as Record<string, unknown>);
    } catch (err: unknown) {
      throw new CelEvaluationError(`Echec d'evaluation CEL « ${expression} » : ${messageOf(err)}`);
    }
    if (typeof result !== 'boolean') {
      throw new CelEvaluationError(
        `Expression CEL non booleenne « ${expression} » -> ${typeof result}`,
      );
    }
    return result;
  }

  #compile(expression: string): CompiledExpression {
    const cached = this.#cache.get(expression);
    if (cached !== undefined) {
      return cached;
    }
    let compiled: CompiledExpression;
    try {
      compiled = this.#env.parse(expression);
    } catch (err: unknown) {
      throw new CelEvaluationError(`Expression CEL invalide « ${expression} » : ${messageOf(err)}`);
    }
    this.#cache.set(expression, compiled);
    return compiled;
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
