/**
 * CEL adapter - implements ExpressionEnginePort using @marcbachmann/cel-js.
 *
 * The vendor lives HERE (adapter package). Sandboxed, read-only, compilations
 * cached. The context {principal, resource, env, tenant} is exposed as-is to
 * expressions; an expression must return a boolean (otherwise an explicit error).
 *
 * Injected date functions (deterministic via Clock): `now()`, `daysUntil(x)`,
 * `businessDaysBetween(a, b)` - for temporal conditions (deadline, business-hours).
 *
 * Known debt (see DEBT.md): an evaluation error (missing variable, non-boolean)
 * is THROWN; the PDP (LayeredDecisionPoint) catches it fail-closed (deny).
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
      // Context variables exposed to policies (dynamic access).
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
      throw new CelEvaluationError(`CEL evaluation failed "${expression}": ${messageOf(err)}`);
    }
    if (typeof result !== 'boolean') {
      throw new CelEvaluationError(
        `Non-boolean CEL expression "${expression}" -> ${typeof result}`,
      );
    }
    return result;
  }

  #compile(expression: string): CompiledExpression {
    const cached = this.#cache.get(expression);
    if (cached !== undefined) {
      return cached;
    }
    assertNoUnboundedRegex(expression);
    let compiled: CompiledExpression;
    try {
      compiled = this.#env.parse(expression);
    } catch (err: unknown) {
      throw new CelEvaluationError(`Invalid CEL expression "${expression}": ${messageOf(err)}`);
    }
    this.#cache.set(expression, compiled);
    return compiled;
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Replaces the CONTENT of string literals (`'...'` / `"..."`, escapes handled) with
 * empty, to analyze an expression's structure without confusing code with a string.
 * Linear pattern (each alternative consumes disjoint characters): no ReDoS here.
 */
function stripStringLiterals(src: string): string {
  return src.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, '""');
}

/**
 * Forbids the CEL `matches` function (fail-closed). The cel-js vendor compiles it to
 * `new RegExp(pattern).test(input)` UNBOUNDED: a catastrophic regex (`(a+)+`) causes
 * exponential backtracking (ReDoS -> PDP DoS) on adversarial input. The Kengela
 * doctrine bounds EVERY regex (cf. `@kengela/iam-mapping` safe-regex); an access
 * condition is thus expressed via `==`, `in`, `startsWith`, `contains`, never via an
 * unbounded regex.
 */
export function assertNoUnboundedRegex(expression: string): void {
  if (/\bmatches\s*\(/.test(stripStringLiterals(expression))) {
    throw new CelEvaluationError(
      `Forbidden CEL "matches" function (unbounded regex, ReDoS risk): "${expression}".`,
    );
  }
}
