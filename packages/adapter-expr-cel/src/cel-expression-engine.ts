/**
 * Adapter CEL — implemente ExpressionEnginePort a l'aide de @marcbachmann/cel-js.
 *
 * Le vendor vit ICI (paquet adapter). Sandboxe, lecture seule, compilations mises
 * en cache. Le contexte {principal, resource, env, tenant} est expose tel quel aux
 * expressions ; une expression doit retourner un booleen (sinon erreur explicite).
 *
 * Dette connue (voir DEBT.md) :
 *  - v1 sans fonctions de dates custom (business-hours) : precalculer dans le
 *    contexte (ContextProvider) ou ajouter un Environment + clock en v2.
 *  - une erreur d'evaluation (variable absente, non-booleen) est LEVEE ; le
 *    fail-closed au niveau PDP (catch -> deny) est un durcissement ulterieur.
 */
import { parse } from '@marcbachmann/cel-js';
import type { ExpressionContext, ExpressionEnginePort } from '@kengela/contracts';

/** Fonction compilee typee au bord vendor (retourne `unknown`, jamais `any`). */
type CompiledExpression = (context: Record<string, unknown>) => unknown;

export class CelEvaluationError extends Error {
  public override readonly name = 'CelEvaluationError';
}

export class CelExpressionEngine implements ExpressionEnginePort {
  readonly #cache = new Map<string, CompiledExpression>();

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
      compiled = parse(expression);
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
