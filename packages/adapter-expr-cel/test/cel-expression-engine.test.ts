import type { ExpressionContext } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { CelEvaluationError, CelExpressionEngine } from '../src/cel-expression-engine.js';

const engine = new CelExpressionEngine();

const context = (
  principalAgency: string,
  resourceAgency: string,
  riskScore: number,
): ExpressionContext => ({
  principal: {
    userId: 'u1',
    tenantId: 't1',
    roles: [],
    agencyId: principalAgency,
    mfaLevel: 'none',
    authMethod: 'credential',
    ctx: { authTime: 0 },
  },
  resource: {
    type: 'data.cashier.register',
    tenantId: 't1',
    attributes: { agencyId: resourceAgency },
  },
  env: { authTime: 0, now: 1000, riskScore },
});

describe('CelExpressionEngine', () => {
  it('evalue une comparaison booleenne', () => {
    expect(engine.evaluateBoolean('env.riskScore > 50', context('A1', 'A1', 80))).toBe(true);
    expect(engine.evaluateBoolean('env.riskScore > 50', context('A1', 'A1', 20))).toBe(false);
  });

  it("evalue le scoping ABAC (egalite d'attributs)", () => {
    const expr = 'resource.attributes.agencyId == principal.agencyId';
    expect(engine.evaluateBoolean(expr, context('A1', 'A1', 0))).toBe(true);
    expect(engine.evaluateBoolean(expr, context('A1', 'A2', 0))).toBe(false);
  });

  it('combine des conditions (&&, ||)', () => {
    const expr = 'env.riskScore <= 50 && resource.attributes.agencyId == principal.agencyId';
    expect(engine.evaluateBoolean(expr, context('A1', 'A1', 10))).toBe(true);
    expect(engine.evaluateBoolean(expr, context('A1', 'A1', 90))).toBe(false);
  });

  it('reutilise le cache sur appels repetes', () => {
    const expr = 'principal.agencyId == "A1"';
    expect(engine.evaluateBoolean(expr, context('A1', 'A1', 0))).toBe(true);
    expect(engine.evaluateBoolean(expr, context('A2', 'A1', 0))).toBe(false);
    expect(engine.evaluateBoolean(expr, context('A1', 'A1', 0))).toBe(true);
  });

  it('leve sur expression non booleenne', () => {
    expect(() => engine.evaluateBoolean('1 + 1', context('A1', 'A1', 0))).toThrow(
      CelEvaluationError,
    );
  });

  it('leve sur variable absente (fail-loud)', () => {
    expect(() => engine.evaluateBoolean('missing.field == 1', context('A1', 'A1', 0))).toThrow(
      CelEvaluationError,
    );
  });
});
