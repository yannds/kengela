/**
 * RED TEAM — evasion du bac a sable CEL (@kengela/adapter-expr-cel).
 *
 * On tente d'acceder aux globals, au prototype, de provoquer un ReDoS, ou de faire passer
 * une expression non booleenne. Chaque test ECHOUE si l'isolement fuit. On prouve aussi le
 * fail-closed de bout en bout : une condition qui leve donne `deny` au PDP.
 */
import type {
  AuthorizationRepository,
  Clock,
  ExpressionContext,
  Grant,
  Policy,
  Principal,
  RelationResolver,
} from '@kengela/contracts';
import { LayeredDecisionPoint } from '@kengela/authz-core';
import { describe, expect, it } from 'vitest';
import { CelEvaluationError, CelExpressionEngine } from '../src/cel-expression-engine.js';

const CLOCK: Clock = { now: () => 1_000_000 };

const principal: Principal = {
  userId: 'u1',
  tenantId: 't1',
  roles: ['cashier'],
  agencyId: 'A1',
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: 0 },
};

const ctx: ExpressionContext = {
  principal,
  resource: { type: 'r', tenantId: 't1', attributes: { amount: 10, name: 'x' } },
  env: { authTime: 0, now: 1_000_000, riskScore: 5 },
  tenant: {},
};

describe('RED — CEL sandbox : pas d’acces aux globals ni au prototype', () => {
  const engine = new CelExpressionEngine({ clock: CLOCK });

  it.each([
    ['process', 'process != null'],
    ['globalThis', 'globalThis != null'],
    ['require', 'require != null'],
    ['constructor', 'principal.constructor == null'],
    ['__proto__', 'principal.__proto__ == null'],
    ['prototype', 'principal.prototype == null'],
  ])('rejette l’acces a %s', (_name, expr) => {
    expect(() => engine.evaluateBoolean(expr, ctx)).toThrow(CelEvaluationError);
  });
});

describe('RED — CEL : typage et variables', () => {
  const engine = new CelExpressionEngine({ clock: CLOCK });

  it('une expression non booleenne est rejetee (pas de coercition silencieuse)', () => {
    expect(() => engine.evaluateBoolean('resource.attributes.amount + 1', ctx)).toThrow(
      CelEvaluationError,
    );
  });

  it('une variable absente leve (le PDP en fera un deny fail-closed)', () => {
    expect(() => engine.evaluateBoolean('attacker == "x"', ctx)).toThrow(CelEvaluationError);
  });

  it('un champ absent leve (pas de undefined silencieux)', () => {
    expect(() => engine.evaluateBoolean('principal.nope == "x"', ctx)).toThrow(CelEvaluationError);
  });

  it('une condition legitime s’evalue normalement', () => {
    expect(engine.evaluateBoolean('principal.tenantId == "t1"', ctx)).toBe(true);
    expect(engine.evaluateBoolean('env.riskScore > 50', ctx)).toBe(false);
  });
});

describe('RED — CEL : ReDoS via matches (DoS)', () => {
  const engine = new CelExpressionEngine({ clock: CLOCK });

  it('rejette IMMEDIATEMENT une regex catastrophique (pas de backtracking exponentiel)', () => {
    const evil = `"${'a'.repeat(60)}!".matches("(a+)+$")`;
    const started = Date.now();
    expect(() => engine.evaluateBoolean(evil, ctx)).toThrow(CelEvaluationError);
    // Si `matches` etait evalue, ce test ne rendrait pas la main (ReDoS). Borne large.
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('interdit `matches` meme avec une regex anodine (fail-closed, doctrine safe-regex)', () => {
    expect(() => engine.evaluateBoolean('principal.userId.matches("^u")', ctx)).toThrow(/matches/i);
  });

  it('ne confond pas une chaine litterale contenant "matches(" avec un appel', () => {
    expect(engine.evaluateBoolean('resource.attributes.name == "matches("', ctx)).toBe(false);
  });
});

describe('BLUE — fail-closed de bout en bout : PDP + CEL reel', () => {
  const grant: Grant = { permission: 'r.read', scope: 'tenant', source: 'MANUAL' };
  const grants: AuthorizationRepository = {
    loadGrantsForUser: () => Promise.resolve([grant]),
    loadRole: () => Promise.resolve(null),
  };
  const relations: RelationResolver = { resolveRelation: () => Promise.resolve('self') };

  const pdpWith = (policies: readonly Policy[]): LayeredDecisionPoint =>
    new LayeredDecisionPoint({
      grants,
      relations,
      policies: { loadPolicies: () => Promise.resolve(policies) },
      expr: new CelExpressionEngine({ clock: CLOCK }),
      clock: CLOCK,
    });

  it('une condition qui LEVE (matches interdit) => deny condition_error', async () => {
    const decision = await pdpWith([
      {
        resource: 'r',
        action: 'read',
        rules: [{ effect: 'allow', when: 'principal.userId.matches("^u")' }],
      },
    ]).check({ principal, action: 'read', resource: { type: 'r', tenantId: 't1' } });
    expect(decision.effect).toBe('deny');
    expect(decision.reason).toBe('condition_error');
  });

  it('une condition CEL saine autorise', async () => {
    const decision = await pdpWith([
      {
        resource: 'r',
        action: 'read',
        rules: [{ effect: 'allow', when: 'principal.tenantId == "t1"' }],
      },
    ]).check({ principal, action: 'read', resource: { type: 'r', tenantId: 't1' } });
    expect(decision.effect).toBe('allow');
  });
});
