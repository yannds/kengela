import type { Clock, ExpressionContext } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { CelExpressionEngine } from '../src/cel-expression-engine.js';
import { businessDaysBetween, daysBetween, toEpochMs } from '../src/dates.js';

const DAY = 86_400_000;
const CLOCK: Clock = { now: () => 1_000_000_000_000 };

const context = (attributes: Record<string, unknown>): ExpressionContext => ({
  principal: {
    userId: 'u',
    tenantId: 't',
    roles: [],
    mfaLevel: 'none',
    authMethod: 'credential',
    ctx: { authTime: 0 },
  },
  resource: { type: 'r', tenantId: 't', attributes },
  env: { authTime: 0, now: CLOCK.now() },
});

describe('fonctions de dates CEL (deterministes via Clock)', () => {
  const engine = new CelExpressionEngine({ clock: CLOCK });

  it('now() reflete l horloge injectee', () => {
    expect(engine.evaluateBoolean('now() == 1000000000000', context({}))).toBe(true);
  });

  it('daysUntil() pour une condition d echeance', () => {
    expect(
      engine.evaluateBoolean('daysUntil(resource.attributes.due) > 5', {
        ...context({ due: CLOCK.now() + 10 * DAY }),
      }),
    ).toBe(true);
    expect(
      engine.evaluateBoolean('daysUntil(resource.attributes.due) > 5', {
        ...context({ due: CLOCK.now() + 2 * DAY }),
      }),
    ).toBe(false);
  });
});

describe('helpers de dates', () => {
  it('daysBetween', () => {
    expect(daysBetween(0, 3 * DAY)).toBe(3);
  });

  it('businessDaysBetween exclut le week-end', () => {
    const monday = Date.UTC(2024, 0, 1);
    const friday = Date.UTC(2024, 0, 5);
    const sunday = Date.UTC(2024, 0, 7);
    expect(businessDaysBetween(monday, friday)).toBe(5);
    expect(businessDaysBetween(monday, sunday)).toBe(5);
  });

  it('toEpochMs accepte number/bigint/Date, rejette le reste', () => {
    expect(toEpochMs(1000)).toBe(1000);
    expect(toEpochMs(1000n)).toBe(1000);
    expect(toEpochMs(new Date(1000))).toBe(1000);
    expect(() => toEpochMs({})).toThrow();
  });
});
