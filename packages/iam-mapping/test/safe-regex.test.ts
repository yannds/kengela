import { describe, expect, it } from 'vitest';
import { compileSafeRegex, SAFE_REGEX_LIMITS, safeRegexTest } from '../src/safe-regex.js';

describe('compileSafeRegex', () => {
  it('compile un motif simple (insensible a la casse)', () => {
    const re = compileSafeRegex('^admin.*');
    expect(re).toBeInstanceOf(RegExp);
    expect(re?.flags).toContain('i');
    expect(re?.test('ADMIN-RH')).toBe(true);
  });

  it('renvoie null sur motif vide ou trop long', () => {
    expect(compileSafeRegex('')).toBeNull();
    expect(compileSafeRegex('a'.repeat(SAFE_REGEX_LIMITS.maxSourceLength + 1))).toBeNull();
  });

  it('renvoie null sur motif invalide (jamais d exception)', () => {
    expect(compileSafeRegex('([a-z]')).toBeNull();
  });

  it('fail-closed sur quantificateurs imbriques (anti-ReDoS)', () => {
    expect(compileSafeRegex('(a+)+')).toBeNull();
    expect(compileSafeRegex('(a*)*')).toBeNull();
    expect(compileSafeRegex('(.+)+')).toBeNull();
    expect(compileSafeRegex('([a-z]+)*')).toBeNull();
    expect(compileSafeRegex('(x+){3}')).toBeNull();
  });
});

describe('safeRegexTest', () => {
  it('teste un motif contre une entree', () => {
    expect(safeRegexTest('^grp-', 'GRP-finance')).toBe(true);
    expect(safeRegexTest('^grp-', 'finance')).toBe(false);
  });

  it('fail-closed : motif rejete => false, jamais d exception', () => {
    expect(safeRegexTest('(a+)+', 'aaaaaaaaaaaaaaaaaaaa!')).toBe(false);
    expect(safeRegexTest('([', 'x')).toBe(false);
  });

  it('tronque l entree au-dela de maxInputLength avant le test', () => {
    const long = 'a'.repeat(SAFE_REGEX_LIMITS.maxInputLength + 500) + 'ZZ';
    // Le suffixe ZZ est tronque : un motif qui l exige ne matche pas.
    expect(safeRegexTest('ZZ$', long)).toBe(false);
    // Un motif sur le prefixe matche bien.
    expect(safeRegexTest('^a', long)).toBe(true);
  });
});
