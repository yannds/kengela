/**
 * RED TEAM - mapping IdP -> roles (@kengela/iam-mapping).
 *
 * ReDoS des regles `matches`, regles vides fail-closed, aucune elevation non configuree,
 * projection SAML/OIDC sans fabrication de groupes. PUR (aucun reseau/DB).
 */
import { describe, expect, it } from 'vitest';
import { compileSafeRegex, safeRegexTest } from '../src/safe-regex.js';
import { evaluateMappings, type IdpMappingRule } from '../src/rules.js';
import { profileFromParts, profileFromSaml } from '../src/profile.js';

describe('RED - safe-regex : anti-ReDoS', () => {
  it('rejette un quantificateur imbrique catastrophique (fail-closed, null)', () => {
    expect(compileSafeRegex('(a+)+$')).toBeNull();
    expect(compileSafeRegex('(a*)*')).toBeNull();
    expect(compileSafeRegex('([a-z]+)*')).toBeNull();
  });

  it('safeRegexTest ne PART PAS en backtracking exponentiel sur une entree adverse', () => {
    const started = Date.now();
    const result = safeRegexTest('(a+)+$', `${'a'.repeat(60)}!`);
    expect(result).toBe(false); // motif rejete => false
    expect(Date.now() - started).toBeLessThan(500);
  });

  it('rejette un motif trop long (borne de source)', () => {
    expect(compileSafeRegex('a'.repeat(201))).toBeNull();
  });

  it('tronque l’entree testee a maxInputLength (borne d’input) sans exception', () => {
    // 5000 'a' tronques a 1024 : un motif exigeant 2000 'a' ne peut plus matcher.
    expect(safeRegexTest('^a{2000}$', 'a'.repeat(5000))).toBe(false);
    // Un motif lineaire sain matche sans exploser.
    expect(safeRegexTest('a', 'a'.repeat(5000))).toBe(true);
  });
});

describe('RED - regles de mapping : fail-closed & pas d’elevation non configuree', () => {
  const admin = profileFromParts({ email: 'a@x.io', groups: ['CN=Admins', 'CN=Cashiers'] });

  it('une regle VIDE (ni all ni any) ne matche JAMAIS', () => {
    const rule: IdpMappingRule = { id: 'r', priority: 0, assignRoleKeys: ['ADM'] };
    const res = evaluateMappings(admin, [rule]);
    expect(res.roleKeys).toEqual([]);
    expect(res.matchedRuleIds).toEqual([]);
  });

  it('aucun role n’est accorde sans regle correspondante (deny-by-default du mapping)', () => {
    const rule: IdpMappingRule = {
      id: 'r',
      priority: 0,
      all: [{ source: 'GROUP', op: 'iequals', value: 'CN=DoesNotExist' }],
      assignRoleKeys: ['ADM'],
    };
    expect(evaluateMappings(admin, [rule]).roleKeys).toEqual([]);
  });

  it('un `matches` catastrophique dans une regle ne fait pas exploser l’evaluation', () => {
    const rule: IdpMappingRule = {
      id: 'r',
      priority: 0,
      all: [{ source: 'GROUP', op: 'matches', value: '(a+)+$' }],
      assignRoleKeys: ['ADM'],
    };
    const victim = profileFromParts({ email: 'a@x.io', groups: [`${'a'.repeat(60)}!`] });
    const started = Date.now();
    expect(evaluateMappings(victim, [rule]).roleKeys).toEqual([]); // motif rejete => pas de match
    expect(Date.now() - started).toBeLessThan(500);
  });

  it('stopOnMatch court-circuite les regles suivantes (deterministe par priorite)', () => {
    const rules: IdpMappingRule[] = [
      {
        id: 'stop',
        priority: 0,
        stopOnMatch: true,
        any: [{ source: 'GROUP', op: 'iequals', value: 'CN=Admins' }],
        assignRoleKeys: ['ADM'],
      },
      {
        id: 'later',
        priority: 1,
        any: [{ source: 'GROUP', op: 'iequals', value: 'CN=Cashiers' }],
        assignRoleKeys: ['CASH'],
      },
    ];
    expect(evaluateMappings(admin, rules).roleKeys).toEqual(['ADM']);
  });
});

describe('RED - projection SAML : pas de fabrication ni d’elevation implicite', () => {
  it('une assertion sans groupe ne produit aucun groupe (donc aucun role via mapping)', () => {
    const profile = profileFromSaml({ nameId: 'evil@x.io', attributes: {} });
    expect(profile.groups).toEqual([]);
    const rule: IdpMappingRule = {
      id: 'r',
      priority: 0,
      any: [{ source: 'GROUP', op: 'present' }],
      assignRoleKeys: ['ADM'],
    };
    expect(evaluateMappings(profile, [rule]).roleKeys).toEqual([]);
  });

  it('les groupes injectes ne donnent un role QUE si le tenant a configure la regle', () => {
    const profile = profileFromSaml({
      nameId: 'user@x.io',
      attributes: { 'http://schemas.xmlsoap.org/claims/Group': ['Cashiers'] },
    });
    // Le tenant ne mappe QUE "Managers" -> ADM : "Cashiers" injecte ne donne rien.
    const rule: IdpMappingRule = {
      id: 'r',
      priority: 0,
      any: [{ source: 'GROUP', op: 'iequals', value: 'Managers' }],
      assignRoleKeys: ['ADM'],
    };
    expect(evaluateMappings(profile, [rule]).roleKeys).toEqual([]);
  });
});
