import { describe, expect, it } from 'vitest';
import { profileFromParts } from '../src/profile.js';
import type { DirectoryProfile } from '../src/profile.js';
import { evaluateMappings } from '../src/rules.js';
import type { IdpMappingRule } from '../src/rules.js';

const profile: DirectoryProfile = {
  ...profileFromParts({
    email: 'user@corp.com',
    firstName: 'Jean',
    attributes: { department: 'Finance', title: 'Comptable' },
    groups: ['GRP-Finance', 'GRP-Approbateurs'],
  }),
  claims: { roles: ['approver', 'auditor'], level: 3, active: true },
};

describe('evaluateMappings - sources de condition', () => {
  it('GROUP avec operateur iequals (insensible a la casse)', () => {
    const rules: IdpMappingRule[] = [
      {
        id: 'r1',
        priority: 0,
        all: [{ source: 'GROUP', op: 'iequals', value: 'grp-finance' }],
        assignRoleKeys: ['FIN'],
      },
    ];
    const res = evaluateMappings(profile, rules);
    expect(res.roleKeys).toEqual(['FIN']);
    expect(res.matchedRuleIds).toEqual(['r1']);
  });

  it('ATTRIBUTE avec equals / contains', () => {
    const rules: IdpMappingRule[] = [
      {
        id: 'r-eq',
        priority: 0,
        all: [{ source: 'ATTRIBUTE', key: 'department', op: 'equals', value: 'Finance' }],
        assignRoleKeys: ['DEP'],
      },
      {
        id: 'r-contains',
        priority: 1,
        all: [{ source: 'ATTRIBUTE', key: 'title', op: 'contains', value: 'compt' }],
        assignRoleKeys: ['CPT'],
      },
    ];
    expect([...evaluateMappings(profile, rules).roleKeys].sort()).toEqual(['CPT', 'DEP']);
  });

  it('CLAIM avec in (liste) et present', () => {
    const rules: IdpMappingRule[] = [
      {
        id: 'r-in',
        priority: 0,
        all: [{ source: 'CLAIM', key: 'roles', op: 'in', value: ['approver', 'admin'] }],
        assignRoleKeys: ['VAL'],
      },
      {
        id: 'r-present',
        priority: 1,
        all: [{ source: 'CLAIM', key: 'level', op: 'present' }],
        assignRoleKeys: ['LVL'],
      },
    ];
    expect([...evaluateMappings(profile, rules).roleKeys].sort()).toEqual(['LVL', 'VAL']);
  });

  it('CLAIM avec matches (regex bornee)', () => {
    const rules: IdpMappingRule[] = [
      {
        id: 'r-rx',
        priority: 0,
        all: [{ source: 'CLAIM', key: 'roles', op: 'matches', value: '^audit' }],
        assignRoleKeys: ['AUD'],
      },
    ];
    expect(evaluateMappings(profile, rules).roleKeys).toEqual(['AUD']);
  });

  it('matches fail-closed sur regex ReDoS => aucun role', () => {
    const rules: IdpMappingRule[] = [
      {
        id: 'r-bad',
        priority: 0,
        all: [{ source: 'GROUP', op: 'matches', value: '(a+)+' }],
        assignRoleKeys: ['X'],
      },
    ];
    expect(evaluateMappings(profile, rules).roleKeys).toEqual([]);
  });
});

describe('evaluateMappings - logique all/any', () => {
  it('all = ET logique (toutes les conditions)', () => {
    const rules: IdpMappingRule[] = [
      {
        id: 'r',
        priority: 0,
        all: [
          { source: 'GROUP', op: 'iequals', value: 'grp-finance' },
          { source: 'ATTRIBUTE', key: 'department', op: 'equals', value: 'RH' },
        ],
        assignRoleKeys: ['NOPE'],
      },
    ];
    expect(evaluateMappings(profile, rules).roleKeys).toEqual([]);
  });

  it('any = OU logique (au moins une)', () => {
    const rules: IdpMappingRule[] = [
      {
        id: 'r',
        priority: 0,
        any: [
          { source: 'ATTRIBUTE', key: 'department', op: 'equals', value: 'RH' },
          { source: 'GROUP', op: 'iequals', value: 'grp-finance' },
        ],
        assignRoleKeys: ['OK'],
      },
    ];
    expect(evaluateMappings(profile, rules).roleKeys).toEqual(['OK']);
  });

  it('regle vide (ni all ni any) ne matche jamais (fail-closed)', () => {
    const rules: IdpMappingRule[] = [{ id: 'r', priority: 0, assignRoleKeys: ['X'] }];
    expect(evaluateMappings(profile, rules).matchedRuleIds).toEqual([]);
  });
});

describe('evaluateMappings - priorite, union, stopOnMatch, orgUnit', () => {
  const match = (
    id: string,
    priority: number,
    extra: Partial<IdpMappingRule> = {},
  ): IdpMappingRule => ({
    id,
    priority,
    all: [{ source: 'GROUP', op: 'iequals', value: 'grp-finance' }],
    ...extra,
  });

  it('accumule les roles en union et deduplique', () => {
    const res = evaluateMappings(profile, [
      match('a', 0, { assignRoleKeys: ['R1', 'R2'] }),
      match('b', 1, { assignRoleKeys: ['R2', 'R3'] }),
    ]);
    expect([...res.roleKeys].sort()).toEqual(['R1', 'R2', 'R3']);
  });

  it('stopOnMatch coupe l evaluation des regles suivantes', () => {
    const res = evaluateMappings(profile, [
      match('b', 1, { assignRoleKeys: ['SECOND'] }),
      match('a', 0, { assignRoleKeys: ['FIRST'], stopOnMatch: true }),
    ]);
    expect(res.matchedRuleIds).toEqual(['a']);
    expect(res.roleKeys).toEqual(['FIRST']);
  });

  it('tri deterministe par (priorite, id) et directives d unite ordonnees', () => {
    const res = evaluateMappings(profile, [
      match('z', 5, { orgUnit: { by: 'code', value: 'LOW' } }),
      match('a', 5, { orgUnit: { by: 'code', value: 'MID' } }),
      match('m', 1, { orgUnit: { by: 'name', value: 'TOP' } }),
    ]);
    // priorite 1 d abord, puis priorite 5 departagee par id (a avant z)
    expect(res.matchedRuleIds).toEqual(['m', 'a', 'z']);
    expect(res.orgUnitDirectives.map((d) => d.value)).toEqual(['TOP', 'MID', 'LOW']);
  });
});
