/**
 * RED TEAM - attaques d'autorisation contre le PDP (isolation, escalade, fail-open, deny-wins).
 *
 * Chaque test materialise une hypothese d'attaque : il ECHOUE si la lib est vulnerable.
 * Hermetique (fakes en memoire), aucune dependance vendor ni reseau.
 */
import type {
  AuthorizationRepository,
  Clock,
  ExpressionContext,
  ExpressionEnginePort,
  Grant,
  OrgRelation,
  Policy,
  Principal,
  RelationResolver,
  ResourceRef,
} from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { RbacDecisionPoint } from '../src/pdp.js';
import { LayeredDecisionPoint } from '../src/policy-pdp.js';

const CLOCK: Clock = { now: () => 1000 };

const grant = (permission: string, scope: Grant['scope']): Grant => ({
  permission,
  scope,
  source: 'MANUAL',
});

const repoWith = (grants: readonly Grant[]): AuthorizationRepository => ({
  loadGrantsForUser: () => Promise.resolve(grants),
  loadRole: () => Promise.resolve(null),
});

/** Resolveur ADVERSE : renvoie toujours la relation la plus large (`tenant`), meme cross-tenant. */
const alwaysTenant: RelationResolver = { resolveRelation: () => Promise.resolve('tenant') };
const relationOf = (relation: OrgRelation): RelationResolver => ({
  resolveRelation: () => Promise.resolve(relation),
});

const principal = (tenantId: string): Principal => ({
  userId: 'u1',
  tenantId,
  roles: ['cashier'],
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: 0 },
});

const resource = (tenantId: string): ResourceRef => ({
  type: 'data.cashier.register',
  tenantId,
  attributes: {},
});

const NEVER_EXPR: ExpressionEnginePort = { evaluateBoolean: () => false };

describe('RED - isolation cross-tenant (smuggling de tenantId)', () => {
  it('un grant `tenant` du tenant A ne franchit PAS vers une ressource du tenant B, meme si le resolveur ment', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: alwaysTenant, // resolveur compromis / bugge
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: resource('tenant-B'),
    });
    expect(decision.effect).toBe('deny');
    expect(decision.reason).toBe('no_grant');
    expect(decision.signals?.['crossTenant']).toBe(true);
  });

  it('meme attaque via le PDP en couches (LayeredDecisionPoint) : deny cross-tenant', async () => {
    const pdp = new LayeredDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: alwaysTenant,
      policies: { loadPolicies: () => Promise.resolve([]) },
      expr: NEVER_EXPR,
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: resource('tenant-B'),
    });
    expect(decision.effect).toBe('deny');
    expect(decision.reason).toBe('no_grant');
  });

  it('meme tenant : le flux legitime reste ALLOW (pas de faux positif)', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: relationOf('self'),
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: resource('tenant-A'),
    });
    expect(decision.effect).toBe('allow');
  });
});

describe('RED - escalade de privilege / plan plateforme', () => {
  it('seul un grant de portee `global` (plan plateforme) franchit un tenant', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('platform.tenants.read', 'global')]),
      relations: relationOf('none'),
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('platform'),
      action: 'read',
      resource: { type: 'platform.tenants', tenantId: 'tenant-B' },
    });
    expect(decision.effect).toBe('allow');
  });

  it('le split de portee n’est pas detourne : `subtree` ne couvre pas une relation `tenant`', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'subtree')]),
      relations: relationOf('tenant'),
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: resource('tenant-A'),
    });
    expect(decision.effect).toBe('deny');
  });

  it('un grant expire ne confere aucun droit (anti-staleness)', async () => {
    const expired: Grant = {
      permission: 'data.cashier.register.read',
      scope: 'tenant',
      source: 'MANUAL',
      expiresAt: new Date(500),
    };
    const pdp = new RbacDecisionPoint({
      grants: repoWith([expired]),
      relations: relationOf('self'),
      clock: CLOCK, // now = 1000 > 500
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: resource('tenant-A'),
    });
    expect(decision.effect).toBe('deny');
  });
});

describe('RED - fail-open & deny-wins', () => {
  it('relation `none` sans grant global => deny (aucun lien organisationnel)', async () => {
    const pdp = new RbacDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: relationOf('none'),
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: resource('tenant-A'),
    });
    expect(decision.effect).toBe('deny');
  });

  it('deny explicite l’emporte quel que soit l’ordre des regles (deny-wins)', async () => {
    const flag: ExpressionEnginePort = {
      evaluateBoolean: (expr: string, ctx: ExpressionContext): boolean =>
        expr === 'deny_flag' ? ctx.resource.attributes?.['blocked'] === true : true,
    };
    const policies: readonly Policy[] = [
      {
        resource: 'data.cashier.register',
        action: 'read',
        rules: [
          { effect: 'deny', when: 'deny_flag', reason: 'explicit_block' },
          { effect: 'allow', when: 'always' },
        ],
      },
    ];
    const pdp = new LayeredDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: relationOf('self'),
      policies: { loadPolicies: () => Promise.resolve(policies) },
      expr: flag,
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: {
        type: 'data.cashier.register',
        tenantId: 'tenant-A',
        attributes: { blocked: true },
      },
    });
    expect(decision.effect).toBe('deny');
    expect(decision.reason).toBe('explicit_block');
  });

  it('une condition qui LEVE donne deny (fail-closed), jamais allow', async () => {
    const throwing: ExpressionEnginePort = {
      evaluateBoolean: () => {
        throw new Error('boom');
      },
    };
    const policies: readonly Policy[] = [
      {
        resource: 'data.cashier.register',
        action: 'read',
        rules: [{ effect: 'allow', when: 'exploding_condition' }],
      },
    ];
    const pdp = new LayeredDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: relationOf('self'),
      policies: { loadPolicies: () => Promise.resolve(policies) },
      expr: throwing,
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: resource('tenant-A'),
    });
    expect(decision.effect).toBe('deny');
    expect(decision.reason).toBe('condition_error');
  });

  it('gate ABAC positif : des regles `allow` presentes mais aucune ne matche => deny', async () => {
    const policies: readonly Policy[] = [
      {
        resource: 'data.cashier.register',
        action: 'read',
        rules: [{ effect: 'allow', when: 'never' }],
      },
    ];
    const pdp = new LayeredDecisionPoint({
      grants: repoWith([grant('data.cashier.register.read', 'tenant')]),
      relations: relationOf('self'),
      policies: { loadPolicies: () => Promise.resolve(policies) },
      expr: NEVER_EXPR,
      clock: CLOCK,
    });
    const decision = await pdp.check({
      principal: principal('tenant-A'),
      action: 'read',
      resource: resource('tenant-A'),
    });
    expect(decision.effect).toBe('deny');
    expect(decision.reason).toBe('no_matching_allow');
  });
});
