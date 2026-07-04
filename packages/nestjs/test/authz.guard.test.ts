import 'reflect-metadata';
import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import type { Reflector } from '@nestjs/core';
import type {
  AuthorizationRepository,
  Decision,
  Grant,
  PolicyDecisionPoint,
  Principal,
  RelationResolver,
} from '@kengela/contracts';
import { LayeredDecisionPoint } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import { describe, expect, it } from 'vitest';
import { KengelaAuthzGuard } from '../src/authz.guard.js';
import { StepUpRequiredException } from '../src/step-up.exception.js';
import { KENGELA_PERMISSION, KENGELA_PUBLIC } from '../src/decorators.js';

const principal = (riskScore = 0): Principal => ({
  userId: 'u1',
  tenantId: 't1',
  roles: ['cashier'],
  agencyId: 'A1',
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: 0, riskScore },
});

function reflectorWith(meta: Readonly<Record<string, unknown>>): Reflector {
  return {
    get: (key: string): unknown => meta[key],
    getAllAndOverride: (key: string): unknown => meta[key],
  } as unknown as Reflector;
}

class FakeController {
  public readonly kind = 'test';
}

function contextWith(user: Principal | undefined): ExecutionContext {
  const handler = (): void => undefined;
  return {
    getHandler: () => handler,
    getClass: () => FakeController,
    switchToHttp: () => ({
      getRequest: () => ({ user }),
      getResponse: () => ({}),
      getNext: () => ({}),
    }),
  } as unknown as ExecutionContext;
}

const pdpReturning = (decision: Decision): PolicyDecisionPoint => ({
  check: () => Promise.resolve(decision),
  checkMany: () => Promise.resolve([decision]),
});

const PERMISSION_META = {
  [KENGELA_PERMISSION]: { resourceType: 'data.cashier.register', action: 'read' },
} as const;

describe('KengelaAuthzGuard', () => {
  it('laisse passer une route publique', async () => {
    const guard = new KengelaAuthzGuard(
      reflectorWith({ [KENGELA_PUBLIC]: true }),
      pdpReturning({ effect: 'deny', reason: 'x' }),
    );
    await expect(guard.canActivate(contextWith(principal()))).resolves.toBe(true);
  });

  it('refuse une route non annotee (deny-by-default)', async () => {
    const guard = new KengelaAuthzGuard(
      reflectorWith({}),
      pdpReturning({ effect: 'allow', reason: 'x' }),
    );
    await expect(guard.canActivate(contextWith(principal()))).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('exige un principal', async () => {
    const guard = new KengelaAuthzGuard(
      reflectorWith(PERMISSION_META),
      pdpReturning({ effect: 'allow', reason: 'x' }),
    );
    await expect(guard.canActivate(contextWith(undefined))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('autorise sur decision allow', async () => {
    const guard = new KengelaAuthzGuard(
      reflectorWith(PERMISSION_META),
      pdpReturning({ effect: 'allow', reason: 'rbac_grant' }),
    );
    await expect(guard.canActivate(contextWith(principal()))).resolves.toBe(true);
  });

  it('refuse sur decision deny (avec raison)', async () => {
    const guard = new KengelaAuthzGuard(
      reflectorWith(PERMISSION_META),
      pdpReturning({ effect: 'deny', reason: 'no_grant' }),
    );
    await expect(guard.canActivate(contextWith(principal()))).rejects.toThrow('no_grant');
  });

  it('leve StepUpRequiredException sur decision step_up', async () => {
    const guard = new KengelaAuthzGuard(
      reflectorWith(PERMISSION_META),
      pdpReturning({
        effect: 'step_up',
        reason: 'step_up_required',
        obligations: [{ type: 'require_passkey' }],
      }),
    );
    await expect(guard.canActivate(contextWith(principal()))).rejects.toBeInstanceOf(
      StepUpRequiredException,
    );
  });
});

describe('KengelaAuthzGuard - integration PDP + CEL reel', () => {
  const GRANT: Grant = {
    permission: 'data.cashier.register.read',
    scope: 'tenant',
    source: 'MANUAL',
  };
  const repo: AuthorizationRepository = {
    loadGrantsForUser: () => Promise.resolve([GRANT]),
    loadRole: () => Promise.resolve(null),
  };
  const relations: RelationResolver = { resolveRelation: () => Promise.resolve('self') };
  const realPdp = (): LayeredDecisionPoint =>
    new LayeredDecisionPoint({
      grants: repo,
      relations,
      policies: {
        loadPolicies: () =>
          Promise.resolve([
            {
              resource: 'data.cashier.register',
              action: 'read',
              rules: [{ effect: 'deny', when: 'env.riskScore > 50', reason: 'high_risk' }],
            },
          ]),
      },
      expr: new CelExpressionEngine(),
      clock: { now: () => 1000 },
    });

  it('conditional access : refuse sur risque eleve via CEL reel', async () => {
    const guard = new KengelaAuthzGuard(reflectorWith(PERMISSION_META), realPdp());
    await expect(guard.canActivate(contextWith(principal(80)))).rejects.toThrow('high_risk');
  });

  it('conditional access : autorise sur risque faible', async () => {
    const guard = new KengelaAuthzGuard(reflectorWith(PERMISSION_META), realPdp());
    await expect(guard.canActivate(contextWith(principal(10)))).resolves.toBe(true);
  });
});
