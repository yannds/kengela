/**
 * RED TEAM - guard NestJS (@kengela/nestjs).
 *
 * On tente le fail-open classique : neutraliser un `@RequirePermission` de HANDLER via un
 * `@PublicRoute` pose sur la CLASSE. Le handler DOIT primer (fail-closed). On verifie aussi
 * le deny-by-default et l'exigence de principal.
 */
import 'reflect-metadata';
import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import type { Reflector } from '@nestjs/core';
import type { Decision, PolicyDecisionPoint, Principal } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { KengelaAuthzGuard } from '../src/authz.guard.js';
import { KENGELA_PERMISSION, KENGELA_PUBLIC } from '../src/decorators.js';

const handler = (): void => undefined;
class Controller {
  public readonly kind = 'test';
}

const principal: Principal = {
  userId: 'u1',
  tenantId: 't1',
  roles: ['cashier'],
  mfaLevel: 'none',
  authMethod: 'credential',
  ctx: { authTime: 0 },
};

function context(user: Principal | undefined): ExecutionContext {
  return {
    getHandler: () => handler,
    getClass: () => Controller,
    switchToHttp: () => ({
      getRequest: () => ({ user }),
      getResponse: () => ({}),
      getNext: () => ({}),
    }),
  } as unknown as ExecutionContext;
}

/** Reflector qui distingue HANDLER et CLASSE par identite de cible (comme le vrai). */
function reflector(
  handlerMeta: Readonly<Record<string, unknown>>,
  classMeta: Readonly<Record<string, unknown>>,
): Reflector {
  return {
    get: (key: string, target: unknown): unknown =>
      target === handler ? handlerMeta[key] : classMeta[key],
  } as unknown as Reflector;
}

const pdpReturning = (decision: Decision): PolicyDecisionPoint & { calls: number } => {
  const stub = {
    calls: 0,
    check: (): Promise<Decision> => {
      stub.calls += 1;
      return Promise.resolve(decision);
    },
    checkMany: (): Promise<readonly Decision[]> => Promise.resolve([decision]),
  };
  return stub;
};

const PERM = { resourceType: 'data.cashier.register', action: 'read' };

describe('RED - @PublicRoute de CLASSE ne neutralise PAS @RequirePermission de HANDLER', () => {
  it('handler protege + classe publique => la decision PDP est bien evaluee (pas de bypass)', async () => {
    const pdp = pdpReturning({ effect: 'deny', reason: 'no_grant' });
    const guard = new KengelaAuthzGuard(
      reflector({ [KENGELA_PERMISSION]: PERM }, { [KENGELA_PUBLIC]: true }),
      pdp,
    );
    await expect(guard.canActivate(context(principal))).rejects.toBeInstanceOf(ForbiddenException);
    expect(pdp.calls).toBe(1); // le PDP a bien tranche : la route sensible n'a pas fuite
  });

  it('handler protege + classe publique + PDP allow => passe apres decision (toujours evalue)', async () => {
    const pdp = pdpReturning({ effect: 'allow', reason: 'rbac_grant' });
    const guard = new KengelaAuthzGuard(
      reflector({ [KENGELA_PERMISSION]: PERM }, { [KENGELA_PUBLIC]: true }),
      pdp,
    );
    await expect(guard.canActivate(context(principal))).resolves.toBe(true);
    expect(pdp.calls).toBe(1);
  });
});

describe('RED - precedence & deny-by-default', () => {
  it('handler explicitement @PublicRoute prime sur une exigence de CLASSE (opt-out volontaire)', async () => {
    const pdp = pdpReturning({ effect: 'deny', reason: 'no_grant' });
    const guard = new KengelaAuthzGuard(
      reflector({ [KENGELA_PUBLIC]: true }, { [KENGELA_PERMISSION]: PERM }),
      pdp,
    );
    await expect(guard.canActivate(context(principal))).resolves.toBe(true);
    expect(pdp.calls).toBe(0); // public : pas d'appel PDP
  });

  it('exigence de CLASSE seule (handler nu) => evaluee', async () => {
    const pdp = pdpReturning({ effect: 'allow', reason: 'rbac_grant' });
    const guard = new KengelaAuthzGuard(reflector({}, { [KENGELA_PERMISSION]: PERM }), pdp);
    await expect(guard.canActivate(context(principal))).resolves.toBe(true);
    expect(pdp.calls).toBe(1);
  });

  it('route non annotee (ni handler ni classe) => deny-by-default', async () => {
    const pdp = pdpReturning({ effect: 'allow', reason: 'x' });
    const guard = new KengelaAuthzGuard(reflector({}, {}), pdp);
    await expect(guard.canActivate(context(principal))).rejects.toBeInstanceOf(ForbiddenException);
    expect(pdp.calls).toBe(0);
  });

  it('principal absent sur une route protegee => 401', async () => {
    const pdp = pdpReturning({ effect: 'allow', reason: 'x' });
    const guard = new KengelaAuthzGuard(reflector({ [KENGELA_PERMISSION]: PERM }, {}), pdp);
    await expect(guard.canActivate(context(undefined))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
