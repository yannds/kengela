/**
 * RED TEAM - adapter better-auth (@kengela/adapter-authn-better-auth).
 *
 * Session invalide/absente, tenant non resoluble, forge de session : le Principal projete
 * doit rester fail-closed (null) ou minimal (roles vides : l'authz recharge les grants).
 */
import { describe, expect, it } from 'vitest';
import type { BetterAuthLike } from '../src/better-auth-like.js';
import { BetterAuthIdentity } from '../src/better-auth-identity.js';

type SessionResult = Awaited<ReturnType<BetterAuthLike['api']['getSession']>>;

function authWith(result: SessionResult): BetterAuthLike {
  return { api: { getSession: () => Promise.resolve(result) } };
}

describe('RED - better-auth : fail-closed sur session/tenant', () => {
  it('session absente (getSession null) => Principal null', async () => {
    const identity = new BetterAuthIdentity({ auth: authWith(null) });
    expect(await identity.verifySession({ strategy: 'bearer', token: 'x' })).toBeNull();
  });

  it('tenant non resoluble (absent) => null (pas de Principal sans tenant)', async () => {
    const identity = new BetterAuthIdentity({
      auth: authWith({ user: { id: 'u1' }, session: {} }),
    });
    expect(await identity.verifySession({ strategy: 'bearer', token: 'x' })).toBeNull();
  });

  it('tenantId de mauvais type (number) => null (defaultTenantId exige une chaine)', async () => {
    const auth = authWith({ user: { id: 'u1', tenantId: 42 }, session: {} });
    const identity = new BetterAuthIdentity({ auth });
    expect(await identity.verifySession({ strategy: 'bearer', token: 'x' })).toBeNull();
  });

  it('session forgee : aucun role/mfa n’est herite du payload (l’authz recharge les grants)', async () => {
    const auth = authWith({
      user: { id: 'u1', tenantId: 't1', roles: ['SUPERADMIN'], mfaLevel: 'passkey' },
      session: { createdAt: new Date(1000) },
    });
    const principal = await new BetterAuthIdentity({ auth }).verifySession({
      strategy: 'bearer',
      token: 'x',
    });
    expect(principal?.roles).toEqual([]); // pas d'elevation via le payload de session
    expect(principal?.mfaLevel).toBe('none');
  });
});
