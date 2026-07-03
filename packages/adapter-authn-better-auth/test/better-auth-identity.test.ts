import { describe, expect, it } from 'vitest';
import type { BetterAuthLike } from '../src/better-auth-like.js';
import { BetterAuthIdentity } from '../src/better-auth-identity.js';

type SessionResult = Awaited<ReturnType<BetterAuthLike['api']['getSession']>>;

function authWith(result: SessionResult): BetterAuthLike {
  return { api: { getSession: () => Promise.resolve(result) } };
}

describe('BetterAuthIdentity', () => {
  it('projette une session en Principal', async () => {
    const auth = authWith({
      user: { id: 'u1', email: 'a@b.io', tenantId: 't1' },
      session: { createdAt: new Date(1000) },
    });
    const principal = await new BetterAuthIdentity({ auth }).verifySession({
      strategy: 'bearer',
      token: 'tok',
    });
    expect(principal?.userId).toBe('u1');
    expect(principal?.tenantId).toBe('t1');
    expect(principal?.authMethod).toBe('oidc');
    expect(principal?.ctx.authTime).toBe(1000);
  });

  it('null si aucune session', async () => {
    const identity = new BetterAuthIdentity({ auth: authWith(null) });
    expect(await identity.verifySession({ strategy: 'cookie', token: 'x' })).toBeNull();
  });

  it('fail-closed si aucun tenant resoluble', async () => {
    const auth = authWith({ user: { id: 'u1' }, session: {} });
    const identity = new BetterAuthIdentity({ auth });
    expect(await identity.verifySession({ strategy: 'bearer', token: 'x' })).toBeNull();
  });

  it('extractTenantId / extractRoles personnalisables', async () => {
    const auth = authWith({ user: { id: 'u1', org: 't9', r: ['admin'] }, session: {} });
    const identity = new BetterAuthIdentity({
      auth,
      extractTenantId: (user) => (typeof user['org'] === 'string' ? user['org'] : null),
      extractRoles: (user) =>
        Array.isArray(user['r']) ? user['r'].filter((x): x is string => typeof x === 'string') : [],
    });
    const principal = await identity.verifySession({ strategy: 'bearer', token: 'x' });
    expect(principal?.tenantId).toBe('t9');
    expect(principal?.roles).toEqual(['admin']);
  });
});
