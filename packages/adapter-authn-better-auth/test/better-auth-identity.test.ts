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

  it('resolvePrincipal absent : comportement par defaut inchange (base retournee)', async () => {
    const auth = authWith({ user: { id: 'u1', tenantId: 't1' }, session: { createdAt: new Date(5) } });
    const principal = await new BetterAuthIdentity({ auth }).verifySession({
      strategy: 'bearer',
      token: 'tok',
    });
    expect(principal?.userId).toBe('u1');
    expect(principal?.tenantId).toBe('t1');
  });

  it('resolvePrincipal remappe le userId (identite auth -> user metier, async)', async () => {
    const auth = authWith({ user: { id: 'auth-1', email: 'a@b.io', tenantId: 't1' }, session: {} });
    const lookup = new Map([['a@b.io:t1', 'domain-42']]);
    const identity = new BetterAuthIdentity({
      auth,
      resolvePrincipal: async ({ user, base }) => {
        if (base === null) return null;
        const email = typeof user['email'] === 'string' ? user['email'] : '';
        const domainId = await Promise.resolve(lookup.get(`${email}:${base.tenantId}`) ?? null);
        return domainId === null ? null : { ...base, userId: domainId, authMethod: 'credential' };
      },
    });
    const principal = await identity.verifySession({ strategy: 'bearer', token: 'x' });
    expect(principal?.userId).toBe('domain-42'); // pas l'id d'auth
    expect(principal?.authMethod).toBe('credential');
  });

  it('resolvePrincipal peut resoudre le tenant depuis base=null (repli email async)', async () => {
    // Pas de tenantId sur le user -> base null ; le hook resout le tenant lui-meme.
    const auth = authWith({ user: { id: 'u1', email: 'sso@corp.io' }, session: {} });
    const identity = new BetterAuthIdentity({
      auth,
      resolvePrincipal: async ({ user }) => {
        const email = typeof user['email'] === 'string' ? user['email'] : null;
        const tenantId = await Promise.resolve(email === 'sso@corp.io' ? 't-corp' : null);
        return tenantId === null
          ? null
          : { userId: user.id, tenantId, roles: [], mfaLevel: 'none', authMethod: 'oidc', ctx: { authTime: 0 } };
      },
    });
    const principal = await identity.verifySession({ strategy: 'bearer', token: 'x' });
    expect(principal?.tenantId).toBe('t-corp');
  });

  it('resolvePrincipal renvoyant null refuse la session (fail-closed)', async () => {
    const auth = authWith({ user: { id: 'u1', tenantId: 't1' }, session: {} });
    const identity = new BetterAuthIdentity({ auth, resolvePrincipal: () => null });
    expect(await identity.verifySession({ strategy: 'bearer', token: 'x' })).toBeNull();
  });
});
