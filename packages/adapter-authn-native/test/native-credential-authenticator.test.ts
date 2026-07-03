import type { AuthContext, CredentialRecord, CredentialStore } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { BcryptPasswordHasher } from '../src/bcrypt-password-hasher.js';
import { NativeCredentialAuthenticator } from '../src/native-credential-authenticator.js';

const CTX: AuthContext = { authTime: 0 };
const hasher = new BcryptPasswordHasher(4);

const record = (
  over: Partial<CredentialRecord> & { passwordHash: string | null },
): CredentialRecord => ({
  userId: 'u1',
  tenantId: 't1',
  isActive: true,
  mfaEnabled: false,
  roles: ['cashier'],
  ...over,
});

function storeOf(
  single: CredentialRecord | null,
  cross: readonly CredentialRecord[] = [],
): CredentialStore {
  return {
    findByEmail: () => Promise.resolve(single),
    findByEmailAcrossTenants: () => Promise.resolve(cross),
  };
}

async function authFor(store: CredentialStore): Promise<NativeCredentialAuthenticator> {
  return NativeCredentialAuthenticator.create(store, hasher);
}

describe('NativeCredentialAuthenticator', () => {
  it('authentifie un credential valide', async () => {
    const hash = await hasher.hash('good');
    const auth = await authFor(storeOf(record({ passwordHash: hash })));
    const out = await auth.authenticate({
      email: 'a@b.io',
      password: 'good',
      tenantId: 't1',
      ctx: CTX,
    });
    expect(out.kind).toBe('authenticated');
    if (out.kind === 'authenticated') {
      expect(out.principal.userId).toBe('u1');
      expect(out.principal.authMethod).toBe('credential');
    }
  });

  it('refuse un mauvais mot de passe', async () => {
    const hash = await hasher.hash('good');
    const auth = await authFor(storeOf(record({ passwordHash: hash })));
    const out = await auth.authenticate({
      email: 'a@b.io',
      password: 'bad',
      tenantId: 't1',
      ctx: CTX,
    });
    expect(out.kind).toBe('invalid_credentials');
  });

  it('refuse un email inconnu (timing-safe, dummy compare)', async () => {
    const auth = await authFor(storeOf(null));
    const out = await auth.authenticate({
      email: 'x@b.io',
      password: 'good',
      tenantId: 't1',
      ctx: CTX,
    });
    expect(out.kind).toBe('invalid_credentials');
  });

  it('refuse un compte inactif', async () => {
    const hash = await hasher.hash('good');
    const auth = await authFor(storeOf(record({ passwordHash: hash, isActive: false })));
    const out = await auth.authenticate({
      email: 'a@b.io',
      password: 'good',
      tenantId: 't1',
      ctx: CTX,
    });
    expect(out.kind).toBe('invalid_credentials');
  });

  it('signale mfa_required avec userId/tenantId', async () => {
    const hash = await hasher.hash('good');
    const auth = await authFor(storeOf(record({ passwordHash: hash, mfaEnabled: true })));
    const out = await auth.authenticate({
      email: 'a@b.io',
      password: 'good',
      tenantId: 't1',
      ctx: CTX,
    });
    expect(out.kind).toBe('mfa_required');
    if (out.kind === 'mfa_required') {
      expect(out.userId).toBe('u1');
      expect(out.tenantId).toBe('t1');
    }
  });

  it('cross-tenant : propose un choix quand plusieurs tenants matchent', async () => {
    const hash = await hasher.hash('good');
    const auth = await authFor(
      storeOf(null, [
        record({ passwordHash: hash, tenantId: 't1' }),
        record({ passwordHash: hash, tenantId: 't2' }),
      ]),
    );
    const out = await auth.authenticateCrossTenant({ email: 'a@b.io', password: 'good', ctx: CTX });
    expect(out.kind).toBe('tenant_choice');
    if (out.kind === 'tenant_choice') {
      expect(out.candidates).toEqual(['t1', 't2']);
    }
  });

  it('cross-tenant : authentifie quand un seul tenant matche', async () => {
    const hash = await hasher.hash('good');
    const auth = await authFor(storeOf(null, [record({ passwordHash: hash, tenantId: 't2' })]));
    const out = await auth.authenticateCrossTenant({ email: 'a@b.io', password: 'good', ctx: CTX });
    expect(out.kind).toBe('authenticated');
  });
});
