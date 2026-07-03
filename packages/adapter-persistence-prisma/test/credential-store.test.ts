import { describe, expect, it } from 'vitest';
import type {
  AccountDelegate,
  AccountRow,
  CredentialPrismaLike,
  CredentialUserDelegate,
  CredentialUserRow,
} from '../src/prisma-like.js';
import { PrismaCredentialStore } from '../src/credential-store.js';

interface StoredAccount extends AccountRow {
  readonly providerId: string;
  readonly accountId: string;
}

function fakeCredentialPrisma(input: {
  readonly accounts: readonly StoredAccount[];
  readonly users: readonly CredentialUserRow[];
}): CredentialPrismaLike {
  const account: AccountDelegate = {
    findFirst: ({ where }) =>
      Promise.resolve(
        input.accounts.find(
          (a) =>
            a.tenantId === where.tenantId &&
            a.providerId === where.providerId &&
            a.accountId === where.accountId,
        ) ?? null,
      ),
    findMany: ({ where }) =>
      Promise.resolve(
        input.accounts.filter(
          (a) => a.providerId === where.providerId && a.accountId === where.accountId,
        ),
      ),
  };
  const user: CredentialUserDelegate = {
    findFirst: ({ where }) =>
      Promise.resolve(
        input.users.find((u) => u.id === where.id && u.tenantId === where.tenantId) ?? null,
      ),
    findMany: ({ where }) => Promise.resolve(input.users.filter((u) => where.id.in.includes(u.id))),
  };
  return { account, user };
}

const userRow = (over: Partial<CredentialUserRow> = {}): CredentialUserRow => ({
  id: 'u1',
  tenantId: 't1',
  isActive: true,
  deletedAt: null,
  mfaEnabled: false,
  roles: ['cashier'],
  ...over,
});

const accountRow = (over: Partial<StoredAccount> = {}): StoredAccount => ({
  userId: 'u1',
  tenantId: 't1',
  password: 'hash-1',
  providerId: 'credential',
  accountId: 'alice@acme.io',
  ...over,
});

describe('PrismaCredentialStore', () => {
  it('findByEmail : joint Account + User -> CredentialRecord', async () => {
    const store = new PrismaCredentialStore(
      fakeCredentialPrisma({ accounts: [accountRow()], users: [userRow()] }),
    );
    const record = await store.findByEmail('alice@acme.io', 't1');
    expect(record).toEqual({
      userId: 'u1',
      tenantId: 't1',
      passwordHash: 'hash-1',
      isActive: true,
      mfaEnabled: false,
      roles: ['cashier'],
    });
  });

  it('findByEmail : introuvable -> null', async () => {
    const store = new PrismaCredentialStore(fakeCredentialPrisma({ accounts: [], users: [] }));
    expect(await store.findByEmail('ghost@acme.io', 't1')).toBeNull();
  });

  it('findByEmail : compte credential orphelin (User absent) -> null (fail-closed)', async () => {
    const store = new PrismaCredentialStore(
      fakeCredentialPrisma({ accounts: [accountRow()], users: [] }),
    );
    expect(await store.findByEmail('alice@acme.io', 't1')).toBeNull();
  });

  it('findByEmail : compte sans mot de passe -> passwordHash null', async () => {
    const store = new PrismaCredentialStore(
      fakeCredentialPrisma({ accounts: [accountRow({ password: null })], users: [userRow()] }),
    );
    const record = await store.findByEmail('alice@acme.io', 't1');
    expect(record?.passwordHash).toBeNull();
  });

  it('findByEmail : compte supprime (deletedAt) -> isActive false', async () => {
    const store = new PrismaCredentialStore(
      fakeCredentialPrisma({
        accounts: [accountRow()],
        users: [userRow({ deletedAt: new Date() })],
      }),
    );
    const record = await store.findByEmail('alice@acme.io', 't1');
    expect(record?.isActive).toBe(false);
  });

  it('findByEmailAcrossTenants : agrege tous les tenants, Users charges en lot', async () => {
    const store = new PrismaCredentialStore(
      fakeCredentialPrisma({
        accounts: [
          accountRow({ tenantId: 't1', userId: 'u1' }),
          accountRow({ tenantId: 't2', userId: 'u2' }),
        ],
        users: [userRow({ id: 'u1', tenantId: 't1' }), userRow({ id: 'u2', tenantId: 't2' })],
      }),
    );
    const records = await store.findByEmailAcrossTenants('alice@acme.io');
    expect(records).toHaveLength(2);
    expect(records.map((r) => r.tenantId).sort()).toEqual(['t1', 't2']);
  });

  it('findByEmailAcrossTenants : aucun compte -> []', async () => {
    const store = new PrismaCredentialStore(fakeCredentialPrisma({ accounts: [], users: [] }));
    expect(await store.findByEmailAcrossTenants('ghost@acme.io')).toEqual([]);
  });

  it('providerId configurable', async () => {
    const store = new PrismaCredentialStore(
      fakeCredentialPrisma({
        accounts: [accountRow({ providerId: 'password' })],
        users: [userRow()],
      }),
      { providerId: 'password' },
    );
    expect(await store.findByEmail('alice@acme.io', 't1')).not.toBeNull();
  });
});
