import type { AccountRow } from '../src/translog-prisma-like.js';
import { describe, expect, it } from 'vitest';
import { TranslogCredentialStore } from '../src/credential-store.js';
import { FakeTranslogPrisma, userRow } from './fake-translog-prisma.js';

const accountRow = (over: Partial<AccountRow>): AccountRow => ({
  userId: 'u1',
  tenantId: 't1',
  password: '$2b$10$hash',
  ...over,
});

describe('TranslogCredentialStore.findByEmail', () => {
  it('joint Account credential + User en CredentialRecord', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({}));
    prisma.seedUser(userRow({ id: 'u1', roleId: 'role-1' }));
    const store = new TranslogCredentialStore(prisma);

    const record = await store.findByEmail('a@x.io', 't1');

    expect(record).toEqual({
      userId: 'u1',
      tenantId: 't1',
      passwordHash: '$2b$10$hash',
      isActive: true,
      mfaEnabled: false,
      roles: ['role-1'],
    });
  });

  it('roles vide quand User.roleId est null', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({}));
    prisma.seedUser(userRow({ id: 'u1', roleId: null }));
    const store = new TranslogCredentialStore(prisma);

    const record = await store.findByEmail('a@x.io', 't1');

    expect(record?.roles).toEqual([]);
  });

  it('passwordHash null quand le compte n a pas de password', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({ password: null }));
    prisma.seedUser(userRow({ id: 'u1' }));
    const store = new TranslogCredentialStore(prisma);

    const record = await store.findByEmail('a@x.io', 't1');

    expect(record?.passwordHash).toBeNull();
  });

  it('isActive=false si User.isActive=false', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({}));
    prisma.seedUser(userRow({ id: 'u1', isActive: false }));
    const store = new TranslogCredentialStore(prisma);

    const record = await store.findByEmail('a@x.io', 't1');

    expect(record?.isActive).toBe(false);
  });

  it('isActive=false si User.deletedAt est renseigne', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({}));
    prisma.seedUser(userRow({ id: 'u1', deletedAt: new Date('2026-01-01T00:00:00Z') }));
    const store = new TranslogCredentialStore(prisma);

    const record = await store.findByEmail('a@x.io', 't1');

    expect(record?.isActive).toBe(false);
  });

  it('null quand aucun compte credential', async () => {
    const store = new TranslogCredentialStore(new FakeTranslogPrisma());
    expect(await store.findByEmail('ghost@x.io', 't1')).toBeNull();
  });

  it('ne resout pas un provider non-credential (ex google)', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('google', 'a@x.io', accountRow({}));
    prisma.seedUser(userRow({ id: 'u1' }));
    const store = new TranslogCredentialStore(prisma);

    expect(await store.findByEmail('a@x.io', 't1')).toBeNull();
  });

  it('fail-closed : compte orphelin (User introuvable) -> null', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({ userId: 'ghost' }));
    const store = new TranslogCredentialStore(prisma);

    expect(await store.findByEmail('a@x.io', 't1')).toBeNull();
  });

  it('isole par tenant', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({ tenantId: 't2', userId: 'u2' }));
    prisma.seedUser(userRow({ id: 'u2', tenantId: 't2' }));
    const store = new TranslogCredentialStore(prisma);

    expect(await store.findByEmail('a@x.io', 't1')).toBeNull();
  });
});

describe('TranslogCredentialStore.findByEmailAcrossTenants', () => {
  it('retourne un enregistrement par tenant, en lot', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({ tenantId: 't1', userId: 'u1' }));
    prisma.seedAccount('credential', 'a@x.io', accountRow({ tenantId: 't2', userId: 'u2' }));
    prisma.seedUser(userRow({ id: 'u1', tenantId: 't1' }));
    prisma.seedUser(userRow({ id: 'u2', tenantId: 't2' }));
    const store = new TranslogCredentialStore(prisma);

    const records = await store.findByEmailAcrossTenants('a@x.io');

    expect(records).toHaveLength(2);
    expect(records.map((r) => r.tenantId).sort()).toEqual(['t1', 't2']);
  });

  it('retourne [] quand aucun compte', async () => {
    const store = new TranslogCredentialStore(new FakeTranslogPrisma());
    expect(await store.findByEmailAcrossTenants('ghost@x.io')).toEqual([]);
  });

  it('fail-closed : ecarte un compte orphelin dans le lot', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedAccount('credential', 'a@x.io', accountRow({ tenantId: 't1', userId: 'u1' }));
    prisma.seedAccount('credential', 'a@x.io', accountRow({ tenantId: 't2', userId: 'ghost' }));
    prisma.seedUser(userRow({ id: 'u1', tenantId: 't1' }));
    const store = new TranslogCredentialStore(prisma);

    const records = await store.findByEmailAcrossTenants('a@x.io');

    expect(records).toHaveLength(1);
    expect(records[0]?.tenantId).toBe('t1');
  });
});
