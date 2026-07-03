import type { GrantRow } from '../src/prisma-like.js';
import { describe, expect, it } from 'vitest';
import { PrismaAuthorizationRepository } from '../src/authorization-repository.js';
import { FakePrisma } from './fake-prisma.js';

const grantRow = (over: Partial<GrantRow>): GrantRow => ({
  permission: 'data.cashier.register.read',
  scope: 'tenant',
  source: 'MANUAL',
  expiresAt: null,
  ...over,
});

describe('PrismaAuthorizationRepository.loadGrantsForUser', () => {
  it('mappe une ligne valide en Grant', async () => {
    const prisma = new FakePrisma();
    prisma.seedGrant('u1', 't1', grantRow({}));
    const repo = new PrismaAuthorizationRepository(prisma);

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants).toEqual([
      { permission: 'data.cashier.register.read', scope: 'tenant', source: 'MANUAL' },
    ]);
  });

  it('mappe expiresAt quand present (sans propriete undefined sinon)', async () => {
    const prisma = new FakePrisma();
    const expiresAt = new Date('2030-01-01T00:00:00Z');
    prisma.seedGrant('u1', 't1', grantRow({ expiresAt }));
    const repo = new PrismaAuthorizationRepository(prisma);

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants[0]?.expiresAt).toBe(expiresAt);
  });

  it('fail-closed : ignore un grant au scope inconnu', async () => {
    const prisma = new FakePrisma();
    const warnings: string[] = [];
    prisma.seedGrant('u1', 't1', grantRow({ scope: 'galaxy' }));
    prisma.seedGrant('u1', 't1', grantRow({}));
    const repo = new PrismaAuthorizationRepository(prisma, {
      logger: { warn: (m) => warnings.push(m) },
    });

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants).toHaveLength(1);
    expect(warnings).toHaveLength(1);
  });

  it('fail-closed : ignore un grant a la source inconnue', async () => {
    const prisma = new FakePrisma();
    prisma.seedGrant('u1', 't1', grantRow({ source: 'HACKED' }));
    const repo = new PrismaAuthorizationRepository(prisma);

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants).toHaveLength(0);
  });

  it('isole par userId et tenantId', async () => {
    const prisma = new FakePrisma();
    prisma.seedGrant('u1', 't1', grantRow({}));
    prisma.seedGrant('u2', 't1', grantRow({}));
    prisma.seedGrant('u1', 't2', grantRow({}));
    const repo = new PrismaAuthorizationRepository(prisma);

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants).toHaveLength(1);
  });
});

describe('PrismaAuthorizationRepository.loadRole', () => {
  it('charge un role avec ses grants valides', async () => {
    const prisma = new FakePrisma();
    prisma.seedRole({
      key: 'cashier',
      tenantId: 't1',
      grants: [grantRow({}), grantRow({ scope: 'bogus' })],
    });
    const repo = new PrismaAuthorizationRepository(prisma);

    const role = await repo.loadRole('cashier', 't1');

    expect(role?.key).toBe('cashier');
    expect(role?.grants).toHaveLength(1);
  });

  it('retourne null si le role est absent', async () => {
    const prisma = new FakePrisma();
    const repo = new PrismaAuthorizationRepository(prisma);

    expect(await repo.loadRole('ghost', 't1')).toBeNull();
  });
});
