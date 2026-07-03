import { describe, expect, it } from 'vitest';
import { TranslogAuthorizationRepository } from '../src/authorization-repository.js';
import { FakeTranslogPrisma, userRow } from './fake-translog-prisma.js';

describe('TranslogAuthorizationRepository.loadGrantsForUser', () => {
  it('split scope agency -> unit', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedUser(userRow({ id: 'u1', roleId: 'role-1' }));
    prisma.seedRolePermission('role-1', { permission: 'data.ticket.scan.agency' });
    const repo = new TranslogAuthorizationRepository(prisma);

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants).toEqual([{ permission: 'data.ticket.scan', scope: 'unit', source: 'MANUAL' }]);
  });

  it('split scope own / tenant / global', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedUser(userRow({ id: 'u1', roleId: 'role-1' }));
    prisma.seedRolePermission('role-1', { permission: 'data.ticket.view.own' });
    prisma.seedRolePermission('role-1', { permission: 'control.trip.cancel.tenant' });
    prisma.seedRolePermission('role-1', { permission: 'platform.tenant.manage.global' });
    const repo = new TranslogAuthorizationRepository(prisma);

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants).toEqual([
      { permission: 'data.ticket.view', scope: 'own', source: 'MANUAL' },
      { permission: 'control.trip.cancel', scope: 'tenant', source: 'MANUAL' },
      { permission: 'platform.tenant.manage', scope: 'global', source: 'MANUAL' },
    ]);
  });

  it('fail-closed : jeton de portee inconnu -> grant ignore', async () => {
    const prisma = new FakeTranslogPrisma();
    const warnings: string[] = [];
    prisma.seedUser(userRow({ id: 'u1', roleId: 'role-1' }));
    prisma.seedRolePermission('role-1', { permission: 'data.ticket.scan.galaxy' });
    prisma.seedRolePermission('role-1', { permission: 'data.ticket.scan.agency' });
    const repo = new TranslogAuthorizationRepository(prisma, {
      logger: { warn: (m) => warnings.push(m) },
    });

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants).toHaveLength(1);
    expect(grants[0]?.scope).toBe('unit');
    expect(warnings).toHaveLength(1);
  });

  it('fail-closed : permission malformee (sans segment de portee) ignoree', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedUser(userRow({ id: 'u1', roleId: 'role-1' }));
    prisma.seedRolePermission('role-1', { permission: 'nodots' });
    prisma.seedRolePermission('role-1', { permission: 'trailing.dot.' });
    const repo = new TranslogAuthorizationRepository(prisma);

    const grants = await repo.loadGrantsForUser('u1', 't1');

    expect(grants).toEqual([]);
  });

  it('User sans roleId -> aucun grant', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedUser(userRow({ id: 'u1', roleId: null }));
    prisma.seedRolePermission('role-1', { permission: 'data.ticket.scan.agency' });
    const repo = new TranslogAuthorizationRepository(prisma);

    expect(await repo.loadGrantsForUser('u1', 't1')).toEqual([]);
  });

  it('User absent (ou mauvais tenant) -> aucun grant', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedUser(userRow({ id: 'u1', tenantId: 't2', roleId: 'role-1' }));
    prisma.seedRolePermission('role-1', { permission: 'data.ticket.scan.agency' });
    const repo = new TranslogAuthorizationRepository(prisma);

    expect(await repo.loadGrantsForUser('u1', 't1')).toEqual([]);
  });
});

describe('TranslogAuthorizationRepository.loadRole', () => {
  it('charge un role avec ses grants (meme split)', async () => {
    const prisma = new FakeTranslogPrisma();
    prisma.seedRolePermission('role-1', { permission: 'data.ticket.scan.agency' });
    prisma.seedRolePermission('role-1', { permission: 'data.ticket.view.own' });
    const repo = new TranslogAuthorizationRepository(prisma);

    const role = await repo.loadRole('role-1', 't1');

    expect(role?.key).toBe('role-1');
    expect(role?.tenantId).toBe('t1');
    expect(role?.grants).toHaveLength(2);
  });

  it('retourne null quand le role n a aucune permission', async () => {
    const prisma = new FakeTranslogPrisma();
    const repo = new TranslogAuthorizationRepository(prisma);

    expect(await repo.loadRole('ghost-role', 't1')).toBeNull();
  });
});
