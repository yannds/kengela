import type { AuthContext, Clock } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { TranslogSessionStore } from '../src/session-store.js';
import { FakeTranslogPrisma } from './fake-translog-prisma.js';

const CTX: AuthContext = {
  authTime: 999,
  ip: '10.0.0.1',
  riskScore: 42,
  geo: { country: 'CG' },
  device: { id: 'd1', trusted: true, userAgent: 'Mozilla/5.0' },
};

const fixedClock = (t: number): Clock => ({ now: () => t });

describe('TranslogSessionStore.create', () => {
  it('genere un token hex 64, calcule expiresAt = now + ttl, persiste ip/ua', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });

    const handle = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    expect(handle.token).toMatch(/^[0-9a-f]{64}$/);
    expect(handle.createdAt.getTime()).toBe(1000);
    expect(handle.expiresAt.getTime()).toBe(6000);
    expect(handle.ctx.ip).toBe('10.0.0.1');
    expect(handle.ctx.device?.userAgent).toBe('Mozilla/5.0');
  });

  it('ctx LOSSY : authTime <- createdAt, geo/risk/device-id perdus', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });

    const handle = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    expect(handle.ctx.authTime).toBe(1000);
    expect(handle.ctx.geo).toBeUndefined();
    expect(handle.ctx.riskScore).toBeUndefined();
    expect(handle.ctx.device?.id).toBeUndefined();
    expect(handle.ctx.device?.trusted).toBeUndefined();
  });

  it('ctx minimal (ni ip ni device) : n ajoute pas les cles absentes', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });

    const handle = await store.create({
      userId: 'u1',
      tenantId: 't1',
      ctx: { authTime: 5 },
      ttlMs: 5000,
    });

    expect(Object.prototype.hasOwnProperty.call(handle.ctx, 'ip')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(handle.ctx, 'device')).toBe(false);
    expect(handle.ctx.authTime).toBe(1000);
  });

  it('device sans userAgent : device non reconstitue', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });

    const handle = await store.create({
      userId: 'u1',
      tenantId: 't1',
      ctx: { authTime: 5, device: { id: 'd9' } },
      ttlMs: 5000,
    });

    expect(handle.ctx.device).toBeUndefined();
  });
});

describe('TranslogSessionStore.get', () => {
  it('retourne le handle', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    const fetched = await store.get(created.token);

    expect(fetched?.userId).toBe('u1');
    expect(fetched?.ctx.ip).toBe('10.0.0.1');
  });

  it('retourne null sur token inconnu', async () => {
    const store = new TranslogSessionStore(new FakeTranslogPrisma());
    expect(await store.get('nope')).toBeNull();
  });
});

describe('TranslogSessionStore.rotate', () => {
  it('emet un nouveau token, invalide l ancien, preserve identite/expiration/ip', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    const rotated = await store.rotate(created.token);

    expect(rotated.token).not.toBe(created.token);
    expect(rotated.userId).toBe('u1');
    expect(rotated.expiresAt.getTime()).toBe(created.expiresAt.getTime());
    expect(rotated.ctx.ip).toBe('10.0.0.1');
    expect(await store.get(created.token)).toBeNull();
    expect(await store.get(rotated.token)).not.toBeNull();
    expect(prisma.sessionCount()).toBe(1);
  });

  it('fonctionne via $transaction quand le client le fournit', async () => {
    const prisma = new FakeTranslogPrisma({ withTransaction: true });
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    const rotated = await store.rotate(created.token);

    expect(rotated.token).not.toBe(created.token);
    expect(prisma.sessionCount()).toBe(1);
  });

  it('leve si la session a tourner est absente', async () => {
    const store = new TranslogSessionStore(new FakeTranslogPrisma());
    await expect(store.rotate('ghost')).rejects.toThrow(/not found/);
  });
});

describe('TranslogSessionStore revoke / list', () => {
  it('revoke est idempotent (aucune erreur si absent)', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    await store.revoke(created.token);
    await store.revoke(created.token);

    expect(await store.get(created.token)).toBeNull();
  });

  it('listForUser ne renvoie que les sessions de l utilisateur', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    await store.create({ userId: 'u2', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    expect(await store.listForUser('u1')).toHaveLength(2);
  });

  it('revokeAllForUser supprime toutes les sessions de l utilisateur', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: fixedClock(1000) });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    await store.create({ userId: 'u2', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    await store.revokeAllForUser('u1');

    expect(await store.listForUser('u1')).toHaveLength(0);
    expect(await store.listForUser('u2')).toHaveLength(1);
  });
});
