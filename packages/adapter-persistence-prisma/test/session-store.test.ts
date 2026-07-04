import type { AuthContext, Clock } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { PrismaSessionStore } from '../src/session-store.js';
import { FakePrisma } from './fake-prisma.js';

const CTX: AuthContext = {
  authTime: 1000,
  ip: '10.0.0.1',
  riskScore: 12,
  geo: { country: 'CG' },
  device: { id: 'd1', trusted: true },
};

const fixedClock = (t: number): Clock => ({ now: () => t });

describe('PrismaSessionStore.create', () => {
  it('genere un token hex 64 et calcule expiresAt = now + ttl', async () => {
    const prisma = new FakePrisma();
    const store = new PrismaSessionStore(prisma, { clock: fixedClock(1000) });

    const handle = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    expect(handle.token).toMatch(/^[0-9a-f]{64}$/);
    expect(handle.createdAt.getTime()).toBe(1000);
    expect(handle.expiresAt.getTime()).toBe(6000);
    expect(handle.ctx).toEqual(CTX);
  });
});

describe('PrismaSessionStore.get', () => {
  it('retourne le handle et reconstitue le ctx', async () => {
    const prisma = new FakePrisma();
    const store = new PrismaSessionStore(prisma, { clock: fixedClock(1000) });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    const fetched = await store.get(created.token);

    expect(fetched?.userId).toBe('u1');
    expect(fetched?.ctx.geo?.country).toBe('CG');
  });

  it('retourne null sur token inconnu', async () => {
    const store = new PrismaSessionStore(new FakePrisma());
    expect(await store.get('nope')).toBeNull();
  });
});

describe('PrismaSessionStore.rotate', () => {
  it('emet un nouveau token, invalide l ancien, preserve identite et expiration', async () => {
    const prisma = new FakePrisma();
    const store = new PrismaSessionStore(prisma, { clock: fixedClock(1000) });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    const rotated = await store.rotate(created.token);

    expect(rotated.token).not.toBe(created.token);
    expect(rotated.userId).toBe('u1');
    expect(rotated.expiresAt.getTime()).toBe(created.expiresAt.getTime());
    expect(await store.get(created.token)).toBeNull();
    expect(await store.get(rotated.token)).not.toBeNull();
    expect(prisma.sessionCount()).toBe(1);
  });

  it('fonctionne via $transaction quand le client le fournit', async () => {
    const prisma = new FakePrisma({ withTransaction: true });
    const store = new PrismaSessionStore(prisma, { clock: fixedClock(1000) });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    const rotated = await store.rotate(created.token);

    expect(rotated.token).not.toBe(created.token);
    expect(prisma.sessionCount()).toBe(1);
  });

  it('leve si la session a tourner est absente', async () => {
    const store = new PrismaSessionStore(new FakePrisma());
    await expect(store.rotate('ghost')).rejects.toThrow(/not found/);
  });
});

describe('PrismaSessionStore revoke / list', () => {
  it('revoke est idempotent (aucune erreur si absent)', async () => {
    const prisma = new FakePrisma();
    const store = new PrismaSessionStore(prisma, { clock: fixedClock(1000) });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    await store.revoke(created.token);
    await store.revoke(created.token);

    expect(await store.get(created.token)).toBeNull();
  });

  it('listForUser ne renvoie que les sessions de l utilisateur', async () => {
    const prisma = new FakePrisma();
    const store = new PrismaSessionStore(prisma, { clock: fixedClock(1000) });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    await store.create({ userId: 'u2', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    expect(await store.listForUser('u1')).toHaveLength(2);
  });

  it('revokeAllForUser supprime toutes les sessions de l utilisateur', async () => {
    const prisma = new FakePrisma();
    const store = new PrismaSessionStore(prisma, { clock: fixedClock(1000) });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    await store.create({ userId: 'u2', tenantId: 't1', ctx: CTX, ttlMs: 5000 });

    await store.revokeAllForUser('u1');

    expect(await store.listForUser('u1')).toHaveLength(0);
    expect(await store.listForUser('u2')).toHaveLength(1);
  });
});
