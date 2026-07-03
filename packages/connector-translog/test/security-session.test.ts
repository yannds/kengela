/**
 * RED TEAM — sessions TransLog (@kengela/connector-translog).
 *
 * Meme surface durcie que l'adapter Prisma : une session EXPIREE n'est jamais restituee,
 * la rotation invalide l'ancien token, et le token opaque est a haute entropie. Fake
 * `TranslogPrismaLike` en memoire.
 */
import type { AuthContext, Clock } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { TranslogSessionStore } from '../src/session-store.js';
import { FakeTranslogPrisma } from './fake-translog-prisma.js';

const CTX: AuthContext = { authTime: 1000, ip: '10.0.0.1' };

function mutableClock(start: number): { clock: Clock; set: (t: number) => void } {
  let t = start;
  return {
    clock: { now: () => t },
    set: (v: number): void => {
      t = v;
    },
  };
}

describe('RED — session TransLog expiree jamais restituee (fail-closed)', () => {
  it('get(token) renvoie null apres expiration, meme si la ligne subsiste', async () => {
    const prisma = new FakeTranslogPrisma();
    const { clock, set } = mutableClock(1000);
    const store = new TranslogSessionStore(prisma, { clock });
    const handle = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    expect(await store.get(handle.token)).not.toBeNull();
    set(6001);
    expect(await store.get(handle.token)).toBeNull();
    expect(prisma.sessionCount()).toBe(1);
  });

  it('rotation : l’ancien token est invalide immediatement', async () => {
    const prisma = new FakeTranslogPrisma();
    const store = new TranslogSessionStore(prisma, { clock: mutableClock(1000).clock });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 50_000 });
    const rotated = await store.rotate(created.token);
    expect(rotated.token).not.toBe(created.token);
    expect(await store.get(created.token)).toBeNull();
    expect(await store.get(rotated.token)).not.toBeNull();
  });

  it('token opaque = 64 hex, unique (haute entropie)', async () => {
    const store = new TranslogSessionStore(new FakeTranslogPrisma(), {
      clock: mutableClock(1000).clock,
    });
    const a = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 50_000 });
    const b = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 50_000 });
    expect(a.token).toMatch(/^[0-9a-f]{64}$/);
    expect(a.token).not.toBe(b.token);
  });
});
