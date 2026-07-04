/**
 * RED TEAM - sessions (@kengela/adapter-persistence-prisma).
 *
 * On tente de rejouer une session EXPIREE, un ancien token apres rotation, et on verifie
 * l'entropie du token + l'effet de `revokeAllForUser`. Fake `PrismaLike` en memoire.
 */
import type { AuthContext, Clock } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { PrismaSessionStore } from '../src/session-store.js';
import { FakePrisma } from './fake-prisma.js';

const CTX: AuthContext = { authTime: 1000, ip: '10.0.0.1' };

/** Horloge mutable pour faire avancer le temps au-dela de l'expiration. */
function mutableClock(start: number): { clock: Clock; set: (t: number) => void } {
  let t = start;
  return {
    clock: { now: () => t },
    set: (v: number): void => {
      t = v;
    },
  };
}

describe('RED - session expiree n’est JAMAIS restituee comme valide (fail-closed)', () => {
  it('get(token) renvoie null une fois l’expiration passee, meme si la ligne subsiste', async () => {
    const prisma = new FakePrisma();
    const { clock, set } = mutableClock(1000);
    const store = new PrismaSessionStore(prisma, { clock });

    const handle = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 5000 });
    // Avant expiration : valide.
    expect(await store.get(handle.token)).not.toBeNull();
    // Apres expiration (now > expiresAt) : rejete, meme si le cleanup n'a pas purge.
    set(6001);
    expect(await store.get(handle.token)).toBeNull();
    // La ligne existe pourtant toujours cote store (pas encore balayee).
    expect(prisma.sessionCount()).toBe(1);
  });

  it('get au tout dernier instant limite (== expiresAt) est deja considere expire', async () => {
    const prisma = new FakePrisma();
    const { clock, set } = mutableClock(1000);
    const store = new PrismaSessionStore(prisma, { clock });
    const handle = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 1000 });
    set(2000); // == expiresAt
    expect(await store.get(handle.token)).toBeNull();
  });
});

describe('RED - rotation & revocation', () => {
  it('l’ancien token est invalide immediatement apres rotation (anti-rejeu)', async () => {
    const prisma = new FakePrisma();
    const { clock } = mutableClock(1000);
    const store = new PrismaSessionStore(prisma, { clock });
    const created = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 50_000 });
    const rotated = await store.rotate(created.token);
    expect(rotated.token).not.toBe(created.token);
    expect(await store.get(created.token)).toBeNull();
    expect(await store.get(rotated.token)).not.toBeNull();
  });

  it('revokeAllForUser coupe toutes les sessions de la victime (kill switch)', async () => {
    const prisma = new FakePrisma();
    const store = new PrismaSessionStore(prisma, { clock: mutableClock(1000).clock });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 50_000 });
    await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 50_000 });
    await store.revokeAllForUser('u1');
    expect(await store.listForUser('u1')).toHaveLength(0);
  });
});

describe('RED - entropie du token opaque', () => {
  it('token = 32 octets aleatoires (64 hex), non devinable et unique', async () => {
    const store = new PrismaSessionStore(new FakePrisma(), { clock: mutableClock(1000).clock });
    const tokens = new Set<string>();
    for (let i = 0; i < 25; i += 1) {
      const h = await store.create({ userId: 'u1', tenantId: 't1', ctx: CTX, ttlMs: 50_000 });
      expect(h.token).toMatch(/^[0-9a-f]{64}$/);
      tokens.add(h.token);
    }
    expect(tokens.size).toBe(25); // aucune collision
  });
});
