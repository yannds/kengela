import type { Clock } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import type {
  MfaChallengeDelegate,
  MfaChallengeRow,
  MfaSecretDelegate,
} from '../src/prisma-like.js';
import { PrismaMfaChallengeStore, PrismaMfaSecretStore } from '../src/mfa-stores.js';

function fakeSecretDelegate(): MfaSecretDelegate {
  const rows = new Map<string, string>();
  const key = (tenantId: string, userId: string): string => `${tenantId}:${userId}`;
  return {
    findFirst: ({ where }) => {
      const secret = rows.get(key(where.tenantId, where.userId));
      return Promise.resolve(secret === undefined ? null : { secret });
    },
    deleteMany: ({ where }) => {
      const had = rows.delete(key(where.tenantId, where.userId));
      return Promise.resolve({ count: had ? 1 : 0 });
    },
    create: ({ data }) => {
      rows.set(key(data.tenantId, data.userId), data.secret);
      return Promise.resolve({});
    },
  };
}

function fakeChallengeDelegate(): MfaChallengeDelegate {
  const rows = new Map<string, MfaChallengeRow>();
  return {
    create: ({ data }) => {
      rows.set(data.id, { ...data });
      return Promise.resolve({});
    },
    findUnique: ({ where }) => Promise.resolve(rows.get(where.id) ?? null),
    delete: ({ where }) => {
      rows.delete(where.id);
      return Promise.resolve({});
    },
  };
}

const CLOCK: Clock = { now: () => 1000 };

describe('PrismaMfaSecretStore', () => {
  it('sauvegarde et relit (idempotent)', async () => {
    const store = new PrismaMfaSecretStore(fakeSecretDelegate());
    await store.save('t1', 'u1', 'enc-A');
    expect(await store.get('t1', 'u1')).toBe('enc-A');
    await store.save('t1', 'u1', 'enc-B'); // overwrite
    expect(await store.get('t1', 'u1')).toBe('enc-B');
    expect(await store.get('t1', 'u2')).toBeNull();
  });
});

describe('PrismaMfaChallengeStore', () => {
  it('issue puis consume (one-shot)', async () => {
    const store = new PrismaMfaChallengeStore(fakeChallengeDelegate(), { clock: CLOCK });
    const id = await store.issue('t1', 'u1', 60_000);
    expect(id.length).toBeGreaterThan(0);
    expect(await store.consume(id)).toEqual({ tenantId: 't1', userId: 'u1' });
    expect(await store.consume(id)).toBeNull(); // deja consomme
  });

  it('refuse un defi expire et un id inconnu', async () => {
    const store = new PrismaMfaChallengeStore(fakeChallengeDelegate(), { clock: CLOCK });
    const id = await store.issue('t1', 'u1', 0); // expire immediatement
    expect(await store.consume(id)).toBeNull();
    expect(await store.consume('inconnu')).toBeNull();
  });
});
