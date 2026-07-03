import type { KeyManagementPort } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import type {
  PiiAccessLogDelegate,
  SubjectKeyDelegate,
  SubjectKeyRow,
} from '../src/prisma-like.js';
import { PrismaPiiAccessLogSink, PrismaSubjectKeyStore } from '../src/pii-stores.js';

function fakeSubjectKeyDelegate(): {
  readonly delegate: SubjectKeyDelegate;
  readonly raw: () => string | undefined;
} {
  const rows = new Map<string, SubjectKeyRow>();
  const id = (tenantId: string, subjectId: string): string => `${tenantId}:${subjectId}`;
  const delegate: SubjectKeyDelegate = {
    findFirst: ({ where }) =>
      Promise.resolve(rows.get(id(where.tenantId, where.subjectId)) ?? null),
    create: ({ data }) => {
      rows.set(id(data.tenantId, data.subjectId), { key: data.key });
      return Promise.resolve({});
    },
    deleteMany: ({ where }) => {
      const had = rows.delete(id(where.tenantId, where.subjectId));
      return Promise.resolve({ count: had ? 1 : 0 });
    },
  };
  return { delegate, raw: () => rows.get('t1:sub1')?.key };
}

/** KMS factice : XOR par octet dérivé du tenant (inversible, suffisant pour un test). */
function fakeKms(): KeyManagementPort {
  const mask = (tenantId: string): number => tenantId.charCodeAt(0) & 0xff;
  const xor = (tenantId: string, data: Uint8Array): Uint8Array =>
    Uint8Array.from(data, (b) => b ^ mask(tenantId));
  return {
    encrypt: (tenantId, plaintext) => Promise.resolve(xor(tenantId, plaintext)),
    decrypt: (tenantId, ciphertext) => Promise.resolve(xor(tenantId, ciphertext)),
  };
}

describe('PrismaSubjectKeyStore', () => {
  it('getOrCreateKey : cree puis relit la MEME cle (idempotent)', async () => {
    const { delegate } = fakeSubjectKeyDelegate();
    const store = new PrismaSubjectKeyStore(delegate);
    const created = await store.getOrCreateKey('t1', 'sub1');
    expect(created).toHaveLength(32);
    const again = await store.getOrCreateKey('t1', 'sub1');
    expect([...again]).toEqual([...created]);
    const fetched = await store.getKey('t1', 'sub1');
    expect(fetched).not.toBeNull();
    expect([...(fetched ?? [])]).toEqual([...created]);
  });

  it('getKey : sujet inconnu -> null', async () => {
    const { delegate } = fakeSubjectKeyDelegate();
    const store = new PrismaSubjectKeyStore(delegate);
    expect(await store.getKey('t1', 'sub1')).toBeNull();
  });

  it('deleteKey : crypto-shredding (la cle disparait -> getKey null)', async () => {
    const { delegate } = fakeSubjectKeyDelegate();
    const store = new PrismaSubjectKeyStore(delegate);
    await store.getOrCreateKey('t1', 'sub1');
    await store.deleteKey('t1', 'sub1');
    expect(await store.getKey('t1', 'sub1')).toBeNull();
  });

  it('chiffrement at-rest : la colonne ne contient JAMAIS la cle en clair', async () => {
    const { delegate, raw } = fakeSubjectKeyDelegate();
    const store = new PrismaSubjectKeyStore(delegate, { keyManagement: fakeKms() });
    const created = await store.getOrCreateKey('t1', 'sub1');
    const storedB64 = raw();
    expect(storedB64).toBeDefined();
    // La valeur stockee (chiffree) differe du clair, mais getKey redonne le clair.
    const clearB64 = Buffer.from(created).toString('base64');
    expect(storedB64).not.toBe(clearB64);
    const roundtrip = await store.getKey('t1', 'sub1');
    expect([...(roundtrip ?? [])]).toEqual([...created]);
  });
});

describe('PrismaPiiAccessLogSink', () => {
  it("record : insere une ligne d'audit (RGPD art. 30)", async () => {
    const captured: unknown[] = [];
    const delegate: PiiAccessLogDelegate = {
      create: ({ data }) => {
        captured.push(data);
        return Promise.resolve({});
      },
    };
    const sink = new PrismaPiiAccessLogSink(delegate);
    await sink.record({
      tenantId: 't1',
      subjectId: 'sub1',
      actorId: 'u9',
      fields: ['email', 'phone'],
      purpose: 'support',
      at: 1000,
    });
    expect(captured).toEqual([
      {
        tenantId: 't1',
        subjectId: 'sub1',
        actorId: 'u9',
        fields: ['email', 'phone'],
        purpose: 'support',
        at: new Date(1000),
      },
    ]);
  });

  it('record : acteur absent -> actorId null (acces systeme)', async () => {
    let seen: { readonly actorId: unknown } | null = null;
    const delegate: PiiAccessLogDelegate = {
      create: ({ data }) => {
        seen = { actorId: data.actorId };
        return Promise.resolve({});
      },
    };
    const sink = new PrismaPiiAccessLogSink(delegate);
    await sink.record({
      tenantId: 't1',
      subjectId: 'sub1',
      fields: ['email'],
      purpose: 'export',
      at: 2000,
    });
    expect(seen).toEqual({ actorId: null });
  });
});
