import { randomBytes } from 'node:crypto';
import type { SubjectKeyStore } from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { SubjectCryptoShredder } from '../src/subject-crypto-shredder.js';
import { SubjectFieldCipher } from '../src/subject-field-cipher.js';

function fakeKeyStore(): SubjectKeyStore {
  const keys = new Map<string, Uint8Array>();
  const id = (tenantId: string, subjectId: string): string => `${tenantId}:${subjectId}`;
  return {
    getOrCreateKey: (tenantId, subjectId) => {
      const key = id(tenantId, subjectId);
      let value = keys.get(key);
      if (value === undefined) {
        value = new Uint8Array(randomBytes(32));
        keys.set(key, value);
      }
      return Promise.resolve(value);
    },
    getKey: (tenantId, subjectId) => Promise.resolve(keys.get(id(tenantId, subjectId)) ?? null),
    deleteKey: (tenantId, subjectId) => {
      keys.delete(id(tenantId, subjectId));
      return Promise.resolve();
    },
  };
}

describe('SubjectFieldCipher + SubjectCryptoShredder', () => {
  it('chiffre/dechiffre par sujet', async () => {
    const cipher = new SubjectFieldCipher(fakeKeyStore());
    const encrypted = await cipher.encryptFor('t1', 'sub1', 'alice@acme.io');
    expect(await cipher.decryptFor('t1', 'sub1', encrypted)).toBe('alice@acme.io');
  });

  it('crypto-shredding : apres effacement, la PII est illisible (null)', async () => {
    const store = fakeKeyStore();
    const cipher = new SubjectFieldCipher(store);
    const shredder = new SubjectCryptoShredder(store);
    const encrypted = await cipher.encryptFor('t1', 'sub1', 'secret');
    await shredder.eraseSubject('t1', 'sub1');
    expect(await cipher.decryptFor('t1', 'sub1', encrypted)).toBeNull();
  });

  it('isolation : un sujet sans cle ne lit rien (null)', async () => {
    const cipher = new SubjectFieldCipher(fakeKeyStore());
    const encrypted = await cipher.encryptFor('t1', 'sub1', 'x');
    expect(await cipher.decryptFor('t1', 'sub2', encrypted)).toBeNull();
  });

  it('isolation : un autre sujet avec sa propre cle ne peut pas dechiffrer', async () => {
    const store = fakeKeyStore();
    const cipher = new SubjectFieldCipher(store);
    const encrypted = await cipher.encryptFor('t1', 'sub1', 'x');
    await cipher.encryptFor('t1', 'sub2', 'y');
    await expect(cipher.decryptFor('t1', 'sub2', encrypted)).rejects.toThrow();
  });
});
