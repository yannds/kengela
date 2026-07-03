import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AesGcmFieldCipher } from '../src/aes-gcm-field-cipher.js';
import { AesGcmKeyManagement } from '../src/aes-gcm-key-management.js';

const KEY = new Uint8Array(randomBytes(32));

describe('AesGcmKeyManagement', () => {
  const km = new AesGcmKeyManagement(KEY);

  it('chiffre/dechiffre (roundtrip)', async () => {
    const cipher = await km.encrypt('t1', new TextEncoder().encode('mfa-secret'));
    expect(new TextDecoder().decode(await km.decrypt('t1', cipher))).toBe('mfa-secret');
  });

  it('rejette un mauvais tenant (isolation cryptographique)', async () => {
    const cipher = await km.encrypt('t1', new TextEncoder().encode('x'));
    await expect(km.decrypt('t2', cipher)).rejects.toThrow();
  });

  it('rejette un chiffre altere (integrite GCM)', async () => {
    const cipher = await km.encrypt('t1', new TextEncoder().encode('x'));
    const last = cipher.length - 1;
    cipher[last] = (cipher[last] ?? 0) ^ 0xff;
    await expect(km.decrypt('t1', cipher)).rejects.toThrow();
  });

  it('refuse une cle maitre trop courte', () => {
    expect(() => new AesGcmKeyManagement(new Uint8Array(16))).toThrow();
  });
});

describe('AesGcmFieldCipher (PII)', () => {
  it('chiffre/dechiffre un champ PII en base64 (roundtrip)', async () => {
    const cipher = new AesGcmFieldCipher(new AesGcmKeyManagement(KEY));
    const encrypted = await cipher.encryptField('t1', 'alice@acme.io');
    expect(encrypted).not.toContain('@');
    expect(await cipher.decryptField('t1', encrypted)).toBe('alice@acme.io');
  });
});
