import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import type { KeyManagementPort, TenantId } from '@kengela/contracts';

const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

/**
 * KeyManagementPort en chiffrement enveloppe AES-256-GCM. Une clé par tenant est
 * dérivée de la clé maître via HKDF-SHA256 (isolation cryptographique inter-tenant).
 * Format du chiffré : iv(12) || tag(16) || ciphertext.
 */
export class AesGcmKeyManagement implements KeyManagementPort {
  readonly #masterKey: Uint8Array;

  public constructor(masterKey: Uint8Array) {
    if (masterKey.length < KEY_LEN) {
      throw new Error(`Clé maître trop courte (>= ${String(KEY_LEN)} octets requis).`);
    }
    this.#masterKey = masterKey;
  }

  public encrypt(tenantId: TenantId, plaintext: Uint8Array): Promise<Uint8Array> {
    // Executor : toute exception synchrone (crypto Node) rejette proprement la promesse.
    return new Promise<Uint8Array>((resolve) => {
      const key = this.#deriveKey(tenantId);
      const iv = randomBytes(IV_LEN);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();
      resolve(new Uint8Array(Buffer.concat([iv, tag, ciphertext])));
    });
  }

  public decrypt(tenantId: TenantId, ciphertext: Uint8Array): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve) => {
      if (ciphertext.length < IV_LEN + TAG_LEN) {
        throw new Error('Chiffré AES-GCM invalide (trop court).');
      }
      const buffer = Buffer.from(ciphertext);
      const iv = buffer.subarray(0, IV_LEN);
      const tag = buffer.subarray(IV_LEN, IV_LEN + TAG_LEN);
      const body = buffer.subarray(IV_LEN + TAG_LEN);
      const decipher = createDecipheriv('aes-256-gcm', this.#deriveKey(tenantId), iv);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
      resolve(new Uint8Array(plaintext));
    });
  }

  #deriveKey(tenantId: TenantId): Buffer {
    const info = `kengela:mfa:${tenantId}`;
    return Buffer.from(hkdfSync('sha256', this.#masterKey, Buffer.alloc(0), info, KEY_LEN));
  }
}
