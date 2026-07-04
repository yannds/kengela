import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import type { KeyManagementPort, TenantId } from '@kengela/contracts';

const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

/** Default HKDF context: preserves the historical behavior (MFA secret at-rest). */
const DEFAULT_CONTEXT = 'kengela:mfa';

/** Envelope encryption options. */
export interface AesGcmKeyManagementOptions {
  /**
   * HKDF CONTEXT label (`info`), prefixed to the `tenantId` during derivation:
   * `<context>:<tenantId>`. Serves cryptographic DOMAIN SEPARATION: two distinct
   * uses of the same master key (MFA secret vs PII field encryption) must derive
   * with DIFFERENT contexts so their keys are never interchangeable.
   * Default: `kengela:mfa` (backward-compatible with the existing data).
   */
  readonly context?: string;
}

/**
 * KeyManagementPort using AES-256-GCM envelope encryption. One key per tenant is
 * derived from the master key via HKDF-SHA256 (cross-tenant cryptographic isolation),
 * within a configurable CONTEXT (`info`) (domain separation per use).
 * Ciphertext format: iv(12) || tag(16) || ciphertext.
 */
export class AesGcmKeyManagement implements KeyManagementPort {
  readonly #masterKey: Uint8Array;
  readonly #context: string;

  public constructor(masterKey: Uint8Array, options: AesGcmKeyManagementOptions = {}) {
    if (masterKey.length < KEY_LEN) {
      throw new Error(`Master key too short (>= ${String(KEY_LEN)} bytes required).`);
    }
    this.#masterKey = masterKey;
    this.#context = options.context ?? DEFAULT_CONTEXT;
  }

  public encrypt(tenantId: TenantId, plaintext: Uint8Array): Promise<Uint8Array> {
    // Executor: any synchronous exception (Node crypto) cleanly rejects the promise.
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
        throw new Error('Invalid AES-GCM ciphertext (too short).');
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
    const info = `${this.#context}:${tenantId}`;
    return Buffer.from(hkdfSync('sha256', this.#masterKey, Buffer.alloc(0), info, KEY_LEN));
  }
}
