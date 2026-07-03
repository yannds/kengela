import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import type { KeyManagementPort, TenantId } from '@kengela/contracts';

const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

/** Contexte HKDF par défaut : conserve le comportement historique (secret MFA at-rest). */
const DEFAULT_CONTEXT = 'kengela:mfa';

/** Options du chiffrement enveloppe. */
export interface AesGcmKeyManagementOptions {
  /**
   * Étiquette de CONTEXTE HKDF (`info`), préfixée au `tenantId` lors de la dérivation :
   * `<context>:<tenantId>`. Sert la SÉPARATION DE DOMAINE cryptographique : deux usages
   * distincts d'une même clé maître (secret MFA vs chiffrement de champ PII) doivent dériver
   * avec des contextes DIFFÉRENTS pour que leurs clés ne soient jamais interchangeables.
   * Défaut : `kengela:mfa` (rétro-compatible avec l'existant).
   */
  readonly context?: string;
}

/**
 * KeyManagementPort en chiffrement enveloppe AES-256-GCM. Une clé par tenant est
 * dérivée de la clé maître via HKDF-SHA256 (isolation cryptographique inter-tenant),
 * dans un CONTEXTE (`info`) configurable (séparation de domaine par usage).
 * Format du chiffré : iv(12) || tag(16) || ciphertext.
 */
export class AesGcmKeyManagement implements KeyManagementPort {
  readonly #masterKey: Uint8Array;
  readonly #context: string;

  public constructor(masterKey: Uint8Array, options: AesGcmKeyManagementOptions = {}) {
    if (masterKey.length < KEY_LEN) {
      throw new Error(`Clé maître trop courte (>= ${String(KEY_LEN)} octets requis).`);
    }
    this.#masterKey = masterKey;
    this.#context = options.context ?? DEFAULT_CONTEXT;
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
    const info = `${this.#context}:${tenantId}`;
    return Buffer.from(hkdfSync('sha256', this.#masterKey, Buffer.alloc(0), info, KEY_LEN));
  }
}
