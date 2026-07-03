import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { SubjectKeyStore, TenantId } from '@kengela/contracts';

const IV_LEN = 12;
const TAG_LEN = 16;

/**
 * Chiffrement de champ PII avec une clé PAR SUJET (crypto-shredding). Chaque
 * personne concernée a sa clé (via SubjectKeyStore) ; détruire la clé
 * (SubjectCryptoShredder) rend ses PII définitivement illisibles (RGPD art. 17).
 * Format base64 : iv(12) || tag(16) || ciphertext.
 */
export class SubjectFieldCipher {
  readonly #keys: SubjectKeyStore;

  public constructor(keys: SubjectKeyStore) {
    this.#keys = keys;
  }

  public async encryptFor(
    tenantId: TenantId,
    subjectId: string,
    plaintext: string,
  ): Promise<string> {
    const key = await this.#keys.getOrCreateKey(tenantId, subjectId);
    return new Promise<string>((resolve) => {
      const iv = randomBytes(IV_LEN);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      resolve(Buffer.concat([iv, tag, body]).toString('base64'));
    });
  }

  /** Retourne null si la clé du sujet a été détruite (donnée « shreddée »). */
  public async decryptFor(
    tenantId: TenantId,
    subjectId: string,
    ciphertext: string,
  ): Promise<string | null> {
    const key = await this.#keys.getKey(tenantId, subjectId);
    if (key === null) {
      return null;
    }
    return new Promise<string>((resolve) => {
      const buffer = Buffer.from(ciphertext, 'base64');
      const iv = buffer.subarray(0, IV_LEN);
      const tag = buffer.subarray(IV_LEN, IV_LEN + TAG_LEN);
      const body = buffer.subarray(IV_LEN + TAG_LEN);
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      resolve(Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8'));
    });
  }
}
