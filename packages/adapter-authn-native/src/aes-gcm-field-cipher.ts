import type { FieldCipherPort, KeyManagementPort, TenantId } from '@kengela/contracts';

/**
 * FieldCipherPort au-dessus d'un KeyManagementPort (AES-256-GCM par tenant).
 * Chiffre une chaîne PII en base64 stockable. [compliance-by-design]
 */
export class AesGcmFieldCipher implements FieldCipherPort {
  readonly #keys: KeyManagementPort;

  public constructor(keys: KeyManagementPort) {
    this.#keys = keys;
  }

  public async encryptField(tenantId: TenantId, plaintext: string): Promise<string> {
    const cipher = await this.#keys.encrypt(tenantId, new TextEncoder().encode(plaintext));
    return Buffer.from(cipher).toString('base64');
  }

  public async decryptField(tenantId: TenantId, ciphertext: string): Promise<string> {
    const plain = await this.#keys.decrypt(
      tenantId,
      new Uint8Array(Buffer.from(ciphertext, 'base64')),
    );
    return new TextDecoder().decode(plain);
  }
}
