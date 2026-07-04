import type { ErasurePort, SubjectKeyStore, TenantId } from '@kengela/contracts';

/**
 * GDPR erasure (art. 17) via crypto-shredding: destroys the subject's key.
 * All PII encrypted with SubjectFieldCipher then becomes unreadable,
 * without having to rewrite every table.
 */
export class SubjectCryptoShredder implements ErasurePort {
  readonly #keys: SubjectKeyStore;

  public constructor(keys: SubjectKeyStore) {
    this.#keys = keys;
  }

  public eraseSubject(tenantId: TenantId, subjectId: string): Promise<void> {
    return this.#keys.deleteKey(tenantId, subjectId);
  }
}
