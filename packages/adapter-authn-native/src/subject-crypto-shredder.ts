import type { ErasurePort, SubjectKeyStore, TenantId } from '@kengela/contracts';

/**
 * Effacement RGPD (art. 17) par crypto-shredding : détruit la clé du sujet.
 * Toutes les PII chiffrées avec SubjectFieldCipher deviennent alors illisibles,
 * sans avoir à réécrire chaque table.
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
