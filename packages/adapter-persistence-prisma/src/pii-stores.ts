/**
 * Stores PII Prisma : clé PAR SUJET (crypto-shredding) + journal d'accès (RGPD art. 30).
 *
 * `PrismaSubjectKeyStore` implémente `SubjectKeyStore` : une clé AES-256 par personne
 * concernée, base du crypto-shredding (détruire la ligne rend les PII du sujet illisibles,
 * RGPD art. 17). `PrismaPiiAccessLogSink` implémente `PiiAccessLogSink` : chaque lecture/export
 * de PII est tracé (qui, quel sujet, quels champs, quelle finalité).
 *
 * CHIFFREMENT AT-REST de la clé de sujet : si un `KeyManagementPort` (chiffrement enveloppe
 * par tenant) est injecté, la clé est WRAPPÉE avant persistance et la colonne ne contient
 * jamais de matériel clair - une fuite de la base seule ne révèle rien sans la clé maître.
 * Sans KMS injecté, la clé est stockée en base64 EN CLAIR : mode dégradé, à réserver au
 * développement (documenté ; le crypto-shredding reste effectif dans les deux cas puisqu'il
 * repose sur la SUPPRESSION de la ligne, pas sur le chiffrement).
 */
import { randomBytes } from 'node:crypto';
import type {
  KeyManagementPort,
  PiiAccessLogSink,
  SubjectKeyStore,
  TenantId,
  UserId,
} from '@kengela/contracts';
import type { PiiAccessLogDelegate, SubjectKeyDelegate } from './prisma-like.js';

const SUBJECT_KEY_BYTES = 32;

export interface PrismaSubjectKeyStoreOptions {
  /** Chiffrement enveloppe de la clé at-rest (recommandé). Absent = stockage base64 en clair. */
  readonly keyManagement?: KeyManagementPort;
  /** Taille de la clé générée, en octets. Défaut : 32 (AES-256). */
  readonly keyBytes?: number;
}

export class PrismaSubjectKeyStore implements SubjectKeyStore {
  readonly #keys: SubjectKeyDelegate;
  readonly #kms: KeyManagementPort | undefined;
  readonly #keyBytes: number;

  public constructor(keys: SubjectKeyDelegate, options: PrismaSubjectKeyStoreOptions = {}) {
    this.#keys = keys;
    this.#kms = options.keyManagement;
    this.#keyBytes = options.keyBytes ?? SUBJECT_KEY_BYTES;
  }

  public async getOrCreateKey(tenantId: TenantId, subjectId: string): Promise<Uint8Array> {
    const existing = await this.#keys.findFirst({ where: { tenantId, subjectId } });
    if (existing !== null) {
      return this.#unwrap(tenantId, existing.key);
    }
    const raw = new Uint8Array(randomBytes(this.#keyBytes));
    const stored = await this.#wrap(tenantId, raw);
    await this.#keys.create({ data: { tenantId, subjectId, key: stored } });
    return raw;
  }

  public async getKey(tenantId: TenantId, subjectId: string): Promise<Uint8Array | null> {
    const row = await this.#keys.findFirst({ where: { tenantId, subjectId } });
    if (row === null) {
      return null;
    }
    return this.#unwrap(tenantId, row.key);
  }

  /** Crypto-shredding : détruire la clé rend toutes les PII du sujet illisibles (RGPD art. 17). */
  public async deleteKey(tenantId: TenantId, subjectId: string): Promise<void> {
    await this.#keys.deleteMany({ where: { tenantId, subjectId } });
  }

  async #wrap(tenantId: TenantId, raw: Uint8Array): Promise<string> {
    const bytes = this.#kms === undefined ? raw : await this.#kms.encrypt(tenantId, raw);
    return Buffer.from(bytes).toString('base64');
  }

  async #unwrap(tenantId: TenantId, stored: string): Promise<Uint8Array> {
    const bytes = new Uint8Array(Buffer.from(stored, 'base64'));
    return this.#kms === undefined ? bytes : this.#kms.decrypt(tenantId, bytes);
  }
}

/** Journal d'accès aux PII : insère une ligne d'audit par accès (RGPD art. 30). */
export class PrismaPiiAccessLogSink implements PiiAccessLogSink {
  readonly #log: PiiAccessLogDelegate;

  public constructor(log: PiiAccessLogDelegate) {
    this.#log = log;
  }

  public async record(entry: {
    readonly tenantId: TenantId;
    readonly subjectId: string;
    readonly actorId?: UserId;
    readonly fields: readonly string[];
    readonly purpose: string;
    readonly at: number;
  }): Promise<void> {
    await this.#log.create({
      data: {
        tenantId: entry.tenantId,
        subjectId: entry.subjectId,
        actorId: entry.actorId ?? null,
        fields: [...entry.fields],
        purpose: entry.purpose,
        at: new Date(entry.at),
      },
    });
  }
}
