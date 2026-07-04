/**
 * Prisma PII stores: PER-SUBJECT key (crypto-shredding) + access log (GDPR art. 30).
 *
 * `PrismaSubjectKeyStore` implements `SubjectKeyStore`: one AES-256 key per data
 * subject, the basis of crypto-shredding (destroying the row makes the subject's PII
 * unreadable, GDPR art. 17). `PrismaPiiAccessLogSink` implements `PiiAccessLogSink`: every
 * PII read/export is traced (who, which subject, which fields, which purpose).
 *
 * AT-REST ENCRYPTION of the subject key: if a `KeyManagementPort` (per-tenant envelope
 * encryption) is injected, the key is WRAPPED before persistence and the column never
 * holds cleartext material. A leak of the database alone reveals nothing without the master
 * key. Without an injected KMS, the key is stored in CLEARTEXT base64: a degraded mode,
 * reserved for development (documented; crypto-shredding stays effective in both cases since
 * it relies on DELETING the row, not on encryption).
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
  /** Envelope encryption of the key at-rest (recommended). Absent = cleartext base64 storage. */
  readonly keyManagement?: KeyManagementPort;
  /** Size of the generated key, in bytes. Default: 32 (AES-256). */
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

  /** Crypto-shredding: destroying the key makes all of the subject's PII unreadable (GDPR art. 17). */
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

/** PII access log: inserts one audit row per access (GDPR art. 30). */
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
