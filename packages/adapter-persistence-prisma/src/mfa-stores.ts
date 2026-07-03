import { randomBytes } from 'node:crypto';
import type {
  Clock,
  MfaChallengeStore,
  MfaSecretStore,
  TenantId,
  UserId,
} from '@kengela/contracts';
import type { MfaChallengeDelegate, MfaSecretDelegate } from './prisma-like.js';

const SYSTEM_CLOCK: Clock = { now: () => Date.now() };

/**
 * MfaSecretStore Prisma : persiste le secret TOTP DÉJÀ chiffré (la MfaService le
 * chiffre via KeyManagement avant de le passer). Idempotent par (tenant, user).
 */
export class PrismaMfaSecretStore implements MfaSecretStore {
  readonly #secrets: MfaSecretDelegate;

  public constructor(secrets: MfaSecretDelegate) {
    this.#secrets = secrets;
  }

  public async save(tenantId: TenantId, userId: UserId, encryptedSecret: string): Promise<void> {
    await this.#secrets.deleteMany({ where: { tenantId, userId } });
    await this.#secrets.create({ data: { tenantId, userId, secret: encryptedSecret } });
  }

  public async get(tenantId: TenantId, userId: UserId): Promise<string | null> {
    const row = await this.#secrets.findFirst({ where: { tenantId, userId } });
    return row?.secret ?? null;
  }
}

export interface PrismaMfaChallengeStoreOptions {
  readonly clock?: Clock;
}

/**
 * MfaChallengeStore Prisma : défi opaque expirant, consommé une seule fois
 * (one-shot). `consume` supprime toujours le défi (même expiré) puis vérifie
 * l'expiration — anti-rejeu.
 */
export class PrismaMfaChallengeStore implements MfaChallengeStore {
  readonly #challenges: MfaChallengeDelegate;
  readonly #clock: Clock;

  public constructor(
    challenges: MfaChallengeDelegate,
    options: PrismaMfaChallengeStoreOptions = {},
  ) {
    this.#challenges = challenges;
    this.#clock = options.clock ?? SYSTEM_CLOCK;
  }

  public async issue(tenantId: TenantId, userId: UserId, ttlMs: number): Promise<string> {
    const id = randomBytes(32).toString('hex');
    await this.#challenges.create({
      data: { id, tenantId, userId, expiresAt: new Date(this.#clock.now() + ttlMs) },
    });
    return id;
  }

  public async consume(
    challengeId: string,
  ): Promise<{ readonly tenantId: TenantId; readonly userId: UserId } | null> {
    const row = await this.#challenges.findUnique({ where: { id: challengeId } });
    if (row === null) {
      return null;
    }
    await this.#challenges.delete({ where: { id: challengeId } });
    if (row.expiresAt.getTime() <= this.#clock.now()) {
      return null;
    }
    return { tenantId: row.tenantId, userId: row.userId };
  }
}
