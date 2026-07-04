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
 * Prisma MfaSecretStore: persists the ALREADY encrypted TOTP secret (MfaService
 * encrypts it via KeyManagement before passing it). Idempotent per (tenant, user).
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
 * Prisma MfaChallengeStore: opaque expiring challenge, consumed only once
 * (one-shot). `consume` always deletes the challenge (even if expired) then checks
 * expiration - anti-replay.
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
