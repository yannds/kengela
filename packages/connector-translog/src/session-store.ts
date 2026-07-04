/**
 * TranslogSessionStore - implemente SessionStore sur TranslogPrismaLike.
 *
 * Token opaque = 32 octets aleatoires (node:crypto) en hex. L'horloge est
 * injectable (Clock) pour des tests deterministes ; defaut = Date.now. Seuls
 * `ipAddress` (<- ctx.ip) et `userAgent` (<- ctx.device.userAgent) sont persistes :
 * le reste du `AuthContext` n'a pas de colonne cote TransLog (voir DEBT.md). La
 * rotation est atomique si le client fournit `$transaction`, sinon degrade en
 * delete + create sequentiels.
 */
import { randomBytes } from 'node:crypto';
import type {
  AuthContext,
  Clock,
  SessionHandle,
  SessionStore,
  TenantId,
  UserId,
} from '@kengela/contracts';
import type { SessionCreateData, SessionRow, TranslogPrismaLike } from './translog-prisma-like.js';
import { toSessionHandle } from './mapping.js';

const SYSTEM_CLOCK: Clock = { now: () => Date.now() };
const TOKEN_BYTES = 32;

export interface TranslogSessionStoreOptions {
  readonly clock?: Clock;
}

function newToken(): string {
  return randomBytes(TOKEN_BYTES).toString('hex');
}

export class TranslogSessionStore implements SessionStore {
  readonly #prisma: TranslogPrismaLike;
  readonly #clock: Clock;

  public constructor(prisma: TranslogPrismaLike, options?: TranslogSessionStoreOptions) {
    this.#prisma = prisma;
    this.#clock = options?.clock ?? SYSTEM_CLOCK;
  }

  public async create(input: {
    readonly userId: UserId;
    readonly tenantId: TenantId;
    readonly ctx: AuthContext;
    readonly ttlMs: number;
  }): Promise<SessionHandle> {
    const now = this.#clock.now();
    const data: SessionCreateData = {
      token: newToken(),
      userId: input.userId,
      tenantId: input.tenantId,
      createdAt: new Date(now),
      expiresAt: new Date(now + input.ttlMs),
      ipAddress: input.ctx.ip ?? null,
      userAgent: input.ctx.device?.userAgent ?? null,
    };
    const row = await this.#prisma.session.create({ data });
    return toSessionHandle(row);
  }

  public async get(token: string): Promise<SessionHandle | null> {
    const row = await this.#prisma.session.findUnique({ where: { token } });
    if (row === null) {
      return null;
    }
    // Fail-closed (durci) : une session expiree n'est JAMAIS restituee comme valide,
    // meme si le balayage differe (cleanup) ne l'a pas encore purgee.
    if (row.expiresAt.getTime() <= this.#clock.now()) {
      return null;
    }
    return toSessionHandle(row);
  }

  public async rotate(token: string): Promise<SessionHandle> {
    const current = await this.#prisma.session.findUnique({ where: { token } });
    if (current === null) {
      throw new Error('TranslogSessionStore.rotate: session introuvable');
    }
    const data: SessionCreateData = {
      token: newToken(),
      userId: current.userId,
      tenantId: current.tenantId,
      createdAt: new Date(this.#clock.now()),
      expiresAt: current.expiresAt,
      ipAddress: current.ipAddress,
      userAgent: current.userAgent,
    };
    const created = await this.#rotateAtomic(token, data);
    return toSessionHandle(created);
  }

  public async revoke(token: string): Promise<void> {
    await this.#prisma.session.deleteMany({ where: { token } });
  }

  public async listForUser(userId: UserId): Promise<readonly SessionHandle[]> {
    const rows = await this.#prisma.session.findMany({ where: { userId } });
    return rows.map((row) => toSessionHandle(row));
  }

  public async revokeAllForUser(userId: UserId): Promise<void> {
    await this.#prisma.session.deleteMany({ where: { userId } });
  }

  async #rotateAtomic(oldToken: string, data: SessionCreateData): Promise<SessionRow> {
    if (this.#prisma.$transaction !== undefined) {
      return this.#prisma.$transaction(async (tx) => {
        await tx.session.delete({ where: { token: oldToken } });
        return tx.session.create({ data });
      });
    }
    await this.#prisma.session.delete({ where: { token: oldToken } });
    return this.#prisma.session.create({ data });
  }
}
