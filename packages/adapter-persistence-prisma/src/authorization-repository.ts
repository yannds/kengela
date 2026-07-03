/**
 * PrismaAuthorizationRepository — implemente AuthorizationRepository sur PrismaLike.
 *
 * Charge les grants d'un utilisateur et les roles depuis Postgres. Le filtrage
 * des grants expires est fait par la couche engine (activeGrants) ; ici on
 * expose `expiresAt` tel quel. Le narrowing des unions est fail-closed.
 */
import type { AuthorizationRepository, Grant, Role, TenantId, UserId } from '@kengela/contracts';
import type { PrismaLike } from './prisma-like.js';
import type { AdapterLogger } from './mapping.js';
import { toGrant, toRole } from './mapping.js';

export interface PrismaRepositoryOptions {
  readonly logger?: AdapterLogger;
}

export class PrismaAuthorizationRepository implements AuthorizationRepository {
  readonly #prisma: PrismaLike;
  readonly #logger: AdapterLogger | undefined;

  public constructor(prisma: PrismaLike, options?: PrismaRepositoryOptions) {
    this.#prisma = prisma;
    this.#logger = options?.logger;
  }

  public async loadGrantsForUser(userId: UserId, tenantId: TenantId): Promise<readonly Grant[]> {
    const rows = await this.#prisma.grant.findMany({ where: { userId, tenantId } });
    const grants: Grant[] = [];
    for (const row of rows) {
      const grant = toGrant(row, this.#logger);
      if (grant !== null) {
        grants.push(grant);
      }
    }
    return grants;
  }

  public async loadRole(roleKey: string, tenantId: TenantId): Promise<Role | null> {
    const row = await this.#prisma.role.findFirst({
      where: { key: roleKey, tenantId },
      include: { grants: true },
    });
    return row === null ? null : toRole(row, this.#logger);
  }
}
