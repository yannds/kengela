/**
 * PrismaAuthorizationRepository - implements AuthorizationRepository on PrismaLike.
 *
 * Loads a user's grants and roles from Postgres. Filtering of expired grants is
 * done by the engine layer (activeGrants); here we expose `expiresAt` as-is.
 * Union narrowing is fail-closed.
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
