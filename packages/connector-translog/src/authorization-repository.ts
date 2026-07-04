/**
 * TranslogAuthorizationRepository - implements AuthorizationRepository on
 * TranslogPrismaLike.
 *
 * TransLog is SINGLE-ROLE: `User.roleId` designates the single role, whose rights
 * live in `RolePermission`. Each `permission` is a string
 * `plane.module.action.SCOPE`: the last segment is the scope token (see
 * mapping.ts). Filtering of expired grants does not happen here (TransLog has no
 * expiration on these static rights).
 */
import type { AuthorizationRepository, Grant, Role, TenantId, UserId } from '@kengela/contracts';
import type { TranslogPrismaLike } from './translog-prisma-like.js';
import type { AdapterLogger } from './mapping.js';
import { permissionsToGrants } from './mapping.js';

export interface TranslogRepositoryOptions {
  readonly logger?: AdapterLogger;
}

export class TranslogAuthorizationRepository implements AuthorizationRepository {
  readonly #prisma: TranslogPrismaLike;
  readonly #logger: AdapterLogger | undefined;

  public constructor(prisma: TranslogPrismaLike, options?: TranslogRepositoryOptions) {
    this.#prisma = prisma;
    this.#logger = options?.logger;
  }

  public async loadGrantsForUser(userId: UserId, tenantId: TenantId): Promise<readonly Grant[]> {
    const user = await this.#prisma.user.findFirst({ where: { id: userId, tenantId } });
    if (user === null) {
      return [];
    }
    if (user.roleId === null) {
      return [];
    }
    const rows = await this.#prisma.rolePermission.findMany({ where: { roleId: user.roleId } });
    return permissionsToGrants(rows, this.#logger);
  }

  public async loadRole(roleKey: string, tenantId: TenantId): Promise<Role | null> {
    const rows = await this.#prisma.rolePermission.findMany({ where: { roleId: roleKey } });
    if (rows.length === 0) {
      return null;
    }
    const grants = permissionsToGrants(rows, this.#logger);
    return { key: roleKey, tenantId, grants };
  }
}
