/**
 * TranslogAuthorizationRepository — implemente AuthorizationRepository sur
 * TranslogPrismaLike.
 *
 * TransLog est MONO-ROLE : `User.roleId` designe l'unique role, dont les droits
 * vivent dans `RolePermission`. Chaque `permission` est une chaine
 * `plane.module.action.SCOPE` : le dernier segment est le jeton de portee (voir
 * mapping.ts). Le filtrage des grants expires n'a pas lieu ici (TransLog n'a pas
 * d'expiration sur ces droits statiques).
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
