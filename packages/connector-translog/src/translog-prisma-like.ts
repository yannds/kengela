/**
 * TranslogPrismaLike - the NARROW surface this connector depends on.
 *
 * DOCTRINE: the port is an airlock, not a hideout. We import NOTHING from
 * `@prisma/client`. We describe exactly the delegates and methods used, with
 * explicit row types drawn from the REAL TransLog Pro schema. A real
 * `PrismaClient` generated from the TransLog schema is structurally compatible
 * on the application side: it fits where `TranslogPrismaLike` is expected (the
 * real rows are supersets of our NARROW rows).
 *
 * Reference schema (excerpt):
 *  - User            { id, tenantId, agencyId?, email, roleId?, userType, isActive,
 *                      mfaEnabled, mfaSecret?, deletedAt? }
 *  - Account         { id, tenantId, userId, providerId, accountId, password?, ... }
 *  - Session         { id, userId, tenantId, token @unique, expiresAt, ipAddress?,
 *                      userAgent?, createdAt }
 *  - RolePermission  { id, roleId, permission }
 */
import type { TenantId, UserId } from '@kengela/contracts';

/** `User` row - NARROW subset of the columns read by the connector. */
export interface UserRow {
  readonly id: UserId;
  readonly tenantId: TenantId;
  readonly roleId: string | null;
  readonly isActive: boolean;
  readonly mfaEnabled: boolean;
  readonly deletedAt: Date | null;
}

/** `Account` row - NARROW subset (the `password` hash is optional). */
export interface AccountRow {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly password: string | null;
}

/** `RolePermission` row - the raw permission `plane.module.action.SCOPE`. */
export interface RolePermissionRow {
  readonly permission: string;
}

/**
 * `Session` row. The login context is NOT stored as JSON on the TransLog side:
 * only `ipAddress` and `userAgent` exist (see DEBT.md). The reconstitution of
 * the `AuthContext` is therefore LOSSY.
 */
export interface SessionRow {
  readonly token: string;
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly ipAddress: string | null;
  readonly userAgent: string | null;
}

/** Write payload of a session (same shape as the row, without the auto `id`). */
export interface SessionCreateData {
  readonly token: string;
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly ipAddress: string | null;
  readonly userAgent: string | null;
}

export interface UserDelegate {
  findFirst(args: {
    readonly where: { readonly id: UserId; readonly tenantId: TenantId };
  }): Promise<UserRow | null>;
  findMany(args: {
    readonly where: { readonly id: { readonly in: UserId[] } };
  }): Promise<readonly UserRow[]>;
}

export interface AccountDelegate {
  findFirst(args: {
    readonly where: {
      readonly tenantId: TenantId;
      readonly providerId: string;
      readonly accountId: string;
    };
  }): Promise<AccountRow | null>;
  findMany(args: {
    readonly where: { readonly providerId: string; readonly accountId: string };
  }): Promise<readonly AccountRow[]>;
}

export interface RolePermissionDelegate {
  findMany(args: {
    readonly where: { readonly roleId: string };
  }): Promise<readonly RolePermissionRow[]>;
}

export interface SessionDelegate {
  create(args: { readonly data: SessionCreateData }): Promise<SessionRow>;
  findUnique(args: { readonly where: { readonly token: string } }): Promise<SessionRow | null>;
  delete(args: { readonly where: { readonly token: string } }): Promise<SessionRow>;
  deleteMany(args: {
    readonly where: { readonly token?: string; readonly userId?: UserId };
  }): Promise<{ readonly count: number }>;
  findMany(args: { readonly where: { readonly userId: UserId } }): Promise<readonly SessionRow[]>;
}

/**
 * The injected client. `$transaction` is OPTIONAL: session rotation uses it if the
 * client provides it, otherwise it degrades to sequential delete + create (see DEBT.md).
 */
export interface TranslogPrismaLike {
  readonly user: UserDelegate;
  readonly account: AccountDelegate;
  readonly rolePermission: RolePermissionDelegate;
  readonly session: SessionDelegate;
  readonly $transaction?:
    (<T>(fn: (tx: TranslogPrismaLike) => Promise<T>) => Promise<T>) | undefined;
}
