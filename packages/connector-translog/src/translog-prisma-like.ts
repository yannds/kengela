/**
 * TranslogPrismaLike - la surface NARROW dont ce connecteur depend.
 *
 * DOCTRINE : le port est un sas, pas une planque. On n'importe RIEN de
 * `@prisma/client`. On decrit exactement les delegues et methodes utilises,
 * avec des types de lignes explicites tires du schema REEL de TransLog Pro.
 * Un vrai `PrismaClient` genere depuis le schema TransLog est structurellement
 * compatible cote application : il se passe la ou `TranslogPrismaLike` est
 * attendu (les lignes reelles sont des sur-ensembles de nos lignes NARROW).
 *
 * Schema de reference (extrait) :
 *  - User            { id, tenantId, agencyId?, email, roleId?, userType, isActive,
 *                      mfaEnabled, mfaSecret?, deletedAt? }
 *  - Account         { id, tenantId, userId, providerId, accountId, password?, ... }
 *  - Session         { id, userId, tenantId, token @unique, expiresAt, ipAddress?,
 *                      userAgent?, createdAt }
 *  - RolePermission  { id, roleId, permission }
 */
import type { TenantId, UserId } from '@kengela/contracts';

/** Ligne `User` - sous-ensemble NARROW des colonnes lues par le connecteur. */
export interface UserRow {
  readonly id: UserId;
  readonly tenantId: TenantId;
  readonly roleId: string | null;
  readonly isActive: boolean;
  readonly mfaEnabled: boolean;
  readonly deletedAt: Date | null;
}

/** Ligne `Account` - sous-ensemble NARROW (le hash `password` est optionnel). */
export interface AccountRow {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly password: string | null;
}

/** Ligne `RolePermission` - la permission brute `plane.module.action.SCOPE`. */
export interface RolePermissionRow {
  readonly permission: string;
}

/**
 * Ligne `Session`. Le contexte de connexion n'est PAS stocke en JSON cote
 * TransLog : seuls `ipAddress` et `userAgent` existent (voir DEBT.md). La
 * reconstitution du `AuthContext` est donc LOSSY.
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

/** Payload d'ecriture d'une session (meme forme que la ligne, sans l'`id` auto). */
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
 * Le client injecte. `$transaction` est OPTIONNEL : la rotation de session
 * l'utilise si le client le fournit, sinon degrade en delete + create
 * sequentiels (voir DEBT.md).
 */
export interface TranslogPrismaLike {
  readonly user: UserDelegate;
  readonly account: AccountDelegate;
  readonly rolePermission: RolePermissionDelegate;
  readonly session: SessionDelegate;
  readonly $transaction?:
    (<T>(fn: (tx: TranslogPrismaLike) => Promise<T>) => Promise<T>) | undefined;
}
