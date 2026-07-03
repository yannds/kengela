/**
 * Fake `TranslogPrismaLike` en memoire (Map/array) pour des tests hermetiques,
 * sans DB. Reproduit les semantiques utilisees par le connecteur : filtres where,
 * `findFirst` premier match, `findMany` avec `id in`, delete levant si absent,
 * deleteMany idempotent, transaction interactive optionnelle.
 */
import type { UserId } from '@kengela/contracts';
import type {
  AccountDelegate,
  AccountRow,
  RolePermissionDelegate,
  RolePermissionRow,
  SessionDelegate,
  SessionRow,
  TranslogPrismaLike,
  UserDelegate,
  UserRow,
} from '../src/translog-prisma-like.js';

interface StoredAccount {
  readonly row: AccountRow;
  readonly providerId: string;
  readonly accountId: string;
}

interface StoredRolePermission {
  readonly roleId: string;
  readonly row: RolePermissionRow;
}

export class FakeTranslogPrisma implements TranslogPrismaLike {
  readonly #users: UserRow[] = [];
  readonly #accounts: StoredAccount[] = [];
  readonly #rolePermissions: StoredRolePermission[] = [];
  readonly #sessions = new Map<string, SessionRow>();

  public readonly $transaction:
    (<T>(fn: (tx: TranslogPrismaLike) => Promise<T>) => Promise<T>) | undefined;

  public constructor(options?: { readonly withTransaction?: boolean }) {
    this.$transaction =
      options?.withTransaction === true
        ? <T>(fn: (tx: TranslogPrismaLike) => Promise<T>): Promise<T> => fn(this)
        : undefined;
  }

  public seedUser(row: UserRow): void {
    this.#users.push(row);
  }

  public seedAccount(providerId: string, accountId: string, row: AccountRow): void {
    this.#accounts.push({ providerId, accountId, row });
  }

  public seedRolePermission(roleId: string, row: RolePermissionRow): void {
    this.#rolePermissions.push({ roleId, row });
  }

  public sessionCount(): number {
    return this.#sessions.size;
  }

  public readonly user: UserDelegate = {
    findFirst: (args) =>
      Promise.resolve(
        this.#users.find((u) => u.id === args.where.id && u.tenantId === args.where.tenantId) ??
          null,
      ),
    findMany: (args) => {
      const ids = new Set(args.where.id.in);
      return Promise.resolve(this.#users.filter((u) => ids.has(u.id)));
    },
  };

  public readonly account: AccountDelegate = {
    findFirst: (args) =>
      Promise.resolve(
        this.#accounts.find(
          (a) =>
            a.providerId === args.where.providerId &&
            a.accountId === args.where.accountId &&
            a.row.tenantId === args.where.tenantId,
        )?.row ?? null,
      ),
    findMany: (args) =>
      Promise.resolve(
        this.#accounts
          .filter(
            (a) => a.providerId === args.where.providerId && a.accountId === args.where.accountId,
          )
          .map((a) => a.row),
      ),
  };

  public readonly rolePermission: RolePermissionDelegate = {
    findMany: (args) =>
      Promise.resolve(
        this.#rolePermissions.filter((p) => p.roleId === args.where.roleId).map((p) => p.row),
      ),
  };

  public readonly session: SessionDelegate = {
    create: (args) => {
      const row: SessionRow = { ...args.data };
      this.#sessions.set(row.token, row);
      return Promise.resolve(row);
    },
    findUnique: (args) => Promise.resolve(this.#sessions.get(args.where.token) ?? null),
    delete: (args) => {
      const row = this.#sessions.get(args.where.token);
      if (row === undefined) {
        return Promise.reject(new Error('FakeTranslogPrisma.session.delete: record not found'));
      }
      this.#sessions.delete(args.where.token);
      return Promise.resolve(row);
    },
    deleteMany: (args) => {
      let count = 0;
      for (const [token, row] of this.#sessions) {
        const matchToken = args.where.token === undefined || row.token === args.where.token;
        const matchUser = args.where.userId === undefined || row.userId === args.where.userId;
        if (matchToken && matchUser) {
          this.#sessions.delete(token);
          count += 1;
        }
      }
      return Promise.resolve({ count });
    },
    findMany: (args) =>
      Promise.resolve([...this.#sessions.values()].filter((r) => r.userId === args.where.userId)),
  };
}

/** Fabrique une ligne User avec des defauts sains, surchargeable. */
export function userRow(over: Partial<UserRow> & { readonly id: UserId }): UserRow {
  return {
    tenantId: 't1',
    roleId: 'role-1',
    isActive: true,
    mfaEnabled: false,
    deletedAt: null,
    ...over,
  };
}
