/**
 * Fake `PrismaLike` en memoire (Map/array) pour des tests hermetiques, sans DB.
 * Reproduit les semantiques utilisees par les adapters : filtres where, delete
 * levant si absent, deleteMany idempotent, transaction interactive optionnelle.
 */
import type { TenantId, UserId } from '@kengela/contracts';
import type {
  GrantDelegate,
  GrantRow,
  PolicyDelegate,
  PolicyRow,
  PrismaLike,
  RoleDelegate,
  RoleRow,
  SessionDelegate,
  SessionRow,
} from '../src/prisma-like.js';

interface StoredGrant {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly row: GrantRow;
}

export class FakePrisma implements PrismaLike {
  readonly #grants: StoredGrant[] = [];
  readonly #roles: RoleRow[] = [];
  readonly #sessions = new Map<string, SessionRow>();
  readonly #policies: PolicyRow[] = [];

  public readonly $transaction: (<T>(fn: (tx: PrismaLike) => Promise<T>) => Promise<T>) | undefined;

  public constructor(options?: { readonly withTransaction?: boolean }) {
    this.$transaction =
      options?.withTransaction === true
        ? <T>(fn: (tx: PrismaLike) => Promise<T>): Promise<T> => fn(this)
        : undefined;
  }

  public seedGrant(userId: UserId, tenantId: TenantId, row: GrantRow): void {
    this.#grants.push({ userId, tenantId, row });
  }

  public seedRole(row: RoleRow): void {
    this.#roles.push(row);
  }

  public seedPolicy(row: PolicyRow): void {
    this.#policies.push(row);
  }

  public sessionCount(): number {
    return this.#sessions.size;
  }

  public readonly grant: GrantDelegate = {
    findMany: (args) =>
      Promise.resolve(
        this.#grants
          .filter((g) => g.userId === args.where.userId && g.tenantId === args.where.tenantId)
          .map((g) => g.row),
      ),
  };

  public readonly role: RoleDelegate = {
    findFirst: (args) =>
      Promise.resolve(
        this.#roles.find((r) => r.key === args.where.key && r.tenantId === args.where.tenantId) ??
          null,
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
        return Promise.reject(new Error('FakePrisma.session.delete: record not found'));
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

  public readonly policy: PolicyDelegate = {
    findMany: (args) =>
      Promise.resolve(this.#policies.filter((p) => p.tenantId === args.where.tenantId)),
  };
}
