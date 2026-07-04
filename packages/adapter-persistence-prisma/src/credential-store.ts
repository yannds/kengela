/**
 * PrismaCredentialStore - implements `CredentialStore` on a NARROW surface
 * `CredentialPrismaLike` (Account + User), a generic analogue of
 * `TranslogCredentialStore` (connector-translog).
 *
 * A password identity lives in `Account` (providerId='credential',
 * accountId=email), the hash in `Account.password`, the account state in `User`.
 * Resolution joins the two:
 *  - findByEmail(email, tenantId)    : the tenant's credential account + its User.
 *  - findByEmailAcrossTenants(email) : all credential accounts (all tenants),
 *                                      Users loaded IN BATCH (anti N+1).
 *
 * An orphan credential account (User not found) is discarded FAIL-CLOSED.
 */
import type { CredentialRecord, CredentialStore, TenantId } from '@kengela/contracts';
import type { AccountRow, CredentialPrismaLike, CredentialUserRow } from './prisma-like.js';

const CREDENTIAL_PROVIDER = 'credential';

/** Store options: name of the credential provider (default `credential`). */
export interface PrismaCredentialStoreOptions {
  readonly providerId?: string;
}

function toRecord(account: AccountRow, user: CredentialUserRow): CredentialRecord {
  return {
    userId: user.id,
    tenantId: account.tenantId,
    passwordHash: account.password ?? null,
    isActive: user.isActive && user.deletedAt === null,
    mfaEnabled: user.mfaEnabled,
    roles: [...user.roles],
  };
}

export class PrismaCredentialStore implements CredentialStore {
  readonly #prisma: CredentialPrismaLike;
  readonly #providerId: string;

  public constructor(prisma: CredentialPrismaLike, options: PrismaCredentialStoreOptions = {}) {
    this.#prisma = prisma;
    this.#providerId = options.providerId ?? CREDENTIAL_PROVIDER;
  }

  public async findByEmail(email: string, tenantId: TenantId): Promise<CredentialRecord | null> {
    const account = await this.#prisma.account.findFirst({
      where: { tenantId, providerId: this.#providerId, accountId: email },
    });
    if (account === null) {
      return null;
    }
    const user = await this.#prisma.user.findFirst({
      where: { id: account.userId, tenantId },
    });
    if (user === null) {
      return null;
    }
    return toRecord(account, user);
  }

  public async findByEmailAcrossTenants(email: string): Promise<readonly CredentialRecord[]> {
    const accounts = await this.#prisma.account.findMany({
      where: { providerId: this.#providerId, accountId: email },
    });
    if (accounts.length === 0) {
      return [];
    }
    const userIds = [...new Set(accounts.map((account) => account.userId))];
    const users = await this.#prisma.user.findMany({ where: { id: { in: userIds } } });
    const usersById = new Map<string, CredentialUserRow>(users.map((user) => [user.id, user]));
    const records: CredentialRecord[] = [];
    for (const account of accounts) {
      const user = usersById.get(account.userId);
      if (user === undefined) {
        continue;
      }
      records.push(toRecord(account, user));
    }
    return records;
  }
}
