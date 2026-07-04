/**
 * TranslogCredentialStore - implements CredentialStore on TranslogPrismaLike.
 *
 * A password identity lives in `Account` (providerId='credential', accountId=email),
 * the bcrypt hash in `Account.password`, the account state in `User`. Resolution joins
 * the two:
 *  - findByEmail(email, tenantId)         : the tenant's credential account + its User.
 *  - findByEmailAcrossTenants(email)      : all credential accounts (all tenants),
 *                                           loaded in a batch to avoid the N+1.
 *
 * An orphan credential account (User not found) is discarded fail-closed.
 */
import type { CredentialRecord, CredentialStore, TenantId } from '@kengela/contracts';
import type { AccountRow, TranslogPrismaLike, UserRow } from './translog-prisma-like.js';

const CREDENTIAL_PROVIDER = 'credential';

function toRecord(account: AccountRow, user: UserRow): CredentialRecord {
  return {
    userId: user.id,
    tenantId: account.tenantId,
    passwordHash: account.password ?? null,
    isActive: user.isActive && user.deletedAt === null,
    mfaEnabled: user.mfaEnabled,
    roles: user.roleId !== null ? [user.roleId] : [],
  };
}

export class TranslogCredentialStore implements CredentialStore {
  readonly #prisma: TranslogPrismaLike;

  public constructor(prisma: TranslogPrismaLike) {
    this.#prisma = prisma;
  }

  public async findByEmail(email: string, tenantId: TenantId): Promise<CredentialRecord | null> {
    const account = await this.#prisma.account.findFirst({
      where: { tenantId, providerId: CREDENTIAL_PROVIDER, accountId: email },
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
      where: { providerId: CREDENTIAL_PROVIDER, accountId: email },
    });
    if (accounts.length === 0) {
      return [];
    }
    const userIds = [...new Set(accounts.map((account) => account.userId))];
    const users = await this.#prisma.user.findMany({ where: { id: { in: userIds } } });
    const usersById = new Map<string, UserRow>(users.map((user) => [user.id, user]));
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
