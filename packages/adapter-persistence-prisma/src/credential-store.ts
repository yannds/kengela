/**
 * PrismaCredentialStore — implemente `CredentialStore` sur une surface NARROW
 * `CredentialPrismaLike` (Account + User), calque generique de
 * `TranslogCredentialStore` (connector-translog).
 *
 * Une identite par mot de passe vit dans `Account` (providerId='credential',
 * accountId=email), le hash dans `Account.password`, l'etat du compte dans `User`.
 * La resolution joint les deux :
 *  - findByEmail(email, tenantId)    : compte credential du tenant + son User.
 *  - findByEmailAcrossTenants(email) : tous les comptes credential (tous tenants),
 *                                      Users charges EN LOT (anti N+1).
 *
 * Un compte credential orphelin (User introuvable) est ecarte FAIL-CLOSED.
 */
import type { CredentialRecord, CredentialStore, TenantId } from '@kengela/contracts';
import type { AccountRow, CredentialPrismaLike, CredentialUserRow } from './prisma-like.js';

const CREDENTIAL_PROVIDER = 'credential';

/** Options du store : nom du provider d'identifiants (defaut `credential`). */
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
