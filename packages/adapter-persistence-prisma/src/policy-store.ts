/**
 * PrismaPolicyStore — implemente PolicyStore sur PrismaLike.
 *
 * Charge les policies d'un tenant avec leurs regles jointes. Le narrowing des
 * effets/scopes est fail-closed (voir mapping.ts) : une regle illisible est
 * ecartee plutot qu'elargie.
 */
import type { Policy, PolicyStore, TenantId } from '@kengela/contracts';
import type { PrismaLike } from './prisma-like.js';
import type { AdapterLogger } from './mapping.js';
import { toPolicy } from './mapping.js';

export interface PrismaPolicyStoreOptions {
  readonly logger?: AdapterLogger;
}

export class PrismaPolicyStore implements PolicyStore {
  readonly #prisma: PrismaLike;
  readonly #logger: AdapterLogger | undefined;

  public constructor(prisma: PrismaLike, options?: PrismaPolicyStoreOptions) {
    this.#prisma = prisma;
    this.#logger = options?.logger;
  }

  public async loadPolicies(tenantId: TenantId): Promise<readonly Policy[]> {
    const rows = await this.#prisma.policy.findMany({
      where: { tenantId },
      include: { rules: true },
    });
    return rows.map((row) => toPolicy(row, this.#logger));
  }
}
