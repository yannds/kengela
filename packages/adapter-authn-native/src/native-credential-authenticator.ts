import { randomBytes } from 'node:crypto';
import type {
  AuthContext,
  AuthOutcome,
  CredentialAuthenticator,
  CredentialRecord,
  CredentialStore,
  PasswordHasher,
  Principal,
  TenantId,
} from '@kengela/contracts';

/**
 * In-house credential authentication, TIMING-SAFE (TransLog differentiator).
 *
 * A bcrypt compare is ALWAYS performed (even for an unknown email) against a valid
 * pre-computed decoy hash, so response time never reveals whether an account exists.
 * Cross-tenant, we do not short-circuit on the first match.
 */
export class NativeCredentialAuthenticator implements CredentialAuthenticator {
  readonly #store: CredentialStore;
  readonly #hasher: PasswordHasher;
  readonly #dummyHash: string;

  public constructor(store: CredentialStore, hasher: PasswordHasher, dummyHash: string) {
    this.#store = store;
    this.#hasher = hasher;
    this.#dummyHash = dummyHash;
  }

  /** Factory that pre-computes the decoy hash (a real random bcrypt hash). */
  public static async create(
    store: CredentialStore,
    hasher: PasswordHasher,
  ): Promise<NativeCredentialAuthenticator> {
    const dummyHash = await hasher.hash(randomBytes(24).toString('hex'));
    return new NativeCredentialAuthenticator(store, hasher, dummyHash);
  }

  public async authenticate(input: {
    readonly email: string;
    readonly password: string;
    readonly tenantId: TenantId;
    readonly ctx: AuthContext;
  }): Promise<AuthOutcome> {
    const record = await this.#store.findByEmail(input.email, input.tenantId);
    const hashToCheck = record?.passwordHash ?? this.#dummyHash;
    const valid = await this.#hasher.verify(input.password, hashToCheck);
    if (record?.passwordHash == null) {
      return { kind: 'invalid_credentials' };
    }
    if (!valid || !record.isActive) {
      return { kind: 'invalid_credentials' };
    }
    return this.#outcomeFor(record, input.ctx);
  }

  public async authenticateCrossTenant(input: {
    readonly email: string;
    readonly password: string;
    readonly ctx: AuthContext;
  }): Promise<AuthOutcome> {
    const records = await this.#store.findByEmailAcrossTenants(input.email);
    if (records.length === 0) {
      // A compare all the same (anti-enumeration).
      await this.#hasher.verify(input.password, this.#dummyHash);
      return { kind: 'invalid_credentials' };
    }
    const matches: CredentialRecord[] = [];
    for (const record of records) {
      const valid = await this.#hasher.verify(
        input.password,
        record.passwordHash ?? this.#dummyHash,
      );
      if (valid && record.passwordHash !== null && record.isActive) {
        matches.push(record);
      }
    }
    if (matches.length > 1) {
      return { kind: 'tenant_choice', candidates: matches.map((m) => m.tenantId) };
    }
    const only = matches[0];
    if (only === undefined) {
      return { kind: 'invalid_credentials' };
    }
    return this.#outcomeFor(only, input.ctx);
  }

  #outcomeFor(record: CredentialRecord, ctx: AuthContext): AuthOutcome {
    if (record.mfaEnabled) {
      return { kind: 'mfa_required', userId: record.userId, tenantId: record.tenantId };
    }
    const principal: Principal = {
      userId: record.userId,
      tenantId: record.tenantId,
      roles: record.roles,
      mfaLevel: 'none',
      authMethod: 'credential',
      ctx,
    };
    return { kind: 'authenticated', principal };
  }
}
