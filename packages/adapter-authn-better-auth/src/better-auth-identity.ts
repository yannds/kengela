import type { IdentityPort, Principal, SessionCredential } from '@kengela/contracts';
import type { BetterAuthLike, BetterAuthSession, BetterAuthUser } from './better-auth-like.js';

export interface BetterAuthIdentityConfig {
  readonly auth: BetterAuthLike;
  /** Extracts the tenant from the better-auth user (default: `tenantId` field). */
  readonly extractTenantId?: (user: BetterAuthUser) => string | null;
  /** Extracts the roles (default: none; authz reloads the grants). */
  readonly extractRoles?: (user: BetterAuthUser) => readonly string[];
}

function defaultTenantId(user: BetterAuthUser): string | null {
  const value = user['tenantId'];
  return typeof value === 'string' ? value : null;
}

function sessionAuthTime(session: BetterAuthSession): number {
  const created = session['createdAt'];
  if (created instanceof Date) {
    return created.getTime();
  }
  return typeof created === 'number' ? created : 0;
}

/**
 * IdentityPort on top of better-auth: verifies a session proof (cookie or bearer) via
 * `auth.api.getSession` and projects the user into a `Principal`.
 * Fail-closed: without a resolvable tenant, the session is refused. The `ctx` (geo/device)
 * is not provided by better-auth - the app enriches it via a ContextProvider.
 */
export class BetterAuthIdentity implements IdentityPort {
  readonly #auth: BetterAuthLike;
  readonly #extractTenantId: (user: BetterAuthUser) => string | null;
  readonly #extractRoles: (user: BetterAuthUser) => readonly string[];

  public constructor(config: BetterAuthIdentityConfig) {
    this.#auth = config.auth;
    this.#extractTenantId = config.extractTenantId ?? defaultTenantId;
    this.#extractRoles = config.extractRoles ?? (() => []);
  }

  public async verifySession(credential: SessionCredential): Promise<Principal | null> {
    const headers = new Headers();
    if (credential.strategy === 'bearer') {
      headers.set('authorization', `Bearer ${credential.token}`);
    } else {
      headers.set('cookie', credential.token);
    }

    const result = await this.#auth.api.getSession({ headers });
    if (result === null) {
      return null;
    }

    const tenantId = this.#extractTenantId(result.user);
    if (tenantId === null) {
      return null;
    }

    return {
      userId: result.user.id,
      tenantId,
      roles: this.#extractRoles(result.user),
      mfaLevel: 'none',
      authMethod: 'oidc',
      ctx: { authTime: sessionAuthTime(result.session) },
    };
  }
}
