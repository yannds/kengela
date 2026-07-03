import type { IdentityPort, Principal, SessionCredential } from '@kengela/contracts';
import type { BetterAuthLike, BetterAuthSession, BetterAuthUser } from './better-auth-like.js';

export interface BetterAuthIdentityConfig {
  readonly auth: BetterAuthLike;
  /** Extrait le tenant depuis l'utilisateur better-auth (défaut : champ `tenantId`). */
  readonly extractTenantId?: (user: BetterAuthUser) => string | null;
  /** Extrait les rôles (défaut : aucun ; l'authz recharge les grants). */
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
 * IdentityPort au-dessus de better-auth : vérifie une preuve de session (cookie ou
 * bearer) via `auth.api.getSession` et projette l'utilisateur en `Principal`.
 * Fail-closed : sans tenant résoluble, la session est refusée. Le `ctx` (géo/device)
 * n'est pas fourni par better-auth — l'app l'enrichit via un ContextProvider.
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
