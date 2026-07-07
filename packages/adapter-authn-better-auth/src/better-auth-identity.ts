import type { IdentityPort, Principal, SessionCredential } from '@kengela/contracts';
import type { BetterAuthLike, BetterAuthSession, BetterAuthUser } from './better-auth-like.js';

/**
 * Input of the final projection hook. Carries the verified better-auth `user`/`session` and the
 * `base` Principal produced by the default logic - `null` when the default tenant extraction failed
 * (lets the hook resolve the tenant itself, e.g. asynchronously by email).
 */
export interface ResolvePrincipalInput {
  readonly user: BetterAuthUser;
  readonly session: BetterAuthSession;
  readonly base: Principal | null;
}

export interface BetterAuthIdentityConfig {
  readonly auth: BetterAuthLike;
  /** Extracts the tenant from the better-auth user (default: `tenantId` field). */
  readonly extractTenantId?: (user: BetterAuthUser) => string | null;
  /** Extracts the roles (default: none; authz reloads the grants). */
  readonly extractRoles?: (user: BetterAuthUser) => readonly string[];
  /**
   * Final Principal projection (optional, may be async). Receives the verified `{user, session}`
   * and the default `base` Principal (or `null` if the tenant could not be resolved by default).
   * Returns the Principal to use, or `null` to REFUSE the session (fail-closed).
   *
   * This is the general extension point for apps whose authentication identity differs from their
   * domain principal: remap `userId` (e.g. auth user -> business user via a DB lookup), resolve the
   * tenant asynchronously (email fallback), set `authMethod`/`mfaLevel` from the session, enrich `ctx`.
   * The adapter itself stays schema-agnostic: all app-specific mapping lives in this callback.
   * Default (absent): returns `base` unchanged - behavior identical to before this hook existed.
   */
  readonly resolvePrincipal?: (
    input: ResolvePrincipalInput,
  ) => Promise<Principal | null> | Principal | null;
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
  readonly #resolvePrincipal:
    | ((input: ResolvePrincipalInput) => Promise<Principal | null> | Principal | null)
    | undefined;

  public constructor(config: BetterAuthIdentityConfig) {
    this.#auth = config.auth;
    this.#extractTenantId = config.extractTenantId ?? defaultTenantId;
    this.#extractRoles = config.extractRoles ?? (() => []);
    this.#resolvePrincipal = config.resolvePrincipal;
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

    // Default projection. `base` is `null` when no tenant resolves by default - the hook may still
    // resolve it (e.g. async email fallback). Without a hook, a null base means fail-closed refusal.
    const tenantId = this.#extractTenantId(result.user);
    const base: Principal | null =
      tenantId === null
        ? null
        : {
            userId: result.user.id,
            tenantId,
            roles: this.#extractRoles(result.user),
            mfaLevel: 'none',
            authMethod: 'oidc',
            ctx: { authTime: sessionAuthTime(result.session) },
          };

    if (this.#resolvePrincipal === undefined) {
      return base;
    }
    return this.#resolvePrincipal({ user: result.user, session: result.session, base });
  }
}
