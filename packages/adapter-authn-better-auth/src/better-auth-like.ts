/**
 * NARROW surface of a better-auth instance actually used by the adapter: session
 * verification. A real better-auth instance is structurally compatible. We do NOT wrap
 * the whole framework - better-auth handles OIDC/OAuth, the DB and the routes on the app
 * side; Kengela only consumes the verified session.
 */
export interface BetterAuthUser {
  readonly id: string;
  readonly email?: string;
  readonly [key: string]: unknown;
}

export type BetterAuthSession = Readonly<Record<string, unknown>>;

export interface BetterAuthLike {
  readonly api: {
    getSession(input: {
      readonly headers: Headers;
    }): Promise<{ readonly user: BetterAuthUser; readonly session: BetterAuthSession } | null>;
  };
}
