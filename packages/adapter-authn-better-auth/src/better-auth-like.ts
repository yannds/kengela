/**
 * Surface NARROW d'une instance better-auth réellement utilisée par l'adapter :
 * la vérification de session. Une vraie instance better-auth est structurellement
 * compatible. On n'enveloppe PAS tout le framework — better-auth gère l'OIDC/OAuth,
 * la DB et les routes côté app ; Kengela ne consomme que la session vérifiée.
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
