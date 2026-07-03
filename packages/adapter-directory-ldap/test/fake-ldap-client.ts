/**
 * Fake `LdapClientLike` en mémoire pour des tests hermétiques, SANS serveur LDAP réel.
 * Reproduit les sémantiques utilisées par l'adapter : bind ok/ko, recherche renvoyant des entrées
 * simulées (dont des `Buffer` pour les binaires), `sizeLimit` respecté, `unbind` idempotent. Enregistre
 * les appels pour l'assertion (bind avec le bon DN/mot de passe, options de recherche transmises).
 */
import type {
  LdapClientLike,
  LdapSearchEntry,
  LdapSearchOptions,
  LdapSearchResult,
} from '../src/ldap-client-like.js';

export interface FakeLdapOptions {
  readonly bindShouldFail?: boolean;
  readonly entries?: readonly LdapSearchEntry[];
}

export interface RecordedBind {
  readonly dn: string;
  readonly password: string;
}

export interface RecordedSearch {
  readonly baseDN: string;
  readonly options: LdapSearchOptions;
}

export class FakeLdapClient implements LdapClientLike {
  public readonly binds: RecordedBind[] = [];
  public readonly searches: RecordedSearch[] = [];
  public unbindCount = 0;

  readonly #bindShouldFail: boolean;
  readonly #entries: readonly LdapSearchEntry[];

  public constructor(options: FakeLdapOptions = {}) {
    this.#bindShouldFail = options.bindShouldFail ?? false;
    this.#entries = options.entries ?? [];
  }

  public bind(dn: string, password: string): Promise<void> {
    this.binds.push({ dn, password });
    if (this.#bindShouldFail) return Promise.reject(new Error('bind failed'));
    return Promise.resolve();
  }

  public search(baseDN: string, options: LdapSearchOptions): Promise<LdapSearchResult> {
    this.searches.push({ baseDN, options });
    const limit = options.sizeLimit;
    const entries =
      typeof limit === 'number' && limit >= 0 ? this.#entries.slice(0, limit) : this.#entries;
    return Promise.resolve({ searchEntries: entries });
  }

  public unbind(): Promise<void> {
    this.unbindCount += 1;
    return Promise.resolve();
  }
}

/** Fabrique renvoyant toujours le même fake (l'adapter crée un client par appel réseau). */
export function fakeFactory(client: FakeLdapClient): () => LdapClientLike {
  return (): LdapClientLike => client;
}
