/**
 * `LdapClientLike` — surface **NARROW** du client LDAP dont dépend cet adapter.
 *
 * DOCTRINE (le port est un sas, pas une planque) : on n'importe RIEN de `ldapts` dans le contrat.
 * On décrit exactement les trois méthodes utilisées — `bind`, `search` (paginée), `unbind` — avec
 * des types de retour explicites. Le vrai `Client` de `ldapts` est **structurellement compatible**
 * (voir la fabrique par défaut dans `ldap-directory-source.ts`), et un fake en mémoire l'est tout
 * autant côté test. Lecture seule : aucune méthode de modification d'annuaire n'est exposée.
 */

/** Portée de recherche LDAP (RFC 4511), alignée sur `ldapts`. */
export type LdapSearchScope = 'base' | 'one' | 'sub';

/** Options du contrôle de résultats paginés (Paged Results Control). */
export interface LdapPagedOptions {
  /** Nombre d'entrées par page. */
  readonly pageSize?: number;
}

/**
 * Options de recherche passées au client. Sous-ensemble STRICT des `SearchOptions` de `ldapts` :
 * uniquement ce que l'adapter utilise, avec des types assez étroits pour qu'un vrai `Client` reste
 * structurellement assignable à `LdapClientLike`.
 */
export interface LdapSearchOptions {
  readonly scope?: LdapSearchScope;
  readonly filter?: string;
  readonly attributes?: string[];
  readonly paged?: boolean | LdapPagedOptions;
  readonly sizeLimit?: number;
}

/**
 * Entrée brute renvoyée par une recherche : DN + attributs. Les valeurs sont laissées en `unknown`
 * car le client `ldapts` renvoie des `Buffer` pour les attributs binaires (ex. `objectGUID`) ; la
 * normalisation (stringify + base64) vit dans l'adapter, pas dans le contrat.
 */
export interface LdapSearchEntry {
  readonly dn: string;
  readonly [attribute: string]: unknown;
}

/** Résultat d'une recherche LDAP — sous-ensemble de `SearchResult` de `ldapts`. */
export interface LdapSearchResult {
  readonly searchEntries: readonly LdapSearchEntry[];
  readonly searchReferences?: readonly string[];
}

/**
 * Surface NARROW du client LDAP. Un vrai `Client` de `ldapts` la satisfait structurellement ; le
 * fake de test aussi. Aucune écriture (add/modify/del) n'est déclarée : cet adapter est en lecture.
 */
export interface LdapClientLike {
  bind(dn: string, password: string): Promise<void>;
  search(baseDN: string, options: LdapSearchOptions): Promise<LdapSearchResult>;
  unbind(): Promise<void>;
}

/** Fabrique de client injectable (tests, client alternatif). Défaut : vrai `Client` de `ldapts`. */
export type LdapClientFactory = () => LdapClientLike;
