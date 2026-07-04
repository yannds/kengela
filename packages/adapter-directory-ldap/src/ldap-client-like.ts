/**
 * `LdapClientLike` - **NARROW** surface of the LDAP client this adapter depends on.
 *
 * DOCTRINE (the port is an airlock, not a hideout): we import NOTHING from `ldapts` in the contract.
 * We describe exactly the three methods used - `bind`, `search` (paginated), `unbind` - with
 * explicit return types. The real `Client` from `ldapts` is **structurally compatible**
 * (see the default factory in `ldap-directory-source.ts`), and an in-memory fake is just as much so
 * on the test side. Read-only: no directory-modification method is exposed.
 */

/** LDAP search scope (RFC 4511), aligned with `ldapts`. */
export type LdapSearchScope = 'base' | 'one' | 'sub';

/** Options for the Paged Results Control. */
export interface LdapPagedOptions {
  /** Number of entries per page. */
  readonly pageSize?: number;
}

/**
 * Search options passed to the client. STRICT subset of the `SearchOptions` from `ldapts`:
 * only what the adapter uses, with types narrow enough that a real `Client` stays
 * structurally assignable to `LdapClientLike`.
 */
export interface LdapSearchOptions {
  readonly scope?: LdapSearchScope;
  readonly filter?: string;
  readonly attributes?: string[];
  readonly paged?: boolean | LdapPagedOptions;
  readonly sizeLimit?: number;
}

/**
 * Raw entry returned by a search: DN + attributes. Values are left as `unknown`
 * because the `ldapts` client returns `Buffer` for binary attributes (e.g. `objectGUID`); the
 * normalization (stringify + base64) lives in the adapter, not in the contract.
 */
export interface LdapSearchEntry {
  readonly dn: string;
  readonly [attribute: string]: unknown;
}

/** Result of an LDAP search - subset of `SearchResult` from `ldapts`. */
export interface LdapSearchResult {
  readonly searchEntries: readonly LdapSearchEntry[];
  readonly searchReferences?: readonly string[];
}

/**
 * NARROW surface of the LDAP client. A real `Client` from `ldapts` satisfies it structurally; so
 * does the test fake. No write (add/modify/del) is declared: this adapter is read-only.
 */
export interface LdapClientLike {
  bind(dn: string, password: string): Promise<void>;
  search(baseDN: string, options: LdapSearchOptions): Promise<LdapSearchResult>;
  unbind(): Promise<void>;
}

/** Injectable client factory (tests, alternative client). Default: real `Client` from `ldapts`. */
export type LdapClientFactory = () => LdapClientLike;
