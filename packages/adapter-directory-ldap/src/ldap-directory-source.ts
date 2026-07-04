/**
 * `LdapDirectorySource` - **AD / LDAP** directory adapter ("pull" twin of the Graph /
 * Google / SCIM connectors). Binds over LDAP(S) (`bind`), walks the directory via paginated search
 * under a `baseDN`, and returns **normalized** `LdapEntryParts` (DN + attributes as strings, binaries
 * in base64) - directly consumable by `profileFromLdap` from `@kengela/iam-mapping`. No role-mapping
 * logic here: this adapter ONLY speaks LDAP, the projection stays in the pure lib.
 *
 * TLS verified by default (LDAPS). The bind password is NEVER logged (this module logs
 * nothing); it is kept in a private field and passed only to the injected client.
 */
import { Client } from 'ldapts';
import {
  type DirectoryProfile,
  type LdapAttributeMap,
  type LdapEntryParts,
  accountActiveFromLdap,
  profileFromLdap,
} from '@kengela/iam-mapping';
import type {
  LdapClientFactory,
  LdapClientLike,
  LdapSearchEntry,
  LdapSearchScope,
} from './ldap-client-like.js';

/**
 * LDAP bounds and defaults (Active Directory), single source of truth - no magic number/string
 * in the code. Overridable via `LdapConnectionConfig` (connector config, never hardcoded).
 */
export const LDAP_SOURCE_DEFAULTS = {
  /** Personal-account filter (AD): excludes machine accounts. */
  userFilter: '(&(objectCategory=person)(objectClass=user))',
  /** Requested attributes (`*` covers the usual ones; `memberOf` explicit for groups). */
  attributes: ['*', 'memberOf'],
  /** Bind + search timeout (ms). */
  timeoutMs: 15_000,
  /** Page size (Paged Results Control). */
  pageSize: 200,
  /** Cap on entries read per pull. */
  maxUsers: 1000,
  /** Verifies the server's TLS certificate (LDAPS). */
  tlsRejectUnauthorized: true,
} as const;

/** Directory connection and read parameters (resolved by the caller from its config). */
export interface LdapConnectionConfig {
  /** Server URL (`ldaps://dc.corp.local:636` recommended; `ldap://` in dev only). */
  readonly url: string;
  /** Service DN for the bind (directory read account). */
  readonly bindDN: string;
  /** Service account password (resolved from a vault by the caller; never logged). */
  readonly bindPassword: string;
  /** Search root (`OU=Users,DC=corp,DC=local`). */
  readonly baseDN: string;
  /** Default search filter (otherwise the Active Directory default). */
  readonly userFilter?: string;
  /** Default requested attributes (otherwise `["*","memberOf"]`). */
  readonly attributes?: readonly string[];
  /** Bind + search timeout (ms). */
  readonly timeoutMs?: number;
  /** Verifies the TLS certificate (LDAPS). Default `true`; disable only for a test directory. */
  readonly tlsRejectUnauthorized?: boolean;
  /** Page size of the paginated search. */
  readonly pageSize?: number;
  /** Cap on entries read per pull. */
  readonly maxUsers?: number;
}

/** Source construction options (client injection for tests). */
export interface LdapDirectorySourceOptions {
  /** Injectable client factory. Default: a real `Client` from `ldapts` configured from the config. */
  readonly clientFactory?: LdapClientFactory;
}

/** Options of a `fetchEntries` call. */
export interface FetchEntriesOptions {
  /** Requested attributes (otherwise those from config, otherwise AD defaults). */
  readonly attributes?: readonly string[];
  /** Entry cap (otherwise `maxUsers`). */
  readonly max?: number;
  /** Search scope (otherwise `sub`). */
  readonly scope?: LdapSearchScope;
  /** LDAP attribute map to attach to each entry (for `profileFromLdap`). */
  readonly attributeMap?: LdapAttributeMap;
}

/** Normalized profile + account activation state (de-provisioning via `userAccountControl`). */
export interface DirectoryRecord {
  readonly profile: DirectoryProfile;
  readonly active: boolean;
}

/** Converts a scalar LDAP attribute value (string or binary) into a stable string, or undefined. */
function stringifyScalar(value: unknown): string | undefined {
  if (Buffer.isBuffer(value)) return value.toString('base64');
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return undefined;
}

/** Normalizes an attribute value (single- or multi-valued) into string(s); binaries in base64. */
function normalizeValue(value: unknown): string | readonly string[] | undefined {
  if (Array.isArray(value)) {
    const out: string[] = [];
    for (const item of value as readonly unknown[]) {
      const s = stringifyScalar(item);
      if (s !== undefined) out.push(s);
    }
    return out.length > 0 ? out : undefined;
  }
  return stringifyScalar(value);
}

/**
 * LDAP directory source. A single network entry point (`fetchEntries`) and a health-check
 * (`checkConnection`); the projection to `DirectoryProfile` goes through the static helpers
 * `toProfiles` / `toRecords` (SSoT `@kengela/iam-mapping`).
 */
export class LdapDirectorySource {
  readonly #factory: LdapClientFactory;
  readonly #bindDN: string;
  readonly #bindPassword: string;
  readonly #baseDN: string;
  readonly #userFilter: string;
  readonly #attributes: readonly string[];
  readonly #maxUsers: number;
  readonly #pageSize: number;

  public constructor(config: LdapConnectionConfig, options: LdapDirectorySourceOptions = {}) {
    this.#bindDN = config.bindDN;
    this.#bindPassword = config.bindPassword;
    this.#baseDN = config.baseDN;
    const filter = config.userFilter?.trim();
    this.#userFilter =
      filter !== undefined && filter !== '' ? filter : LDAP_SOURCE_DEFAULTS.userFilter;
    this.#attributes = config.attributes ?? LDAP_SOURCE_DEFAULTS.attributes;
    this.#maxUsers = config.maxUsers ?? LDAP_SOURCE_DEFAULTS.maxUsers;
    this.#pageSize = config.pageSize ?? LDAP_SOURCE_DEFAULTS.pageSize;
    this.#factory = options.clientFactory ?? createLdapClientFactory(config);
  }

  /**
   * Binds, walks the directory (paginated search under `baseDN`), normalizes and unbinds. Returns
   * `LdapEntryParts` (DN + attributes as strings, `objectGUID` in base64) capped by `max`. Pure
   * network read (outside any DB transaction). The `unbind` is guaranteed even on failure.
   */
  public async fetchEntries(
    filter?: string,
    options: FetchEntriesOptions = {},
  ): Promise<readonly LdapEntryParts[]> {
    const max = options.max ?? this.#maxUsers;
    const requested = options.attributes ?? this.#attributes;
    const trimmed = filter?.trim();
    const searchFilter = trimmed !== undefined && trimmed !== '' ? trimmed : this.#userFilter;

    const client = this.#factory();
    try {
      await client.bind(this.#bindDN, this.#bindPassword);
      const result = await client.search(this.#baseDN, {
        scope: options.scope ?? 'sub',
        filter: searchFilter,
        attributes: [...requested],
        paged: { pageSize: this.#pageSize },
        sizeLimit: max,
      });
      return result.searchEntries
        .slice(0, max)
        .map((entry) => normalizeEntry(entry, options.attributeMap));
    } finally {
      await client.unbind().catch(() => undefined);
    }
  }

  /**
   * Health-check: binds, verifies access then unbinds. `true` if connectivity + credentials +
   * TLS are valid, `false` otherwise (no exception leaks; the password is not logged).
   */
  public async checkConnection(): Promise<boolean> {
    const client = this.#factory();
    try {
      await client.bind(this.#bindDN, this.#bindPassword);
      return true;
    } catch {
      return false;
    } finally {
      await client.unbind().catch(() => undefined);
    }
  }

  /**
   * Projects normalized entries into `DirectoryProfile` via `profileFromLdap` (SSoT). If `map` is
   * provided and the entry does not already have its own map, it is applied.
   */
  public static toProfiles(
    entries: readonly LdapEntryParts[],
    map?: LdapAttributeMap,
  ): readonly DirectoryProfile[] {
    return entries.map((entry) => profileFromLdap(withAttributeMap(entry, map)));
  }

  /**
   * Like `toProfiles`, but joins the account activation state (`accountActiveFromLdap`: the
   * `ACCOUNTDISABLE` 0x2 bit of `userAccountControl`) to drive de-provisioning.
   */
  public static toRecords(
    entries: readonly LdapEntryParts[],
    map?: LdapAttributeMap,
  ): readonly DirectoryRecord[] {
    return entries.map((entry) => {
      const parts = withAttributeMap(entry, map);
      return { profile: profileFromLdap(parts), active: accountActiveFromLdap(parts) };
    });
  }
}

/** Applies `map` to an entry that lacks a map, otherwise leaves it as-is. */
function withAttributeMap(
  entry: LdapEntryParts,
  map: LdapAttributeMap | undefined,
): LdapEntryParts {
  if (map === undefined || entry.attributeMap !== undefined) return entry;
  return { ...entry, attributeMap: map };
}

/** Normalizes a raw search entry into `LdapEntryParts` (attributes as strings, binaries base64). */
function normalizeEntry(
  entry: LdapSearchEntry,
  attributeMap: LdapAttributeMap | undefined,
): LdapEntryParts {
  const dn = typeof entry.dn === 'string' ? entry.dn : '';
  const attributes: Record<string, string | readonly string[]> = {};
  for (const key of Object.keys(entry)) {
    if (key === 'dn') continue;
    const normalized = normalizeValue(entry[key]);
    if (normalized !== undefined) attributes[key] = normalized;
  }
  return attributeMap !== undefined ? { dn, attributes, attributeMap } : { dn, attributes };
}

/** Default factory: a real `Client` from `ldapts` (LDAPS verified), structurally `LdapClientLike`. */
function createLdapClientFactory(config: LdapConnectionConfig): LdapClientFactory {
  const timeout = config.timeoutMs ?? LDAP_SOURCE_DEFAULTS.timeoutMs;
  const rejectUnauthorized =
    config.tlsRejectUnauthorized ?? LDAP_SOURCE_DEFAULTS.tlsRejectUnauthorized;
  return (): LdapClientLike =>
    new Client({
      url: config.url,
      timeout,
      connectTimeout: timeout,
      tlsOptions: { rejectUnauthorized },
    });
}
