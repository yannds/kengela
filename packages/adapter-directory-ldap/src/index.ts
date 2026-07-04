/**
 * `@kengela/adapter-directory-ldap` - **AD / LDAP** directory connector ("pull" IdP work).
 *
 * - `LdapDirectorySource` : LDAP(S) bind + paginated search -> normalized `LdapEntryParts`, health-check.
 * - `LdapClientLike`      : NARROW surface of the client (the real `Client` from `ldapts` satisfies it).
 * - Helpers `toProfiles` / `toRecords` : compose `profileFromLdap` / `accountActiveFromLdap` (SSoT).
 *
 * The adapter ONLY speaks LDAP; role mapping stays in `@kengela/iam-mapping` (pure).
 */
export { LdapDirectorySource, LDAP_SOURCE_DEFAULTS } from './ldap-directory-source.js';
export type {
  DirectoryRecord,
  FetchEntriesOptions,
  LdapConnectionConfig,
  LdapDirectorySourceOptions,
} from './ldap-directory-source.js';
export type {
  LdapClientFactory,
  LdapClientLike,
  LdapPagedOptions,
  LdapSearchEntry,
  LdapSearchOptions,
  LdapSearchResult,
  LdapSearchScope,
} from './ldap-client-like.js';
// Convenient re-exports (SSoT `@kengela/iam-mapping`) to compose without a double dependency.
export { accountActiveFromLdap, profileFromLdap } from '@kengela/iam-mapping';
export type { DirectoryProfile, LdapAttributeMap, LdapEntryParts } from '@kengela/iam-mapping';
