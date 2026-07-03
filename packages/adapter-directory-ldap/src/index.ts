/**
 * `@kengela/adapter-directory-ldap` — connecteur d'annuaire **AD / LDAP** (chantier IdP « pull »).
 *
 * - `LdapDirectorySource` : bind LDAP(S) + recherche paginée → `LdapEntryParts` normalisés, health-check.
 * - `LdapClientLike`      : surface NARROW du client (le vrai `Client` de `ldapts` la satisfait).
 * - Helpers `toProfiles` / `toRecords` : composent `profileFromLdap` / `accountActiveFromLdap` (SSoT).
 *
 * L'adapter ne fait QUE parler LDAP ; le mapping des rôles reste dans `@kengela/iam-mapping` (pur).
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
// Ré-exports pratiques (SSoT `@kengela/iam-mapping`) pour composer sans double dépendance.
export { accountActiveFromLdap, profileFromLdap } from '@kengela/iam-mapping';
export type { DirectoryProfile, LdapAttributeMap, LdapEntryParts } from '@kengela/iam-mapping';
