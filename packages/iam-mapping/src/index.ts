/**
 * `@kengela/iam-mapping` — pont entre l'identité d'entreprise (Entra/AD/ADFS/Okta via
 * OIDC, SAML, SCIM, Microsoft Graph ou Google Workspace) et le modèle interne rôles +
 * organigramme (ADR-014).
 *
 * - `profile`    : normalisation des 6 sources IdP → `DirectoryProfile`.
 * - `rules`      : moteur de mapping groupes/claims/attributs → rôles + unité.
 * - `safe-regex` : compilation/évaluation de regex sûres (anti-ReDoS), fail-closed.
 *
 * Tout est PUR (testable hors infra) ; les adapters (SCIM controller, login SSO)
 * fournissent le payload IdP et appliquent le résultat via les repos.
 */
export {
  type DirectoryAttributes,
  type DirectoryProfile,
  type GraphUserParts,
  type LdapAttributeMap,
  type LdapEntryParts,
  type GoogleDirectoryUserParts,
  type GoogleOrganization,
  type GoogleRelation,
  type SamlAttributeMap,
  type SamlAssertionParts,
  type ScimAttributeMap,
  type OidcAttributeMap,
  type AttributeMapField,
  profileFromScim,
  profileFromOidcClaims,
  profileFromGraph,
  profileFromLdap,
  accountActiveFromLdap,
  profileFromGoogle,
  accountActiveFromGoogle,
  profileFromSaml,
  profileFromParts,
  DIRECTORY_ATTRIBUTE_KEYS,
  IDENTITY_FIELD_KEYS,
  ATTRIBUTE_MAP_FIELDS,
  LDAP_AD_ATTRIBUTE_DEFAULTS,
  SAML_DEFAULT_ATTRIBUTE_KEYS,
  SCIM_DEFAULT_ATTRIBUTE_KEYS,
  OIDC_DEFAULT_ATTRIBUTE_KEYS,
} from './profile.js';
export {
  type MappingSource,
  type MatchOp,
  type MappingCondition,
  type OrgUnitDirective,
  type IdpMappingRule,
  type MappingResult,
  evaluateMappings,
} from './rules.js';
export {
  type SafeRegexLimits,
  SAFE_REGEX_LIMITS,
  compileSafeRegex,
  safeRegexTest,
} from './safe-regex.js';
export { type ContractsProfileMeta, toContractsProfile } from './contracts-projection.js';
export {
  type ScimMultiValued,
  type ScimName,
  type ScimAddress,
  type ScimGroupRef,
  type ScimManagerRef,
  type ScimEnterpriseExtension,
  type ScimMeta,
  type KengelaScimUser,
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  SCIM_SCHEMA_GROUP,
  KENGELA_SCIM_ATTRIBUTE_PATHS,
  projectScimUser,
} from './scim-schema.js';
