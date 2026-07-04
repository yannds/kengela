/**
 * `@kengela/iam-mapping` - bridge between enterprise identity (Entra/AD/ADFS/Okta via
 * OIDC, SAML, SCIM, Microsoft Graph or Google Workspace) and the internal roles +
 * org-chart model (ADR-014).
 *
 * - `profile`    : normalization of the 6 IdP sources -> `DirectoryProfile`.
 * - `rules`      : group/claim/attribute -> roles + unit mapping engine.
 * - `safe-regex` : safe regex compilation/evaluation (anti-ReDoS), fail-closed.
 *
 * Everything is PURE (testable outside infra); the adapters (SCIM controller, SSO login)
 * provide the IdP payload and apply the result through the repos.
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
