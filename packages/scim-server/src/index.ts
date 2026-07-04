/**
 * `@kengela/scim-server` - SCIM 2.0 core (Users + Groups), FRAMEWORK-AGNOSTIC.
 *
 * The package exposes:
 *  - the `ScimStore` PORT (NARROW, SCIM-oriented persistence) and its row types;
 *  - PURE HANDLERS `(store, parsed request) -> response` (no HTTP dependency);
 *  - SCIM serialization / parsing (resources, ListResponse, Error, PATCH, filters).
 *
 * An adapter (NestJS, Express...) resolves the tenant, parses the body/request, calls a
 * handler and serializes the `ScimResponse` as `application/scim+json`.
 */

// -- Port + contract types ----------------------------------------------------
export type {
  ScimStore,
  ScimUserRow,
  ScimGroupRow,
  ScimUserWriteInput,
  ScimUserIdentityPatch,
  ScimUserPatch,
  ScimGroupWriteInput,
  GroupMemberPatch,
  ScimUserListOptions,
  ScimGroupListOptions,
  ScimListPage,
  ScimQuery,
  ScimRequest,
  ScimResponse,
  ScimHandler,
} from './types.js';

// -- Pure handlers ------------------------------------------------------------
export {
  handleUsersPost,
  handleUsersPostStrict,
  handleUsersGet,
  handleUsersList,
  handleUsersPatch,
  handleUsersPut,
  handleUsersDelete,
} from './users.js';
export {
  handleGroupsPost,
  handleGroupsGet,
  handleGroupsList,
  handleGroupsPatch,
  handleGroupsPut,
  handleGroupsDelete,
} from './groups.js';

// -- Discovery endpoints (self-description) -----------------------------------
export {
  SCIM_SCHEMA_SERVICE_PROVIDER_CONFIG,
  SCIM_SCHEMA_RESOURCE_TYPE,
  SCIM_SCHEMA_SCHEMA,
  serviceProviderConfig,
  resourceTypes,
  schemaDefinitions,
  handleServiceProviderConfig,
  handleResourceTypes,
  handleSchemas,
} from './discovery.js';

// -- Schema validation (self-check) -------------------------------------------
export { validateScimUser, validateScimGroup } from './validate.js';
export type { ScimValidationResult } from './validate.js';

// -- SCIM serialization / parsing ---------------------------------------------
export {
  SCIM_SCHEMA_LIST_RESPONSE,
  SCIM_SCHEMA_ERROR,
  SCIM_SCHEMA_PATCH_OP,
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
  asRecord,
  toScimUser,
  toScimGroup,
  userListResponse,
  groupListResponse,
  scimError,
  emailOf,
  givenNameOf,
  familyNameOf,
  displayNameOf,
  groupDisplayNameOf,
  externalIdOf,
  activeOf,
  parseUserPatch,
  memberIdsOf,
  parseGroupMemberPatch,
  parseUserNameFilter,
  parseExternalIdFilter,
  parseDisplayNameFilter,
  parsePagination,
} from './serialize.js';

// -- Useful SCIM re-exports (types + Kengela canonical URNs) ------------------
export {
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  SCIM_SCHEMA_GROUP,
} from '@kengela/iam-mapping';
export type {
  KengelaScimUser,
  ScimName,
  ScimMultiValued,
  ScimAddress,
  ScimGroupRef,
  ScimManagerRef,
  ScimEnterpriseExtension,
  ScimMeta,
} from '@kengela/iam-mapping';
