/**
 * `@kengela/scim-server` — cœur SCIM 2.0 (Users + Groups) FRAMEWORK-AGNOSTIQUE.
 *
 * Le paquet expose :
 *  - le PORT `ScimStore` (persistance NARROW, orientée SCIM) et ses types de lignes ;
 *  - des HANDLERS PURS `(store, requête parsée) → réponse` (aucune dépendance HTTP) ;
 *  - la sérialisation / le parsing SCIM (ressources, ListResponse, Error, PATCH, filtres).
 *
 * Un adapter (NestJS, Express…) résout le tenant, parse le corps/la requête, appelle un
 * handler et sérialise la `ScimResponse` en `application/scim+json`.
 */

// ── Port + types de contrat ──────────────────────────────────────────────────
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

// ── Handlers purs ────────────────────────────────────────────────────────────
export {
  handleUsersPost,
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

// ── Sérialisation / parsing SCIM ─────────────────────────────────────────────
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
  parseDisplayNameFilter,
  parsePagination,
} from './serialize.js';

// ── Ré-exports SCIM utiles (types + URNs canoniques Kengela) ─────────────────
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
