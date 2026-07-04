/**
 * SCIM 2.0 `/Groups` handlers - PURE (`(store, request) -> response`), no HTTP.
 *
 * The IdP (Entra/Okta) pushes groups and their members here (RFC 7643 §4.2). Full CRUD
 * + member management via PATCH (add/remove/replace) and full replacement via PUT.
 */
import type { ScimGroupListOptions, ScimRequest, ScimResponse, ScimStore } from './types.js';
import {
  asRecord,
  externalIdOf,
  groupDisplayNameOf,
  groupListResponse,
  memberIdsOf,
  parseDisplayNameFilter,
  parseGroupMemberPatch,
  parsePagination,
  scimError,
  toScimGroup,
} from './serialize.js';

function missingId(): ScimResponse {
  return { status: 400, body: scimError(400, 'Resource identifier required.', 'invalidValue') };
}

function notFound(): ScimResponse {
  return { status: 404, body: scimError(404, 'Group not found.') };
}

/** POST `/Groups`: creates a group (+ initial members). `displayName` required (400 otherwise). */
export async function handleGroupsPost(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  const body = asRecord(request.body);
  const displayName = groupDisplayNameOf(body);
  if (displayName === null) {
    return { status: 400, body: scimError(400, 'displayName required.', 'invalidValue') };
  }
  const created = await store.createGroup(request.tenantId, {
    displayName,
    externalId: externalIdOf(body),
    memberIds: memberIdsOf(body),
  });
  return { status: 201, body: toScimGroup(created) };
}

/** GET `/Groups/:id`: 200 with the resource, or 404 SCIM. */
export async function handleGroupsGet(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  if (request.pathId === undefined) {
    return missingId();
  }
  const group = await store.getGroup(request.tenantId, request.pathId);
  return group === null ? notFound() : { status: 200, body: toScimGroup(group) };
}

/**
 * GET `/Groups`: SCIM `ListResponse`. Supports the `displayName eq "..."` filter +
 * pagination. Filter present but unsupported => empty list.
 */
export async function handleGroupsList(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  const filter = request.query?.filter;
  const displayName = parseDisplayNameFilter(filter);
  const { startIndex, count } = parsePagination(request.query);
  if (filter !== undefined && displayName === null) {
    return {
      status: 200,
      body: groupListResponse({ resources: [], totalResults: 0, startIndex, itemsPerPage: 0 }),
    };
  }
  const options: ScimGroupListOptions =
    displayName === null ? { startIndex, count } : { displayName, startIndex, count };
  const page = await store.listGroups(request.tenantId, options);
  return { status: 200, body: groupListResponse(page) };
}

/**
 * PATCH `/Groups/:id`: member management (add/remove/replace, RFC 7644 §3.5.2), including
 * the targeted removal `members[value eq "<id>"]`. 404 if the group does not exist.
 */
export async function handleGroupsPatch(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  if (request.pathId === undefined) {
    return missingId();
  }
  const ops = parseGroupMemberPatch(asRecord(request.body));
  const updated = await store.patchGroup(request.tenantId, request.pathId, ops);
  return updated === null ? notFound() : { status: 200, body: toScimGroup(updated) };
}

/**
 * PUT `/Groups/:id`: full replacement (displayName + members). 404 if absent, 400 if
 * `displayName` is missing.
 */
export async function handleGroupsPut(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  if (request.pathId === undefined) {
    return missingId();
  }
  const body = asRecord(request.body);
  const displayName = groupDisplayNameOf(body);
  if (displayName === null) {
    return { status: 400, body: scimError(400, 'displayName required.', 'invalidValue') };
  }
  const updated = await store.replaceGroup(request.tenantId, request.pathId, {
    displayName,
    externalId: externalIdOf(body),
    memberIds: memberIdsOf(body),
  });
  return updated === null ? notFound() : { status: 200, body: toScimGroup(updated) };
}

/** DELETE `/Groups/:id`: deletes the group (members are not deleted). 204/404. */
export async function handleGroupsDelete(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  if (request.pathId === undefined) {
    return missingId();
  }
  const deleted = await store.deleteGroup(request.tenantId, request.pathId);
  return deleted ? { status: 204 } : notFound();
}
