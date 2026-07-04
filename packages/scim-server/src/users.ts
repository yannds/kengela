/**
 * SCIM 2.0 `/Users` handlers - PURE (`(store, request) -> response`), no HTTP.
 *
 * Doctrine (RFC 7644): provisioning RECONCILED BY EMAIL (case-insensitive, never a
 * duplicate), deprovisioning = DEACTIVATION (never deletion), conforming SCIM errors.
 * The adapter (NestJS...) resolves the tenant + parses the body, then delegates here.
 */
import type { ScimRequest, ScimResponse, ScimStore, ScimUserListOptions } from './types.js';
import {
  activeOf,
  asRecord,
  displayNameOf,
  emailOf,
  externalIdOf,
  familyNameOf,
  givenNameOf,
  parseExternalIdFilter,
  parsePagination,
  parseUserNameFilter,
  parseUserPatch,
  scimError,
  toScimUser,
  userListResponse,
} from './serialize.js';

function missingId(): ScimResponse {
  return { status: 400, body: scimError(400, 'Resource identifier required.', 'invalidValue') };
}

function notFound(): ScimResponse {
  return { status: 404, body: scimError(404, 'User not found.') };
}

/**
 * POST `/Users`: creates the user, or RECONCILES an existing one by email (idempotent).
 * Existing => 200 without duplicate; new => 201. `userName`/email required (400 otherwise).
 */
export async function handleUsersPost(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  const body = asRecord(request.body);
  const email = emailOf(body);
  if (email === null) {
    return { status: 400, body: scimError(400, 'userName (email) required.', 'invalidValue') };
  }
  const existing = await store.findUserByEmail(request.tenantId, email);
  if (existing !== null) {
    return { status: 200, body: toScimUser(existing) };
  }
  const created = await store.createUser(request.tenantId, {
    userName: email,
    externalId: externalIdOf(body),
    firstName: givenNameOf(body),
    lastName: familyNameOf(body),
    displayName: displayNameOf(body),
    active: activeOf(body),
  });
  return { status: 201, body: toScimUser(created) };
}

/**
 * POST `/Users` in STRICT mode RFC 7644 §3.3 / Microsoft Entra validator: a `userName`
 * already present (case-insensitive) => 409 `uniqueness` (NEVER reconciliation). To be
 * wired when the IdP expects duplicate rejection rather than email idempotency.
 */
export async function handleUsersPostStrict(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  const body = asRecord(request.body);
  const email = emailOf(body);
  if (email === null) {
    return { status: 400, body: scimError(400, 'userName (email) required.', 'invalidValue') };
  }
  const existing = await store.findUserByEmail(request.tenantId, email);
  if (existing !== null) {
    return {
      status: 409,
      body: scimError(409, `userName already in use: ${email}.`, 'uniqueness'),
    };
  }
  const created = await store.createUser(request.tenantId, {
    userName: email,
    externalId: externalIdOf(body),
    firstName: givenNameOf(body),
    lastName: familyNameOf(body),
    displayName: displayNameOf(body),
    active: activeOf(body),
  });
  return { status: 201, body: toScimUser(created) };
}

/** GET `/Users/:id`: 200 with the resource, or 404 SCIM. */
export async function handleUsersGet(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  if (request.pathId === undefined) {
    return missingId();
  }
  const user = await store.getUser(request.tenantId, request.pathId);
  return user === null ? notFound() : { status: 200, body: toScimUser(user) };
}

/**
 * GET `/Users`: SCIM `ListResponse`. Supports the `userName eq "..."` AND
 * `externalId eq "..."` filters (required by the Entra validator) + pagination (`startIndex`/`count`).
 * Filter present but unsupported => empty list (never an error).
 */
export async function handleUsersList(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  const filter = request.query?.filter;
  const userName = parseUserNameFilter(filter);
  const externalId = parseExternalIdFilter(filter);
  const { startIndex, count } = parsePagination(request.query);
  if (filter !== undefined && userName === null && externalId === null) {
    return {
      status: 200,
      body: userListResponse({ resources: [], totalResults: 0, startIndex, itemsPerPage: 0 }),
    };
  }
  const options: ScimUserListOptions = {
    startIndex,
    count,
    ...(userName === null ? {} : { userName }),
    ...(externalId === null ? {} : { externalId }),
  };
  const page = await store.listUsers(request.tenantId, options);
  return { status: 200, body: userListResponse(page) };
}

/**
 * PATCH `/Users/:id` (RFC 7644 §3.5.2): activation/deactivation and identity fields.
 * Partial: absent fields are not touched. 404 if the user does not exist.
 */
export async function handleUsersPatch(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  if (request.pathId === undefined) {
    return missingId();
  }
  const patch = parseUserPatch(asRecord(request.body));
  const updated = await store.patchUser(request.tenantId, request.pathId, patch);
  return updated === null ? notFound() : { status: 200, body: toScimUser(updated) };
}

/**
 * PUT `/Users/:id`: full replacement (identity + `active`). Activation can change
 * (reactivation/IdP deprovisioning). 404 if absent, 400 if the email is missing.
 */
export async function handleUsersPut(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  if (request.pathId === undefined) {
    return missingId();
  }
  const body = asRecord(request.body);
  const email = emailOf(body);
  if (email === null) {
    return { status: 400, body: scimError(400, 'userName (email) required.', 'invalidValue') };
  }
  const updated = await store.replaceUser(request.tenantId, request.pathId, {
    userName: email,
    externalId: externalIdOf(body),
    firstName: givenNameOf(body),
    lastName: familyNameOf(body),
    displayName: displayNameOf(body),
    active: activeOf(body),
  });
  return updated === null ? notFound() : { status: 200, body: toScimUser(updated) };
}

/**
 * DELETE `/Users/:id`: DEPROVISIONING = DEACTIVATION (active=false), never physical
 * deletion. 204 if done, 404 if the user does not exist.
 */
export async function handleUsersDelete(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  if (request.pathId === undefined) {
    return missingId();
  }
  const deactivated = await store.deactivateUser(request.tenantId, request.pathId);
  return deactivated === null ? notFound() : { status: 204 };
}
