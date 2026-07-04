/**
 * Handlers SCIM 2.0 `/Groups` - PURS (`(store, requête) → réponse`), sans HTTP.
 *
 * L'IdP (Entra/Okta) pousse ici les groupes et leurs membres (RFC 7643 §4.2). CRUD complet
 * + gestion des membres via PATCH (add/remove/replace) et remplacement complet via PUT.
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
  return { status: 400, body: scimError(400, 'Identifiant de ressource requis.', 'invalidValue') };
}

function notFound(): ScimResponse {
  return { status: 404, body: scimError(404, 'Groupe introuvable.') };
}

/** POST `/Groups` : crée un groupe (+ membres initiaux). `displayName` obligatoire (400 sinon). */
export async function handleGroupsPost(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  const body = asRecord(request.body);
  const displayName = groupDisplayNameOf(body);
  if (displayName === null) {
    return { status: 400, body: scimError(400, 'displayName requis.', 'invalidValue') };
  }
  const created = await store.createGroup(request.tenantId, {
    displayName,
    externalId: externalIdOf(body),
    memberIds: memberIdsOf(body),
  });
  return { status: 201, body: toScimGroup(created) };
}

/** GET `/Groups/:id` : 200 avec la ressource, ou 404 SCIM. */
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
 * GET `/Groups` : `ListResponse` SCIM. Supporte le filtre `displayName eq "..."` +
 * pagination. Filtre présent mais non supporté ⇒ liste vide.
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
 * PATCH `/Groups/:id` : gestion des membres (add/remove/replace, RFC 7644 §3.5.2), y
 * compris le retrait ciblé `members[value eq "<id>"]`. 404 si le groupe n'existe pas.
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
 * PUT `/Groups/:id` : remplacement complet (displayName + membres). 404 si absent, 400 si
 * `displayName` manque.
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
    return { status: 400, body: scimError(400, 'displayName requis.', 'invalidValue') };
  }
  const updated = await store.replaceGroup(request.tenantId, request.pathId, {
    displayName,
    externalId: externalIdOf(body),
    memberIds: memberIdsOf(body),
  });
  return updated === null ? notFound() : { status: 200, body: toScimGroup(updated) };
}

/** DELETE `/Groups/:id` : suppression du groupe (les membres ne sont pas supprimés). 204/404. */
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
