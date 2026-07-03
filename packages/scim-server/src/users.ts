/**
 * Handlers SCIM 2.0 `/Users` — PURS (`(store, requête) → réponse`), sans HTTP.
 *
 * Doctrine (RFC 7644) : provisioning RÉCONCILIÉ PAR E-MAIL (insensible à la casse, jamais
 * de doublon), déprovisionnement = DÉSACTIVATION (jamais de suppression), erreurs SCIM
 * conformes. L'adapter (NestJS…) résout tenant + parse le corps, puis délègue ici.
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
  return { status: 400, body: scimError(400, 'Identifiant de ressource requis.', 'invalidValue') };
}

function notFound(): ScimResponse {
  return { status: 404, body: scimError(404, 'Utilisateur introuvable.') };
}

/**
 * POST `/Users` : crée l'utilisateur, ou RÉCONCILIE un existant par e-mail (idempotent).
 * Existant ⇒ 200 sans doublon ; nouveau ⇒ 201. `userName`/e-mail obligatoire (400 sinon).
 */
export async function handleUsersPost(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  const body = asRecord(request.body);
  const email = emailOf(body);
  if (email === null) {
    return { status: 400, body: scimError(400, 'userName (e-mail) requis.', 'invalidValue') };
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
 * POST `/Users` en mode STRICT RFC 7644 §3.3 / validateur Microsoft Entra : un `userName`
 * déjà présent (insensible à la casse) ⇒ 409 `uniqueness` (JAMAIS de réconciliation). À
 * câbler quand l'IdP attend le rejet de doublon plutôt que l'idempotence par e-mail.
 */
export async function handleUsersPostStrict(
  store: ScimStore,
  request: ScimRequest,
): Promise<ScimResponse> {
  const body = asRecord(request.body);
  const email = emailOf(body);
  if (email === null) {
    return { status: 400, body: scimError(400, 'userName (e-mail) requis.', 'invalidValue') };
  }
  const existing = await store.findUserByEmail(request.tenantId, email);
  if (existing !== null) {
    return {
      status: 409,
      body: scimError(409, `userName déjà utilisé : ${email}.`, 'uniqueness'),
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

/** GET `/Users/:id` : 200 avec la ressource, ou 404 SCIM. */
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
 * GET `/Users` : `ListResponse` SCIM. Supporte les filtres `userName eq "..."` ET
 * `externalId eq "..."` (exigés par le validateur Entra) + pagination (`startIndex`/`count`).
 * Filtre présent mais non supporté ⇒ liste vide (jamais d'erreur).
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
 * PATCH `/Users/:id` (RFC 7644 §3.5.2) : activation/désactivation et champs d'identité.
 * Partiel : les champs absents ne sont pas touchés. 404 si l'utilisateur n'existe pas.
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
 * PUT `/Users/:id` : remplacement complet (identité + `active`). L'activation peut changer
 * (réactivation/déprovisionnement IdP). 404 si absent, 400 si l'e-mail manque.
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
    return { status: 400, body: scimError(400, 'userName (e-mail) requis.', 'invalidValue') };
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
 * DELETE `/Users/:id` : DÉPROVISIONNEMENT = DÉSACTIVATION (active=false), jamais de
 * suppression physique. 204 si effectué, 404 si l'utilisateur n'existe pas.
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
