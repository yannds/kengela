/**
 * SCIM 2.0 serialization and parsing - PURE functions (RFC 7643/7644).
 *
 * Serializes store rows into SCIM resources (`schemas`/`id`/`meta`), builds the
 * `ListResponse` and `Error`, and interprets incoming bodies: email (userName union emails),
 * identity, Users/Groups PATCH, `eq` filters (bounded regex, anti-ReDoS) and pagination.
 */
import { SCIM_SCHEMA_CORE_USER, SCIM_SCHEMA_GROUP } from '@kengela/iam-mapping';
import type {
  GroupMemberPatch,
  ScimGroupRow,
  ScimListPage,
  ScimQuery,
  ScimUserPatch,
  ScimUserRow,
} from './types.js';

// -- URNs of the SCIM API messages (RFC 7644 §3.4 / §3.12) --------------------
export const SCIM_SCHEMA_LIST_RESPONSE = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
export const SCIM_SCHEMA_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';
export const SCIM_SCHEMA_PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

/** Default page size and cap (bounds the `itemsPerPage` requested by the IdP). */
export const DEFAULT_PAGE_SIZE = 100;
export const MAX_PAGE_SIZE = 200;

// -- Narrowing helpers (fail-closed, no `any`) --------------------------------
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** Coerces an unknown object entry into a readable record (never `any`). */
export function asRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function coerceBool(value: unknown): boolean {
  return value === true || value === 'true' || value === 'True';
}

function strOf(value: unknown): string | null {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return null;
}

// -- Resource serialization ---------------------------------------------------
/** SCIM 2.0 representation of a user (RFC 7643 §4.1). */
export function toScimUser(row: ScimUserRow): Record<string, unknown> {
  const out: Record<string, unknown> = {
    schemas: [SCIM_SCHEMA_CORE_USER],
    id: row.id,
    userName: row.userName,
    emails: [{ value: row.userName, primary: true }],
    active: row.active,
    meta: {
      resourceType: 'User',
      location: `Users/${row.id}`,
      created: row.createdAt,
      lastModified: row.lastModified,
    },
  };
  if (row.externalId !== null) {
    out['externalId'] = row.externalId;
  }
  if (row.firstName !== null || row.lastName !== null) {
    const name: Record<string, unknown> = {};
    if (row.firstName !== null) {
      name['givenName'] = row.firstName;
    }
    if (row.lastName !== null) {
      name['familyName'] = row.lastName;
    }
    out['name'] = name;
  }
  if (row.displayName !== null) {
    out['displayName'] = row.displayName;
  }
  return out;
}

/** SCIM 2.0 representation of a group + its members (RFC 7643 §4.2). */
export function toScimGroup(row: ScimGroupRow): Record<string, unknown> {
  const out: Record<string, unknown> = {
    schemas: [SCIM_SCHEMA_GROUP],
    id: row.id,
    displayName: row.displayName,
    members: row.memberIds.map((value) => ({ value })),
    meta: {
      resourceType: 'Group',
      location: `Groups/${row.id}`,
      created: row.createdAt,
      lastModified: row.lastModified,
    },
  };
  if (row.externalId !== null) {
    out['externalId'] = row.externalId;
  }
  return out;
}

function buildListResponse(
  resources: readonly Record<string, unknown>[],
  totalResults: number,
  startIndex: number,
): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMA_LIST_RESPONSE],
    totalResults,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

/** SCIM `ListResponse` of a page of users (RFC 7644 §3.4.2). */
export function userListResponse(page: ScimListPage<ScimUserRow>): Record<string, unknown> {
  return buildListResponse(
    page.resources.map((row) => toScimUser(row)),
    page.totalResults,
    page.startIndex,
  );
}

/** SCIM `ListResponse` of a page of groups. */
export function groupListResponse(page: ScimListPage<ScimGroupRow>): Record<string, unknown> {
  return buildListResponse(
    page.resources.map((row) => toScimGroup(row)),
    page.totalResults,
    page.startIndex,
  );
}

/** SCIM error envelope (RFC 7644 §3.12): `status` (string) + `scimType` + `detail`. */
export function scimError(
  status: number,
  detail: string,
  scimType?: string,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    schemas: [SCIM_SCHEMA_ERROR],
    status: String(status),
    detail,
  };
  if (scimType !== undefined) {
    out['scimType'] = scimType;
  }
  return out;
}

// -- Reading incoming bodies --------------------------------------------------
/** Email of a SCIM body: `userName` first, otherwise the primary email, otherwise null. */
export function emailOf(body: Record<string, unknown>): string | null {
  const userName = body['userName'];
  if (typeof userName === 'string' && userName.trim() !== '') {
    return userName.trim();
  }
  const emails = body['emails'];
  if (Array.isArray(emails)) {
    const list: readonly unknown[] = emails;
    const primary = list.find((entry) => isRecord(entry) && entry['primary'] === true);
    const chosen = primary ?? list[0];
    if (isRecord(chosen)) {
      const value = chosen['value'];
      if (typeof value === 'string' && value.trim() !== '') {
        return value.trim();
      }
    }
  }
  return null;
}

/** First name (`name.givenName`) non-empty, otherwise null. */
export function givenNameOf(body: Record<string, unknown>): string | null {
  const name = body['name'];
  if (isRecord(name)) {
    const value = name['givenName'];
    if (typeof value === 'string' && value.trim() !== '') {
      return value.trim();
    }
  }
  return null;
}

/** Last name (`name.familyName`) non-empty, otherwise null. */
export function familyNameOf(body: Record<string, unknown>): string | null {
  const name = body['name'];
  if (isRecord(name)) {
    const value = name['familyName'];
    if (typeof value === 'string' && value.trim() !== '') {
      return value.trim();
    }
  }
  return null;
}

/** Display name: explicit `displayName`, otherwise `givenName + familyName`, otherwise null. */
export function displayNameOf(body: Record<string, unknown>): string | null {
  const dn = body['displayName'];
  if (typeof dn === 'string' && dn.trim() !== '') {
    return dn.trim();
  }
  const parts = [givenNameOf(body), familyNameOf(body)].filter(
    (part): part is string => part !== null,
  );
  return parts.length > 0 ? parts.join(' ') : null;
}

/** Group `displayName` (required): non-empty string, otherwise null. */
export function groupDisplayNameOf(body: Record<string, unknown>): string | null {
  const dn = body['displayName'];
  return typeof dn === 'string' && dn.trim() !== '' ? dn.trim() : null;
}

/** `externalId` non-empty, otherwise null. */
export function externalIdOf(body: Record<string, unknown>): string | null {
  const value = body['externalId'];
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

/** `active` field of a full resource (PUT). Absent => true (SCIM default). */
export function activeOf(body: Record<string, unknown>): boolean {
  const value = body['active'];
  return value === undefined ? true : coerceBool(value);
}

/**
 * Interprets a SCIM `/Users` PATCH (RFC 7644 §3.5.2). Handles operations with an explicit
 * `path` (`active`, `displayName`, `name.givenName`, `name.familyName`) AND the "pathless"
 * form (partial `value` object emitted by some IdPs). `remove` => value cleared.
 */
export function parseUserPatch(body: Record<string, unknown>): ScimUserPatch {
  const identity: {
    firstName?: string | null;
    lastName?: string | null;
    displayName?: string | null;
  } = {};
  let active: boolean | null = null;
  const ops = body['Operations'];
  if (Array.isArray(ops)) {
    const list: readonly unknown[] = ops;
    for (const raw of list) {
      if (!isRecord(raw)) {
        continue;
      }
      const op = raw['op'];
      const kind = typeof op === 'string' ? op.toLowerCase() : '';
      if (kind !== 'add' && kind !== 'replace' && kind !== 'remove') {
        continue;
      }
      const removing = kind === 'remove';
      const pathRaw = raw['path'];
      const path = typeof pathRaw === 'string' ? pathRaw.trim() : '';
      const value = raw['value'];
      if (path === '') {
        if (isRecord(value)) {
          const av = value['active'];
          if (av !== undefined) {
            active = coerceBool(av);
          }
          const dn = value['displayName'];
          if (typeof dn === 'string') {
            identity.displayName = dn;
          }
          const gn = givenNameOf(value);
          if (gn !== null) {
            identity.firstName = gn;
          }
          const fn = familyNameOf(value);
          if (fn !== null) {
            identity.lastName = fn;
          }
        }
        continue;
      }
      if (path === 'active') {
        active = removing ? false : coerceBool(value);
      } else if (path === 'displayName') {
        identity.displayName = removing ? null : strOf(value);
      } else if (path === 'name.givenName') {
        identity.firstName = removing ? null : strOf(value);
      } else if (path === 'name.familyName') {
        identity.lastName = removing ? null : strOf(value);
      }
    }
  }
  return { active, identity };
}

/** Member ids (`members[].value`) of a SCIM group body. */
export function memberIdsOf(body: Record<string, unknown>): readonly string[] {
  return valuesOf(body['members']);
}

function valuesOf(value: unknown): readonly string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const list: readonly unknown[] = value;
  const out: string[] = [];
  for (const item of list) {
    if (isRecord(item)) {
      const v = item['value'];
      if (typeof v === 'string' && v !== '') {
        out.push(v);
      }
    }
  }
  return out;
}

const MEMBERS_PATH = /^members\[/i;
const MEMBER_VALUE_EQ = /value eq "?([^"\]]{1,256})"?/i;

/**
 * Interprets a SCIM `/Groups` PATCH (members, RFC 7644 §3.5.2) -> normalized operations.
 * Handles add/remove/replace on `members` and the targeted removal `members[value eq "<id>"]`
 * (emitted by Entra/Okta). Bounded filter (anti-ReDoS).
 */
export function parseGroupMemberPatch(body: Record<string, unknown>): readonly GroupMemberPatch[] {
  const ops = body['Operations'];
  if (!Array.isArray(ops)) {
    return [];
  }
  const list: readonly unknown[] = ops;
  const out: GroupMemberPatch[] = [];
  for (const raw of list) {
    if (!isRecord(raw)) {
      continue;
    }
    const op = raw['op'];
    const kind = typeof op === 'string' ? op.toLowerCase() : '';
    const pathRaw = raw['path'];
    const path = typeof pathRaw === 'string' ? pathRaw.trim() : '';
    if (kind === 'remove' && MEMBERS_PATH.test(path)) {
      const matched = MEMBER_VALUE_EQ.exec(path);
      const id = matched?.[1];
      if (id !== undefined && id !== '') {
        out.push({ kind: 'remove', members: [id] });
      }
      continue;
    }
    if (path !== '' && path !== 'members') {
      continue;
    }
    const members = valuesOf(raw['value']);
    if (kind === 'add') {
      out.push({ kind: 'add', members });
    } else if (kind === 'remove') {
      out.push({ kind: 'remove', members });
    } else if (kind === 'replace') {
      out.push({ kind: 'replace', members });
    }
  }
  return out;
}

// -- `eq` filters (bounded) + pagination ---------------------------------------
const USERNAME_FILTER = /^userName eq "([^"]{1,320})"$/i;
const EXTERNALID_FILTER = /^externalId eq "([^"]{1,320})"$/i;
const DISPLAYNAME_FILTER = /^displayName eq "([^"]{1,320})"$/i;

/** Value of a `userName eq "..."` filter (bounded regex), otherwise null. */
export function parseUserNameFilter(filter: string | undefined): string | null {
  if (filter === undefined) {
    return null;
  }
  const matched = USERNAME_FILTER.exec(filter.trim());
  return matched === null ? null : (matched[1] ?? null);
}

/**
 * Value of an `externalId eq "..."` filter (bounded regex), otherwise null. Required by the
 * Microsoft Entra validator to look up a user by its `externalId` anchor.
 */
export function parseExternalIdFilter(filter: string | undefined): string | null {
  if (filter === undefined) {
    return null;
  }
  const matched = EXTERNALID_FILTER.exec(filter.trim());
  return matched === null ? null : (matched[1] ?? null);
}

/** Value of a `displayName eq "..."` filter (bounded regex), otherwise null. */
export function parseDisplayNameFilter(filter: string | undefined): string | null {
  if (filter === undefined) {
    return null;
  }
  const matched = DISPLAYNAME_FILTER.exec(filter.trim());
  return matched === null ? null : (matched[1] ?? null);
}

function toInt(value: string | number | undefined, fallback: number): number {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10);
    if (Number.isInteger(parsed)) {
      return parsed;
    }
  }
  return fallback;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/** SCIM pagination: `startIndex` >= 1 (1-based) and `count` bounded to [0, MAX_PAGE_SIZE]. */
export function parsePagination(query: ScimQuery | undefined): {
  readonly startIndex: number;
  readonly count: number;
} {
  const startIndex = Math.max(1, toInt(query?.startIndex, 1));
  const count = clamp(toInt(query?.count, DEFAULT_PAGE_SIZE), 0, MAX_PAGE_SIZE);
  return { startIndex, count };
}
