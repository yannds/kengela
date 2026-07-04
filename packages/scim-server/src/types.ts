/**
 * SCIM 2.0 core contracts (RFC 7643/7644) - `ScimStore` port + request/response shapes.
 * Framework-agnostic: no HTTP reference, no vendor dependency.
 *
 * The port is NARROW and SCIM-oriented: it exposes exactly what the handlers need (email
 * reconciliation, pagination, deactivation != deletion, group members). An adapter
 * (Prisma, NestJS...) implements it; the handlers consume it.
 */
import type { TenantId } from '@kengela/contracts';

// -- Persistence rows (explicit shapes) ---------------------------------------
/** SCIM user as stored/reread. `userName` carries the email (reconciliation key). */
export interface ScimUserRow {
  readonly id: string;
  readonly userName: string;
  readonly externalId: string | null;
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly active: boolean;
  /** ISO 8601 creation timestamp. */
  readonly createdAt: string;
  /** ISO 8601 last-modification timestamp. */
  readonly lastModified: string;
}

/** SCIM group as stored/reread, with its members (user ids). */
export interface ScimGroupRow {
  readonly id: string;
  readonly displayName: string;
  readonly externalId: string | null;
  readonly memberIds: readonly string[];
  readonly createdAt: string;
  readonly lastModified: string;
}

// -- Write inputs -------------------------------------------------------------
/** Fields of a user to create (POST) or fully replace (PUT). */
export interface ScimUserWriteInput {
  readonly userName: string;
  readonly externalId: string | null;
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly active: boolean;
}

/**
 * Identity fields touched by a PATCH. `undefined` = untouched; `null` = cleared;
 * string = value set (RFC 7644 §3.5.2, add/replace/remove semantics).
 */
export interface ScimUserIdentityPatch {
  readonly firstName?: string | null;
  readonly lastName?: string | null;
  readonly displayName?: string | null;
}

/** Normalized user PATCH: activation + touched identity fields. */
export interface ScimUserPatch {
  /** New value of `active`, or `null` if the PATCH does not touch it. */
  readonly active: boolean | null;
  readonly identity: ScimUserIdentityPatch;
}

/** Fields of a group to create (POST) or fully replace (PUT). */
export interface ScimGroupWriteInput {
  readonly displayName: string;
  readonly externalId: string | null;
  readonly memberIds: readonly string[];
}

/** Normalized group-member operation from a SCIM PATCH (RFC 7644 §3.5.2). */
export type GroupMemberPatch =
  | { readonly kind: 'add'; readonly members: readonly string[] }
  | { readonly kind: 'remove'; readonly members: readonly string[] }
  | { readonly kind: 'replace'; readonly members: readonly string[] };

// -- List options + page ------------------------------------------------------
/**
 * `listUsers` options: optional `userName eq` / `externalId eq` filters (at least one of the
 * two, never both at once) + 1-based pagination. `userName` equals in a CASE-INSENSITIVE way;
 * `externalId` is `caseExact` (exact comparison).
 */
export interface ScimUserListOptions {
  readonly userName?: string;
  readonly externalId?: string;
  readonly startIndex: number;
  readonly count: number;
}

/** `listGroups` options: optional `displayName eq` filter + 1-based pagination. */
export interface ScimGroupListOptions {
  readonly displayName?: string;
  readonly startIndex: number;
  readonly count: number;
}

/**
 * Page of results returned by the store. `totalResults` = total BEFORE pagination;
 * `resources` = requested slice; `itemsPerPage` = slice size.
 */
export interface ScimListPage<TRow> {
  readonly resources: readonly TRow[];
  readonly totalResults: number;
  readonly startIndex: number;
  readonly itemsPerPage: number;
}

// -- Persistence port ---------------------------------------------------------
/**
 * SCIM persistence port (Users + Groups). Every operation is bounded to the tenant.
 *
 * Invariants expected from the implementation:
 *  - `findUserByEmail`: CASE-INSENSITIVE reconciliation (provisioning idempotency).
 *  - `deactivateUser`: DEACTIVATES (active=false), never DELETES (GDPR-safe deprovisioning).
 *  - `listUsers`/`listGroups`: return `totalResults` = filtered total BEFORE pagination.
 */
export interface ScimStore {
  getUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null>;
  findUserByEmail(tenantId: TenantId, email: string): Promise<ScimUserRow | null>;
  listUsers(tenantId: TenantId, options: ScimUserListOptions): Promise<ScimListPage<ScimUserRow>>;
  createUser(tenantId: TenantId, input: ScimUserWriteInput): Promise<ScimUserRow>;
  replaceUser(
    tenantId: TenantId,
    id: string,
    input: ScimUserWriteInput,
  ): Promise<ScimUserRow | null>;
  patchUser(tenantId: TenantId, id: string, patch: ScimUserPatch): Promise<ScimUserRow | null>;
  deactivateUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null>;

  getGroup(tenantId: TenantId, id: string): Promise<ScimGroupRow | null>;
  listGroups(
    tenantId: TenantId,
    options: ScimGroupListOptions,
  ): Promise<ScimListPage<ScimGroupRow>>;
  createGroup(tenantId: TenantId, input: ScimGroupWriteInput): Promise<ScimGroupRow>;
  replaceGroup(
    tenantId: TenantId,
    id: string,
    input: ScimGroupWriteInput,
  ): Promise<ScimGroupRow | null>;
  patchGroup(
    tenantId: TenantId,
    id: string,
    ops: readonly GroupMemberPatch[],
  ): Promise<ScimGroupRow | null>;
  deleteGroup(tenantId: TenantId, id: string): Promise<boolean>;
}

// -- Request / response of the pure handlers ----------------------------------
/** SCIM query parameters already extracted by the HTTP layer (adapter). */
export interface ScimQuery {
  readonly filter?: string;
  readonly startIndex?: string | number;
  readonly count?: string | number;
}

/**
 * Parsed SCIM request, transport-independent. `pathId` = `/:id` segment; `body` =
 * already-deserialized JSON (validated by the handler); `query` = list parameters.
 */
export interface ScimRequest {
  readonly tenantId: TenantId;
  readonly pathId?: string;
  readonly query?: ScimQuery;
  readonly body?: unknown;
}

/**
 * Neutral SCIM response: an HTTP status + a JSON body (absent for 204). The adapter
 * serializes it as `application/scim+json`.
 */
export interface ScimResponse {
  readonly status: number;
  readonly body?: Readonly<Record<string, unknown>>;
}

/** Common signature of a pure SCIM handler: `(store, request) -> response`. */
export type ScimHandler = (store: ScimStore, request: ScimRequest) => Promise<ScimResponse>;
