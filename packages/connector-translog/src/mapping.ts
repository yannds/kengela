/**
 * Mapping TransLog schema -> Kengela contracts, FAIL-CLOSED.
 *
 * Two conversions live here:
 *  1. TransLog permission `plane.module.action.SCOPE` -> Kengela Grant. The LAST
 *     segment is the scope token; the rest is the Kengela permission. An UNKNOWN
 *     scope token DROPS the grant (never a phantom broadening).
 *  2. `Session` row -> `SessionHandle`. The `AuthContext` is reconstituted in a LOSSY
 *     way: TransLog persists only `ipAddress` + `userAgent` (no geo, no risk, no
 *     device-id). `exactOptionalPropertyTypes` requires NOT adding absent keys.
 */
import type { AuthContext, Grant, Scope, SessionHandle } from '@kengela/contracts';
import type { RolePermissionRow, SessionRow } from './translog-prisma-like.js';

/** Minimal log to trace what the fail-closed mapping discarded. */
export interface AdapterLogger {
  warn(message: string): void;
}

/**
 * Mapping of a TransLog scope token -> Kengela `Scope`.
 *  own -> own | agency -> unit | tenant -> tenant | global -> global.
 * Any other token is UNKNOWN => fail-closed.
 */
const SCOPE_TOKEN_MAP: ReadonlyMap<string, Scope> = new Map<string, Scope>([
  ['own', 'own'],
  ['agency', 'unit'],
  ['tenant', 'tenant'],
  ['global', 'global'],
]);

/**
 * Converts a TransLog permission into a Kengela `Grant`. Returns `null` (ignored) if the
 * string is malformed (no scope segment) or if the scope token is unknown. `source` =
 * MANUAL (static RBAC), no expiration.
 */
export function permissionToGrant(raw: string, logger?: AdapterLogger): Grant | null {
  const idx = raw.lastIndexOf('.');
  if (idx <= 0 || idx === raw.length - 1) {
    logger?.warn(`connector-translog: malformed permission ignored (${raw})`);
    return null;
  }
  const scopeToken = raw.slice(idx + 1);
  const permission = raw.slice(0, idx);
  const scope = SCOPE_TOKEN_MAP.get(scopeToken);
  if (scope === undefined) {
    logger?.warn(
      `connector-translog: unknown scope, grant ignored (token=${scopeToken}, permission=${raw})`,
    );
    return null;
  }
  return { permission, scope, source: 'MANUAL' };
}

/** Maps `RolePermission` rows, discarding the invalid ones fail-closed. */
export function permissionsToGrants(
  rows: readonly RolePermissionRow[],
  logger?: AdapterLogger,
): Grant[] {
  const grants: Grant[] = [];
  for (const row of rows) {
    const grant = permissionToGrant(row.permission, logger);
    if (grant !== null) {
      grants.push(grant);
    }
  }
  return grants;
}

/**
 * Reconstitutes (LOSSY) an `AuthContext` from a TransLog session row.
 *  - authTime <- createdAt.getTime() (approximation: TransLog has no dedicated authTime)
 *  - ip <- ipAddress (omitted if null)
 *  - device <- { userAgent } (omitted if userAgent null)
 * geo, riskScore and device.id/trusted are LOST (not stored on the TransLog side).
 */
export function toSessionHandle(row: SessionRow): SessionHandle {
  const ctx: AuthContext = {
    authTime: row.createdAt.getTime(),
    ...(row.ipAddress !== null ? { ip: row.ipAddress } : {}),
    ...(row.userAgent !== null ? { device: { userAgent: row.userAgent } } : {}),
  };
  return {
    token: row.token,
    userId: row.userId,
    tenantId: row.tenantId,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    ctx,
  };
}
