/**
 * Mapping schema TransLog -> contrats Kengela, FAIL-CLOSED.
 *
 * Deux conversions vivent ici :
 *  1. Permission TransLog `plane.module.action.SCOPE` -> Grant Kengela. Le DERNIER
 *     segment est le jeton de portee ; le reste est la permission Kengela. Un jeton
 *     de portee INCONNU fait TOMBER le grant (jamais d'elargissement fantome).
 *  2. Ligne `Session` -> `SessionHandle`. Le `AuthContext` est reconstitue de
 *     maniere LOSSY : TransLog ne persiste que `ipAddress` + `userAgent` (ni geo,
 *     ni risk, ni device-id). `exactOptionalPropertyTypes` impose de NE PAS ajouter
 *     les cles absentes.
 */
import type { AuthContext, Grant, Scope, SessionHandle } from '@kengela/contracts';
import type { RolePermissionRow, SessionRow } from './translog-prisma-like.js';

/** Journal minimal pour tracer ce que le mapping fail-closed a ecarte. */
export interface AdapterLogger {
  warn(message: string): void;
}

/**
 * Correspondance jeton de portee TransLog -> `Scope` Kengela.
 *  own -> own | agency -> unit | tenant -> tenant | global -> global.
 * Tout autre jeton est INCONNU => fail-closed.
 */
const SCOPE_TOKEN_MAP: ReadonlyMap<string, Scope> = new Map<string, Scope>([
  ['own', 'own'],
  ['agency', 'unit'],
  ['tenant', 'tenant'],
  ['global', 'global'],
]);

/**
 * Convertit une permission TransLog en `Grant` Kengela. Retourne `null` (ignore)
 * si la chaine est malformee (pas de segment de portee) ou si le jeton de portee
 * est inconnu. `source` = MANUAL (RBAC statique), sans expiration.
 */
export function permissionToGrant(raw: string, logger?: AdapterLogger): Grant | null {
  const idx = raw.lastIndexOf('.');
  if (idx <= 0 || idx === raw.length - 1) {
    logger?.warn(`connector-translog: permission malformee ignoree (${raw})`);
    return null;
  }
  const scopeToken = raw.slice(idx + 1);
  const permission = raw.slice(0, idx);
  const scope = SCOPE_TOKEN_MAP.get(scopeToken);
  if (scope === undefined) {
    logger?.warn(
      `connector-translog: scope inconnu, grant ignore (token=${scopeToken}, permission=${raw})`,
    );
    return null;
  }
  return { permission, scope, source: 'MANUAL' };
}

/** Mappe des lignes `RolePermission`, en ecartant fail-closed les invalides. */
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
 * Reconstitue (LOSSY) un `AuthContext` depuis une ligne de session TransLog.
 *  - authTime <- createdAt.getTime() (approximation : TransLog n'a pas d'authTime dedie)
 *  - ip <- ipAddress (omis si null)
 *  - device <- { userAgent } (omis si userAgent null)
 * geo, riskScore et device.id/trusted sont PERDUS (non stockes cote TransLog).
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
