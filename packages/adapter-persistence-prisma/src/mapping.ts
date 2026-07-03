/**
 * Mapping Row -> types de contrats, FAIL-CLOSED.
 *
 * Postgres renvoie `null` et des `string` larges ; nos contrats utilisent des
 * unions litterales et l'absence de propriete (exactOptionalPropertyTypes). Ce
 * module fait la conversion sure : toute valeur d'union inconnue fait TOMBER
 * l'element concerne (grant ou regle), jamais un `allow` fantome. Aucune
 * confiance aveugle dans la colonne JSON `ctx` / `obligations`.
 */
import type {
  AuthContext,
  Effect,
  Grant,
  Obligation,
  Policy,
  PolicyRule,
  Role,
  Scope,
  SessionHandle,
} from '@kengela/contracts';
import type { GrantRow, PolicyRow, PolicyRuleRow, RoleRow, SessionRow } from './prisma-like.js';

/** Journal minimal pour tracer ce que le mapping fail-closed a ecarte. */
export interface AdapterLogger {
  warn(message: string): void;
}

const SCOPE_VALUES: ReadonlySet<string> = new Set(['own', 'unit', 'subtree', 'tenant', 'global']);
const SOURCE_VALUES: ReadonlySet<string> = new Set(['MANUAL', 'IDP', 'DELEGATION']);
const EFFECT_VALUES: ReadonlySet<string> = new Set(['allow', 'deny', 'step_up']);
const OBLIGATION_TYPES: ReadonlySet<string> = new Set([
  'require_mfa',
  'require_passkey',
  'reauthenticate',
  'notify',
]);

function toScope(raw: string): Scope | null {
  return SCOPE_VALUES.has(raw) ? (raw as Scope) : null;
}

function toSource(raw: string): Grant['source'] | null {
  return SOURCE_VALUES.has(raw) ? (raw as Grant['source']) : null;
}

function toEffect(raw: string): Effect | null {
  return EFFECT_VALUES.has(raw) ? (raw as Effect) : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

/** Mappe un grant. Retourne `null` (ignore) si scope ou source est inconnu. */
export function toGrant(row: GrantRow, logger?: AdapterLogger): Grant | null {
  const scope = toScope(row.scope);
  const source = toSource(row.source);
  if (scope === null || source === null) {
    logger?.warn(
      `prisma-adapter: grant ignore (scope=${row.scope}, source=${row.source}, permission=${row.permission})`,
    );
    return null;
  }
  return row.expiresAt === null
    ? { permission: row.permission, scope, source }
    : { permission: row.permission, scope, source, expiresAt: row.expiresAt };
}

/** Mappe un role, en ecartant fail-closed les grants invalides. */
export function toRole(row: RoleRow, logger?: AdapterLogger): Role {
  const grants: Grant[] = [];
  for (const grantRow of row.grants) {
    const grant = toGrant(grantRow, logger);
    if (grant !== null) {
      grants.push(grant);
    }
  }
  return { key: row.key, tenantId: row.tenantId, grants };
}

/** Mappe une obligation JSON. Retourne `null` si type inconnu. */
export function toObligation(raw: unknown, logger?: AdapterLogger): Obligation | null {
  const rec = asRecord(raw);
  if (rec === null) {
    return null;
  }
  const type = asString(rec['type']);
  if (type === null || !OBLIGATION_TYPES.has(type)) {
    logger?.warn(`prisma-adapter: obligation ignoree (type=${type ?? 'null'})`);
    return null;
  }
  const obligationType = type as Obligation['type'];
  const params = asRecord(rec['params']);
  return params === null ? { type: obligationType } : { type: obligationType, params };
}

function toObligations(raw: unknown, logger?: AdapterLogger): Obligation[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const items: readonly unknown[] = raw;
  const obligations: Obligation[] = [];
  for (const item of items) {
    const obligation = toObligation(item, logger);
    if (obligation !== null) {
      obligations.push(obligation);
    }
  }
  return obligations;
}

/**
 * Mappe une regle. Fail-closed : une regle a l'effet inconnu OU au scope present
 * mais invalide est ECARTEE (retour `null`), jamais elargie.
 */
export function toPolicyRule(row: PolicyRuleRow, logger?: AdapterLogger): PolicyRule | null {
  const effect = toEffect(row.effect);
  if (effect === null) {
    logger?.warn(`prisma-adapter: regle ignoree (effect inconnu=${row.effect})`);
    return null;
  }
  let scope: Scope | undefined;
  if (row.scope !== null) {
    const parsed = toScope(row.scope);
    if (parsed === null) {
      logger?.warn(`prisma-adapter: regle ignoree (scope inconnu=${row.scope})`);
      return null;
    }
    scope = parsed;
  }
  const when = row.when ?? undefined;
  const reason = row.reason ?? undefined;
  const obligations = row.obligations === null ? undefined : toObligations(row.obligations, logger);
  return {
    effect,
    ...(scope !== undefined ? { scope } : {}),
    ...(when !== undefined ? { when } : {}),
    ...(obligations !== undefined ? { obligations } : {}),
    ...(reason !== undefined ? { reason } : {}),
  };
}

/** Mappe une policy, en ecartant fail-closed les regles invalides. */
export function toPolicy(row: PolicyRow, logger?: AdapterLogger): Policy {
  const rules: PolicyRule[] = [];
  for (const ruleRow of row.rules) {
    const rule = toPolicyRule(ruleRow, logger);
    if (rule !== null) {
      rules.push(rule);
    }
  }
  return { resource: row.resource, action: row.action, rules };
}

function toGeo(raw: unknown): AuthContext['geo'] {
  const rec = asRecord(raw);
  if (rec === null) {
    return undefined;
  }
  const country = asString(rec['country']) ?? undefined;
  const lat = asNumber(rec['lat']) ?? undefined;
  const lng = asNumber(rec['lng']) ?? undefined;
  if (country === undefined && lat === undefined && lng === undefined) {
    return undefined;
  }
  return {
    ...(country !== undefined ? { country } : {}),
    ...(lat !== undefined ? { lat } : {}),
    ...(lng !== undefined ? { lng } : {}),
  };
}

function toDevice(raw: unknown): AuthContext['device'] {
  const rec = asRecord(raw);
  if (rec === null) {
    return undefined;
  }
  const id = asString(rec['id']) ?? undefined;
  const trusted = asBoolean(rec['trusted']) ?? undefined;
  const userAgent = asString(rec['userAgent']) ?? undefined;
  if (id === undefined && trusted === undefined && userAgent === undefined) {
    return undefined;
  }
  return {
    ...(id !== undefined ? { id } : {}),
    ...(trusted !== undefined ? { trusted } : {}),
    ...(userAgent !== undefined ? { userAgent } : {}),
  };
}

/**
 * Reconstitue un `AuthContext` depuis la colonne JSON `ctx`. Fail-closed :
 * `authTime` retombe a 0 si absent/illisible ; les sous-objets vides sont omis.
 */
export function toAuthContext(raw: unknown): AuthContext {
  const rec = asRecord(raw);
  if (rec === null) {
    return { authTime: 0 };
  }
  const authTime = asNumber(rec['authTime']) ?? 0;
  const ip = asString(rec['ip']) ?? undefined;
  const riskScore = asNumber(rec['riskScore']) ?? undefined;
  const geo = toGeo(rec['geo']);
  const device = toDevice(rec['device']);
  return {
    authTime,
    ...(ip !== undefined ? { ip } : {}),
    ...(riskScore !== undefined ? { riskScore } : {}),
    ...(geo !== undefined ? { geo } : {}),
    ...(device !== undefined ? { device } : {}),
  };
}

/** Mappe une ligne de session en `SessionHandle`. */
export function toSessionHandle(row: SessionRow): SessionHandle {
  return {
    token: row.token,
    userId: row.userId,
    tenantId: row.tenantId,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    ctx: toAuthContext(row.ctx),
  };
}
