/**
 * Mapping Row -> contract types, FAIL-CLOSED.
 *
 * Postgres returns `null` and wide `string` values; our contracts use literal
 * unions and property absence (exactOptionalPropertyTypes). This module does the
 * safe conversion: any unknown union value DROPS the affected element (grant or
 * rule), never a phantom `allow`. No blind trust in the JSON column `ctx` /
 * `obligations`.
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

/** Minimal log to trace what the fail-closed mapping discarded. */
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

/** Maps a grant. Returns `null` (ignored) if scope or source is unknown. */
export function toGrant(row: GrantRow, logger?: AdapterLogger): Grant | null {
  const scope = toScope(row.scope);
  const source = toSource(row.source);
  if (scope === null || source === null) {
    logger?.warn(
      `prisma-adapter: grant ignored (scope=${row.scope}, source=${row.source}, permission=${row.permission})`,
    );
    return null;
  }
  return row.expiresAt === null
    ? { permission: row.permission, scope, source }
    : { permission: row.permission, scope, source, expiresAt: row.expiresAt };
}

/** Maps a role, discarding invalid grants fail-closed. */
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

/** Maps a JSON obligation. Returns `null` if the type is unknown. */
export function toObligation(raw: unknown, logger?: AdapterLogger): Obligation | null {
  const rec = asRecord(raw);
  if (rec === null) {
    return null;
  }
  const type = asString(rec['type']);
  if (type === null || !OBLIGATION_TYPES.has(type)) {
    logger?.warn(`prisma-adapter: obligation ignored (type=${type ?? 'null'})`);
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
 * Maps a rule. Fail-closed: a rule with an unknown effect OR with a scope present
 * but invalid is DISCARDED (returns `null`), never widened.
 */
export function toPolicyRule(row: PolicyRuleRow, logger?: AdapterLogger): PolicyRule | null {
  const effect = toEffect(row.effect);
  if (effect === null) {
    logger?.warn(`prisma-adapter: rule ignored (unknown effect=${row.effect})`);
    return null;
  }
  let scope: Scope | undefined;
  if (row.scope !== null) {
    const parsed = toScope(row.scope);
    if (parsed === null) {
      logger?.warn(`prisma-adapter: rule ignored (unknown scope=${row.scope})`);
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

/** Maps a policy, discarding invalid rules fail-closed. */
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
 * Rebuilds an `AuthContext` from the JSON column `ctx`. Fail-closed:
 * `authTime` falls back to 0 if absent/unreadable; empty sub-objects are omitted.
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

/** Maps a session row into a `SessionHandle`. */
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
