/**
 * Mapping engine IdP → application roles + organizational attachment.
 *
 * Rules are **configurable per tenant** (never hardcoded, consistent with the `Role` RBAC
 * of the tenant catalog). Each rule tests the `DirectoryProfile` (security groups, OIDC
 * claims, SCIM attributes) and, on a match, grants role keys and/or an attachment directive
 * to an org-chart unit.
 *
 * Deterministic: evaluation by ascending priority, tie-broken by `id`. Roles accumulate
 * (union); the first unit directive wins (highest priority). `stopOnMatch` enables
 * "short-circuit" rules.
 *
 * PURE: no infra dependency.
 */
import type { DirectoryProfile } from './profile.js';
import { safeRegexTest } from './safe-regex.js';

export type MappingSource = 'GROUP' | 'CLAIM' | 'ATTRIBUTE';

/**
 * Comparison operators (whitespace-insensitive). `matches` = regular expression (implicitly
 * anchored by the author), `in` = membership in a list, `present` = non-empty field (value
 * ignored).
 */
export type MatchOp = 'equals' | 'iequals' | 'contains' | 'matches' | 'in' | 'present';

export interface MappingCondition {
  readonly source: MappingSource;
  /** Name of the target claim/attribute. Ignored for `GROUP` (tests the group list). */
  readonly key?: string;
  readonly op: MatchOp;
  /** Comparison value (string) or list (for `in`); regex source for `matches`. */
  readonly value?: string | readonly string[];
}

/** Target attachment to an org-chart unit produced by a rule. */
export interface OrgUnitDirective {
  /** Resolution by code (`OrgUnit.code`) or by name (`OrgUnit.name`). */
  readonly by: 'code' | 'name';
  /** Literal value, OR if absent, read from the profile's `fromAttribute` attribute. */
  readonly value?: string;
  readonly fromAttribute?: keyof DirectoryProfile['attributes'];
}

export interface IdpMappingRule {
  readonly id: string;
  readonly description?: string;
  /** Ascending: 0 evaluated first. Stable tie-break by `id`. */
  readonly priority: number;
  /** If the rule matches, stops evaluating the remaining rules. */
  readonly stopOnMatch?: boolean;
  /** All conditions must be true (logical AND). */
  readonly all?: readonly MappingCondition[];
  /** At least one condition must be true (logical OR). */
  readonly any?: readonly MappingCondition[];
  /** Role keys from the tenant catalog to grant (e.g. `"VAL"`, `"ADM"`). */
  readonly assignRoleKeys?: readonly string[];
  /** Organizational attachment directive. */
  readonly orgUnit?: OrgUnitDirective;
}

export interface MappingResult {
  /** Union of the role keys granted by the matching rules. */
  readonly roleKeys: readonly string[];
  /** Unit directives, by priority (the first = the highest priority). */
  readonly orgUnitDirectives: readonly OrgUnitDirective[];
  /** Ids of the rules that matched (audit / dry-run). */
  readonly matchedRuleIds: readonly string[];
}

function norm(s: string): string {
  return s.trim().toLowerCase();
}

function valuesFor(profile: DirectoryProfile, cond: MappingCondition): string[] {
  if (cond.source === 'GROUP') return [...profile.groups];
  if (cond.source === 'ATTRIBUTE') {
    const v = cond.key ? (profile.attributes as Record<string, unknown>)[cond.key] : undefined;
    return typeof v === 'string' && v ? [v] : [];
  }
  // CLAIM
  const raw = cond.key ? profile.claims[cond.key] : undefined;
  if (typeof raw === 'string') return raw ? [raw] : [];
  if (Array.isArray(raw)) return raw.filter((x): x is string => typeof x === 'string');
  if (typeof raw === 'number' || typeof raw === 'boolean') return [String(raw)];
  return [];
}

function condMatches(profile: DirectoryProfile, cond: MappingCondition): boolean {
  const actual = valuesFor(profile, cond);
  if (cond.op === 'present') return actual.length > 0;
  if (actual.length === 0) return false;

  switch (cond.op) {
    case 'equals':
      return actual.some((a) => a === cond.value);
    case 'iequals':
      return (
        typeof cond.value === 'string' && actual.some((a) => norm(a) === norm(cond.value as string))
      );
    case 'contains':
      return (
        typeof cond.value === 'string' &&
        actual.some((a) => norm(a).includes(norm(cond.value as string)))
      );
    case 'in': {
      const set = new Set(
        (Array.isArray(cond.value) ? cond.value : [cond.value as string]).map(norm),
      );
      return actual.some((a) => set.has(norm(a)));
    }
    case 'matches': {
      if (typeof cond.value !== 'string') return false;
      // Bounded regex (anti-ReDoS): invalid/too-complex pattern → fail-closed (see safe-regex.ts).
      return actual.some((a) => safeRegexTest(cond.value as string, a));
    }
    default:
      return false;
  }
}

function ruleMatches(profile: DirectoryProfile, rule: IdpMappingRule): boolean {
  const all = rule.all ?? [];
  const any = rule.any ?? [];
  if (all.length === 0 && any.length === 0) return false; // empty rule ⇒ never (fail-closed)
  const allOk = all.every((c) => condMatches(profile, c));
  const anyOk = any.length === 0 || any.some((c) => condMatches(profile, c));
  return allOk && anyOk;
}

/**
 * Evaluates a tenant's full rule set against a profile. Deterministic: sorted by
 * (priority, id). Accumulates roles (union), collects unit directives in priority
 * order, honors `stopOnMatch`.
 */
export function evaluateMappings(
  profile: DirectoryProfile,
  rules: readonly IdpMappingRule[],
): MappingResult {
  const ordered = [...rules].sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
  const roleKeys = new Set<string>();
  const orgUnitDirectives: OrgUnitDirective[] = [];
  const matchedRuleIds: string[] = [];

  for (const rule of ordered) {
    if (!ruleMatches(profile, rule)) continue;
    matchedRuleIds.push(rule.id);
    for (const key of rule.assignRoleKeys ?? []) roleKeys.add(key);
    if (rule.orgUnit) orgUnitDirectives.push(rule.orgUnit);
    if (rule.stopOnMatch) break;
  }

  return { roleKeys: [...roleKeys], orgUnitDirectives, matchedRuleIds };
}
