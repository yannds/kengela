/**
 * Moteur de mapping IdP → rôles applicatifs + rattachement organisationnel.
 *
 * Règles **configurables par tenant** (jamais en dur, cohérent avec le RBAC `Role`
 * du catalogue tenant). Chaque règle teste le `DirectoryProfile` (groupes de sécurité,
 * claims OIDC, attributs SCIM) et, si elle correspond, accorde des clés de rôle et/ou
 * une directive de rattachement à une unité d'organigramme.
 *
 * Déterministe : évaluation par priorité croissante, départage par `id`. Les rôles
 * s'accumulent (union) ; la première directive d'unité gagne (priorité la plus haute).
 * `stopOnMatch` permet des règles « court-circuit ».
 *
 * PUR : aucune dépendance infra.
 */
import type { DirectoryProfile } from './profile.js';
import { safeRegexTest } from './safe-regex.js';

export type MappingSource = 'GROUP' | 'CLAIM' | 'ATTRIBUTE';

/**
 * Opérateurs de comparaison (insensibles aux espaces). `matches` = expression
 * régulière (ancrée implicitement par l'auteur), `in` = appartenance à une liste,
 * `present` = champ non vide (valeur ignorée).
 */
export type MatchOp = 'equals' | 'iequals' | 'contains' | 'matches' | 'in' | 'present';

export interface MappingCondition {
  readonly source: MappingSource;
  /** Nom du claim/attribut visé. Ignoré pour `GROUP` (teste la liste des groupes). */
  readonly key?: string;
  readonly op: MatchOp;
  /** Valeur de comparaison (chaîne) ou liste (pour `in`) ; regex source pour `matches`. */
  readonly value?: string | readonly string[];
}

/** Cible de rattachement à une unité d'organigramme produite par une règle. */
export interface OrgUnitDirective {
  /** Résolution par code (`OrgUnit.code`) ou par nom (`OrgUnit.name`). */
  readonly by: 'code' | 'name';
  /** Valeur littérale, OU si absente, lue dans l'attribut `fromAttribute` du profil. */
  readonly value?: string;
  readonly fromAttribute?: keyof DirectoryProfile['attributes'];
}

export interface IdpMappingRule {
  readonly id: string;
  readonly description?: string;
  /** Croissant : 0 évalué en premier. Départage stable par `id`. */
  readonly priority: number;
  /** Si la règle correspond, arrête l'évaluation des règles suivantes. */
  readonly stopOnMatch?: boolean;
  /** Toutes les conditions doivent être vraies (ET logique). */
  readonly all?: readonly MappingCondition[];
  /** Au moins une condition doit être vraie (OU logique). */
  readonly any?: readonly MappingCondition[];
  /** Clés de rôle du catalogue tenant à accorder (ex. `"VAL"`, `"ADM"`). */
  readonly assignRoleKeys?: readonly string[];
  /** Directive de rattachement organisationnel. */
  readonly orgUnit?: OrgUnitDirective;
}

export interface MappingResult {
  /** Union des clés de rôle accordées par les règles correspondantes. */
  readonly roleKeys: readonly string[];
  /** Directives d'unité, par priorité (la première = la plus prioritaire). */
  readonly orgUnitDirectives: readonly OrgUnitDirective[];
  /** Ids des règles qui ont correspondu (audit / dry-run). */
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
      // Regex bornée (anti-ReDoS) : motif invalide/trop complexe → fail-closed (cf. safe-regex.ts).
      return actual.some((a) => safeRegexTest(cond.value as string, a));
    }
    default:
      return false;
  }
}

function ruleMatches(profile: DirectoryProfile, rule: IdpMappingRule): boolean {
  const all = rule.all ?? [];
  const any = rule.any ?? [];
  if (all.length === 0 && any.length === 0) return false; // règle vide ⇒ jamais (fail-closed)
  const allOk = all.every((c) => condMatches(profile, c));
  const anyOk = any.length === 0 || any.some((c) => condMatches(profile, c));
  return allOk && anyOk;
}

/**
 * Évalue l'ensemble des règles d'un tenant contre un profil. Déterministe :
 * tri par (priorité, id). Accumule les rôles (union), collecte les directives
 * d'unité dans l'ordre de priorité, respecte `stopOnMatch`.
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
