/**
 * Safe regular expression compilation/evaluation (anti-ReDoS).
 *
 * The `matches` mapping operator (rules.ts) compiles a regex provided by the admin, then tests it
 * against directory values (groups, claims). A "catastrophic" regex (nested quantifiers such as
 * `(a+)+`) can blow up the evaluation time on an adversarial input -> denial of service. Since the
 * engine is PURE (no native dependency such as `re2`), the risk is bounded by two deterministic
 * guardrails:
 *
 *  1. Length bound (source + tested input).
 *  2. Rejection heuristic for patterns with nested quantifiers (classic ReDoS cause).
 *
 * Fail-closed: any suspicious or overly long pattern => `null` (the condition does not match), never
 * an exception nor an unbounded evaluation. PURE: no infra dependency.
 */

/** Safety bounds, single source of truth (never hardcoded at the callers). */
export interface SafeRegexLimits {
  /** Maximum length of the pattern (regex source). */
  readonly maxSourceLength: number;
  /** Maximum length of the tested input (the excess is truncated before `.test`). */
  readonly maxInputLength: number;
}

export const SAFE_REGEX_LIMITS: SafeRegexLimits = {
  maxSourceLength: 200,
  maxInputLength: 1024,
};

/**
 * Detects nested quantifiers, the main cause of catastrophic backtracking: a group `( ... )` that
 * is itself quantified (`* + ? {...}`, possibly followed by a lazy `?`) whose content already
 * carries a quantifier. E.g. `(a+)+`, `(a*)*`, `(.+)+`, `([a-z]+)*`. Deliberately broad heuristic
 * (fail-closed): a false positive rejects a legitimate but exotic pattern, never the opposite.
 */
const NESTED_QUANTIFIER = /\([^()]*[+*}][^()]*\)[+*]|\([^()]*[+*][^()]*\)\{\d/;

/**
 * Compiles a "safe" regex (always case-insensitive, as the current `matches` usage) or returns
 * `null` if the pattern is invalid, too long, or suspected of ReDoS. Never throws.
 */
export function compileSafeRegex(
  source: string,
  limits: SafeRegexLimits = SAFE_REGEX_LIMITS,
): RegExp | null {
  if (typeof source !== 'string' || source.length === 0 || source.length > limits.maxSourceLength) {
    return null;
  }
  if (NESTED_QUANTIFIER.test(source)) return null;
  try {
    return new RegExp(source, 'i');
  } catch {
    return null;
  }
}

/**
 * Tests a pattern against an input, in a bounded way: rejected pattern (cf. `compileSafeRegex`) =>
 * `false`; input truncated to `maxInputLength` before the test. Never throws.
 */
export function safeRegexTest(
  source: string,
  input: string,
  limits: SafeRegexLimits = SAFE_REGEX_LIMITS,
): boolean {
  const re = compileSafeRegex(source, limits);
  if (!re) return false;
  return re.test(
    input.length > limits.maxInputLength ? input.slice(0, limits.maxInputLength) : input,
  );
}
