/**
 * Compilation/évaluation d'expressions régulières sûres (anti-ReDoS).
 *
 * L'opérateur de mapping `matches` (rules.ts) compile une regex fournie par l'admin, puis la teste
 * contre des valeurs d'annuaire (groupes, claims). Une regex « catastrophique » (quantificateurs
 * imbriqués type `(a+)+`) peut faire exploser le temps d'évaluation sur une entrée adverse → déni de
 * service. Le moteur étant PUR (pas de dépendance native type `re2`), on borne le risque par deux
 * garde-fous déterministes :
 *
 *  1. Borne de longueur (source + entrée testée).
 *  2. Heuristique de rejet des motifs à quantificateurs imbriqués (cause classique de ReDoS).
 *
 * Fail-closed : tout motif suspect ou trop long ⇒ `null` (la condition ne correspond pas), jamais
 * d'exception ni d'évaluation non bornée. PUR : aucune dépendance infra.
 */

/** Bornes de sûreté, source unique de vérité (jamais en dur chez les appelants). */
export interface SafeRegexLimits {
  /** Longueur maximale du motif (source de la regex). */
  readonly maxSourceLength: number;
  /** Longueur maximale de l'entrée testée (l'excédent est tronqué avant `.test`). */
  readonly maxInputLength: number;
}

export const SAFE_REGEX_LIMITS: SafeRegexLimits = {
  maxSourceLength: 200,
  maxInputLength: 1024,
};

/**
 * Détecte les quantificateurs imbriqués, principale cause de retour arrière catastrophique :
 * un groupe `( … )` lui-même quantifié (`* + ? {…}`, éventuellement suivi de `?` lazy) dont le
 * contenu porte déjà un quantificateur. Ex. `(a+)+`, `(a*)*`, `(.+)+`, `([a-z]+)*`. Heuristique
 * volontairement large (fail-closed) : un faux positif rejette un motif légitime mais exotique,
 * jamais l'inverse.
 */
const NESTED_QUANTIFIER = /\([^()]*[+*}][^()]*\)[+*]|\([^()]*[+*][^()]*\)\{\d/;

/**
 * Compile une regex « sûre » (toujours insensible à la casse, comme l'usage `matches` actuel) ou
 * renvoie `null` si le motif est invalide, trop long, ou suspecté de ReDoS. Ne lève jamais.
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
 * Teste un motif contre une entrée, de façon bornée : motif refusé (cf. `compileSafeRegex`) ⇒
 * `false` ; entrée tronquée à `maxInputLength` avant le test. Jamais d'exception.
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
