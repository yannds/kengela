import type { PiiSensitivity } from './classification.js';

/**
 * Politique de rétention (RGPD art. 5.1.e) : durée maximale de conservation par
 * niveau de sensibilité, en millisecondes. `null` = pas de limite (rétention
 * indéfinie, à justifier). Une app fixe ses propres durées.
 */
export type RetentionPolicy = Readonly<Record<PiiSensitivity, number | null>>;

/** Défaut prudent : PII 2 ans, catégories sensibles 6 mois, non-personnel illimité. */
export const DEFAULT_RETENTION: RetentionPolicy = {
  none: null,
  pii: 730 * 24 * 60 * 60 * 1000,
  sensitive: 182 * 24 * 60 * 60 * 1000,
};

/** true si une donnée de cette sensibilité, âgée de `ageMs`, a dépassé sa rétention. */
export function retentionExpired(
  sensitivity: PiiSensitivity,
  ageMs: number,
  policy: RetentionPolicy = DEFAULT_RETENTION,
): boolean {
  const limit = policy[sensitivity];
  if (limit === null) {
    return false;
  }
  return ageMs > limit;
}
