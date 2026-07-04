import type { PiiSensitivity } from './classification.js';

/**
 * Retention policy (GDPR art. 5.1.e): maximum retention duration per
 * sensitivity level, in milliseconds. `null` = no limit (indefinite
 * retention, to be justified). An app sets its own durations.
 */
export type RetentionPolicy = Readonly<Record<PiiSensitivity, number | null>>;

/** Prudent default: PII 2 years, sensitive categories 6 months, non-personal unlimited. */
export const DEFAULT_RETENTION: RetentionPolicy = {
  none: null,
  pii: 730 * 24 * 60 * 60 * 1000,
  sensitive: 182 * 24 * 60 * 60 * 1000,
};

/** true if a datum of this sensitivity, aged `ageMs`, has exceeded its retention. */
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
