import { describe, expect, it } from 'vitest';
import { DEFAULT_RETENTION, retentionExpired, type RetentionPolicy } from '../src/retention.js';

const DAY = 24 * 60 * 60 * 1000;

describe('retention', () => {
  it('none = jamais expire', () => {
    expect(retentionExpired('none', 100 * 365 * DAY)).toBe(false);
  });

  it('pii expire apres la duree par defaut (2 ans)', () => {
    expect(retentionExpired('pii', 400 * DAY)).toBe(false);
    expect(retentionExpired('pii', 800 * DAY)).toBe(true);
  });

  it('politique personnalisee', () => {
    const policy: RetentionPolicy = { none: null, pii: 10 * DAY, sensitive: 5 * DAY };
    expect(retentionExpired('pii', 20 * DAY, policy)).toBe(true);
    expect(retentionExpired('pii', 5 * DAY, policy)).toBe(false);
  });

  it('defaut : sensible conserve moins longtemps que pii', () => {
    expect(DEFAULT_RETENTION.sensitive ?? 0).toBeLessThan(DEFAULT_RETENTION.pii ?? 0);
  });
});
