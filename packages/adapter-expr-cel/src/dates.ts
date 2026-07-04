const DAY_MS = 86_400_000;

/** Converts an expression value (bigint/number/Date/ISO string) to epoch ms. */
export function toEpochMs(value: unknown): number {
  if (typeof value === 'bigint') {
    return Number(value);
  }
  if (typeof value === 'number') {
    return value;
  }
  if (value instanceof Date) {
    return value.getTime();
  }
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }
  throw new Error(`Invalid date in a CEL expression: ${typeof value}`);
}

/** Number of calendar days (rounded) from `fromMs` to `toMs`. */
export function daysBetween(fromMs: number, toMs: number): number {
  return Math.round((toMs - fromMs) / DAY_MS);
}

function startOfUtcDay(ms: number): number {
  const date = new Date(ms);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

/** Business days (Mon-Fri) between two instants, bounds included. */
export function businessDaysBetween(aMs: number, bMs: number): number {
  const start = startOfUtcDay(Math.min(aMs, bMs));
  const end = Math.max(aMs, bMs);
  let count = 0;
  for (let t = start; t <= end; t += DAY_MS) {
    const day = new Date(t).getUTCDay();
    if (day !== 0 && day !== 6) {
      count += 1;
    }
  }
  return count;
}
