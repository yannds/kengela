import { hash as argonHash, verify as argonVerify } from '@node-rs/argon2';
import type { PasswordHasher } from '@kengela/contracts';

/**
 * argon2id parameters aligned with the OWASP recommendations:
 * m = 19456 KiB (19 MiB), t = 2 iterations, p = 1. Recommended default for any
 * new deployment (memory-hard, GPU/ASIC resistant).
 */
const MEMORY_COST = 19456;
const TIME_COST = 2;
const PARALLELISM = 1;

/** argon2id PasswordHasher (recommended default). */
export class Argon2PasswordHasher implements PasswordHasher {
  public hash(plain: string): Promise<string> {
    // @node-rs/argon2 uses Argon2id by default (verified: `$argon2id$` output).
    return argonHash(plain, {
      memoryCost: MEMORY_COST,
      timeCost: TIME_COST,
      parallelism: PARALLELISM,
    });
  }

  public verify(plain: string, hash: string): Promise<boolean> {
    return argonVerify(hash, plain);
  }

  public needsRehash(hash: string): boolean {
    const match = /^\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)/.exec(hash);
    if (match === null) {
      return true; // not argon2id, or unknown format -> re-hash
    }
    const memory = Number.parseInt(match[1] ?? '0', 10);
    const time = Number.parseInt(match[2] ?? '0', 10);
    const parallelism = Number.parseInt(match[3] ?? '0', 10);
    return memory < MEMORY_COST || time < TIME_COST || parallelism < PARALLELISM;
  }
}
