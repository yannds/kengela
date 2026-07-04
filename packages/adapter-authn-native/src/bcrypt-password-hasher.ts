import { compare as bcryptCompare, hash as bcryptHash } from 'bcryptjs';
import type { PasswordHasher } from '@kengela/contracts';

/** Default bcrypt cost (aligned with TransLog practice). */
const DEFAULT_COST = 12;

/** bcrypt PasswordHasher. `compare` is constant-time (anti-timing). */
export class BcryptPasswordHasher implements PasswordHasher {
  readonly #cost: number;

  public constructor(cost: number = DEFAULT_COST) {
    this.#cost = cost;
  }

  public hash(plain: string): Promise<string> {
    return bcryptHash(plain, this.#cost);
  }

  public verify(plain: string, hash: string): Promise<boolean> {
    return bcryptCompare(plain, hash);
  }

  public needsRehash(hash: string): boolean {
    const match = /^\$2[aby]\$(\d{2})\$/.exec(hash);
    if (match === null) {
      return true; // unknown format (e.g. argon2) -> re-hash
    }
    return Number.parseInt(match[1] ?? '0', 10) < this.#cost;
  }
}
