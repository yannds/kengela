import { compare as bcryptCompare, hash as bcryptHash } from 'bcryptjs';
import type { PasswordHasher } from '@kengela/contracts';

/** Coût bcrypt par défaut (aligné sur la pratique TransLog). */
const DEFAULT_COST = 12;

/** PasswordHasher bcrypt. `compare` est à temps constant (anti-timing). */
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
      return true; // format inconnu (ex. argon2) -> re-hasher
    }
    return Number.parseInt(match[1] ?? '0', 10) < this.#cost;
  }
}
