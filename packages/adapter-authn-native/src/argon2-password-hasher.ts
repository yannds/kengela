import { hash as argonHash, verify as argonVerify } from '@node-rs/argon2';
import type { PasswordHasher } from '@kengela/contracts';

/**
 * Paramètres argon2id alignés sur les recommandations OWASP :
 * m = 19456 KiB (19 MiB), t = 2 itérations, p = 1. Défaut recommandé pour tout
 * nouveau déploiement (mémoire-dur, résistant GPU/ASIC).
 */
const MEMORY_COST = 19456;
const TIME_COST = 2;
const PARALLELISM = 1;

/** PasswordHasher argon2id (défaut recommandé). */
export class Argon2PasswordHasher implements PasswordHasher {
  public hash(plain: string): Promise<string> {
    // @node-rs/argon2 utilise Argon2id par defaut (verifie : sortie `$argon2id$`).
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
      return true; // pas de l'argon2id, ou format inconnu -> re-hasher
    }
    const memory = Number.parseInt(match[1] ?? '0', 10);
    const time = Number.parseInt(match[2] ?? '0', 10);
    const parallelism = Number.parseInt(match[3] ?? '0', 10);
    return memory < MEMORY_COST || time < TIME_COST || parallelism < PARALLELISM;
  }
}
