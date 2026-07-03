/**
 * RED TEAM — authentification & crypto (@kengela/adapter-authn-native).
 *
 * Enumeration par timing, altfrom AES-GCM, non-reutilisation de nonce, crypto-shredding
 * irreversible, rejeu MFA. Hermetique (fakes en memoire), aucun reseau.
 */
import { randomBytes } from 'node:crypto';
import type {
  AuthContext,
  CredentialRecord,
  CredentialStore,
  MfaChallengeStore,
  MfaSecretStore,
  PasswordHasher,
  SubjectKeyStore,
  TenantId,
  UserId,
} from '@kengela/contracts';
import { describe, expect, it } from 'vitest';
import { AesGcmKeyManagement } from '../src/aes-gcm-key-management.js';
import { BcryptPasswordHasher } from '../src/bcrypt-password-hasher.js';
import { NativeCredentialAuthenticator } from '../src/native-credential-authenticator.js';
import { SubjectCryptoShredder } from '../src/subject-crypto-shredder.js';
import { SubjectFieldCipher } from '../src/subject-field-cipher.js';
import { TotpMfaService } from '../src/totp-mfa-service.js';
import { TotpVerifier } from '../src/totp-verifier.js';

const CTX: AuthContext = { authTime: 0 };

/** Hasher qui COMPTE les verifications, pour prouver le compare systematique (anti-timing). */
class CountingHasher implements PasswordHasher {
  public verifyCalls = 0;
  readonly #inner: PasswordHasher;
  public constructor(inner: PasswordHasher) {
    this.#inner = inner;
  }
  public hash(plain: string): Promise<string> {
    return this.#inner.hash(plain);
  }
  public verify(plain: string, hash: string): Promise<boolean> {
    this.verifyCalls += 1;
    return this.#inner.verify(plain, hash);
  }
  public needsRehash(hash: string): boolean {
    return this.#inner.needsRehash(hash);
  }
}

const record = (
  over: Partial<CredentialRecord> & { passwordHash: string | null },
): CredentialRecord => ({
  userId: 'u1',
  tenantId: 't1',
  isActive: true,
  mfaEnabled: false,
  roles: ['cashier'],
  ...over,
});

function storeOf(
  single: CredentialRecord | null,
  cross: readonly CredentialRecord[] = [],
): CredentialStore {
  return {
    findByEmail: () => Promise.resolve(single),
    findByEmailAcrossTenants: () => Promise.resolve(cross),
  };
}

describe('RED — enumeration de comptes par timing (NativeCredentialAuthenticator)', () => {
  it('email INCONNU : un compare bcrypt leurre est TOUJOURS effectue', async () => {
    const hasher = new CountingHasher(new BcryptPasswordHasher(4));
    const auth = await NativeCredentialAuthenticator.create(storeOf(null), hasher);
    const before = hasher.verifyCalls;
    const out = await auth.authenticate({
      email: 'ghost@x.io',
      password: 'p',
      tenantId: 't1',
      ctx: CTX,
    });
    expect(out.kind).toBe('invalid_credentials');
    expect(hasher.verifyCalls).toBe(before + 1); // pas de court-circuit revelateur
  });

  it('compte inactif : le compare est effectue AVANT le refus (pas d’oracle)', async () => {
    const hasher = new CountingHasher(new BcryptPasswordHasher(4));
    const hash = await new BcryptPasswordHasher(4).hash('good');
    const auth = await NativeCredentialAuthenticator.create(
      storeOf(record({ passwordHash: hash, isActive: false })),
      hasher,
    );
    const before = hasher.verifyCalls;
    const out = await auth.authenticate({
      email: 'a@b.io',
      password: 'good',
      tenantId: 't1',
      ctx: CTX,
    });
    expect(out.kind).toBe('invalid_credentials');
    expect(hasher.verifyCalls).toBe(before + 1);
  });

  it('cross-tenant : PAS de court-circuit au 1er match (compare pour chaque enregistrement)', async () => {
    const hasher = new CountingHasher(new BcryptPasswordHasher(4));
    const hash = await new BcryptPasswordHasher(4).hash('good');
    const auth = await NativeCredentialAuthenticator.create(
      storeOf(null, [
        record({ passwordHash: hash, tenantId: 't1' }),
        record({ passwordHash: hash, tenantId: 't2' }),
        record({ passwordHash: hash, tenantId: 't3' }),
      ]),
      hasher,
    );
    const before = hasher.verifyCalls;
    const out = await auth.authenticateCrossTenant({ email: 'a@b.io', password: 'good', ctx: CTX });
    expect(out.kind).toBe('tenant_choice');
    expect(hasher.verifyCalls).toBe(before + 3);
  });

  it('cross-tenant email inconnu : un compare leurre quand meme (anti-enumeration)', async () => {
    const hasher = new CountingHasher(new BcryptPasswordHasher(4));
    const auth = await NativeCredentialAuthenticator.create(storeOf(null, []), hasher);
    const before = hasher.verifyCalls;
    const out = await auth.authenticateCrossTenant({
      email: 'ghost@x.io',
      password: 'p',
      ctx: CTX,
    });
    expect(out.kind).toBe('invalid_credentials');
    expect(hasher.verifyCalls).toBe(before + 1);
  });
});

describe('RED — AES-256-GCM : integrite, isolation, nonce (AesGcmKeyManagement)', () => {
  const km = new AesGcmKeyManagement(new Uint8Array(randomBytes(32)));

  it('nonce unique : deux chiffres du meme clair different (IV aleatoire, pas de reutilisation)', async () => {
    const a = await km.encrypt('t1', new TextEncoder().encode('same'));
    const b = await km.encrypt('t1', new TextEncoder().encode('same'));
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(b).toString('hex'));
    // Les 12 premiers octets (IV) different.
    expect(Buffer.from(a.subarray(0, 12)).toString('hex')).not.toBe(
      Buffer.from(b.subarray(0, 12)).toString('hex'),
    );
  });

  it('IV altere => rejet', async () => {
    const c = await km.encrypt('t1', new TextEncoder().encode('secret'));
    c[0] = (c[0] ?? 0) ^ 0xff;
    await expect(km.decrypt('t1', c)).rejects.toThrow();
  });

  it('TAG altere => rejet', async () => {
    const c = await km.encrypt('t1', new TextEncoder().encode('secret'));
    c[12] = (c[12] ?? 0) ^ 0xff; // premier octet du tag
    await expect(km.decrypt('t1', c)).rejects.toThrow();
  });

  it('chiffre tronque (plus court que iv+tag) => rejet', async () => {
    await expect(km.decrypt('t1', new Uint8Array(10))).rejects.toThrow();
  });

  it('mauvaise cle tenant => rejet (isolation cryptographique)', async () => {
    const c = await km.encrypt('t1', new TextEncoder().encode('secret'));
    await expect(km.decrypt('t2', c)).rejects.toThrow();
  });
});

describe('RED — crypto-shredding irreversible (RGPD art.17)', () => {
  function fakeKeyStore(): SubjectKeyStore {
    const keys = new Map<string, Uint8Array>();
    const id = (t: string, s: string): string => `${t}:${s}`;
    return {
      getOrCreateKey: (t, s) => {
        const k = id(t, s);
        let v = keys.get(k);
        if (v === undefined) {
          v = new Uint8Array(randomBytes(32));
          keys.set(k, v);
        }
        return Promise.resolve(v);
      },
      getKey: (t, s) => Promise.resolve(keys.get(id(t, s)) ?? null),
      deleteKey: (t, s) => {
        keys.delete(id(t, s));
        return Promise.resolve();
      },
    };
  }

  it('apres eraseSubject, la PII chiffree est definitivement illisible (null)', async () => {
    const store = fakeKeyStore();
    const cipher = new SubjectFieldCipher(store);
    const shredder = new SubjectCryptoShredder(store);
    const blob = await cipher.encryptFor('t1', 'subject-A', 'jean@dupont.io');
    expect(await cipher.decryptFor('t1', 'subject-A', blob)).toBe('jean@dupont.io');

    await shredder.eraseSubject('t1', 'subject-A');
    expect(await cipher.decryptFor('t1', 'subject-A', blob)).toBeNull();
  });

  it('la clef d’un autre sujet ne dechiffre pas la PII (isolation par sujet)', async () => {
    const store = fakeKeyStore();
    const cipher = new SubjectFieldCipher(store);
    const blob = await cipher.encryptFor('t1', 'subject-A', 'secret');
    await store.getOrCreateKey('t1', 'subject-B'); // materialise une autre clef
    await expect(cipher.decryptFor('t1', 'subject-B', blob)).rejects.toThrow();
  });
});

describe('RED — MFA TOTP : rejeu & bypass (TotpMfaService)', () => {
  class MemSecret implements MfaSecretStore {
    readonly map = new Map<string, string>();
    public save(t: TenantId, u: UserId, s: string): Promise<void> {
      this.map.set(`${t}:${u}`, s);
      return Promise.resolve();
    }
    public get(t: TenantId, u: UserId): Promise<string | null> {
      return Promise.resolve(this.map.get(`${t}:${u}`) ?? null);
    }
  }
  class MemChallenge implements MfaChallengeStore {
    readonly map = new Map<string, { tenantId: TenantId; userId: UserId; exp: number }>();
    #n = 0;
    public issue(t: TenantId, u: UserId, ttlMs: number): Promise<string> {
      const id = `c${String((this.#n += 1))}`;
      this.map.set(id, { tenantId: t, userId: u, exp: Date.now() + ttlMs });
      return Promise.resolve(id);
    }
    public consume(id: string): Promise<{ tenantId: TenantId; userId: UserId } | null> {
      const e = this.map.get(id);
      if (e === undefined) return Promise.resolve(null);
      this.map.delete(id);
      if (e.exp < Date.now()) return Promise.resolve(null);
      return Promise.resolve({ tenantId: e.tenantId, userId: e.userId });
    }
  }

  async function setup(): Promise<{ mfa: TotpMfaService; code: () => Promise<string> }> {
    const totp = new TotpVerifier();
    const km = new AesGcmKeyManagement(new Uint8Array(randomBytes(32)));
    const secret = new MemSecret();
    const chall = new MemChallenge();
    const mfa = new TotpMfaService(totp, km, secret, chall);
    await mfa.enroll({ tenantId: 't1', userId: 'u1', account: 'a', issuer: 'Kengela' });
    const code = async (): Promise<string> => {
      const enc = await secret.get('t1', 'u1');
      const plain = await km.decrypt('t1', new Uint8Array(Buffer.from(enc ?? '', 'base64')));
      return totp.currentCode(new TextDecoder().decode(plain));
    };
    return { mfa, code };
  }

  it('challengeId one-shot : le rejeu du meme defi (meme code valide) echoue', async () => {
    const { mfa, code } = await setup();
    const { challengeId } = await mfa.challenge({ tenantId: 't1', userId: 'u1' });
    const c = await code();
    expect(await mfa.verify(challengeId, c)).toBe(true);
    expect(await mfa.verify(challengeId, c)).toBe(false); // rejeu bloque
  });

  it('bypass sans secret : verify sur un user sans enroll => false', async () => {
    const totp = new TotpVerifier();
    const km = new AesGcmKeyManagement(new Uint8Array(randomBytes(32)));
    const mfa = new TotpMfaService(totp, km, new MemSecret(), new MemChallenge());
    const { challengeId } = await mfa.challenge({ tenantId: 't1', userId: 'ghost' });
    expect(await mfa.verify(challengeId, '000000')).toBe(false);
  });

  it('challengeId forge (inconnu) => false', async () => {
    const { mfa, code } = await setup();
    expect(await mfa.verify('forge', await code())).toBe(false);
  });
});
