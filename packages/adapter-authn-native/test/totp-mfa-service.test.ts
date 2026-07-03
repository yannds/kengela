import { randomBytes, randomUUID } from 'node:crypto';
import type { MfaChallengeStore, MfaSecretStore, TenantId, UserId } from '@kengela/contracts';
import { beforeEach, describe, expect, it } from 'vitest';
import { AesGcmKeyManagement } from '../src/aes-gcm-key-management.js';
import { TotpMfaService } from '../src/totp-mfa-service.js';
import { TotpVerifier } from '../src/totp-verifier.js';

/** Store de secrets en mémoire (fake hermétique). */
class InMemorySecretStore implements MfaSecretStore {
  readonly map = new Map<string, string>();

  public save(tenantId: TenantId, userId: UserId, encryptedSecret: string): Promise<void> {
    this.map.set(`${tenantId}:${userId}`, encryptedSecret);
    return Promise.resolve();
  }

  public get(tenantId: TenantId, userId: UserId): Promise<string | null> {
    return Promise.resolve(this.map.get(`${tenantId}:${userId}`) ?? null);
  }
}

/** Store de défis en mémoire, one-shot + expirant (fake hermétique). */
class InMemoryChallengeStore implements MfaChallengeStore {
  readonly map = new Map<
    string,
    { readonly tenantId: TenantId; readonly userId: UserId; readonly expiresAt: number }
  >();

  public issue(tenantId: TenantId, userId: UserId, ttlMs: number): Promise<string> {
    const challengeId = randomUUID();
    this.map.set(challengeId, { tenantId, userId, expiresAt: Date.now() + ttlMs });
    return Promise.resolve(challengeId);
  }

  public consume(
    challengeId: string,
  ): Promise<{ readonly tenantId: TenantId; readonly userId: UserId } | null> {
    const entry = this.map.get(challengeId);
    if (entry === undefined) {
      return Promise.resolve(null);
    }
    this.map.delete(challengeId);
    if (entry.expiresAt < Date.now()) {
      return Promise.resolve(null);
    }
    return Promise.resolve({ tenantId: entry.tenantId, userId: entry.userId });
  }
}

const TENANT: TenantId = 't-acme';
const USER: UserId = 'u-alice';

describe('TotpMfaService', () => {
  let totp: TotpVerifier;
  let keyManagement: AesGcmKeyManagement;
  let secretStore: InMemorySecretStore;
  let challengeStore: InMemoryChallengeStore;
  let mfa: TotpMfaService;

  beforeEach(() => {
    totp = new TotpVerifier();
    keyManagement = new AesGcmKeyManagement(new Uint8Array(randomBytes(32)));
    secretStore = new InMemorySecretStore();
    challengeStore = new InMemoryChallengeStore();
    mfa = new TotpMfaService(totp, keyManagement, secretStore, challengeStore);
  });

  async function currentCode(): Promise<string> {
    const encrypted = await secretStore.get(TENANT, USER);
    expect(encrypted).not.toBeNull();
    const plaintext = await keyManagement.decrypt(
      TENANT,
      new Uint8Array(Buffer.from(encrypted ?? '', 'base64')),
    );
    return totp.currentCode(new TextDecoder().decode(plaintext));
  }

  it('enroll renvoie une secretUri otpauth', async () => {
    const { secretUri } = await mfa.enroll({
      tenantId: TENANT,
      userId: USER,
      account: 'alice@acme.io',
      issuer: 'Kengela',
    });
    expect(secretUri.startsWith('otpauth://totp/')).toBe(true);
  });

  it('enroll renvoie un QR en data URL PNG', async () => {
    const { qr } = await mfa.enroll({
      tenantId: TENANT,
      userId: USER,
      account: 'alice@acme.io',
      issuer: 'Kengela',
    });
    expect(qr.startsWith('data:image/png;base64,')).toBe(true);
    expect(qr.length).toBeGreaterThan('data:image/png;base64,'.length);
  });

  it('enroll stocke le secret CHIFFRÉ (jamais en clair)', async () => {
    await mfa.enroll({
      tenantId: TENANT,
      userId: USER,
      account: 'alice@acme.io',
      issuer: 'Kengela',
    });
    const stored = await secretStore.get(TENANT, USER);
    expect(stored).not.toBeNull();
    // Le stocké se déchiffre vers un secret base32 non vide.
    const plaintext = await keyManagement.decrypt(
      TENANT,
      new Uint8Array(Buffer.from(stored ?? '', 'base64')),
    );
    const secret = new TextDecoder().decode(plaintext);
    expect(secret.length).toBeGreaterThan(0);
    // Le blob base64 stocké ne contient pas le secret en clair.
    expect(stored).not.toContain(secret);
  });

  it('enroll isole les secrets par tenant/user', async () => {
    await mfa.enroll({ tenantId: TENANT, userId: USER, account: 'a', issuer: 'Kengela' });
    await mfa.enroll({ tenantId: TENANT, userId: 'u-bob', account: 'b', issuer: 'Kengela' });
    expect(await secretStore.get(TENANT, USER)).not.toBe(await secretStore.get(TENANT, 'u-bob'));
  });

  it('challenge renvoie un challengeId opaque non vide', async () => {
    const { challengeId } = await mfa.challenge({ tenantId: TENANT, userId: USER });
    expect(typeof challengeId).toBe('string');
    expect(challengeId.length).toBeGreaterThan(0);
  });

  it('verify réussit avec le code courant', async () => {
    await mfa.enroll({ tenantId: TENANT, userId: USER, account: 'a', issuer: 'Kengela' });
    const { challengeId } = await mfa.challenge({ tenantId: TENANT, userId: USER });
    expect(await mfa.verify(challengeId, await currentCode())).toBe(true);
  });

  it('verify échoue avec un code faux', async () => {
    await mfa.enroll({ tenantId: TENANT, userId: USER, account: 'a', issuer: 'Kengela' });
    const { challengeId } = await mfa.challenge({ tenantId: TENANT, userId: USER });
    expect(await mfa.verify(challengeId, '000000')).toBe(false);
  });

  it('verify échoue avec un challenge inconnu', async () => {
    await mfa.enroll({ tenantId: TENANT, userId: USER, account: 'a', issuer: 'Kengela' });
    expect(await mfa.verify('inconnu', await currentCode())).toBe(false);
  });

  it('verify échoue si le secret est absent (pas d’enroll)', async () => {
    const { challengeId } = await mfa.challenge({ tenantId: TENANT, userId: USER });
    expect(await mfa.verify(challengeId, '123456')).toBe(false);
  });

  it('challenge est one-shot : le 2e verify sur le même challengeId échoue', async () => {
    await mfa.enroll({ tenantId: TENANT, userId: USER, account: 'a', issuer: 'Kengela' });
    const { challengeId } = await mfa.challenge({ tenantId: TENANT, userId: USER });
    const code = await currentCode();
    expect(await mfa.verify(challengeId, code)).toBe(true);
    expect(await mfa.verify(challengeId, code)).toBe(false);
  });

  it('challenge expiré (ttl 0) échoue à la consommation', async () => {
    const expiring = new TotpMfaService(totp, keyManagement, secretStore, challengeStore, {
      challengeTtlMs: 0,
    });
    await expiring.enroll({ tenantId: TENANT, userId: USER, account: 'a', issuer: 'Kengela' });
    const { challengeId } = await expiring.challenge({ tenantId: TENANT, userId: USER });
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(await expiring.verify(challengeId, await currentCode())).toBe(false);
  });
});
