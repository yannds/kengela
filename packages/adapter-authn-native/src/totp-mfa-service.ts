import * as QRCode from 'qrcode';
import type {
  KeyManagementPort,
  MfaChallengeStore,
  MfaSecretStore,
  MfaService,
  TenantId,
  UserId,
} from '@kengela/contracts';
import type { TotpVerifier } from './totp-verifier.js';

/** Default TTL of an MFA challenge (2 minutes) if the caller does not override it. */
const DEFAULT_CHALLENGE_TTL_MS = 120_000;

export interface TotpMfaServiceOptions {
  readonly challengeTtlMs?: number;
}

/**
 * Full TOTP MFA cycle (enroll/challenge/verify) by composing the platform building blocks:
 * `TotpVerifier` (RFC 6238), `KeyManagementPort` (secret encrypted at-rest per tenant),
 * `MfaSecretStore` (secret persistence) and `MfaChallengeStore` (one-shot challenges).
 *
 * The TOTP secret is NEVER stored in cleartext: it is encrypted through the per-tenant
 * envelope KMS before reaching the store, and decrypted on the fly only to verify a code.
 */
export class TotpMfaService implements MfaService {
  readonly #totp: TotpVerifier;
  readonly #keyManagement: KeyManagementPort;
  readonly #secretStore: MfaSecretStore;
  readonly #challengeStore: MfaChallengeStore;
  readonly #challengeTtlMs: number;

  public constructor(
    totp: TotpVerifier,
    keyManagement: KeyManagementPort,
    secretStore: MfaSecretStore,
    challengeStore: MfaChallengeStore,
    options: TotpMfaServiceOptions = {},
  ) {
    this.#totp = totp;
    this.#keyManagement = keyManagement;
    this.#secretStore = secretStore;
    this.#challengeStore = challengeStore;
    this.#challengeTtlMs = options.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  }

  public async enroll(input: {
    readonly tenantId: TenantId;
    readonly userId: UserId;
    readonly account: string;
    readonly issuer: string;
  }): Promise<{ readonly secretUri: string; readonly qr: string }> {
    const secret = this.#totp.generateSecret();
    const encrypted = await this.#keyManagement.encrypt(
      input.tenantId,
      new TextEncoder().encode(secret),
    );
    await this.#secretStore.save(
      input.tenantId,
      input.userId,
      Buffer.from(encrypted).toString('base64'),
    );
    const secretUri = this.#totp.keyUri(secret, input.account, input.issuer);
    const qr = await QRCode.toDataURL(secretUri);
    return { secretUri, qr };
  }

  public async challenge(input: {
    readonly tenantId: TenantId;
    readonly userId: UserId;
  }): Promise<{ readonly challengeId: string }> {
    const challengeId = await this.#challengeStore.issue(
      input.tenantId,
      input.userId,
      this.#challengeTtlMs,
    );
    return { challengeId };
  }

  public async verify(challengeId: string, code: string): Promise<boolean> {
    const challenge = await this.#challengeStore.consume(challengeId);
    if (challenge === null) {
      return false;
    }
    const encrypted = await this.#secretStore.get(challenge.tenantId, challenge.userId);
    if (encrypted === null) {
      return false;
    }
    const plaintext = await this.#keyManagement.decrypt(
      challenge.tenantId,
      new Uint8Array(Buffer.from(encrypted, 'base64')),
    );
    const secret = new TextDecoder().decode(plaintext);
    return this.#totp.verify(secret, code);
  }
}
