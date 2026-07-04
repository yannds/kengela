import { generateSecret, generateSync, generateURI, verifySync } from 'otplib';

/**
 * TOTP verifier (RFC 6238), a reusable building block for MFA. The secret is
 * encrypted at-rest elsewhere (AesGcmKeyManagement); here we only generate
 * and verify codes.
 */
export class TotpVerifier {
  /** Generates a base32 secret (Google Authenticator compatible). */
  public generateSecret(): string {
    return generateSecret();
  }

  /** otpauth:// URI for a QR code (the app renders the QR). */
  public keyUri(secret: string, account: string, issuer: string): string {
    return generateURI({ secret, label: account, issuer });
  }

  /** Generates the current code (useful for tests / setup). */
  public currentCode(secret: string): string {
    return generateSync({ secret });
  }

  /** Verifies a TOTP code against a secret. */
  public verify(secret: string, token: string): boolean {
    return verifySync({ token, secret }).valid;
  }
}
