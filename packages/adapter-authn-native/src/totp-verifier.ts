import { generateSecret, generateSync, generateURI, verifySync } from 'otplib';

/**
 * Vérificateur TOTP (RFC 6238) — brique réutilisable pour la MFA. Le secret est
 * chiffré at-rest par ailleurs (AesGcmKeyManagement) ; ici on ne fait que générer
 * et vérifier des codes.
 */
export class TotpVerifier {
  /** Génère un secret base32 (compatible Google Authenticator). */
  public generateSecret(): string {
    return generateSecret();
  }

  /** URI otpauth:// pour QR code (l'app rend le QR). */
  public keyUri(secret: string, account: string, issuer: string): string {
    return generateURI({ secret, label: account, issuer });
  }

  /** Génère le code courant (utile pour les tests / setup). */
  public currentCode(secret: string): string {
    return generateSync({ secret });
  }

  /** Vérifie un code TOTP contre un secret. */
  public verify(secret: string, token: string): boolean {
    return verifySync({ token, secret }).valid;
  }
}
