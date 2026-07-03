import { describe, expect, it } from 'vitest';
import { TotpVerifier } from '../src/totp-verifier.js';

describe('TotpVerifier', () => {
  const totp = new TotpVerifier();

  it('genere un secret et verifie le code courant', () => {
    const secret = totp.generateSecret();
    expect(totp.verify(secret, totp.currentCode(secret))).toBe(true);
    expect(totp.verify(secret, '000000')).toBe(false);
  });

  it('produit une URI otpauth pour QR', () => {
    const uri = totp.keyUri(totp.generateSecret(), 'a@b.io', 'Kengela');
    expect(uri.startsWith('otpauth://totp/')).toBe(true);
  });
});
