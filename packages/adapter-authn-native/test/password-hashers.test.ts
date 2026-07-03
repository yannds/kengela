import { describe, expect, it } from 'vitest';
import { Argon2PasswordHasher } from '../src/argon2-password-hasher.js';
import { BcryptPasswordHasher } from '../src/bcrypt-password-hasher.js';

describe('Argon2PasswordHasher (defaut recommande)', () => {
  const hasher = new Argon2PasswordHasher();

  it('hash argon2id + verifie', async () => {
    const hash = await hasher.hash('s3cret');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await hasher.verify('s3cret', hash)).toBe(true);
    expect(await hasher.verify('mauvais', hash)).toBe(false);
  });

  it('needsRehash : false si params courants, true si faibles ou autre algo', async () => {
    expect(hasher.needsRehash(await hasher.hash('x'))).toBe(false);
    expect(hasher.needsRehash('$argon2id$v=19$m=8,t=1,p=1$abc$def')).toBe(true);
    expect(hasher.needsRehash('$2a$12$0123456789012345678901')).toBe(true);
  });
});

describe('BcryptPasswordHasher (compat)', () => {
  it('hash + verifie (cout bas pour le test)', async () => {
    const hasher = new BcryptPasswordHasher(4);
    const hash = await hasher.hash('s3cret');
    expect(await hasher.verify('s3cret', hash)).toBe(true);
    expect(await hasher.verify('mauvais', hash)).toBe(false);
  });

  it('needsRehash quand le cout stocke < cible (migration transparente)', async () => {
    const weak = await new BcryptPasswordHasher(4).hash('x');
    expect(new BcryptPasswordHasher(12).needsRehash(weak)).toBe(true);
    expect(new BcryptPasswordHasher(4).needsRehash(weak)).toBe(false);
    expect(new BcryptPasswordHasher(12).needsRehash('$argon2id$v=19$m=19456,t=2,p=1$a$b')).toBe(
      true,
    );
  });
});
