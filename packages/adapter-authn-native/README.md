# @kengela/adapter-authn-native

> A hardened in-house authentication adapter: timing-safe credentials, AES-256-GCM encryption, and TOTP MFA.

This package implements the authentication and compliance ports from `@kengela/contracts` without an external auth framework: password hashing (argon2id and bcrypt), timing-safe credential authentication, envelope and per-field encryption, per-subject crypto-shredding, and TOTP-based MFA. It is the adapter ring.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/adapter-authn-native
```

## Usage

```ts
import { Argon2PasswordHasher, NativeCredentialAuthenticator } from '@kengela/adapter-authn-native';

const hasher = new Argon2PasswordHasher();
const authenticator = new NativeCredentialAuthenticator({
  store, // CredentialStore
  hasher,
});

const outcome = await authenticator.authenticate({ email, password, tenantId, ctx });
```

## Key exports

- `Argon2PasswordHasher`, `BcryptPasswordHasher` - `PasswordHasher` implementations with rehash support.
- `NativeCredentialAuthenticator` - timing-safe `CredentialAuthenticator`.
- `AesGcmKeyManagement` - per-tenant envelope encryption (`KeyManagementPort`).
- `AesGcmFieldCipher`, `SubjectFieldCipher` - field-level PII encryption (`FieldCipherPort`).
- `SubjectCryptoShredder` - per-subject crypto-shredding erasure.
- `TotpVerifier`, `TotpMfaService` - TOTP verification and enrollment MFA service.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
