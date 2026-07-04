# @kengela/pii

> Classification, minimization, and redaction of personal data (GDPR).

This package provides pure helpers to classify directory profile fields by sensitivity, strip non-essential personal data (data minimization), redact profiles for logs and non-privileged views, and evaluate retention expiry. It is the core ring: pure functions with no infrastructure dependency, built on top of `@kengela/iam-mapping`.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/pii
```

## Usage

```ts
import { classify, redactProfile, retentionExpired, DEFAULT_RETENTION } from '@kengela/pii';

const sensitivity = classify('email'); // PiiSensitivity

const safeForLogs = redactProfile(directoryProfile);

if (retentionExpired(record.createdAt, DEFAULT_RETENTION, Date.now())) {
  // schedule erasure
}
```

## Key exports

- `classify`, `isPii`, `PII_FIELDS` - field-level sensitivity classification.
- `minimizeProfile` - strips non-essential personal data from a profile.
- `redactProfile` - produces a redacted profile safe for logs and non-privileged views.
- `retentionExpired`, `DEFAULT_RETENTION`, `RetentionPolicy` - retention window evaluation.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
