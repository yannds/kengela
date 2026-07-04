# @kengela/adapter-persistence-prisma

> A Prisma/Postgres persistence adapter for the authorization, session, policy, credential, MFA, and PII ports.

This package implements the persistence-facing ports from `@kengela/contracts` (authorization repository, session store, policy store, credential store, MFA secret and challenge stores, subject-key store, PII access log) against Prisma and Postgres. It is the adapter ring, and depends on a narrow `PrismaLike` surface rather than `@prisma/client` directly, so a generated client is structurally compatible.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/adapter-persistence-prisma
```

## Usage

```ts
import {
  PrismaAuthorizationRepository,
  PrismaSessionStore,
} from '@kengela/adapter-persistence-prisma';

const repository = new PrismaAuthorizationRepository({ prisma });
const sessions = new PrismaSessionStore({ prisma, now: () => Date.now() });

const grants = await repository.loadGrantsForUser(userId, tenantId);
```

## Key exports

- `PrismaAuthorizationRepository` - loads grants and roles (`AuthorizationRepository`).
- `PrismaSessionStore` - opaque session storage (`SessionStore`).
- `PrismaPolicyStore` - declarative policy source (`PolicyStore`).
- `PrismaCredentialStore` - credential lookup (`CredentialStore`).
- `PrismaMfaSecretStore`, `PrismaMfaChallengeStore` - MFA secret and challenge stores.
- `PrismaSubjectKeyStore`, `PrismaPiiAccessLogSink` - per-subject keys and PII access logging.
- `PrismaLike` and the row/delegate types - the narrow Prisma surface the adapter needs.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
