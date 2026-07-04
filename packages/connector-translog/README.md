# @kengela/connector-translog

> A reference connector implementing the Kengela ports against the real TransLog Pro Prisma schema.

This package implements the `@kengela/contracts` ports (`CredentialStore`, `AuthorizationRepository`, `SessionStore`, `PolicyStore`) against the actual TransLog Pro Prisma schema. It is the connector ring: a private reference package that proves the ports fit an existing production schema, intended to move into TransLog once `@kengela/*` is published.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/connector-translog
```

## Narrow surface

The connector does not depend on `@prisma/client`. It describes a narrow surface, `TranslogPrismaLike`, with explicit row types (`UserRow`, `AccountRow`, `SessionRow`, `RolePermissionRow`). A real `PrismaClient` generated from the TransLog schema is structurally compatible and passes where `TranslogPrismaLike` is expected.

## Usage

```ts
import {
  TranslogCredentialStore,
  TranslogAuthorizationRepository,
} from '@kengela/connector-translog';

const credentials = new TranslogCredentialStore({ prisma });
const authz = new TranslogAuthorizationRepository({ prisma });

const record = await credentials.findByEmail(email, tenantId);
const grants = await authz.loadGrantsForUser(userId, tenantId);
```

## Fail-closed

Any unknown scope or malformed permission drops the affected grant, so there is no phantom widening. A credential account with no matching user is discarded.

## Key exports

- `TranslogCredentialStore` - `CredentialStore` over `Account` (credential) joined with `User`.
- `TranslogAuthorizationRepository` - `AuthorizationRepository` mapping `RolePermission` to grants.
- `TranslogSessionStore` - `SessionStore` over the `Session` table.
- `TranslogPolicyStore` - `PolicyStore` returning an empty policy set (RBAC only).
- `permissionToGrant`, `permissionsToGrants`, `toSessionHandle` - mapping helpers.
- `TranslogPrismaLike` and the row/delegate types - the narrow Prisma surface used by the connector.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
