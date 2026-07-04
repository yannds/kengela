# @kengela/scim-server

> A framework-agnostic SCIM 2.0 core (Users + Groups): the `ScimStore` port plus pure request-to-response handlers.

This package provides the SCIM 2.0 protocol core: a narrow `ScimStore` persistence port, pure handlers that turn a parsed request into a response with no HTTP dependency, SCIM serialization and parsing (resources, ListResponse, Error, PATCH, filters), discovery endpoints, and schema validation. It is the core ring: an adapter (NestJS, Express) resolves the tenant, parses the request, calls a handler, and serializes the `ScimResponse`.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/scim-server
```

## Usage

```ts
import { handleUsersPost, handleUsersList } from '@kengela/scim-server';
import type { ScimStore, ScimRequest } from '@kengela/scim-server';

// store: ScimStore implemented by your persistence layer
const created = await handleUsersPost(store, request satisfies ScimRequest);
// created.status, created.body -> serialize as application/scim+json
```

## Key exports

- `handleUsersPost`, `handleUsersGet`, `handleUsersList`, `handleUsersPatch`, `handleUsersPut`, `handleUsersDelete` - pure User handlers.
- `handleGroupsPost`, `handleGroupsGet`, `handleGroupsList`, `handleGroupsPatch`, `handleGroupsPut`, `handleGroupsDelete` - pure Group handlers.
- `ScimStore`, `ScimRequest`, `ScimResponse`, `ScimHandler` - the port and request/response contract types.
- `handleServiceProviderConfig`, `handleResourceTypes`, `handleSchemas` - discovery endpoints.
- `validateScimUser`, `validateScimGroup` - schema validation.
- `toScimUser`, `toScimGroup`, `scimError`, `parseUserPatch`, `parsePagination` - serialization and parsing helpers.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
