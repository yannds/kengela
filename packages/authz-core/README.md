# @kengela/authz-core

> The pure authorization engine: RBAC scope + organizational relation + deny-by-default policy decision points.

This package implements the authorization logic against the `@kengela/contracts` ports: permission syntax and coverage, scope-versus-relation checks, and two policy decision points (RBAC-only, and a layered PDP that adds declarative policies and conditions). It is the core ring: pure and framework-agnostic, with no persistence or vendor dependencies.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/authz-core
```

## Usage

```ts
import { RbacDecisionPoint } from '@kengela/authz-core';
import type { AccessRequest, AuthorizationRepository, RelationResolver } from '@kengela/contracts';

const pdp = new RbacDecisionPoint({
  repository, // AuthorizationRepository
  relations, // RelationResolver
  now: () => Date.now(),
});

const decision = await pdp.check(request satisfies AccessRequest);
if (decision.effect === 'allow') {
  // proceed
}
```

## Key exports

- `RbacDecisionPoint` - deny-by-default PDP over grants and relations.
- `LayeredDecisionPoint` - PDP layering declarative policies and conditions on RBAC.
- `PrincipalRelationResolver` - resolves the actor-resource organizational relation.
- `isAuthorized`, `grantCovers`, `activeGrants` - core grant evaluation helpers.
- `permissionCovers`, `assertPermissionSyntax`, `PermissionSyntaxError` - permission grammar.
- `scopeCoversRelation`, `relationRank`, `SCOPE_RANK` - scope-versus-relation logic.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
