# @kengela/nestjs

> NestJS integration: an authorization guard backed by the policy decision point, plus decorators.

This package wires the Kengela `PolicyDecisionPoint` into NestJS as a guard, with decorators to declare the required permission per route, mark routes public, and inject the current principal. It is the integration ring: it depends on the PDP contract, and your application provides a concrete PDP through the injection token.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/nestjs
```

Required peer dependencies to install too: `@nestjs/common` (>=10), `@nestjs/core` (>=10), and `reflect-metadata` (>=0.1.13).

## Usage

```ts
import { APP_GUARD } from '@nestjs/core';
import { KengelaAuthzGuard, KENGELA_PDP, RequirePermission } from '@kengela/nestjs';

@Module({
  providers: [
    { provide: KENGELA_PDP, useExisting: MyPolicyDecisionPoint },
    { provide: APP_GUARD, useClass: KengelaAuthzGuard },
  ],
})
export class AuthzModule {}

@Controller('invoices')
class InvoicesController {
  @RequirePermission('invoice', 'read')
  @Get()
  list() {
    /* ... */
  }
}
```

## Key exports

- `KengelaAuthzGuard` - `CanActivate` guard that runs the PDP per request.
- `KENGELA_PDP` - injection token for the application's `PolicyDecisionPoint`.
- `RequirePermission` - declares the required resource type and action on a route.
- `PublicRoute` - marks a route as not requiring authorization.
- `CurrentPrincipal` - param decorator injecting the resolved `Principal`.
- `StepUpRequiredException` - thrown when the decision requires step-up.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
