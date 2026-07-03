# 05 - NestJS Integration

`@kengela/nestjs` wires the PDP into NestJS: a **deny-by-default guard**, decorators to declare the
required access, an injection token for the PDP, and a dedicated exception for step-up.

> `@nestjs/common`, `@nestjs/core` and `reflect-metadata` are **peerDependencies**: your
> application is the one that provides them.

```sh
npm add @kengela/nestjs @kengela/authz-core @kengela/adapter-expr-cel
```

## What the package exports

| Export                                    | Type                | Role                                                                 |
| ----------------------------------------- | ------------------- | -------------------------------------------------------------------- |
| `KengelaAuthzGuard`                       | guard               | Deny-by-default; builds an `AccessRequest` and delegates to the PDP. |
| `RequirePermission(resourceType, action)` | decorator           | Declares the access a route requires.                                |
| `PublicRoute()`                           | decorator           | Marks a route as public (deliberate opt-out).                        |
| `CurrentPrincipal()`                      | parameter decorator | Injects the `Principal` (placed on `req.user`).                      |
| `KENGELA_PDP`                             | token (symbol)      | Injection point for the `PolicyDecisionPoint` implementation.        |
| `StepUpRequiredException`                 | exception           | Thrown when the PDP returns `step_up`.                               |

## Wiring the guard and the PDP

The guard installs as `APP_GUARD` (global). The PDP is provided under the `KENGELA_PDP` token:
the application picks its implementation (here `LayeredDecisionPoint`).

```ts
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { KengelaAuthzGuard, KENGELA_PDP } from '@kengela/nestjs';
import { LayeredDecisionPoint } from '@kengela/authz-core';
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import type { PolicyDecisionPoint } from '@kengela/contracts';

@Module({
  providers: [
    {
      provide: KENGELA_PDP,
      useFactory: (grants, relations, policies): PolicyDecisionPoint =>
        new LayeredDecisionPoint({ grants, relations, policies, expr: new CelExpressionEngine() }),
      inject: [/* your AuthorizationRepository, RelationResolver, PolicyStore providers */],
    },
    { provide: APP_GUARD, useClass: KengelaAuthzGuard },
  ],
})
export class AuthzModule {}
```

The `Principal` must be placed on `req.user` **upstream** of the guard (authentication
middleware/guard, e.g. via `BetterAuthIdentity` or `IdentityPort`, see
[03-authentication.md](./03-authentication.md)).

## Declaring route access

`@RequirePermission(resourceType, action)` declares the `` `${resourceType}.${action}` `` permission.
`@CurrentPrincipal()` injects the current `Principal`:

```ts
import { Controller, Get, Post } from '@nestjs/common';
import { RequirePermission, PublicRoute, CurrentPrincipal } from '@kengela/nestjs';
import type { Principal } from '@kengela/contracts';

@Controller('orders')
export class OrdersController {
  @Get()
  @RequirePermission('data.orders', 'read')
  list(@CurrentPrincipal() principal: Principal) {
    // reached only if the PDP answered allow
  }

  @Post('refund')
  @RequirePermission('data.orders', 'refund')
  refund() {
    // if a policy returns step_up → StepUpRequiredException (see below)
  }

  @Get('health')
  @PublicRoute()
  health() {
    return { ok: true };
  }
}
```

## Deny-by-default and handler > class precedence

Two security guarantees, proven by test:

1. **Deny-by-default.** A route **without** `@RequirePermission` **or** `@PublicRoute` is **denied**
   (`ForbiddenException('route_not_annotated')`). We never expose a route through a forgotten
   annotation. A `Principal` missing on a protected route → `UnauthorizedException('no_principal')`
   (401).

2. **Handler > class precedence (fail-closed).** The **handler** annotation **always** takes
   precedence over the **class** one. A `@PublicRoute()` placed on the controller **cannot** neutralize
   a `@RequirePermission` placed on a handler. The exact order:

   | Priority | Annotation                   | Effect                                 |
   | -------- | ---------------------------- | -------------------------------------- |
   | 1        | handler `@RequirePermission` | evaluate (even if the class is public) |
   | 2        | handler `@PublicRoute`       | public                                 |
   | 3        | class `@RequirePermission`   | evaluate                               |
   | 4        | class `@PublicRoute`         | public                                 |
   | 5        | nothing                      | **deny** (unannotated route)           |

This hardening fixes a classic fail-open where a class-level `@PublicRoute` made every route public,
including a sensitive handler.

## Mapping the decision

The guard builds an `AccessRequest` (resource at **type** level + the principal's tenant), calls
`pdp.check()`, and maps the effect:

| `decision.effect` | HTTP result                                                   |
| ----------------- | ------------------------------------------------------------- |
| `allow`           | the request passes                                            |
| `deny`            | `ForbiddenException(decision.reason)` → 403                   |
| `step_up`         | `StepUpRequiredException(obligations, reason)` → enriched 403 |

```ts
// Body of the StepUpRequiredException (403):
{
  statusCode: 403,
  error: 'step_up_required',
  reason: 'refund_needs_passkey',
  obligations: [{ type: 'require_passkey' }],
}
```

On the client side, `step_up_required` triggers a **challenge** (re-run MFA/passkey), not a definitive
failure.

> **Guard scope.** The guard covers **RBAC** + **context** conditions (`principal.ctx`:
> risk/geo/mfa = conditional access). ABAC conditions on the **attributes of a specific resource**
> (e.g. "same agency") are checked **at the service level**, by calling the PDP directly with the
> loaded resource:

```ts
@Injectable()
export class OrdersService {
  constructor(@Inject(KENGELA_PDP) private readonly pdp: PolicyDecisionPoint) {}

  async read(principal: Principal, order: Order) {
    const decision = await this.pdp.check({
      principal,
      action: 'read',
      resource: {
        type: 'data.orders',
        id: order.id,
        tenantId: principal.tenantId,
        attributes: { agencyId: order.agencyId, ownerId: order.ownerId },
      },
    });
    if (decision.effect !== 'allow') throw new ForbiddenException(decision.reason);
    return order;
  }
}
```

The guard filters coarsely (can we read _some_ orders?); the service decides finely (can we read
_this_ order?).

## SCIM under NestJS

`@kengela/scim-server` is framework-agnostic (pure handlers). A NestJS controller just resolves the
tenant, parses the body, calls the handler and returns `status`/`body`. See
[04-identity-federation.md](./04-identity-federation.md).
