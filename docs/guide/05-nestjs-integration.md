# 05 - Intégration NestJS

`@kengela/nestjs` branche le PDP dans NestJS : un **guard deny-by-default**, des décorateurs pour
déclarer l'accès requis, un jeton d'injection pour le PDP, et une exception dédiée au step-up.

> `@nestjs/common`, `@nestjs/core` et `reflect-metadata` sont des **peerDependencies** : c'est votre
> application qui les fournit.

```sh
npm add @kengela/nestjs @kengela/authz-core @kengela/adapter-expr-cel
```

## Ce que le paquet exporte

| Export                                    | Type                    | Rôle                                                               |
| ----------------------------------------- | ----------------------- | ------------------------------------------------------------------ |
| `KengelaAuthzGuard`                       | guard                   | Deny-by-default ; construit une `AccessRequest` et délègue au PDP. |
| `RequirePermission(resourceType, action)` | décorateur              | Déclare l'accès requis d'une route.                                |
| `PublicRoute()`                           | décorateur              | Marque une route publique (opt-out volontaire).                    |
| `CurrentPrincipal()`                      | décorateur de paramètre | Injecte le `Principal` (posé sur `req.user`).                      |
| `KENGELA_PDP`                             | jeton (symbol)          | Point d'injection de l'implémentation `PolicyDecisionPoint`.       |
| `StepUpRequiredException`                 | exception               | Levée quand le PDP renvoie `step_up`.                              |

## Câbler le guard et le PDP

Le guard s'installe en `APP_GUARD` (global). Le PDP est fourni sous le jeton `KENGELA_PDP` :
l'application choisit son implémentation (ici `LayeredDecisionPoint`).

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
      inject: [/* vos providers AuthorizationRepository, RelationResolver, PolicyStore */],
    },
    { provide: APP_GUARD, useClass: KengelaAuthzGuard },
  ],
})
export class AuthzModule {}
```

Le `Principal` doit être posé sur `req.user` **en amont** du guard (middleware/guard
d'authentification, ex. via `BetterAuthIdentity` ou `IdentityPort`, voir
[03-authentication.md](./03-authentication.md)).

## Déclarer l'accès des routes

`@RequirePermission(resourceType, action)` déclare la permission `` `${resourceType}.${action}` ``.
`@CurrentPrincipal()` injecte le `Principal` courant :

```ts
import { Controller, Get, Post } from '@nestjs/common';
import { RequirePermission, PublicRoute, CurrentPrincipal } from '@kengela/nestjs';
import type { Principal } from '@kengela/contracts';

@Controller('orders')
export class OrdersController {
  @Get()
  @RequirePermission('data.orders', 'read')
  list(@CurrentPrincipal() principal: Principal) {
    // atteint seulement si le PDP a répondu allow
  }

  @Post('refund')
  @RequirePermission('data.orders', 'refund')
  refund() {
    // si une policy renvoie step_up → StepUpRequiredException (voir plus bas)
  }

  @Get('health')
  @PublicRoute()
  health() {
    return { ok: true };
  }
}
```

## Deny-by-default et précédence handler > classe

Deux garanties de sécurité, prouvées par test :

1. **Deny-by-default.** Une route **sans** `@RequirePermission` **ni** `@PublicRoute` est **refusée**
   (`ForbiddenException('route_not_annotated')`). On n'expose jamais une route par oubli
   d'annotation. Un `Principal` absent sur une route protégée → `UnauthorizedException('no_principal')`
   (401).

2. **Précédence handler > classe (fail-closed).** L'annotation du **handler** prime **toujours** sur
   celle de la **classe**. Un `@PublicRoute()` posé sur le contrôleur ne peut **pas** neutraliser un
   `@RequirePermission` posé sur un handler. L'ordre exact :

   | Priorité | Annotation                   | Effet                                      |
   | -------- | ---------------------------- | ------------------------------------------ |
   | 1        | handler `@RequirePermission` | on évalue (même si la classe est publique) |
   | 2        | handler `@PublicRoute`       | public                                     |
   | 3        | classe `@RequirePermission`  | on évalue                                  |
   | 4        | classe `@PublicRoute`        | public                                     |
   | 5        | rien                         | **deny** (route non annotée)               |

Ce durcissement corrige un fail-open classique où un `@PublicRoute` de classe rendait publiques
toutes les routes, y compris un handler sensible.

## Mapping de la décision

Le guard construit une `AccessRequest` (ressource au niveau **type** + tenant du principal), appelle
`pdp.check()`, et mappe l'effet :

| `decision.effect` | Résultat HTTP                                                |
| ----------------- | ------------------------------------------------------------ |
| `allow`           | la requête passe                                             |
| `deny`            | `ForbiddenException(decision.reason)` → 403                  |
| `step_up`         | `StepUpRequiredException(obligations, reason)` → 403 enrichi |

```ts
// Corps de la StepUpRequiredException (403) :
{
  statusCode: 403,
  error: 'step_up_required',
  reason: 'refund_needs_passkey',
  obligations: [{ type: 'require_passkey' }],
}
```

Côté client, `step_up_required` déclenche un **défi** (relancer MFA/passkey), pas un échec définitif.

> **Portée du guard.** Le guard couvre le **RBAC** + les conditions de **contexte** (`principal.ctx` :
> risque/géo/mfa = conditional access). Les conditions ABAC sur les **attributs d'une ressource
> précise** (ex. « même agence ») se vérifient **au niveau service**, en appelant directement le PDP
> avec la ressource chargée :

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

Le guard filtre grossièrement (peut-on lire _des_ commandes ?) ; le service tranche finement (peut-on
lire _cette_ commande ?).

## SCIM sous NestJS

`@kengela/scim-server` est framework-agnostique (handlers purs). Un contrôleur NestJS se contente de
résoudre le tenant, parser le corps, appeler le handler et renvoyer `status`/`body`. Voir
[04-identity-federation.md](./04-identity-federation.md).
</content>
