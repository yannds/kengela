import {
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { AccessRequest, PolicyDecisionPoint, Principal } from '@kengela/contracts';
import { KENGELA_PERMISSION, KENGELA_PUBLIC, type RequiredAccess } from './decorators.js';
import { StepUpRequiredException } from './step-up.exception.js';
import { KENGELA_PDP } from './tokens.js';

/**
 * Zero Trust authorization guard.
 *
 * Deny-by-default: a route with neither `@RequirePermission` NOR `@PublicRoute` is DENIED
 * (fixes the classic fail-open). Otherwise, builds an AccessRequest from the Principal
 * (`req.user`) and the metadata, delegates to the PDP, and maps the decision:
 *  - allow    -> pass
 *  - deny     -> ForbiddenException(reason)
 *  - step_up  -> StepUpRequiredException(obligations) - authz requires an authn factor
 *
 * PRECEDENCE (fail-closed): the HANDLER annotation ALWAYS prevails over the CLASS one.
 * A `@RequirePermission` set on a handler thus CANNOT be neutralized by a `@PublicRoute`
 * set on the controller (otherwise a sensitive route would leak). The order is:
 *  1. handler `@RequirePermission`  -> we evaluate (even if the class is public)
 *  2. handler `@PublicRoute`        -> public
 *  3. class   `@RequirePermission`  -> we evaluate
 *  4. class   `@PublicRoute`        -> public
 *  5. nothing                       -> deny (unannotated route)
 *
 * NB: the guard provides the resource at the TYPE level (+ tenant). ABAC conditions on
 * the ATTRIBUTES of a specific resource (e.g. same agency) are checked at the service
 * level by calling the PDP directly with the loaded resource. The guard covers RBAC +
 * CONTEXT conditions (principal.ctx: risk/geo/mfa) = conditional access.
 */
@Injectable()
export class KengelaAuthzGuard implements CanActivate {
  public constructor(
    private readonly reflector: Reflector,
    @Inject(KENGELA_PDP) private readonly pdp: PolicyDecisionPoint,
  ) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const handler = context.getHandler();
    const controller = context.getClass();

    // Precedence handler > class, evaluated level by level (fail-closed): a
    // CLASS @PublicRoute can never neutralize a HANDLER @RequirePermission.
    const handlerPermission = this.reflector.get<RequiredAccess | undefined>(
      KENGELA_PERMISSION,
      handler,
    );
    const handlerPublic = this.reflector.get<boolean | undefined>(KENGELA_PUBLIC, handler);
    const classPermission = this.reflector.get<RequiredAccess | undefined>(
      KENGELA_PERMISSION,
      controller,
    );
    const classPublic = this.reflector.get<boolean | undefined>(KENGELA_PUBLIC, controller);

    const required = handlerPermission ?? (handlerPublic === true ? undefined : classPermission);
    if (required === undefined) {
      if (handlerPublic === true || classPublic === true) {
        return true;
      }
      throw new ForbiddenException('route_not_annotated');
    }

    const principal = this.#principalOf(context);
    if (principal === undefined) {
      throw new UnauthorizedException('no_principal');
    }

    const request: AccessRequest = {
      principal,
      action: required.action,
      resource: { type: required.resourceType, tenantId: principal.tenantId },
    };

    const decision = await this.pdp.check(request);
    switch (decision.effect) {
      case 'allow':
        return true;
      case 'step_up':
        throw new StepUpRequiredException(decision.obligations ?? [], decision.reason);
      case 'deny':
        throw new ForbiddenException(decision.reason);
    }
  }

  #principalOf(context: ExecutionContext): Principal | undefined {
    return context.switchToHttp().getRequest<{ user?: Principal }>().user;
  }
}
