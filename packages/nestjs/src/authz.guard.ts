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
 * Guard d'autorisation Zero Trust.
 *
 * Deny-by-default : une route sans `@RequirePermission` NI `@PublicRoute` est REFUSEE
 * (corrige le fail-open classique). Sinon, construit une AccessRequest a partir du
 * Principal (`req.user`) et de la metadata, delegue au PDP, et mappe la decision :
 *  - allow    -> passe
 *  - deny     -> ForbiddenException(raison)
 *  - step_up  -> StepUpRequiredException(obligations) — l'authz exige un facteur d'authn
 *
 * NB : le guard fournit la ressource au niveau TYPE (+ tenant). Les conditions ABAC sur
 * les ATTRIBUTS d'une ressource precise (ex. meme agence) se verifient au niveau service
 * en appelant directement le PDP avec la ressource chargee. Le guard couvre RBAC + les
 * conditions de CONTEXTE (principal.ctx : risque/geo/mfa) = conditional access.
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

    const isPublic = this.reflector.getAllAndOverride<boolean>(KENGELA_PUBLIC, [
      handler,
      controller,
    ]);
    if (isPublic) {
      return true;
    }

    const required = this.reflector.getAllAndOverride<RequiredAccess | undefined>(
      KENGELA_PERMISSION,
      [handler, controller],
    );
    if (required === undefined) {
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
