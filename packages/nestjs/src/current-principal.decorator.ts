import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { Principal } from '@kengela/contracts';

/**
 * Injecte le Principal courant (pose sur `req.user` par la couche d'authentification).
 * Ex. `foo(@CurrentPrincipal() principal: Principal) {}`.
 */
export const CurrentPrincipal = createParamDecorator(
  (_data: unknown, context: ExecutionContext): Principal | undefined => {
    const request = context.switchToHttp().getRequest<{ user?: Principal }>();
    return request.user;
  },
);
