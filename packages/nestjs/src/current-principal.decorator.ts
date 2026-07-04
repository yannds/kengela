import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { Principal } from '@kengela/contracts';

/**
 * Injects the current Principal (set on `req.user` by the authentication layer).
 * E.g. `foo(@CurrentPrincipal() principal: Principal) {}`.
 */
export const CurrentPrincipal = createParamDecorator(
  (_data: unknown, context: ExecutionContext): Principal | undefined => {
    const request = context.switchToHttp().getRequest<{ user?: Principal }>();
    return request.user;
  },
);
