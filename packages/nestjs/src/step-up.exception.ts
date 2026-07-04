import { ForbiddenException } from '@nestjs/common';
import type { Obligation } from '@kengela/contracts';

/**
 * Thrown when the PDP returns `step_up`: access is conditional on satisfying
 * obligations (e.g. passkey re-authentication). The intimate authz -> authn
 * link: authorization requires an authentication factor.
 */
export class StepUpRequiredException extends ForbiddenException {
  public readonly obligations: readonly Obligation[];

  public constructor(obligations: readonly Obligation[], reason: string) {
    super({ statusCode: 403, error: 'step_up_required', reason, obligations });
    this.obligations = obligations;
  }
}
