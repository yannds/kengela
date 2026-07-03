import { ForbiddenException } from '@nestjs/common';
import type { Obligation } from '@kengela/contracts';

/**
 * Levee quand le PDP renvoie `step_up` : l'acces est conditionnel a la
 * satisfaction d'obligations (ex. re-authentification passkey). Le lien intime
 * authz -> authn : l'autorisation exige un facteur d'authentification.
 */
export class StepUpRequiredException extends ForbiddenException {
  public readonly obligations: readonly Obligation[];

  public constructor(obligations: readonly Obligation[], reason: string) {
    super({ statusCode: 403, error: 'step_up_required', reason, obligations });
    this.obligations = obligations;
  }
}
