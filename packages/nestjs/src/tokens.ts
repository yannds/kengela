/**
 * NestJS injection token for the PolicyDecisionPoint.
 * The application provides the implementation (e.g. authz-core's LayeredDecisionPoint).
 */
export const KENGELA_PDP = Symbol('KENGELA_PDP');
