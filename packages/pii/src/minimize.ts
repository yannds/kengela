import type { DirectoryProfile } from '@kengela/iam-mapping';

/**
 * Minimisation des données (RGPD art. 5.1.c) : ne conserve QUE les attributs
 * explicitement autorisés pour la finalité de l'app. Les `claims` bruts sont
 * supprimés, les champs d'identité non autorisés sont neutralisés (`null`).
 *
 * C'est le pendant "données" du principe Kengela « chaque app pioche son
 * sous-ensemble » : TransLog n'a pas besoin de la moitié des attributs.
 */
export function minimizeProfile(
  profile: DirectoryProfile,
  allowedFields: readonly string[],
): DirectoryProfile {
  const allow = new Set(allowedFields);
  const attributes: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(profile.attributes)) {
    if (value !== undefined && allow.has(key)) {
      attributes[key] = value;
    }
  }
  return {
    email: profile.email,
    externalId: profile.externalId,
    firstName: allow.has('firstName') ? profile.firstName : null,
    lastName: allow.has('lastName') ? profile.lastName : null,
    displayName: allow.has('displayName') ? profile.displayName : null,
    attributes,
    groups: profile.groups,
    claims: {},
  };
}
