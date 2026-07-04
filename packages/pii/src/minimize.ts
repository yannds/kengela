import type { DirectoryProfile } from '@kengela/iam-mapping';

/**
 * Data minimization (GDPR art. 5.1.c): keeps ONLY the attributes explicitly
 * allowed for the app's purpose. Raw `claims` are dropped, and unauthorized
 * identity fields are nulled out (`null`).
 *
 * This is the "data" counterpart of the Kengela principle "each app picks its
 * own subset": TransLog does not need half of the attributes.
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
