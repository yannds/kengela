/**
 * Projection of the RICH `DirectoryProfile` (iam-mapping) → MINIMAL `DirectoryProfile` (contracts).
 *
 * TWO types share the name `DirectoryProfile`:
 *  - the one from `iam-mapping` (this package) is RICH: broken-out identity (firstName/lastName/
 *    displayName), typed `attributes` (DirectoryAttributes), raw `claims`. It is the normalization
 *    target for the 6 IdP sources.
 *  - the one from `@kengela/contracts` (`ProfileForContracts` below) is MINIMAL and STABLE:
 *    `externalId` (non-null), `email?`, `displayName?`, `groups`, `attributes` (free record),
 *    `active`, `source`. It is the shape the `ScimRepository` port consumes.
 *
 * `toContractsProfile` is the PURE projection function between the two. Two fields of the contracts
 * profile do NOT exist in the rich profile and must be provided by the caller:
 *  - `active`: the rich profile does not carry the activation state (it comes from `accountActiveFrom*`
 *    or from the provisioning semantics);
 *  - `source`: the directory source (`oidc`/`scim`/`saml`/`ldap`/`graph`/`google`), known to the
 *    adapter that produced the profile.
 *
 * BRIDGE `ScimStore` (scim-server) ↔ `ScimRepository` (contracts)
 * -----------------------------------------------------------------
 * `ScimStore` (the `@kengela/scim-server` package) is a RICH, CRUD-oriented SCIM persistence port
 * (getUser/createUser/replaceUser/patchUser/listUsers + Groups), with its own rows
 * (`ScimUserRow`…). `ScimRepository` (contracts) is a MINIMAL, reconciliation-oriented federation
 * port (`upsertUserByEmail(tenantId, DirectoryProfile) → {id, created}` +
 * `deactivateUser(tenantId, id)`). The two are therefore NOT interchangeable: the second is a
 * synchronization VIEW on top of the first.
 *
 * A `ScimStore → ScimRepository` adapter is not provided here BY DESIGN, for three design reasons:
 *  1. Placement: it would have to depend both on `@kengela/scim-server` (SCIM rows) and on
 *     `@kengela/contracts`. `iam-mapping` is a CORE package (no vendor, and `scim-server` ALREADY
 *     depends on `iam-mapping` - the reverse would create a cycle). Its natural home is therefore a
 *     composition adapter/app, not this core.
 *  2. Impedance: the contracts `DirectoryProfile` has an OPTIONAL `email`, whereas SCIM requires a
 *     `userName` (reconciliation key); and it has no first-class `firstName`/`lastName` (they live in
 *     `attributes`). Converting to `ScimUserWriteInput` therefore requires application-level
 *     decisions (email fallback, extracting names from `attributes`).
 *  3. The genuinely hard part - projecting any IdP source to a common shape - is exactly what
 *     `toContractsProfile` solves. Once the contracts profile is obtained,
 *     `ScimRepository.upsertUserByEmail(tenantId, profile)` is a direct call on the app side.
 *
 * Sketch of the adapter (to be written on the app side, see guide):
 *   const profile = toContractsProfile(profileFromScim(body), { source: 'scim', active });
 *   await scimRepository.upsertUserByEmail(tenantId, profile);
 */
import type { DirectoryProfile as ContractsDirectoryProfile } from '@kengela/contracts';
import type { DirectoryProfile } from './profile.js';

/** Metadata not carried by the rich profile, required by the contracts profile. */
export interface ContractsProfileMeta {
  readonly source: ContractsDirectoryProfile['source'];
  readonly active: boolean;
}

/** Non-empty string, or `undefined` (respects exactOptionalPropertyTypes). */
function nonEmpty(value: string | null | undefined): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * Projects a rich `DirectoryProfile` to the MINIMAL shape of `@kengela/contracts`.
 *
 * - `externalId` (required, non-null on the contracts side): `rich.externalId`, falling back to the
 *   email (stable fallback); never empty thanks to this fallback (a source with neither is already
 *   pathological and yields an empty string, which the caller is responsible for rejecting).
 * - `email` / `displayName`: omitted (not `undefined`) when absent.
 * - `attributes`: the directory attributes (department/title…) plus `firstName`/`lastName` folded
 *   back in (the contracts profile has no dedicated name field) so nothing is lost.
 *   The raw `claims` are NOT carried over (volume + potential PII).
 */
export function toContractsProfile(
  rich: DirectoryProfile,
  meta: ContractsProfileMeta,
): ContractsDirectoryProfile {
  const email = nonEmpty(rich.email);
  const displayName = nonEmpty(rich.displayName);
  const firstName = nonEmpty(rich.firstName);
  const lastName = nonEmpty(rich.lastName);

  const attributes: Record<string, unknown> = { ...rich.attributes };
  if (firstName !== undefined) {
    attributes['firstName'] = firstName;
  }
  if (lastName !== undefined) {
    attributes['lastName'] = lastName;
  }

  return {
    externalId: nonEmpty(rich.externalId) ?? rich.email,
    ...(email !== undefined ? { email } : {}),
    ...(displayName !== undefined ? { displayName } : {}),
    groups: [...rich.groups],
    attributes,
    active: meta.active,
    source: meta.source,
  };
}
