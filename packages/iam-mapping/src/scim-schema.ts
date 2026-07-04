/**
 * Kengela canonical SCIM 2.0 schema - a SUPERSET that reaches beyond any single IdP.
 *
 * Covers the SCIM core (RFC 7643), the enterprise extension, and the richness of the
 * well-known IdPs (Okta, Microsoft Entra / Azure AD, Google Workspace). Each application
 * picks the subset it cares about: TransLog uses only a fraction, another app uses more.
 * The library never FREEZES the list (the `extensions` bag).
 *
 * PURE: types + projection to `DirectoryProfile`. No dependencies.
 */
import type { DirectoryAttributes, DirectoryProfile } from './profile.js';

// ── Schema URNs ──────────────────────────────────────────────────────────────
export const SCIM_SCHEMA_CORE_USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
export const SCIM_SCHEMA_ENTERPRISE_USER =
  'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
export const SCIM_SCHEMA_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';

// ── SCIM sub-structures ──────────────────────────────────────────────────────
/** SCIM multi-valued attribute (emails, phoneNumbers, ims, photos, roles, entitlements). */
export interface ScimMultiValued {
  readonly value?: string;
  readonly type?: string;
  readonly primary?: boolean;
  readonly display?: string;
  readonly ref?: string;
}

export interface ScimName {
  readonly formatted?: string;
  readonly familyName?: string;
  readonly givenName?: string;
  readonly middleName?: string;
  readonly honorificPrefix?: string;
  readonly honorificSuffix?: string;
}

export interface ScimAddress {
  readonly type?: string;
  readonly formatted?: string;
  readonly streetAddress?: string;
  readonly locality?: string;
  readonly region?: string;
  readonly postalCode?: string;
  readonly country?: string;
  readonly primary?: boolean;
}

export interface ScimGroupRef {
  readonly value?: string;
  readonly display?: string;
  readonly ref?: string;
  readonly type?: string;
}

export interface ScimManagerRef {
  readonly value?: string;
  readonly displayName?: string;
  readonly ref?: string;
}

/** SCIM enterprise extension - Okta/Entra populate it heavily. */
export interface ScimEnterpriseExtension {
  readonly employeeNumber?: string;
  readonly costCenter?: string;
  readonly organization?: string;
  readonly division?: string;
  readonly department?: string;
  readonly manager?: ScimManagerRef;
}

export interface ScimMeta {
  readonly resourceType?: string;
  readonly created?: string;
  readonly lastModified?: string;
  readonly location?: string;
  readonly version?: string;
}

/**
 * Kengela canonical SCIM 2.0 user. Every app consumes the subset it needs.
 */
export interface KengelaScimUser {
  readonly schemas?: readonly string[];
  readonly id?: string;
  readonly externalId?: string;
  readonly userName: string;
  readonly name?: ScimName;
  readonly displayName?: string;
  readonly nickName?: string;
  readonly profileUrl?: string;
  readonly title?: string;
  readonly userType?: string;
  readonly preferredLanguage?: string;
  readonly locale?: string;
  readonly timezone?: string;
  readonly active?: boolean;
  readonly emails?: readonly ScimMultiValued[];
  readonly phoneNumbers?: readonly ScimMultiValued[];
  readonly ims?: readonly ScimMultiValued[];
  readonly photos?: readonly ScimMultiValued[];
  readonly addresses?: readonly ScimAddress[];
  readonly groups?: readonly ScimGroupRef[];
  readonly entitlements?: readonly ScimMultiValued[];
  readonly roles?: readonly ScimMultiValued[];
  readonly x509Certificates?: readonly ScimMultiValued[];
  readonly meta?: ScimMeta;
  /** Enterprise extension (dedicated URN). */
  readonly enterprise?: ScimEnterpriseExtension;
  /** Custom schema attributes (Okta app schema, Entra extensions) preserved raw. */
  readonly extensions?: Readonly<Record<string, unknown>>;
}

/**
 * Registry of the canonical attribute paths Kengela can carry. Single source of truth:
 * an app picks what it maps (never hardcoded on the UI side).
 */
export const KENGELA_SCIM_ATTRIBUTE_PATHS: readonly string[] = [
  'userName',
  'externalId',
  'name.givenName',
  'name.familyName',
  'name.formatted',
  'displayName',
  'nickName',
  'title',
  'userType',
  'preferredLanguage',
  'locale',
  'timezone',
  'active',
  'emails',
  'phoneNumbers',
  'addresses',
  'groups',
  'roles',
  'entitlements',
  'photos',
  `${SCIM_SCHEMA_ENTERPRISE_USER}:employeeNumber`,
  `${SCIM_SCHEMA_ENTERPRISE_USER}:costCenter`,
  `${SCIM_SCHEMA_ENTERPRISE_USER}:organization`,
  `${SCIM_SCHEMA_ENTERPRISE_USER}:division`,
  `${SCIM_SCHEMA_ENTERPRISE_USER}:department`,
  `${SCIM_SCHEMA_ENTERPRISE_USER}:manager`,
];

// ── Projection to the internal profile ───────────────────────────────────────
function clean(value: string | undefined): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function primaryValue(list: readonly ScimMultiValued[] | undefined): string | undefined {
  if (list === undefined || list.length === 0) {
    return undefined;
  }
  const chosen = list.find((e) => e.primary === true) ?? list[0];
  return clean(chosen?.value);
}

function primaryAddress(list: readonly ScimAddress[] | undefined): ScimAddress | undefined {
  if (list === undefined || list.length === 0) {
    return undefined;
  }
  return list.find((a) => a.primary === true) ?? list[0];
}

function buildAttributes(
  scalar: Readonly<Record<string, string | undefined>>,
  extensions: Readonly<Record<string, unknown>>,
): DirectoryAttributes {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(scalar)) {
    if (value !== undefined) {
      out[key] = value;
    }
  }
  if (Object.keys(extensions).length > 0) {
    out['extensions'] = extensions;
  }
  return out;
}

/**
 * Projects a canonical SCIM user to the internal `DirectoryProfile`, keeping the rich
 * attributes (enterprise, address, phone, locale...) and preserving custom extensions
 * in `attributes.extensions` + `claims`.
 */
export function projectScimUser(user: KengelaScimUser): DirectoryProfile {
  const enterprise = user.enterprise;
  const address = primaryAddress(user.addresses);
  const email = primaryValue(user.emails) ?? clean(user.userName) ?? '';
  const groups = (user.groups ?? [])
    .map((g) => clean(g.display) ?? clean(g.value))
    .filter((g): g is string => g !== undefined);

  const scalar: Record<string, string | undefined> = {
    department: clean(enterprise?.department),
    division: clean(enterprise?.division),
    title: clean(user.title),
    employeeNumber: clean(enterprise?.employeeNumber),
    costCenter: clean(enterprise?.costCenter),
    manager: clean(enterprise?.manager?.value) ?? clean(enterprise?.manager?.displayName),
    organization: clean(enterprise?.organization),
    employeeType: clean(user.userType),
    preferredLanguage: clean(user.preferredLanguage),
    locale: clean(user.locale),
    timezone: clean(user.timezone),
    phoneNumber: primaryValue(user.phoneNumbers),
    streetAddress: clean(address?.streetAddress),
    city: clean(address?.locality),
    state: clean(address?.region),
    postalCode: clean(address?.postalCode),
    country: clean(address?.country),
  };

  const extensions = user.extensions ?? {};
  const claims: Record<string, unknown> = { ...extensions };
  if (enterprise !== undefined) {
    claims['enterprise'] = enterprise;
  }

  return {
    email,
    externalId: clean(user.externalId) ?? null,
    firstName: clean(user.name?.givenName) ?? null,
    lastName: clean(user.name?.familyName) ?? null,
    displayName: clean(user.displayName) ?? clean(user.name?.formatted) ?? null,
    attributes: buildAttributes(scalar, extensions),
    groups,
    claims,
  };
}
