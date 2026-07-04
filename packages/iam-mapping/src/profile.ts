/**
 * Normalized directory profile (ADR-014, enterprise IdP integration).
 *
 * Single internal source of truth for role mapping and organizational classification,
 * whatever the origin: OIDC claims (Entra/Okta), SAML 2.0 assertion (ADFS via bridge),
 * or SCIM 2.0 attributes + groups. The app NEVER reasons about the raw shape of an IdP:
 * each adapter projects to this `DirectoryProfile`.
 *
 * PURE: no infra dependency (testable without database or network).
 */

/**
 * "Enterprise standard" directory attributes (SCIM enterprise extension + usual Entra/AD
 * claims). All optional: an AD account can be incomplete, and that is precisely the case
 * the classification must catch through groups.
 */
export interface DirectoryAttributes {
  readonly department?: string;
  readonly division?: string;
  readonly title?: string;
  readonly employeeNumber?: string;
  readonly costCenter?: string;
  readonly officeLocation?: string;
  /** email/identifier of the reporting manager (feeds the approval chain). */
  readonly manager?: string;
  // --- Kengela superset (beyond a single IdP: Okta, Entra, Google, LDAP...) ---
  readonly organization?: string;
  readonly companyName?: string;
  readonly employeeType?: string;
  readonly preferredLanguage?: string;
  readonly locale?: string;
  readonly timezone?: string;
  readonly phoneNumber?: string;
  readonly mobilePhone?: string;
  readonly streetAddress?: string;
  readonly city?: string;
  readonly state?: string;
  readonly postalCode?: string;
  readonly country?: string;
  /**
   * Additional attributes not modeled up front (custom Okta/Entra schemas, proprietary
   * extensions...). EXTENSIBLE: each application picks what it needs without the library
   * freezing the list.
   */
  readonly extensions?: Readonly<Record<string, unknown>>;
}

/** Normalized profile of a user as seen by the IdP at login / SCIM sync time. */
export interface DirectoryProfile {
  readonly email: string;
  /** Stable IdP-side identifier (`sub` OIDC / `nameID` SAML / `externalId` SCIM). */
  readonly externalId: string | null;
  /** First name (SCIM `name.givenName` / OIDC `given_name`), or null. */
  readonly firstName: string | null;
  /** Last name (SCIM `name.familyName` / OIDC `family_name`), or null. */
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly attributes: DirectoryAttributes;
  /** Security groups (names or ids depending on the IdP), source of group-based mapping. */
  readonly groups: readonly string[];
  /** Remaining raw claims (e.g. `roles`, `wids`...), for advanced rules. */
  readonly claims: Readonly<Record<string, unknown>>;
}

/**
 * Directory attribute keys recognized by the mapping engine (source `ATTRIBUTE`).
 * Single source of truth: feeds admin-side discovery/autocompletion (never hardcoded in
 * the UI). Stays aligned with `DirectoryAttributes`.
 */
export const DIRECTORY_ATTRIBUTE_KEYS: readonly (keyof DirectoryAttributes)[] = [
  'department',
  'division',
  'title',
  'employeeNumber',
  'costCenter',
  'officeLocation',
  'manager',
  'organization',
  'companyName',
  'employeeType',
  'preferredLanguage',
  'locale',
  'timezone',
  'phoneNumber',
  'mobilePhone',
  'streetAddress',
  'city',
  'state',
  'postalCode',
  'country',
];

/**
 * Profile identity fields (outside directory attributes), mappable from the IdP.
 * Single source of truth: feeds map validation and the mapper UI (never hardcoded).
 */
export const IDENTITY_FIELD_KEYS: readonly string[] = [
  'email',
  'firstName',
  'lastName',
  'displayName',
  'externalId',
  'groups',
];

/**
 * All canonical mappable fields (identity + directory attributes). This is the set of
 * allowed keys of an attribute map (`ScimAttributeMap`/`OidcAttributeMap`/...). Single source.
 */
export const ATTRIBUTE_MAP_FIELDS: readonly string[] = [
  ...IDENTITY_FIELD_KEYS,
  ...DIRECTORY_ATTRIBUTE_KEYS,
];

export type AttributeMapField = (typeof ATTRIBUTE_MAP_FIELDS)[number];

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

function firstString(...vals: unknown[]): string | undefined {
  for (const v of vals) {
    const s = str(v);
    if (s) return s;
  }
  return undefined;
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => str(x)).filter((x): x is string => !!x);
}

/** Removes `undefined` keys (respects `exactOptionalPropertyTypes`). */
function compact(o: Record<string, string | undefined>): DirectoryAttributes {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(o)) if (v !== undefined) out[k] = v;
  return out;
}

/**
 * Builds a `DirectoryProfile` from already-normalized pieces (persisted state: decrypted
 * attributes + group names in database). Used to re-sync from storage (group change)
 * without the original IdP payload.
 */
export function profileFromParts(input: {
  email: string;
  externalId?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  displayName?: string | null;
  attributes?: DirectoryAttributes;
  groups?: readonly string[];
}): DirectoryProfile {
  return {
    email: input.email.toLowerCase(),
    externalId: input.externalId ?? null,
    firstName: input.firstName ?? null,
    lastName: input.lastName ?? null,
    displayName: input.displayName ?? null,
    attributes: input.attributes ?? {},
    groups: [...new Set(input.groups ?? [])],
    claims: {},
  };
}

const ENTERPRISE_EXT = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

/**
 * Attribute map **SCIM -> profile fields** (config-driven, ADR-014). A SCIM resource mixes
 * "core" attributes (top-level) and the enterprise extension (`urn:...:User`). As for LDAP/SAML,
 * the admin can override, field by field, the **path** read on the SCIM side; otherwise a list
 * of usual candidates is tried (the provided path wins, then the defaults). Mini path syntax:
 * `enterprise.<attr>` (extension), `name.givenName` (nested), `emails[primary]` (primary email).
 */
export interface ScimAttributeMap {
  readonly email?: string;
  readonly firstName?: string;
  readonly lastName?: string;
  readonly displayName?: string;
  readonly externalId?: string;
  readonly groups?: string;
  readonly department?: string;
  readonly division?: string;
  readonly title?: string;
  readonly employeeNumber?: string;
  readonly costCenter?: string;
  readonly officeLocation?: string;
  readonly manager?: string;
}

/**
 * Candidate SCIM paths per field (single source of truth), tried in order. Reproduces the
 * historical extraction exactly: without an override, the profile is strictly the same as before.
 */
export const SCIM_DEFAULT_ATTRIBUTE_KEYS: Record<keyof ScimAttributeMap, readonly string[]> = {
  email: ['userName', 'emails[primary]'],
  firstName: ['name.givenName'],
  lastName: ['name.familyName'],
  displayName: ['displayName'],
  externalId: ['externalId'],
  groups: ['groups'],
  department: ['enterprise.department', 'department'],
  division: ['enterprise.division'],
  title: ['title', 'enterprise.title'],
  employeeNumber: ['enterprise.employeeNumber'],
  costCenter: ['enterprise.costCenter'],
  officeLocation: ['enterprise.officeLocation', 'officeLocation'],
  manager: ['enterprise.manager'],
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** The SCIM `manager` can be an object `{value,$ref}` (reference) or a string (email/UPN). */
function scimManagerValue(manager: unknown): string | undefined {
  if (isRecord(manager)) return firstString(manager['value'], manager['$ref']);
  return str(manager);
}

/** Candidate keys for a field: the admin override (if present) wins, then the defaults. */
function scimKeysFor(field: keyof ScimAttributeMap, map: ScimAttributeMap | undefined): string[] {
  const override = map?.[field];
  const defaults = SCIM_DEFAULT_ATTRIBUTE_KEYS[field];
  return override ? [override, ...defaults] : [...defaults];
}

/** Resolves a scalar SCIM value from a path (mini syntax), or undefined. */
function scimResolve(
  body: Record<string, unknown>,
  enterprise: Record<string, unknown>,
  path: string,
): string | undefined {
  if (path === 'emails[primary]') {
    const emails = Array.isArray(body['emails'])
      ? (body['emails'] as Record<string, unknown>[])
      : [];
    return str(emails.find((e) => e['primary'])?.['value']) ?? str(emails[0]?.['value']);
  }
  if (path.startsWith('enterprise.')) {
    const key = path.slice('enterprise.'.length);
    return key === 'manager' ? scimManagerValue(enterprise['manager']) : str(enterprise[key]);
  }
  if (path === 'manager') return scimManagerValue(body['manager']);
  if (path.includes('.')) {
    const parts = path.split('.');
    let cur: unknown = body;
    for (const k of parts) cur = isRecord(cur) ? cur[k] : undefined;
    return str(cur);
  }
  return str(body[path]);
}

/** First non-empty SCIM value among a field's candidate paths. */
function scimFirst(
  body: Record<string, unknown>,
  enterprise: Record<string, unknown>,
  keys: readonly string[],
): string | undefined {
  for (const k of keys) {
    const v = scimResolve(body, enterprise, k);
    if (v) return v;
  }
  return undefined;
}

/** SCIM groups from the first candidate path carrying a list (objects `{display,value}` or strings). */
function scimGroups(body: Record<string, unknown>, keys: readonly string[]): string[] {
  for (const k of keys) {
    const raw = isRecord(body[k]) ? undefined : body[k];
    if (!Array.isArray(raw)) continue;
    const arr = raw
      .map((g) => (isRecord(g) ? firstString(g['display'], g['value']) : str(g)))
      .filter((g): g is string => !!g);
    if (arr.length) return arr;
  }
  return [];
}

/**
 * Projects a SCIM 2.0 user (core + enterprise extension) to `DirectoryProfile`.
 * Tolerant: missing fields -> undefined. `attributeMap` (tenant config) overrides the read paths;
 * without it, the extraction is strictly identical to the historical one. `groups` comes from the
 * SCIM memberships (`groups`) when present.
 */
export function profileFromScim(
  body: Record<string, unknown>,
  attributeMap?: ScimAttributeMap,
): DirectoryProfile {
  const enterprise = (body[ENTERPRISE_EXT] as Record<string, unknown> | undefined) ?? {};
  const k = (field: keyof ScimAttributeMap): string[] => scimKeysFor(field, attributeMap);
  const firstName = scimFirst(body, enterprise, k('firstName'));
  const lastName = scimFirst(body, enterprise, k('lastName'));

  return {
    email: (scimFirst(body, enterprise, k('email')) ?? '').toLowerCase(),
    externalId: scimFirst(body, enterprise, k('externalId')) ?? null,
    firstName: firstName ?? null,
    lastName: lastName ?? null,
    displayName:
      firstString(
        scimFirst(body, enterprise, k('displayName')),
        [firstName, lastName].filter(Boolean).join(' '),
      ) ?? null,
    attributes: compact({
      department: scimFirst(body, enterprise, k('department')),
      division: scimFirst(body, enterprise, k('division')),
      title: scimFirst(body, enterprise, k('title')),
      employeeNumber: scimFirst(body, enterprise, k('employeeNumber')),
      costCenter: scimFirst(body, enterprise, k('costCenter')),
      officeLocation: scimFirst(body, enterprise, k('officeLocation')),
      manager: scimFirst(body, enterprise, k('manager')),
    }),
    groups: scimGroups(body, k('groups')),
    claims: body,
  };
}

/** Directory user read via Microsoft Graph (`/users`) - structural shape (no infra dependency). */
export interface GraphUserParts {
  readonly id?: string | null;
  readonly userPrincipalName?: string | null;
  readonly mail?: string | null;
  readonly displayName?: string | null;
  readonly givenName?: string | null;
  readonly surname?: string | null;
  readonly jobTitle?: string | null;
  readonly department?: string | null;
  readonly officeLocation?: string | null;
  readonly employeeId?: string | null;
  /** email/UPN of the reporting manager (Graph `manager` navigation property). */
  readonly manager?: string | null;
  readonly groups?: readonly string[];
}

/**
 * Projects a **Microsoft Graph** user (`/users` + groups) to `DirectoryProfile`.
 * The "pull" counterpart of SCIM "push" provisioning: same normalized target => **same role
 * mapping and same classification** as SCIM/OIDC, whatever the sync direction.
 */
export function profileFromGraph(user: GraphUserParts): DirectoryProfile {
  return {
    email: (firstString(user.mail, user.userPrincipalName) ?? '').toLowerCase(),
    externalId: str(user.id) ?? null,
    firstName: str(user.givenName) ?? null,
    lastName: str(user.surname) ?? null,
    displayName:
      firstString(
        user.displayName,
        [str(user.givenName), str(user.surname)].filter(Boolean).join(' '),
      ) ?? null,
    attributes: compact({
      department: str(user.department),
      title: str(user.jobTitle),
      employeeNumber: str(user.employeeId),
      officeLocation: str(user.officeLocation),
      manager: str(user.manager),
    }),
    groups: [...new Set(asStringArray(user.groups))],
    claims: {},
  };
}

/**
 * Attribute map **LDAP -> profile fields** (config-driven, ADR-014). An LDAP directory has no
 * universal attribute schema: Active Directory says `sn`/`memberOf`, an OpenLDAP may say
 * `surname`/`groupMembership`. The admin can therefore override each attribute name per tenant.
 * Any missing field falls back to the Active Directory default (`LDAP_AD_ATTRIBUTE_DEFAULTS`).
 */
export interface LdapAttributeMap {
  readonly email?: string;
  readonly firstName?: string;
  readonly lastName?: string;
  readonly displayName?: string;
  readonly externalId?: string;
  readonly groups?: string;
  readonly department?: string;
  readonly division?: string;
  readonly title?: string;
  readonly employeeNumber?: string;
  readonly costCenter?: string;
  readonly officeLocation?: string;
  readonly manager?: string;
}

/**
 * Default LDAP attribute names (**Active Directory**), single source of truth. Overridable
 * one by one via `attributeMap` (never hardcoded in the UI: also feeds admin-side assisted input).
 * `costCenter` has no standard AD attribute (empty string => no default).
 */
export const LDAP_AD_ATTRIBUTE_DEFAULTS: Required<LdapAttributeMap> = {
  email: 'mail',
  firstName: 'givenName',
  lastName: 'sn',
  displayName: 'displayName',
  externalId: 'objectGUID',
  groups: 'memberOf',
  department: 'department',
  division: 'division',
  title: 'title',
  employeeNumber: 'employeeNumber',
  costCenter: '',
  officeLocation: 'physicalDeliveryOfficeName',
  manager: 'manager',
};

/** Normalized LDAP directory entry: DN + attributes (single- or multi-valued already as strings). */
export interface LdapEntryParts {
  readonly dn: string;
  /** LDAP attributes. The client is responsible for stringifying binaries (e.g. `objectGUID`). */
  readonly attributes: Readonly<Record<string, string | readonly string[] | undefined>>;
  /** Override of attribute names (otherwise Active Directory defaults). */
  readonly attributeMap?: LdapAttributeMap;
}

/** Values (non-empty strings) of an LDAP attribute, always as an array. */
function ldapValues(attrs: LdapEntryParts['attributes'], name: string | undefined): string[] {
  if (!name) return [];
  const v = attrs[name];
  if (v === undefined) return [];
  return (Array.isArray(v) ? v : [v]).map((x) => str(x)).filter((x): x is string => !!x);
}

/** First value of an LDAP attribute, or undefined. */
function ldapFirst(
  attrs: LdapEntryParts['attributes'],
  name: string | undefined,
): string | undefined {
  return ldapValues(attrs, name)[0];
}

/** Extracts the CN of a DN's first RDN (`CN=HR Group,OU=Groups,DC=corp` -> `HR Group`). Fallback: raw DN. */
function cnFromDn(dn: string): string {
  const m = /^\s*cn\s*=\s*([^,]+)/i.exec(dn);
  return (m?.[1] ?? dn).trim();
}

/**
 * Projects an **LDAP / Active Directory** entry to `DirectoryProfile`. Same normalized target as
 * Graph/OIDC/SCIM => **same role mapping and same classification**, without rewriting the engine.
 * Groups come from `memberOf` (DN => CN). The manager (`manager`, a DN in AD) is reduced to its CN
 * for lack of a second call (V2 debt: resolve the manager DN to an email).
 */
export function profileFromLdap(e: LdapEntryParts): DirectoryProfile {
  const map = { ...LDAP_AD_ATTRIBUTE_DEFAULTS, ...(e.attributeMap ?? {}) };
  const a = e.attributes;
  const managerRaw = ldapFirst(a, map.manager);
  return {
    email: (ldapFirst(a, map.email) ?? ldapFirst(a, 'userPrincipalName') ?? '').toLowerCase(),
    externalId: ldapFirst(a, map.externalId) ?? str(e.dn) ?? null,
    firstName: ldapFirst(a, map.firstName) ?? null,
    lastName: ldapFirst(a, map.lastName) ?? null,
    displayName:
      firstString(
        ldapFirst(a, map.displayName),
        ldapFirst(a, 'cn'),
        [ldapFirst(a, map.firstName), ldapFirst(a, map.lastName)].filter(Boolean).join(' '),
      ) ?? null,
    attributes: compact({
      department: ldapFirst(a, map.department),
      division: ldapFirst(a, map.division),
      title: ldapFirst(a, map.title),
      employeeNumber: firstString(ldapFirst(a, map.employeeNumber), ldapFirst(a, 'employeeID')),
      costCenter: ldapFirst(a, map.costCenter),
      officeLocation: ldapFirst(a, map.officeLocation),
      manager: managerRaw ? cnFromDn(managerRaw) : undefined,
    }),
    groups: [...new Set(ldapValues(a, map.groups).map(cnFromDn))],
    claims: {},
  };
}

/**
 * Active LDAP account? Active Directory encodes deactivation in `userAccountControl` (bit
 * `0x2`, ACCOUNTDISABLE). Missing attribute (OpenLDAP and derivatives) => considered **active**
 * (deprovisioning then goes through the import scope, not this flag).
 */
export function accountActiveFromLdap(e: LdapEntryParts): boolean {
  const uac = Number(ldapFirst(e.attributes, 'userAccountControl'));
  if (Number.isFinite(uac)) return (uac & 0x2) === 0;
  return true;
}

/** Google Workspace organization (Admin SDK Directory `users.organizations[]`). */
export interface GoogleOrganization {
  readonly department?: string | null;
  readonly title?: string | null;
  readonly costCenter?: string | null;
  readonly location?: string | null;
  readonly primary?: boolean | null;
}

/** Google Workspace relation (`users.relations[]`) - carries the reporting manager in particular. */
export interface GoogleRelation {
  readonly type?: string | null;
  readonly value?: string | null;
}

/** Google Workspace user (Admin SDK Directory `users.list` + client-resolved groups). */
export interface GoogleDirectoryUserParts {
  readonly id?: string | null;
  readonly primaryEmail?: string | null;
  readonly name?: {
    givenName?: string | null;
    familyName?: string | null;
    fullName?: string | null;
  } | null;
  readonly organizations?: readonly GoogleOrganization[] | null;
  readonly relations?: readonly GoogleRelation[] | null;
  readonly suspended?: boolean | null;
  /** Names (or emails) of the user's groups, resolved by the client (`groups.list`). */
  readonly groups?: readonly string[];
}

/** "Primary" organization of a Google account (`primary` flag, otherwise the first one). */
function primaryOrganization(orgs: GoogleDirectoryUserParts['organizations']): GoogleOrganization {
  if (!orgs?.length) return {};
  return orgs.find((o) => o.primary) ?? orgs[0] ?? {};
}

/**
 * Projects a **Google Workspace** user (Admin SDK Directory) to `DirectoryProfile`. Same
 * normalized target as Graph/OIDC/SCIM/LDAP => **same role mapping and same classification**.
 * Groups are provided pre-resolved by the client (`groups.list per user`). The manager comes
 * from the typed `manager` relation.
 */
export function profileFromGoogle(u: GoogleDirectoryUserParts): DirectoryProfile {
  const org = primaryOrganization(u.organizations);
  const managerRel = (u.relations ?? []).find((r) => str(r.type)?.toLowerCase() === 'manager');
  const name = u.name ?? {};
  return {
    email: (str(u.primaryEmail) ?? '').toLowerCase(),
    externalId: str(u.id) ?? null,
    firstName: str(name.givenName) ?? null,
    lastName: str(name.familyName) ?? null,
    displayName:
      firstString(
        name.fullName,
        [str(name.givenName), str(name.familyName)].filter(Boolean).join(' '),
      ) ?? null,
    attributes: compact({
      department: str(org.department),
      title: str(org.title),
      costCenter: str(org.costCenter),
      officeLocation: str(org.location),
      manager: str(managerRel?.value),
    }),
    groups: [...new Set(asStringArray(u.groups))],
    claims: {},
  };
}

/** Active Google account? `suspended === true` => deactivated (deprovisioning). */
export function accountActiveFromGoogle(u: GoogleDirectoryUserParts): boolean {
  return u.suspended !== true;
}

/**
 * Attribute map **SAML -> profile fields** (config-driven, ADR-014). A SAML assertion has no
 * universal attribute name: ADFS emits long URIs (`http://schemas.xmlsoap.org/.../emailaddress`),
 * other IdPs use short names (`mail`, `givenName`). The admin can therefore override each field per
 * tenant; otherwise a list of **usual candidates** is tried (ADFS + Entra + short names + urn:oid).
 */
export interface SamlAttributeMap {
  readonly email?: string;
  readonly firstName?: string;
  readonly lastName?: string;
  readonly displayName?: string;
  readonly groups?: string;
  readonly department?: string;
  readonly division?: string;
  readonly title?: string;
  readonly employeeNumber?: string;
  readonly costCenter?: string;
  readonly officeLocation?: string;
  readonly manager?: string;
}

/**
 * Candidate SAML attributes per field (single source of truth), tried in order. Covers the ADFS
 * conventions (URIs `schemas.xmlsoap.org`/`schemas.microsoft.com`), Entra, short names and
 * `urn:oid`. Overridable field by field via `SamlAttributeMap` (the provided name wins).
 */
export const SAML_DEFAULT_ATTRIBUTE_KEYS: Record<keyof SamlAttributeMap, readonly string[]> = {
  email: [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'email',
    'mail',
    'urn:oid:0.9.2342.19200300.100.1.3',
  ],
  firstName: [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    'givenName',
    'first_name',
    'urn:oid:2.5.4.42',
  ],
  lastName: [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    'surname',
    'sn',
    'last_name',
    'urn:oid:2.5.4.4',
  ],
  displayName: [
    'http://schemas.microsoft.com/identity/claims/displayname',
    'displayName',
    'name',
    'cn',
  ],
  groups: [
    'http://schemas.xmlsoap.org/claims/Group',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
    'groups',
    'memberOf',
    'Role',
  ],
  department: ['http://schemas.xmlsoap.org/claims/department', 'department'],
  division: ['division'],
  title: ['title', 'jobTitle'],
  employeeNumber: ['employeeNumber', 'employeeId', 'urn:oid:2.16.840.1.113730.3.1.3'],
  costCenter: ['costCenter'],
  officeLocation: ['officeLocation', 'physicalDeliveryOfficeName'],
  manager: ['manager', 'managerEmail'],
};

/** Normalized SAML 2.0 assertion: nameID + attributes (single- or multi-valued) + optional map. */
export interface SamlAssertionParts {
  /** SAML subject identifier (`<NameID>`), often the email. Used as externalId and email fallback. */
  readonly nameId: string | null;
  readonly attributes: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly attributeMap?: SamlAttributeMap;
}

/** Candidate keys for a field: the admin override (if present) wins, then the defaults. */
function samlKeysFor(field: keyof SamlAttributeMap, map: SamlAttributeMap | undefined): string[] {
  const override = map?.[field];
  const defaults = SAML_DEFAULT_ATTRIBUTE_KEYS[field];
  return override ? [override, ...defaults] : [...defaults];
}

/** Values (non-empty strings) of the first SAML attribute present among the candidate keys. */
function samlValues(attrs: SamlAssertionParts['attributes'], keys: readonly string[]): string[] {
  for (const k of keys) {
    const v = attrs[k];
    if (v === undefined) continue;
    const arr = (Array.isArray(v) ? v : [v]).map((x) => str(x)).filter((x): x is string => !!x);
    if (arr.length) return arr;
  }
  return [];
}

function samlFirst(
  attrs: SamlAssertionParts['attributes'],
  keys: readonly string[],
): string | undefined {
  return samlValues(attrs, keys)[0];
}

/**
 * Projects a **SAML 2.0 assertion** (ADFS, Entra, Okta, Keycloak via SAML) to `DirectoryProfile`.
 * This is the "hard part" of the SAML connector: once the assertion is projected to this common
 * target, **the existing role mapping and classification work as is**, as for OIDC/SCIM.
 * `nameID` serves as a stable externalId and email fallback. Groups come from the IdP's group or
 * role claim. The raw attributes are kept in `claims` for advanced rules.
 */
export function profileFromSaml(a: SamlAssertionParts): DirectoryProfile {
  const map = a.attributeMap;
  const k = (field: keyof SamlAttributeMap): string[] => samlKeysFor(field, map);
  const firstName = samlFirst(a.attributes, k('firstName'));
  const lastName = samlFirst(a.attributes, k('lastName'));
  return {
    email: (samlFirst(a.attributes, k('email')) ?? str(a.nameId) ?? '').toLowerCase(),
    externalId: str(a.nameId) ?? null,
    firstName: firstName ?? null,
    lastName: lastName ?? null,
    displayName:
      firstString(
        samlFirst(a.attributes, k('displayName')),
        [firstName, lastName].filter(Boolean).join(' '),
      ) ?? null,
    attributes: compact({
      department: samlFirst(a.attributes, k('department')),
      division: samlFirst(a.attributes, k('division')),
      title: samlFirst(a.attributes, k('title')),
      employeeNumber: samlFirst(a.attributes, k('employeeNumber')),
      costCenter: samlFirst(a.attributes, k('costCenter')),
      officeLocation: samlFirst(a.attributes, k('officeLocation')),
      manager: samlFirst(a.attributes, k('manager')),
    }),
    groups: [...new Set(samlValues(a.attributes, k('groups')))],
    claims: a.attributes,
  };
}

/**
 * Attribute map **OIDC -> profile fields** (config-driven, ADR-014). Claims vary by IdP
 * (Entra `jobTitle`, Okta `title`...). The admin can override, claim by claim, the read name;
 * otherwise a list of usual claims is tried (the provided name wins, then the defaults). The
 * `groups` aggregate (union) **all** candidate claims (an IdP may populate `groups`, `roles` and `wids`).
 */
export interface OidcAttributeMap {
  readonly email?: string;
  readonly firstName?: string;
  readonly lastName?: string;
  readonly displayName?: string;
  readonly externalId?: string;
  readonly groups?: string;
  readonly department?: string;
  readonly division?: string;
  readonly title?: string;
  readonly employeeNumber?: string;
  readonly costCenter?: string;
  readonly officeLocation?: string;
  readonly manager?: string;
}

/**
 * Candidate OIDC claims per field (single source of truth), tried in order. Reproduces the
 * historical extraction exactly: without an override, the profile is strictly the same as before.
 */
export const OIDC_DEFAULT_ATTRIBUTE_KEYS: Record<keyof OidcAttributeMap, readonly string[]> = {
  email: ['email', 'preferred_username', 'upn'],
  firstName: ['given_name', 'givenName'],
  lastName: ['family_name', 'familyName', 'surname'],
  displayName: ['name', 'given_name'],
  externalId: ['sub', 'oid'],
  groups: ['groups', 'roles', 'wids'],
  department: ['department'],
  division: ['division'],
  title: ['jobTitle', 'title'],
  employeeNumber: ['employeeId', 'employeeNumber'],
  costCenter: ['costCenter'],
  officeLocation: ['officeLocation', 'physicalDeliveryOfficeName'],
  manager: ['manager', 'managerEmail'],
};

function oidcKeysFor(field: keyof OidcAttributeMap, map: OidcAttributeMap | undefined): string[] {
  const override = map?.[field];
  const defaults = OIDC_DEFAULT_ATTRIBUTE_KEYS[field];
  return override ? [override, ...defaults] : [...defaults];
}

/** First non-empty claim value among the candidates. */
function oidcFirst(claims: Record<string, unknown>, keys: readonly string[]): string | undefined {
  return firstString(...keys.map((key) => claims[key]));
}

/**
 * Projects the claims of an OIDC token (Entra ID / Okta / Keycloak) to `DirectoryProfile`.
 * `attributeMap` (tenant config) overrides the read claims; without it, the extraction is strictly
 * identical to the historical one. Groups aggregate all candidate claims (`groups`/`roles`/`wids`).
 */
export function profileFromOidcClaims(
  claims: Record<string, unknown>,
  attributeMap?: OidcAttributeMap,
): DirectoryProfile {
  const k = (field: keyof OidcAttributeMap): string[] => oidcKeysFor(field, attributeMap);
  const groups = k('groups').flatMap((key) => asStringArray(claims[key]));
  return {
    email: (oidcFirst(claims, k('email')) ?? '').toLowerCase(),
    externalId: oidcFirst(claims, k('externalId')) ?? null,
    firstName: oidcFirst(claims, k('firstName')) ?? null,
    lastName: oidcFirst(claims, k('lastName')) ?? null,
    displayName: oidcFirst(claims, k('displayName')) ?? null,
    attributes: compact({
      department: oidcFirst(claims, k('department')),
      division: oidcFirst(claims, k('division')),
      title: oidcFirst(claims, k('title')),
      employeeNumber: oidcFirst(claims, k('employeeNumber')),
      costCenter: oidcFirst(claims, k('costCenter')),
      officeLocation: oidcFirst(claims, k('officeLocation')),
      manager: oidcFirst(claims, k('manager')),
    }),
    groups: [...new Set(groups)],
    claims,
  };
}
