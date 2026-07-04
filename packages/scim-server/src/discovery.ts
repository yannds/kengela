/**
 * SCIM 2.0 DISCOVERY endpoints (RFC 7644 §4) - PURE handlers, no HTTP nor store.
 *
 * Provides the core SELF-DESCRIPTION: service provider capabilities
 * (`/ServiceProviderConfig`), resource types (`/ResourceTypes`) and schema definitions
 * (`/Schemas`) for OUR schema - core User (RFC 7643 §4.1), enterprise extension (§4.3)
 * and Group (§4.2). The Microsoft Entra validator queries them to configure itself.
 *
 * The definitions describe exactly what `KengelaScimUser` / `toScimUser` can carry:
 * they are the source of truth consumed by `validateScimUser`.
 */
import {
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  SCIM_SCHEMA_GROUP,
} from '@kengela/iam-mapping';
import { MAX_PAGE_SIZE, SCIM_SCHEMA_LIST_RESPONSE } from './serialize.js';
import type { ScimResponse } from './types.js';

// -- URNs of the discovery resources (RFC 7643 §5/§6/§7) ----------------------
export const SCIM_SCHEMA_SERVICE_PROVIDER_CONFIG =
  'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig';
export const SCIM_SCHEMA_RESOURCE_TYPE = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType';
export const SCIM_SCHEMA_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Schema';

// -- Schema attribute definition (RFC 7643 §7) --------------------------------
type ScimAttributeType = 'string' | 'boolean' | 'complex' | 'reference';
type ScimMutability = 'readOnly' | 'readWrite' | 'immutable' | 'writeOnly';
type ScimReturned = 'always' | 'never' | 'default' | 'request';
type ScimUniqueness = 'none' | 'server' | 'global';

interface AttributeSpec {
  readonly name: string;
  readonly type?: ScimAttributeType;
  readonly multiValued?: boolean;
  readonly required?: boolean;
  readonly caseExact?: boolean;
  readonly mutability?: ScimMutability;
  readonly returned?: ScimReturned;
  readonly uniqueness?: ScimUniqueness;
  readonly description?: string;
  readonly canonicalValues?: readonly string[];
  readonly subAttributes?: readonly AttributeSpec[];
}

/** Expands an `AttributeSpec` into a full SCIM schema attribute (RFC 7643 §7 defaults). */
function attribute(spec: AttributeSpec): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: spec.name,
    type: spec.type ?? 'string',
    multiValued: spec.multiValued ?? false,
    description: spec.description ?? spec.name,
    required: spec.required ?? false,
    caseExact: spec.caseExact ?? false,
    mutability: spec.mutability ?? 'readWrite',
    returned: spec.returned ?? 'default',
    uniqueness: spec.uniqueness ?? 'none',
  };
  if (spec.canonicalValues !== undefined) {
    out['canonicalValues'] = [...spec.canonicalValues];
  }
  if (spec.subAttributes !== undefined) {
    out['subAttributes'] = spec.subAttributes.map((sub) => attribute(sub));
  }
  return out;
}

const MULTI_VALUE_SUBS: readonly AttributeSpec[] = [
  { name: 'value', description: 'Entry value (e.g. email address).' },
  { name: 'type', description: 'Type label (e.g. work, home).' },
  { name: 'primary', type: 'boolean', description: 'Marks the primary entry.' },
  { name: 'display', mutability: 'readOnly', description: 'Human-readable label.' },
];

const NAME_SUBS: readonly AttributeSpec[] = [
  { name: 'formatted', description: 'Full formatted name.' },
  { name: 'familyName', description: 'Family name.' },
  { name: 'givenName', description: 'Given name.' },
  { name: 'middleName', description: 'Middle name.' },
  { name: 'honorificPrefix', description: 'Honorific prefix (Mrs, Mr).' },
  { name: 'honorificSuffix', description: 'Honorific suffix.' },
];

const USER_ATTRIBUTES: readonly AttributeSpec[] = [
  {
    name: 'userName',
    required: true,
    uniqueness: 'server',
    description: 'Unique login identifier (carries the email).',
  },
  { name: 'name', type: 'complex', subAttributes: NAME_SUBS, description: 'Name components.' },
  { name: 'displayName', description: "User's display name." },
  { name: 'nickName', description: 'Nickname.' },
  { name: 'title', description: 'Job title.' },
  { name: 'userType', description: 'User category.' },
  { name: 'preferredLanguage', description: 'Preferred language (BCP 47).' },
  { name: 'locale', description: 'Locale (e.g. fr-FR).' },
  { name: 'timezone', description: 'Time zone (IANA).' },
  {
    name: 'active',
    type: 'boolean',
    description: 'Administrative status (provisioning/deprovisioning).',
  },
  {
    name: 'emails',
    type: 'complex',
    multiValued: true,
    subAttributes: MULTI_VALUE_SUBS,
    description: "User's email addresses.",
  },
  {
    name: 'phoneNumbers',
    type: 'complex',
    multiValued: true,
    subAttributes: MULTI_VALUE_SUBS,
    description: 'Phone numbers.',
  },
];

const ENTERPRISE_ATTRIBUTES: readonly AttributeSpec[] = [
  { name: 'employeeNumber', description: "Employee's staff number." },
  { name: 'costCenter', description: 'Cost center.' },
  { name: 'organization', description: 'Organization.' },
  { name: 'division', description: 'Division.' },
  { name: 'department', description: 'Department.' },
  {
    name: 'manager',
    type: 'complex',
    description: "User's manager.",
    subAttributes: [
      { name: 'value', description: 'Manager id.' },
      { name: 'displayName', mutability: 'readOnly', description: 'Manager name.' },
      { name: '$ref', type: 'reference', description: 'URI of the manager resource.' },
    ],
  },
];

const GROUP_ATTRIBUTES: readonly AttributeSpec[] = [
  {
    name: 'displayName',
    required: true,
    description: "Group's display name.",
  },
  {
    name: 'members',
    type: 'complex',
    multiValued: true,
    description: 'Group members.',
    subAttributes: [
      { name: 'value', mutability: 'immutable', description: 'Member id.' },
      { name: '$ref', type: 'reference', mutability: 'immutable', description: 'Member URI.' },
      { name: 'type', mutability: 'immutable', description: 'Member type (User/Group).' },
      { name: 'display', mutability: 'immutable', description: 'Member label.' },
    ],
  },
];

function schemaResource(
  id: string,
  name: string,
  description: string,
  attributes: readonly AttributeSpec[],
): Record<string, unknown> {
  return {
    id,
    name,
    description,
    attributes: attributes.map((spec) => attribute(spec)),
    meta: { resourceType: 'Schema', location: `Schemas/${id}` },
  };
}

/**
 * SCIM schema definitions of OUR core (RFC 7643 §7): core User, enterprise extension
 * and Group. Self-description of `KengelaScimUser`, consumed by `validateScimUser`.
 */
export function schemaDefinitions(): readonly Record<string, unknown>[] {
  return [
    schemaResource(
      SCIM_SCHEMA_CORE_USER,
      'User',
      'SCIM 2.0 user (RFC 7643 §4.1).',
      USER_ATTRIBUTES,
    ),
    schemaResource(
      SCIM_SCHEMA_ENTERPRISE_USER,
      'EnterpriseUser',
      'Enterprise extension of the user (RFC 7643 §4.3).',
      ENTERPRISE_ATTRIBUTES,
    ),
    schemaResource(SCIM_SCHEMA_GROUP, 'Group', 'SCIM 2.0 group (RFC 7643 §4.2).', GROUP_ATTRIBUTES),
  ];
}

/** Exposed resource types (RFC 7643 §6): User (+ enterprise extension) and Group. */
export function resourceTypes(): readonly Record<string, unknown>[] {
  return [
    {
      schemas: [SCIM_SCHEMA_RESOURCE_TYPE],
      id: 'User',
      name: 'User',
      endpoint: '/Users',
      description: 'Provisioned user (RFC 7643 §4.1).',
      schema: SCIM_SCHEMA_CORE_USER,
      schemaExtensions: [{ schema: SCIM_SCHEMA_ENTERPRISE_USER, required: false }],
      meta: { resourceType: 'ResourceType', location: 'ResourceTypes/User' },
    },
    {
      schemas: [SCIM_SCHEMA_RESOURCE_TYPE],
      id: 'Group',
      name: 'Group',
      endpoint: '/Groups',
      description: 'Provisioned group (RFC 7643 §4.2).',
      schema: SCIM_SCHEMA_GROUP,
      meta: { resourceType: 'ResourceType', location: 'ResourceTypes/Group' },
    },
  ];
}

/**
 * Service provider configuration (RFC 7643 §5): the REAL capabilities of this core.
 * PATCH supported, filter supported (bounded), bulk/sort/etag/changePassword unsupported;
 * authentication via OAuth bearer token.
 */
export function serviceProviderConfig(): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMA_SERVICE_PROVIDER_CONFIG],
    documentationUri: 'https://datatracker.ietf.org/doc/html/rfc7644',
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: MAX_PAGE_SIZE },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: 'oauthbearertoken',
        name: 'OAuth Bearer Token',
        description: 'Authentication via OAuth 2.0 bearer token (Authorization header).',
        specUri: 'https://datatracker.ietf.org/doc/html/rfc6750',
        documentationUri: 'https://datatracker.ietf.org/doc/html/rfc6750',
        primary: true,
      },
    ],
    meta: {
      resourceType: 'ServiceProviderConfig',
      location: 'ServiceProviderConfig',
    },
  };
}

function discoveryList(resources: readonly Record<string, unknown>[]): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMA_LIST_RESPONSE],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

function notFound(detail: string): ScimResponse {
  return {
    status: 404,
    body: {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '404',
      scimType: 'invalidValue',
      detail,
    },
  };
}

/** GET `/ServiceProviderConfig`: 200 with the provider configuration. */
export function handleServiceProviderConfig(): ScimResponse {
  return { status: 200, body: serviceProviderConfig() };
}

/**
 * GET `/ResourceTypes` (list) or `/ResourceTypes/:id` (single resource). 404 if the requested
 * `id` is unknown.
 */
export function handleResourceTypes(pathId?: string): ScimResponse {
  const all = resourceTypes();
  if (pathId === undefined) {
    return { status: 200, body: discoveryList(all) };
  }
  const found = all.find((rt) => rt['id'] === pathId);
  return found === undefined
    ? notFound(`Resource type not found: ${pathId}.`)
    : { status: 200, body: found };
}

/**
 * GET `/Schemas` (list) or `/Schemas/:id` (single definition by URN). 404 if the requested
 * URN is not one of ours.
 */
export function handleSchemas(pathId?: string): ScimResponse {
  const all = schemaDefinitions();
  if (pathId === undefined) {
    return { status: 200, body: discoveryList(all) };
  }
  const found = all.find((s) => s['id'] === pathId);
  return found === undefined
    ? notFound(`Schema not found: ${pathId}.`)
    : { status: 200, body: found };
}
