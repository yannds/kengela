/**
 * Endpoints de DÉCOUVERTE SCIM 2.0 (RFC 7644 §4) — handlers PURS, sans HTTP ni store.
 *
 * Fournit l'AUTO-DESCRIPTION du cœur : capacités du fournisseur de service
 * (`/ServiceProviderConfig`), types de ressources (`/ResourceTypes`) et définitions de
 * schéma (`/Schemas`) pour NOTRE schéma — core User (RFC 7643 §4.1), extension enterprise
 * (§4.3) et Group (§4.2). Le validateur Microsoft Entra les interroge pour se configurer.
 *
 * Les définitions décrivent exactement ce que `KengelaScimUser` / `toScimUser` savent
 * porter : elles sont la source de vérité consommée par `validateScimUser`.
 */
import {
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  SCIM_SCHEMA_GROUP,
} from '@kengela/iam-mapping';
import { MAX_PAGE_SIZE, SCIM_SCHEMA_LIST_RESPONSE } from './serialize.js';
import type { ScimResponse } from './types.js';

// ── URNs des ressources de découverte (RFC 7643 §5/§6/§7) ────────────────────
export const SCIM_SCHEMA_SERVICE_PROVIDER_CONFIG =
  'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig';
export const SCIM_SCHEMA_RESOURCE_TYPE = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType';
export const SCIM_SCHEMA_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Schema';

// ── Définition d'attribut de schéma (RFC 7643 §7) ────────────────────────────
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

/** Développe une `AttributeSpec` en attribut de schéma SCIM complet (défauts RFC 7643 §7). */
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
  { name: 'value', description: "Valeur de l'entrée (ex. adresse e-mail)." },
  { name: 'type', description: 'Étiquette de type (ex. work, home).' },
  { name: 'primary', type: 'boolean', description: "Marque l'entrée primaire." },
  { name: 'display', mutability: 'readOnly', description: 'Libellé lisible.' },
];

const NAME_SUBS: readonly AttributeSpec[] = [
  { name: 'formatted', description: 'Nom complet formaté.' },
  { name: 'familyName', description: 'Nom de famille.' },
  { name: 'givenName', description: 'Prénom.' },
  { name: 'middleName', description: 'Deuxième prénom.' },
  { name: 'honorificPrefix', description: 'Civilité (Mme, M.).' },
  { name: 'honorificSuffix', description: 'Suffixe honorifique.' },
];

const USER_ATTRIBUTES: readonly AttributeSpec[] = [
  {
    name: 'userName',
    required: true,
    uniqueness: 'server',
    description: "Identifiant de connexion unique (porte l'e-mail).",
  },
  { name: 'name', type: 'complex', subAttributes: NAME_SUBS, description: 'Composants du nom.' },
  { name: 'displayName', description: "Nom affiché de l'utilisateur." },
  { name: 'nickName', description: 'Surnom.' },
  { name: 'title', description: 'Intitulé de poste.' },
  { name: 'userType', description: "Catégorie d'utilisateur." },
  { name: 'preferredLanguage', description: 'Langue préférée (BCP 47).' },
  { name: 'locale', description: 'Locale (ex. fr-FR).' },
  { name: 'timezone', description: 'Fuseau horaire (IANA).' },
  {
    name: 'active',
    type: 'boolean',
    description: 'Statut administratif (provisioning/déprovisioning).',
  },
  {
    name: 'emails',
    type: 'complex',
    multiValued: true,
    subAttributes: MULTI_VALUE_SUBS,
    description: "Adresses e-mail de l'utilisateur.",
  },
  {
    name: 'phoneNumbers',
    type: 'complex',
    multiValued: true,
    subAttributes: MULTI_VALUE_SUBS,
    description: 'Numéros de téléphone.',
  },
];

const ENTERPRISE_ATTRIBUTES: readonly AttributeSpec[] = [
  { name: 'employeeNumber', description: "Matricule de l'employé." },
  { name: 'costCenter', description: 'Centre de coût.' },
  { name: 'organization', description: 'Organisation.' },
  { name: 'division', description: 'Division.' },
  { name: 'department', description: 'Département.' },
  {
    name: 'manager',
    type: 'complex',
    description: "Manager de l'utilisateur.",
    subAttributes: [
      { name: 'value', description: 'Id du manager.' },
      { name: 'displayName', mutability: 'readOnly', description: 'Nom du manager.' },
      { name: '$ref', type: 'reference', description: 'URI de la ressource manager.' },
    ],
  },
];

const GROUP_ATTRIBUTES: readonly AttributeSpec[] = [
  {
    name: 'displayName',
    required: true,
    description: 'Nom affiché du groupe.',
  },
  {
    name: 'members',
    type: 'complex',
    multiValued: true,
    description: 'Membres du groupe.',
    subAttributes: [
      { name: 'value', mutability: 'immutable', description: 'Id du membre.' },
      { name: '$ref', type: 'reference', mutability: 'immutable', description: 'URI du membre.' },
      { name: 'type', mutability: 'immutable', description: 'Type de membre (User/Group).' },
      { name: 'display', mutability: 'immutable', description: 'Libellé du membre.' },
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
 * Définitions de schéma SCIM de NOTRE cœur (RFC 7643 §7) : core User, extension enterprise
 * et Group. Auto-description de `KengelaScimUser`, consommée par `validateScimUser`.
 */
export function schemaDefinitions(): readonly Record<string, unknown>[] {
  return [
    schemaResource(
      SCIM_SCHEMA_CORE_USER,
      'User',
      'Utilisateur SCIM 2.0 (RFC 7643 §4.1).',
      USER_ATTRIBUTES,
    ),
    schemaResource(
      SCIM_SCHEMA_ENTERPRISE_USER,
      'EnterpriseUser',
      "Extension enterprise de l'utilisateur (RFC 7643 §4.3).",
      ENTERPRISE_ATTRIBUTES,
    ),
    schemaResource(
      SCIM_SCHEMA_GROUP,
      'Group',
      'Groupe SCIM 2.0 (RFC 7643 §4.2).',
      GROUP_ATTRIBUTES,
    ),
  ];
}

/** Types de ressources exposés (RFC 7643 §6) : User (+ extension enterprise) et Group. */
export function resourceTypes(): readonly Record<string, unknown>[] {
  return [
    {
      schemas: [SCIM_SCHEMA_RESOURCE_TYPE],
      id: 'User',
      name: 'User',
      endpoint: '/Users',
      description: 'Utilisateur provisionné (RFC 7643 §4.1).',
      schema: SCIM_SCHEMA_CORE_USER,
      schemaExtensions: [{ schema: SCIM_SCHEMA_ENTERPRISE_USER, required: false }],
      meta: { resourceType: 'ResourceType', location: 'ResourceTypes/User' },
    },
    {
      schemas: [SCIM_SCHEMA_RESOURCE_TYPE],
      id: 'Group',
      name: 'Group',
      endpoint: '/Groups',
      description: 'Groupe provisionné (RFC 7643 §4.2).',
      schema: SCIM_SCHEMA_GROUP,
      meta: { resourceType: 'ResourceType', location: 'ResourceTypes/Group' },
    },
  ];
}

/**
 * Configuration du fournisseur de service (RFC 7643 §5) : capacités RÉELLES de ce cœur.
 * PATCH supporté, filtre supporté (borné), bulk/sort/etag/changePassword non supportés ;
 * authentification par jeton porteur OAuth.
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
        description: 'Authentification via jeton porteur OAuth 2.0 (en-tête Authorization).',
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

/** GET `/ServiceProviderConfig` : 200 avec la configuration du fournisseur. */
export function handleServiceProviderConfig(): ScimResponse {
  return { status: 200, body: serviceProviderConfig() };
}

/**
 * GET `/ResourceTypes` (liste) ou `/ResourceTypes/:id` (ressource unique). 404 si l'`id`
 * demandé est inconnu.
 */
export function handleResourceTypes(pathId?: string): ScimResponse {
  const all = resourceTypes();
  if (pathId === undefined) {
    return { status: 200, body: discoveryList(all) };
  }
  const found = all.find((rt) => rt['id'] === pathId);
  return found === undefined
    ? notFound(`Type de ressource introuvable : ${pathId}.`)
    : { status: 200, body: found };
}

/**
 * GET `/Schemas` (liste) ou `/Schemas/:id` (définition unique par URN). 404 si l'URN
 * demandée n'est pas l'une des nôtres.
 */
export function handleSchemas(pathId?: string): ScimResponse {
  const all = schemaDefinitions();
  if (pathId === undefined) {
    return { status: 200, body: discoveryList(all) };
  }
  const found = all.find((s) => s['id'] === pathId);
  return found === undefined
    ? notFound(`Schéma introuvable : ${pathId}.`)
    : { status: 200, body: found };
}
