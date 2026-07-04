/**
 * SCIM 2.0 schema validation - "check OUR own schema" (RFC 7643).
 *
 * `validateScimUser` / `validateScimGroup` check that a resource conforms to the Kengela
 * schema, ON INPUT (body pushed by the IdP) as well as ON OUTPUT (round-trip: the output
 * of `toScimUser` must pass validation). PURE, fail-closed, no `any`.
 *
 * Checks: `schemas` present/non-empty/recognized URNs; required attributes present
 * (`userName` for User, `displayName` for Group); correct scalar types; well-formed
 * multi-valued attributes (array of objects with a string `value`).
 */
import {
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  SCIM_SCHEMA_GROUP,
} from '@kengela/iam-mapping';

/** Validation result: conforming or not + the EXHAUSTIVE list of discrepancies. */
export interface ScimValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
}

const KNOWN_USER_SCHEMAS: ReadonlySet<string> = new Set([
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
]);
const KNOWN_GROUP_SCHEMAS: ReadonlySet<string> = new Set([SCIM_SCHEMA_GROUP]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Checks the `schemas` array: present, non-empty, string URNs, all recognized. */
function checkSchemas(
  body: Record<string, unknown>,
  known: ReadonlySet<string>,
  required: string,
  errors: string[],
): void {
  const schemas = body['schemas'];
  if (!Array.isArray(schemas)) {
    errors.push('`schemas` is required and must be an array.');
    return;
  }
  if (schemas.length === 0) {
    errors.push('`schemas` cannot be empty.');
    return;
  }
  let hasRequired = false;
  for (const entry of schemas) {
    if (typeof entry !== 'string') {
      errors.push('`schemas` must contain only strings (URNs).');
      continue;
    }
    if (entry === required) {
      hasRequired = true;
    }
    if (!known.has(entry)) {
      errors.push(`Declared schema not recognized: ${entry}.`);
    }
  }
  if (!hasRequired) {
    errors.push(`The required schema is missing from \`schemas\`: ${required}.`);
  }
}

/** Checks that an attribute, if present, is a non-empty string. */
function checkOptionalString(body: Record<string, unknown>, key: string, errors: string[]): void {
  const value = body[key];
  if (value === undefined) {
    return;
  }
  if (typeof value !== 'string' || value.trim() === '') {
    errors.push(`\`${key}\` must be a non-empty string.`);
  }
}

/** Checks that a multi-valued attribute, if present, is an array of objects with a `value`. */
function checkMultiValued(body: Record<string, unknown>, key: string, errors: string[]): void {
  const value = body[key];
  if (value === undefined) {
    return;
  }
  if (!Array.isArray(value)) {
    errors.push(`\`${key}\` must be an array (multi-valued attribute).`);
    return;
  }
  for (const entry of value) {
    if (!isRecord(entry)) {
      errors.push(`Each entry of \`${key}\` must be an object.`);
      continue;
    }
    const inner = entry['value'];
    if (inner !== undefined && typeof inner !== 'string') {
      errors.push(`\`${key}[].value\` must be a string.`);
    }
  }
}

/**
 * Validates a SCIM user resource against the Kengela schema (core + enterprise).
 * Required: `schemas` (containing the core User) and `userName`. Also checks the types of
 * `externalId`, `displayName`, `active`, `name`, and the multi-valued `emails`/`phoneNumbers`.
 */
export function validateScimUser(input: unknown): ScimValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { valid: false, errors: ['The user resource must be a JSON object.'] };
  }
  checkSchemas(input, KNOWN_USER_SCHEMAS, SCIM_SCHEMA_CORE_USER, errors);

  const userName = input['userName'];
  if (userName === undefined) {
    errors.push('`userName` is required.');
  } else if (typeof userName !== 'string' || userName.trim() === '') {
    errors.push('`userName` must be a non-empty string.');
  }

  checkOptionalString(input, 'externalId', errors);
  checkOptionalString(input, 'displayName', errors);

  const active = input['active'];
  if (active !== undefined && typeof active !== 'boolean') {
    errors.push('`active` must be a boolean.');
  }

  const name = input['name'];
  if (name !== undefined && !isRecord(name)) {
    errors.push('`name` must be a complex object.');
  } else if (isRecord(name)) {
    for (const sub of ['givenName', 'familyName', 'formatted'] as const) {
      const value = name[sub];
      if (value !== undefined && typeof value !== 'string') {
        errors.push(`\`name.${sub}\` must be a string.`);
      }
    }
  }

  checkMultiValued(input, 'emails', errors);
  checkMultiValued(input, 'phoneNumbers', errors);

  return { valid: errors.length === 0, errors };
}

/**
 * Validates a SCIM group resource against the Kengela schema. Required: `schemas` (containing
 * the Group) and `displayName`. Checks the type of `externalId` and the shape of `members`.
 */
export function validateScimGroup(input: unknown): ScimValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { valid: false, errors: ['The group resource must be a JSON object.'] };
  }
  checkSchemas(input, KNOWN_GROUP_SCHEMAS, SCIM_SCHEMA_GROUP, errors);

  const displayName = input['displayName'];
  if (displayName === undefined) {
    errors.push('`displayName` is required.');
  } else if (typeof displayName !== 'string' || displayName.trim() === '') {
    errors.push('`displayName` must be a non-empty string.');
  }

  checkOptionalString(input, 'externalId', errors);
  checkMultiValued(input, 'members', errors);

  return { valid: errors.length === 0, errors };
}
