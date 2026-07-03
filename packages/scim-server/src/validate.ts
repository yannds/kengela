/**
 * Validation de schéma SCIM 2.0 — « vérifier NOTRE propre schéma » (RFC 7643).
 *
 * `validateScimUser` / `validateScimGroup` contrôlent la conformité d'une ressource au
 * schéma Kengela, À L'ENTRÉE (corps poussé par l'IdP) comme À LA SORTIE (round-trip : la
 * sortie de `toScimUser` doit passer la validation). PUR, fail-closed, sans `any`.
 *
 * Contrôles : `schemas` présent/non vide/URNs reconnues ; attributs requis présents
 * (`userName` pour User, `displayName` pour Group) ; types scalaires corrects ; attributs
 * multi-valués bien formés (tableau d'objets à `value` chaîne).
 */
import {
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  SCIM_SCHEMA_GROUP,
} from '@kengela/iam-mapping';

/** Résultat d'une validation : conforme ou non + la liste EXHAUSTIVE des écarts. */
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

/** Contrôle le tableau `schemas` : présent, non vide, URNs chaînes, toutes reconnues. */
function checkSchemas(
  body: Record<string, unknown>,
  known: ReadonlySet<string>,
  required: string,
  errors: string[],
): void {
  const schemas = body['schemas'];
  if (!Array.isArray(schemas)) {
    errors.push('`schemas` est requis et doit être un tableau.');
    return;
  }
  if (schemas.length === 0) {
    errors.push('`schemas` ne peut pas être vide.');
    return;
  }
  let hasRequired = false;
  for (const entry of schemas) {
    if (typeof entry !== 'string') {
      errors.push('`schemas` ne doit contenir que des chaînes (URNs).');
      continue;
    }
    if (entry === required) {
      hasRequired = true;
    }
    if (!known.has(entry)) {
      errors.push(`Schéma déclaré non reconnu : ${entry}.`);
    }
  }
  if (!hasRequired) {
    errors.push(`Le schéma requis est manquant dans \`schemas\` : ${required}.`);
  }
}

/** Vérifie qu'un attribut, s'il est présent, est une chaîne non vide. */
function checkOptionalString(body: Record<string, unknown>, key: string, errors: string[]): void {
  const value = body[key];
  if (value === undefined) {
    return;
  }
  if (typeof value !== 'string' || value.trim() === '') {
    errors.push(`\`${key}\` doit être une chaîne non vide.`);
  }
}

/** Vérifie qu'un attribut multi-valué, s'il est présent, est un tableau d'objets à `value`. */
function checkMultiValued(body: Record<string, unknown>, key: string, errors: string[]): void {
  const value = body[key];
  if (value === undefined) {
    return;
  }
  if (!Array.isArray(value)) {
    errors.push(`\`${key}\` doit être un tableau (attribut multi-valué).`);
    return;
  }
  for (const entry of value) {
    if (!isRecord(entry)) {
      errors.push(`Chaque entrée de \`${key}\` doit être un objet.`);
      continue;
    }
    const inner = entry['value'];
    if (inner !== undefined && typeof inner !== 'string') {
      errors.push(`\`${key}[].value\` doit être une chaîne.`);
    }
  }
}

/**
 * Valide une ressource utilisateur SCIM contre le schéma Kengela (core + enterprise).
 * Requis : `schemas` (contenant le core User) et `userName`. Contrôle aussi les types de
 * `externalId`, `displayName`, `active`, `name`, et les multi-valués `emails`/`phoneNumbers`.
 */
export function validateScimUser(input: unknown): ScimValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { valid: false, errors: ['La ressource utilisateur doit être un objet JSON.'] };
  }
  checkSchemas(input, KNOWN_USER_SCHEMAS, SCIM_SCHEMA_CORE_USER, errors);

  const userName = input['userName'];
  if (userName === undefined) {
    errors.push('`userName` est requis.');
  } else if (typeof userName !== 'string' || userName.trim() === '') {
    errors.push('`userName` doit être une chaîne non vide.');
  }

  checkOptionalString(input, 'externalId', errors);
  checkOptionalString(input, 'displayName', errors);

  const active = input['active'];
  if (active !== undefined && typeof active !== 'boolean') {
    errors.push('`active` doit être un booléen.');
  }

  const name = input['name'];
  if (name !== undefined && !isRecord(name)) {
    errors.push('`name` doit être un objet complexe.');
  } else if (isRecord(name)) {
    for (const sub of ['givenName', 'familyName', 'formatted'] as const) {
      const value = name[sub];
      if (value !== undefined && typeof value !== 'string') {
        errors.push(`\`name.${sub}\` doit être une chaîne.`);
      }
    }
  }

  checkMultiValued(input, 'emails', errors);
  checkMultiValued(input, 'phoneNumbers', errors);

  return { valid: errors.length === 0, errors };
}

/**
 * Valide une ressource groupe SCIM contre le schéma Kengela. Requis : `schemas` (contenant
 * le Group) et `displayName`. Contrôle le type de `externalId` et la bonne forme de `members`.
 */
export function validateScimGroup(input: unknown): ScimValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return { valid: false, errors: ['La ressource groupe doit être un objet JSON.'] };
  }
  checkSchemas(input, KNOWN_GROUP_SCHEMAS, SCIM_SCHEMA_GROUP, errors);

  const displayName = input['displayName'];
  if (displayName === undefined) {
    errors.push('`displayName` est requis.');
  } else if (typeof displayName !== 'string' || displayName.trim() === '') {
    errors.push('`displayName` doit être une chaîne non vide.');
  }

  checkOptionalString(input, 'externalId', errors);
  checkMultiValued(input, 'members', errors);

  return { valid: errors.length === 0, errors };
}
