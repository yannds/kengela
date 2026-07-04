/**
 * Attribute classification by sensitivity (GDPR).
 *  - `none`      : non-personal (technical identifier, org attachment).
 *  - `pii`       : personal datum (direct/indirect identifiability).
 *  - `sensitive` : special category (GDPR art. 9: health, biometrics...) -
 *                  none in a standard directory, reserved for extension.
 *
 * Keys = normalized `DirectoryProfile` / `DirectoryAttributes` fields.
 */
export type PiiSensitivity = 'none' | 'pii' | 'sensitive';

const REGISTRY: Readonly<Record<string, PiiSensitivity>> = {
  // Identity
  email: 'pii',
  firstName: 'pii',
  lastName: 'pii',
  displayName: 'pii',
  externalId: 'none',
  // Contact details
  phoneNumber: 'pii',
  mobilePhone: 'pii',
  streetAddress: 'pii',
  city: 'pii',
  state: 'pii',
  postalCode: 'pii',
  country: 'pii',
  // Organizational attachment (non-personal)
  department: 'none',
  division: 'none',
  title: 'none',
  organization: 'none',
  companyName: 'none',
  costCenter: 'none',
  officeLocation: 'none',
  employeeType: 'none',
  preferredLanguage: 'none',
  locale: 'none',
  timezone: 'none',
  // Employee number = indirect identifier of a person
  employeeNumber: 'pii',
  manager: 'pii',
};

/** Sensitivity of a field (default `none` if unknown). */
export function classify(field: string): PiiSensitivity {
  return REGISTRY[field] ?? 'none';
}

/** true if the field is a personal datum (pii or sensitive). */
export function isPii(field: string): boolean {
  return classify(field) !== 'none';
}

/** List of fields classified as personal data. */
export const PII_FIELDS: readonly string[] = Object.keys(REGISTRY).filter(
  (field) => REGISTRY[field] !== 'none',
);
