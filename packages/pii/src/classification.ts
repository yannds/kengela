/**
 * Classification des attributs par sensibilité (RGPD).
 *  - `none`      : non personnel (identifiant technique, rattachement org).
 *  - `pii`       : donnée personnelle (identifiabilité directe/indirecte).
 *  - `sensitive` : catégorie particulière (RGPD art. 9 : santé, biométrie...) —
 *                  aucune dans un annuaire standard, prévu pour extension.
 *
 * Clés = champs du `DirectoryProfile` / `DirectoryAttributes` normalisés.
 */
export type PiiSensitivity = 'none' | 'pii' | 'sensitive';

const REGISTRY: Readonly<Record<string, PiiSensitivity>> = {
  // Identité
  email: 'pii',
  firstName: 'pii',
  lastName: 'pii',
  displayName: 'pii',
  externalId: 'none',
  // Coordonnées
  phoneNumber: 'pii',
  mobilePhone: 'pii',
  streetAddress: 'pii',
  city: 'pii',
  state: 'pii',
  postalCode: 'pii',
  country: 'pii',
  // Rattachement organisationnel (non personnel)
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
  // Numéro d'employé = identifiant indirect d'une personne
  employeeNumber: 'pii',
  manager: 'pii',
};

/** Sensibilité d'un champ (défaut `none` si inconnu). */
export function classify(field: string): PiiSensitivity {
  return REGISTRY[field] ?? 'none';
}

/** true si le champ est une donnée personnelle (pii ou sensible). */
export function isPii(field: string): boolean {
  return classify(field) !== 'none';
}

/** Liste des champs classés comme données personnelles. */
export const PII_FIELDS: readonly string[] = Object.keys(REGISTRY).filter(
  (field) => REGISTRY[field] !== 'none',
);
