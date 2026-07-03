import type { DirectoryProfile } from '@kengela/iam-mapping';

function maskEmail(value: string): string {
  const at = value.indexOf('@');
  if (at <= 0) {
    return '***';
  }
  return `${value.slice(0, 1)}***${value.slice(at)}`;
}

function maskName(value: string): string {
  if (value.length <= 1) {
    return '***';
  }
  return `${value.slice(0, 1)}***`;
}

/**
 * Redaction/masquage des champs d'identité personnels pour affichage/journaux
 * sans exposer la PII en clair. Les valeurs sont partiellement masquées, pas
 * supprimées (utile pour le support tout en respectant la minimisation).
 */
export function redactProfile(profile: DirectoryProfile): DirectoryProfile {
  return {
    ...profile,
    email: maskEmail(profile.email),
    firstName: profile.firstName === null ? null : maskName(profile.firstName),
    lastName: profile.lastName === null ? null : maskName(profile.lastName),
    displayName: profile.displayName === null ? null : maskName(profile.displayName),
  };
}
