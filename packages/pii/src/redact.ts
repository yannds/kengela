import type { DirectoryProfile } from '@kengela/iam-mapping';
import { isPii } from './classification.js';

function maskEmail(value: string): string {
  const at = value.indexOf('@');
  if (at <= 0) {
    return '***';
  }
  return `${value.slice(0, 1)}***${value.slice(at)}`;
}

function maskValue(value: string): string {
  if (value.length <= 1) {
    return '***';
  }
  return `${value.slice(0, 1)}***`;
}

/**
 * Redaction/masking of personal data for display/logs without exposing
 * PII in cleartext. Masks identity (email/name) AND attributes classified `pii`
 * (phone, address...). Non-personal fields stay unchanged.
 */
export function redactProfile(profile: DirectoryProfile): DirectoryProfile {
  const attributes: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(profile.attributes)) {
    attributes[key] = isPii(key) && typeof value === 'string' ? maskValue(value) : value;
  }
  return {
    ...profile,
    email: maskEmail(profile.email),
    firstName: profile.firstName === null ? null : maskValue(profile.firstName),
    lastName: profile.lastName === null ? null : maskValue(profile.lastName),
    displayName: profile.displayName === null ? null : maskValue(profile.displayName),
    attributes,
  };
}
