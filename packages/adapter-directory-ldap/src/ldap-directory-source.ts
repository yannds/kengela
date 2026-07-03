/**
 * `LdapDirectorySource` — adapter d'annuaire **AD / LDAP** (jumeau « pull » des connecteurs Graph /
 * Google / SCIM). Se lie en LDAP(S) (`bind`), parcourt l'annuaire par recherche paginée sous une
 * `baseDN`, et renvoie des `LdapEntryParts` **normalisés** (DN + attributs en chaînes, binaires en
 * base64) — directement consommables par `profileFromLdap` de `@kengela/iam-mapping`. Aucune logique
 * de mapping de rôles ici : cet adapter ne fait QUE parler LDAP, la projection reste dans la lib pure.
 *
 * TLS vérifié par défaut (LDAPS). Le mot de passe de bind n'est JAMAIS journalisé (ce module ne
 * journalise rien) ; il est conservé en champ privé et transmis au seul client injecté.
 */
import { Client } from 'ldapts';
import {
  type DirectoryProfile,
  type LdapAttributeMap,
  type LdapEntryParts,
  accountActiveFromLdap,
  profileFromLdap,
} from '@kengela/iam-mapping';
import type {
  LdapClientFactory,
  LdapClientLike,
  LdapSearchEntry,
  LdapSearchScope,
} from './ldap-client-like.js';

/**
 * Bornes et défauts LDAP (Active Directory), source unique de vérité — aucun nombre/chaîne magique
 * dans le code. Surchargeables par `LdapConnectionConfig` (config connecteur, jamais en dur).
 */
export const LDAP_SOURCE_DEFAULTS = {
  /** Filtre des comptes personnels (AD) : exclut les comptes machine. */
  userFilter: '(&(objectCategory=person)(objectClass=user))',
  /** Attributs demandés (`*` couvre les usuels ; `memberOf` explicite pour les groupes). */
  attributes: ['*', 'memberOf'],
  /** Timeout bind + recherche (ms). */
  timeoutMs: 15_000,
  /** Taille de page (Paged Results Control). */
  pageSize: 200,
  /** Plafond d'entrées lues par pull. */
  maxUsers: 1000,
  /** Vérifie le certificat TLS du serveur (LDAPS). */
  tlsRejectUnauthorized: true,
} as const;

/** Paramètres de connexion et de lecture de l'annuaire (résolus par l'appelant depuis sa config). */
export interface LdapConnectionConfig {
  /** URL du serveur (`ldaps://dc.corp.local:636` recommandé ; `ldap://` en dev seulement). */
  readonly url: string;
  /** DN de service pour le bind (compte de lecture d'annuaire). */
  readonly bindDN: string;
  /** Mot de passe du compte de service (résolu depuis un coffre par l'appelant ; jamais journalisé). */
  readonly bindPassword: string;
  /** Racine de recherche (`OU=Users,DC=corp,DC=local`). */
  readonly baseDN: string;
  /** Filtre de recherche par défaut (sinon défaut Active Directory). */
  readonly userFilter?: string;
  /** Attributs demandés par défaut (sinon `["*","memberOf"]`). */
  readonly attributes?: readonly string[];
  /** Timeout bind + recherche (ms). */
  readonly timeoutMs?: number;
  /** Vérifie le certificat TLS (LDAPS). Défaut `true` ; ne désactiver que pour un annuaire de test. */
  readonly tlsRejectUnauthorized?: boolean;
  /** Taille de page de la recherche paginée. */
  readonly pageSize?: number;
  /** Plafond d'entrées lues par pull. */
  readonly maxUsers?: number;
}

/** Options de construction de la source (injection de client pour les tests). */
export interface LdapDirectorySourceOptions {
  /** Fabrique de client injectable. Défaut : un vrai `Client` de `ldapts` configuré depuis la config. */
  readonly clientFactory?: LdapClientFactory;
}

/** Options d'un appel `fetchEntries`. */
export interface FetchEntriesOptions {
  /** Attributs demandés (sinon ceux de la config, sinon défauts AD). */
  readonly attributes?: readonly string[];
  /** Plafond d'entrées (sinon `maxUsers`). */
  readonly max?: number;
  /** Portée de recherche (sinon `sub`). */
  readonly scope?: LdapSearchScope;
  /** Carte d'attributs LDAP à attacher à chaque entrée (pour `profileFromLdap`). */
  readonly attributeMap?: LdapAttributeMap;
}

/** Profil normalisé + état d'activation du compte (dé-provisioning via `userAccountControl`). */
export interface DirectoryRecord {
  readonly profile: DirectoryProfile;
  readonly active: boolean;
}

/** Convertit une valeur scalaire d'attribut LDAP (chaîne ou binaire) en chaîne stable, ou undefined. */
function stringifyScalar(value: unknown): string | undefined {
  if (Buffer.isBuffer(value)) return value.toString('base64');
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return undefined;
}

/** Normalise une valeur d'attribut (mono- ou multi-valuée) en chaîne(s) ; binaires en base64. */
function normalizeValue(value: unknown): string | readonly string[] | undefined {
  if (Array.isArray(value)) {
    const out: string[] = [];
    for (const item of value as readonly unknown[]) {
      const s = stringifyScalar(item);
      if (s !== undefined) out.push(s);
    }
    return out.length > 0 ? out : undefined;
  }
  return stringifyScalar(value);
}

/**
 * Source d'annuaire LDAP. Un seul point d'entrée réseau (`fetchEntries`) et un health-check
 * (`checkConnection`) ; la projection vers `DirectoryProfile` passe par les helpers statiques
 * `toProfiles` / `toRecords` (SSoT `@kengela/iam-mapping`).
 */
export class LdapDirectorySource {
  readonly #factory: LdapClientFactory;
  readonly #bindDN: string;
  readonly #bindPassword: string;
  readonly #baseDN: string;
  readonly #userFilter: string;
  readonly #attributes: readonly string[];
  readonly #maxUsers: number;
  readonly #pageSize: number;

  public constructor(config: LdapConnectionConfig, options: LdapDirectorySourceOptions = {}) {
    this.#bindDN = config.bindDN;
    this.#bindPassword = config.bindPassword;
    this.#baseDN = config.baseDN;
    const filter = config.userFilter?.trim();
    this.#userFilter =
      filter !== undefined && filter !== '' ? filter : LDAP_SOURCE_DEFAULTS.userFilter;
    this.#attributes = config.attributes ?? LDAP_SOURCE_DEFAULTS.attributes;
    this.#maxUsers = config.maxUsers ?? LDAP_SOURCE_DEFAULTS.maxUsers;
    this.#pageSize = config.pageSize ?? LDAP_SOURCE_DEFAULTS.pageSize;
    this.#factory = options.clientFactory ?? createLdapClientFactory(config);
  }

  /**
   * Se lie, parcourt l'annuaire (recherche paginée sous `baseDN`), normalise et se délie. Renvoie des
   * `LdapEntryParts` (DN + attributs en chaînes, `objectGUID` en base64) plafonnés par `max`. Lecture
   * réseau pure (hors transaction DB). Le `unbind` est garanti même en cas d'échec.
   */
  public async fetchEntries(
    filter?: string,
    options: FetchEntriesOptions = {},
  ): Promise<readonly LdapEntryParts[]> {
    const max = options.max ?? this.#maxUsers;
    const requested = options.attributes ?? this.#attributes;
    const trimmed = filter?.trim();
    const searchFilter = trimmed !== undefined && trimmed !== '' ? trimmed : this.#userFilter;

    const client = this.#factory();
    try {
      await client.bind(this.#bindDN, this.#bindPassword);
      const result = await client.search(this.#baseDN, {
        scope: options.scope ?? 'sub',
        filter: searchFilter,
        attributes: [...requested],
        paged: { pageSize: this.#pageSize },
        sizeLimit: max,
      });
      return result.searchEntries
        .slice(0, max)
        .map((entry) => normalizeEntry(entry, options.attributeMap));
    } finally {
      await client.unbind().catch(() => undefined);
    }
  }

  /**
   * Health-check : se lie, vérifie l'accès puis se délie. `true` si connectivité + identifiants +
   * TLS sont valides, `false` sinon (aucune exception ne fuit ; le mot de passe n'est pas journalisé).
   */
  public async checkConnection(): Promise<boolean> {
    const client = this.#factory();
    try {
      await client.bind(this.#bindDN, this.#bindPassword);
      return true;
    } catch {
      return false;
    } finally {
      await client.unbind().catch(() => undefined);
    }
  }

  /**
   * Projette des entrées normalisées en `DirectoryProfile` via `profileFromLdap` (SSoT). Si `map` est
   * fournie et que l'entrée n'a pas déjà sa propre carte, elle est appliquée.
   */
  public static toProfiles(
    entries: readonly LdapEntryParts[],
    map?: LdapAttributeMap,
  ): readonly DirectoryProfile[] {
    return entries.map((entry) => profileFromLdap(withAttributeMap(entry, map)));
  }

  /**
   * Comme `toProfiles`, mais joint l'état d'activation du compte (`accountActiveFromLdap` : bit
   * `ACCOUNTDISABLE` 0x2 de `userAccountControl`) pour piloter le dé-provisioning.
   */
  public static toRecords(
    entries: readonly LdapEntryParts[],
    map?: LdapAttributeMap,
  ): readonly DirectoryRecord[] {
    return entries.map((entry) => {
      const parts = withAttributeMap(entry, map);
      return { profile: profileFromLdap(parts), active: accountActiveFromLdap(parts) };
    });
  }
}

/** Applique `map` à une entrée dépourvue de carte, sinon la laisse telle quelle. */
function withAttributeMap(
  entry: LdapEntryParts,
  map: LdapAttributeMap | undefined,
): LdapEntryParts {
  if (map === undefined || entry.attributeMap !== undefined) return entry;
  return { ...entry, attributeMap: map };
}

/** Normalise une entrée brute de recherche en `LdapEntryParts` (attributs en chaînes, binaires base64). */
function normalizeEntry(
  entry: LdapSearchEntry,
  attributeMap: LdapAttributeMap | undefined,
): LdapEntryParts {
  const dn = typeof entry.dn === 'string' ? entry.dn : '';
  const attributes: Record<string, string | readonly string[]> = {};
  for (const key of Object.keys(entry)) {
    if (key === 'dn') continue;
    const normalized = normalizeValue(entry[key]);
    if (normalized !== undefined) attributes[key] = normalized;
  }
  return attributeMap !== undefined ? { dn, attributes, attributeMap } : { dn, attributes };
}

/** Fabrique par défaut : un vrai `Client` de `ldapts` (LDAPS vérifié), structurellement `LdapClientLike`. */
function createLdapClientFactory(config: LdapConnectionConfig): LdapClientFactory {
  const timeout = config.timeoutMs ?? LDAP_SOURCE_DEFAULTS.timeoutMs;
  const rejectUnauthorized =
    config.tlsRejectUnauthorized ?? LDAP_SOURCE_DEFAULTS.tlsRejectUnauthorized;
  return (): LdapClientLike =>
    new Client({
      url: config.url,
      timeout,
      connectTimeout: timeout,
      tlsOptions: { rejectUnauthorized },
    });
}
