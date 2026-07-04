/**
 * Profil d'annuaire normalisé (ADR-014, intégration IdP entreprise).
 *
 * Source unique de vérité interne pour le mapping des rôles et la classification
 * organisationnelle, quelle que soit l'origine : claims OIDC (Entra/Okta), assertion
 * SAML 2.0 (ADFS via bridge), ou attributs + groupes SCIM 2.0. L'app ne raisonne JAMAIS
 * sur la forme brute d'un IdP : chaque adapter projette vers ce `DirectoryProfile`.
 *
 * PUR : aucune dépendance infra (testable sans base ni réseau).
 */

/**
 * Attributs d'annuaire « standards entreprise » (extension SCIM enterprise + claims
 * usuels Entra/AD). Tous facultatifs : un compte AD peut être incomplet - c'est
 * précisément le cas que la classification doit rattraper via les groupes.
 */
export interface DirectoryAttributes {
  readonly department?: string;
  readonly division?: string;
  readonly title?: string;
  readonly employeeNumber?: string;
  readonly costCenter?: string;
  readonly officeLocation?: string;
  /** e-mail/identifiant du responsable hiérarchique (alimente la chaîne d'approbation). */
  readonly manager?: string;
  // --- Superset Kengela (au-delà d'un seul IdP : Okta, Entra, Google, LDAP...) ---
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
   * Attributs additionnels non modélisés en premier plan (schémas custom Okta/Entra,
   * extensions propriétaires...). EXTENSIBLE : chaque application pioche ce dont elle a
   * besoin sans que la lib fige la liste.
   */
  readonly extensions?: Readonly<Record<string, unknown>>;
}

/** Profil normalisé d'un utilisateur tel que vu par l'IdP au login / à la synchro SCIM. */
export interface DirectoryProfile {
  readonly email: string;
  /** Identifiant stable côté IdP (`sub` OIDC / `nameID` SAML / `externalId` SCIM). */
  readonly externalId: string | null;
  /** Prénom (SCIM `name.givenName` · OIDC `given_name`), ou null. */
  readonly firstName: string | null;
  /** Nom de famille (SCIM `name.familyName` · OIDC `family_name`), ou null. */
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly attributes: DirectoryAttributes;
  /** Groupes de sécurité (noms ou ids selon l'IdP), source du mapping par groupe. */
  readonly groups: readonly string[];
  /** Claims bruts restants (ex. `roles`, `wids`…), pour des règles avancées. */
  readonly claims: Readonly<Record<string, unknown>>;
}

/**
 * Clés d'attributs d'annuaire reconnues par le moteur de mapping (source `ATTRIBUTE`).
 * Source unique de vérité : alimente la découverte/autocomplétion côté admin (jamais en dur
 * dans l'UI). Reste aligné avec `DirectoryAttributes`.
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
 * Champs d'identité du profil (hors attributs d'annuaire), mappables depuis l'IdP.
 * Source unique de vérité : alimente la validation des cartes et l'UI du mapper (jamais en dur).
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
 * Tous les champs canoniques mappables (identité + attributs d'annuaire). C'est l'ensemble des clés
 * autorisées d'une carte d'attributs (`ScimAttributeMap`/`OidcAttributeMap`/…). Source unique.
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

/** Retire les clés `undefined` (respecte `exactOptionalPropertyTypes`). */
function compact(o: Record<string, string | undefined>): DirectoryAttributes {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(o)) if (v !== undefined) out[k] = v;
  return out;
}

/**
 * Construit un `DirectoryProfile` à partir de morceaux déjà normalisés (état persisté :
 * attributs déchiffrés + noms de groupes en base). Utilisé pour re-synchroniser depuis le
 * stockage (changement de groupe) sans le payload IdP d'origine.
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
 * Carte d'attributs **SCIM → champs de profil** (config-driven, ADR-014). Une ressource SCIM mêle
 * attributs « core » (top-level) et extension enterprise (`urn:…:User`). Comme pour LDAP/SAML,
 * l'admin peut surcharger, champ par champ, le **chemin** lu côté SCIM ; à défaut on essaie une
 * liste de candidats usuels (le chemin fourni prime, puis les défauts). Mini-syntaxe de chemin :
 * `enterprise.<attr>` (extension), `name.givenName` (imbriqué), `emails[primary]` (e-mail primaire).
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
 * Chemins SCIM candidats par champ (source unique de vérité), essayés dans l'ordre. Reproduit à
 * l'identique l'extraction historique : sans surcharge, le profil est strictement le même qu'avant.
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

/** Le `manager` SCIM peut être un objet `{value,$ref}` (référence) ou une chaîne (e-mail/UPN). */
function scimManagerValue(manager: unknown): string | undefined {
  if (isRecord(manager)) return firstString(manager['value'], manager['$ref']);
  return str(manager);
}

/** Clés candidates pour un champ : la surcharge admin (si présente) prime, puis les défauts. */
function scimKeysFor(field: keyof ScimAttributeMap, map: ScimAttributeMap | undefined): string[] {
  const override = map?.[field];
  const defaults = SCIM_DEFAULT_ATTRIBUTE_KEYS[field];
  return override ? [override, ...defaults] : [...defaults];
}

/** Résout une valeur scalaire SCIM à partir d'un chemin (mini-syntaxe), ou undefined. */
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

/** Première valeur SCIM non vide parmi les chemins candidats d'un champ. */
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

/** Groupes SCIM depuis le premier chemin candidat portant une liste (objets `{display,value}` ou chaînes). */
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
 * Projette un utilisateur SCIM 2.0 (core + extension enterprise) vers `DirectoryProfile`.
 * Tolérant : champs absents → undefined. `attributeMap` (config tenant) surcharge les chemins lus ;
 * sans elle, l'extraction est strictement identique à l'historique. `groups` provient des
 * memberships SCIM (`groups`) lorsqu'ils sont présents.
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

/** Utilisateur d'annuaire lu via Microsoft Graph (`/users`) - forme structurelle (sans dépendre de l'infra). */
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
  /** e-mail/UPN du responsable hiérarchique (propriété de navigation Graph `manager`). */
  readonly manager?: string | null;
  readonly groups?: readonly string[];
}

/**
 * Projette un utilisateur **Microsoft Graph** (`/users` + groupes) vers `DirectoryProfile`.
 * Pendant « pull » du provisioning SCIM « push » : même cible normalisée ⇒ **même mapping de
 * rôles et même classification** que SCIM/OIDC, quel que soit le sens de la synchro.
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
 * Carte d'attributs **LDAP → champs de profil** (config-driven, ADR-014). Un annuaire LDAP n'a pas
 * de schéma d'attributs universel : Active Directory dit `sn`/`memberOf`, un OpenLDAP peut dire
 * `surname`/`groupMembership`. L'admin peut donc surcharger chaque nom d'attribut par tenant. Tout
 * champ absent retombe sur le défaut Active Directory (`LDAP_AD_ATTRIBUTE_DEFAULTS`).
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
 * Noms d'attributs LDAP par défaut (**Active Directory**), source unique de vérité. Surchargeables
 * un par un via `attributeMap` (jamais en dur dans l'UI : alimente aussi la saisie assistée côté admin).
 * `costCenter` n'a pas d'attribut AD standard (chaîne vide ⇒ aucun défaut).
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

/** Entrée d'annuaire LDAP normalisée : DN + attributs (mono- ou multi-valués déjà en chaînes). */
export interface LdapEntryParts {
  readonly dn: string;
  /** Attributs LDAP. Le client est responsable de stringifier les binaires (ex. `objectGUID`). */
  readonly attributes: Readonly<Record<string, string | readonly string[] | undefined>>;
  /** Surcharge des noms d'attributs (sinon défauts Active Directory). */
  readonly attributeMap?: LdapAttributeMap;
}

/** Valeurs (chaînes non vides) d'un attribut LDAP, toujours sous forme de tableau. */
function ldapValues(attrs: LdapEntryParts['attributes'], name: string | undefined): string[] {
  if (!name) return [];
  const v = attrs[name];
  if (v === undefined) return [];
  return (Array.isArray(v) ? v : [v]).map((x) => str(x)).filter((x): x is string => !!x);
}

/** Première valeur d'un attribut LDAP, ou undefined. */
function ldapFirst(
  attrs: LdapEntryParts['attributes'],
  name: string | undefined,
): string | undefined {
  return ldapValues(attrs, name)[0];
}

/** Extrait le CN du 1er RDN d'un DN (`CN=Groupe RH,OU=Groupes,DC=corp` → `Groupe RH`). Repli : DN brut. */
function cnFromDn(dn: string): string {
  const m = /^\s*cn\s*=\s*([^,]+)/i.exec(dn);
  return (m?.[1] ?? dn).trim();
}

/**
 * Projette une entrée **LDAP / Active Directory** vers `DirectoryProfile`. Même cible normalisée que
 * Graph/OIDC/SCIM ⇒ **même mapping de rôles et même classification**, sans réécrire le moteur. Les
 * groupes proviennent de `memberOf` (DN ⇒ CN). Le responsable (`manager`, un DN en AD) est réduit à
 * son CN faute de second appel (dette V2 : résoudre le DN du manager en e-mail).
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
 * Compte LDAP actif ? Active Directory encode la désactivation dans `userAccountControl` (bit
 * `0x2`, ACCOUNTDISABLE). Attribut absent (OpenLDAP et dérivés) ⇒ considéré **actif** (le
 * déprovisionnement passe alors par le périmètre d'import, pas par ce drapeau).
 */
export function accountActiveFromLdap(e: LdapEntryParts): boolean {
  const uac = Number(ldapFirst(e.attributes, 'userAccountControl'));
  if (Number.isFinite(uac)) return (uac & 0x2) === 0;
  return true;
}

/** Organisation Google Workspace (Admin SDK Directory `users.organizations[]`). */
export interface GoogleOrganization {
  readonly department?: string | null;
  readonly title?: string | null;
  readonly costCenter?: string | null;
  readonly location?: string | null;
  readonly primary?: boolean | null;
}

/** Relation Google Workspace (`users.relations[]`) - porte notamment le responsable hiérarchique. */
export interface GoogleRelation {
  readonly type?: string | null;
  readonly value?: string | null;
}

/** Utilisateur Google Workspace (Admin SDK Directory `users.list` + groupes résolus côté client). */
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
  /** Noms (ou e-mails) des groupes de l'utilisateur, résolus par le client (`groups.list`). */
  readonly groups?: readonly string[];
}

/** Organisation « principale » d'un compte Google (drapeau `primary`, sinon la première). */
function primaryOrganization(orgs: GoogleDirectoryUserParts['organizations']): GoogleOrganization {
  if (!orgs?.length) return {};
  return orgs.find((o) => o.primary) ?? orgs[0] ?? {};
}

/**
 * Projette un utilisateur **Google Workspace** (Admin SDK Directory) vers `DirectoryProfile`. Même
 * cible normalisée que Graph/OIDC/SCIM/LDAP ⇒ **même mapping de rôles et même classification**. Les
 * groupes sont fournis pré-résolus par le client (`groups.list per user`). Le responsable provient
 * de la relation typée `manager`.
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

/** Compte Google actif ? `suspended === true` ⇒ désactivé (déprovisionnement). */
export function accountActiveFromGoogle(u: GoogleDirectoryUserParts): boolean {
  return u.suspended !== true;
}

/**
 * Carte d'attributs **SAML → champs de profil** (config-driven, ADR-014). Une assertion SAML n'a pas
 * de nom d'attribut universel : ADFS émet des URI longues (`http://schemas.xmlsoap.org/.../emailaddress`),
 * d'autres IdP des noms courts (`mail`, `givenName`). L'admin peut donc surcharger chaque champ par
 * tenant ; à défaut on essaie une liste de **candidats usuels** (ADFS + Entra + noms courts + urn:oid).
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
 * Candidats d'attributs SAML par champ (source unique de vérité), essayés dans l'ordre. Couvre les
 * conventions ADFS (URI `schemas.xmlsoap.org`/`schemas.microsoft.com`), Entra, les noms courts et
 * `urn:oid`. Surchargeable champ par champ via `SamlAttributeMap` (le nom fourni prime).
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

/** Assertion SAML 2.0 normalisée : nameID + attributs (mono- ou multi-valués) + carte optionnelle. */
export interface SamlAssertionParts {
  /** Identifiant de sujet SAML (`<NameID>`), souvent l'e-mail. Sert d'externalId et de repli d'e-mail. */
  readonly nameId: string | null;
  readonly attributes: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly attributeMap?: SamlAttributeMap;
}

/** Clés candidates pour un champ : la surcharge admin (si présente) prime, puis les défauts. */
function samlKeysFor(field: keyof SamlAttributeMap, map: SamlAttributeMap | undefined): string[] {
  const override = map?.[field];
  const defaults = SAML_DEFAULT_ATTRIBUTE_KEYS[field];
  return override ? [override, ...defaults] : [...defaults];
}

/** Valeurs (chaînes non vides) du premier attribut SAML présent parmi les clés candidates. */
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
 * Projette une **assertion SAML 2.0** (ADFS, Entra, Okta, Keycloak via SAML) vers `DirectoryProfile`.
 * C'est le « point dur » du connecteur SAML : une fois l'assertion projetée vers cette cible commune,
 * **le mapping de rôles et la classification existants marchent tels quels**, comme pour OIDC/SCIM.
 * `nameID` sert d'externalId stable et de repli d'e-mail. Les groupes proviennent du claim de groupe
 * ou de rôle de l'IdP. Les attributs bruts sont conservés dans `claims` pour des règles avancées.
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
 * Carte d'attributs **OIDC → champs de profil** (config-driven, ADR-014). Les claims varient selon
 * l'IdP (Entra `jobTitle`, Okta `title`…). L'admin peut surcharger, claim par claim, le nom lu ; à
 * défaut on essaie une liste de claims usuels (le nom fourni prime, puis les défauts). Les `groups`
 * agrègent (union) **tous** les claims candidats (un IdP peut peupler `groups`, `roles` et `wids`).
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
 * Claims OIDC candidats par champ (source unique de vérité), essayés dans l'ordre. Reproduit à
 * l'identique l'extraction historique : sans surcharge, le profil est strictement le même qu'avant.
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

/** Première valeur de claim non vide parmi les candidats. */
function oidcFirst(claims: Record<string, unknown>, keys: readonly string[]): string | undefined {
  return firstString(...keys.map((key) => claims[key]));
}

/**
 * Projette les claims d'un jeton OIDC (Entra ID / Okta / Keycloak) vers `DirectoryProfile`.
 * `attributeMap` (config tenant) surcharge les claims lus ; sans elle, l'extraction est strictement
 * identique à l'historique. Les groupes agrègent tous les claims candidats (`groups`/`roles`/`wids`).
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
