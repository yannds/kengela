/**
 * @kengela/contracts — Les contrats de ports du socle Kengela.
 *
 * INVARIANT du projet : la forme stable dont core, adapters et apps dependent.
 *
 * DOCTRINE
 *  - Ce paquet ne contient QUE des types et interfaces. Zero implementation, zero import vendor.
 *  - Le CORE depend de ces ports ; les ADAPTERS les implementent ; les APPS composent.
 *  - Zero Trust : le PDP est deny-by-default, evalue PAR REQUETE, avec contexte continu.
 *
 * PROVENANCE (tag sur chaque port)
 *  - [ATRIUM]   : existe deja dans Atrium, on l'extrait.
 *  - [TRANSLOG] : le muscle durci de TransLog a porter dans un adapter.
 *  - [NOUVEAU]  : a creer (le differenciant Entra-like / ZTNA).
 */

/* ============================================================================
 * 1. TYPES CENTRAUX (le vocabulaire partage)
 * ========================================================================== */

/** Identifiant opaque tenant. La lib n'impose aucun format. */
export type TenantId = string;
export type UserId = string;

/** Grammaire de permission commune Atrium + TransLog : plane.resource.action.scope */
export type PermissionString = string;

export type Plane = 'platform' | 'control' | 'data' | 'public';

/** Portee ordonnee : own subset unit subset subtree subset tenant subset global. [ATRIUM] */
export type Scope = 'own' | 'unit' | 'subtree' | 'tenant' | 'global';

/** Relation organisationnelle acteur-ressource, resolue sur l'organigramme. [ATRIUM] */
export type OrgRelation = 'self' | 'unit' | 'subtree' | 'tenant' | 'none';

/** Signaux contextuels ZTNA, promus d'audit-only a entrees de decision. [NOUVEAU] */
export interface AuthContext {
  readonly ip?: string;
  readonly geo?: { readonly country?: string; readonly lat?: number; readonly lng?: number };
  readonly device?: {
    readonly id?: string;
    readonly trusted?: boolean;
    readonly userAgent?: string;
  };
  /** Score de risque calcule (voyage impossible, IP reputee, device inconnu...). */
  readonly riskScore?: number;
  /** Horodatage de l'authentification (fraicheur de session). */
  readonly authTime: number;
}

/**
 * Le PONT authn-authz. L'authn le PRODUIT, l'authz le CONSOMME.
 * Contient tout ce qu'une decision Zero Trust peut exiger.
 */
export interface Principal {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  /** Multi-role (union des grants). [NOUVEAU vs TransLog mono-role] */
  readonly roles: readonly string[];
  readonly orgUnitId?: string;
  readonly agencyId?: string;
  readonly coverageUnits?: readonly string[];
  readonly activeStationId?: string;
  /** Force d'authentification atteinte (pour le step-up). */
  readonly mfaLevel: 'none' | 'totp' | 'passkey';
  readonly authMethod:
    'credential' | 'passwordless' | 'oidc' | 'saml' | 'passkey' | 'impersonation';
  /** Contexte de connexion = entrees du conditional access ZTNA. [NOUVEAU] */
  readonly ctx: AuthContext;
}

/** Reference a la ressource visee. Attributs libres = matiere de l'ABAC. */
export interface ResourceRef {
  readonly type: string;
  readonly id?: string;
  readonly tenantId: TenantId;
  /** Attributs evalues par les conditions CEL (agencyId, ownerId, amount...). */
  readonly attributes?: Readonly<Record<string, unknown>>;
}

/** Une demande d'acces soumise au PDP. */
export interface AccessRequest {
  readonly principal: Principal;
  readonly action: string;
  readonly resource: ResourceRef;
  /** Contexte environnemental au moment du check. */
  readonly env?: Partial<AuthContext> & { readonly now?: number };
}

export type Effect = 'allow' | 'deny' | 'step_up';

export interface Obligation {
  readonly type: 'require_mfa' | 'require_passkey' | 'reauthenticate' | 'notify';
  readonly params?: Readonly<Record<string, unknown>>;
}

/** Le resultat d'un check. Jamais un simple booleen (ZTNA + obligations). [NOUVEAU] */
export interface Decision {
  readonly effect: Effect;
  /** Obligations a satisfaire si effect = step_up. */
  readonly obligations?: readonly Obligation[];
  /** Policy/regle qui a decide (tracabilite). */
  readonly matchedPolicy?: string;
  /** Raison lisible : "no_grant", "condition_failed", "outside_business_hours"... */
  readonly reason: string;
  /** Signaux ayant influence la decision (pour le decision log). */
  readonly signals?: Readonly<Record<string, unknown>>;
}

/** Un grant (droit), avec provenance et expiration. [ATRIUM] */
export interface Grant {
  readonly permission: PermissionString;
  readonly scope: Scope;
  readonly source: 'MANUAL' | 'IDP' | 'DELEGATION';
  readonly expiresAt?: Date;
}

export interface Role {
  readonly key: string;
  readonly tenantId: TenantId;
  readonly grants: readonly Grant[];
}

/* ============================================================================
 * 2. PORTS AUTHN
 * ========================================================================== */

export type SessionStrategy = 'cookie' | 'bearer';

export interface SessionCredential {
  readonly strategy: SessionStrategy;
  readonly token: string;
}

/** Frontiere d'authentification. Resout une preuve de session en Principal. [ATRIUM] */
export interface IdentityPort {
  verifySession(credential: SessionCredential): Promise<Principal | null>;
}

export interface SessionHandle {
  readonly token: string;
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly ctx: AuthContext;
}

/**
 * Stockage de session opaque durci. [TRANSLOG]
 * L'adapter native porte : rotation a mi-TTL, plafond FIFO, IP-binding, cleanup.
 */
export interface SessionStore {
  create(input: {
    readonly userId: UserId;
    readonly tenantId: TenantId;
    readonly ctx: AuthContext;
    readonly ttlMs: number;
  }): Promise<SessionHandle>;
  get(token: string): Promise<SessionHandle | null>;
  /** Rotation : emet un nouveau token, invalide l'ancien. */
  rotate(token: string): Promise<SessionHandle>;
  revoke(token: string): Promise<void>;
  listForUser(userId: UserId): Promise<readonly SessionHandle[]>;
  revokeAllForUser(userId: UserId): Promise<void>;
}

export type AuthOutcome =
  | { readonly kind: 'authenticated'; readonly principal: Principal }
  | { readonly kind: 'mfa_required'; readonly userId: UserId; readonly tenantId: TenantId }
  | { readonly kind: 'tenant_choice'; readonly candidates: readonly TenantId[] }
  | { readonly kind: 'invalid_credentials' }
  | { readonly kind: 'captcha_required' };

/**
 * Authentification par identifiants. [TRANSLOG]
 * L'implementation DOIT etre timing-safe (compare systematique, dummy hash).
 */
export interface CredentialAuthenticator {
  authenticate(input: {
    readonly email: string;
    readonly password: string;
    readonly tenantId: TenantId;
    readonly ctx: AuthContext;
  }): Promise<AuthOutcome>;
  /** Login mobile multi-tenant : peut retourner un choix de tenant. [TRANSLOG] */
  authenticateCrossTenant(input: {
    readonly email: string;
    readonly password: string;
    readonly ctx: AuthContext;
  }): Promise<AuthOutcome>;
}

/** Hash de mot de passe (argon2id recommande, bcrypt en compat). [TRANSLOG] */
export interface PasswordHasher {
  hash(plain: string): Promise<string>;
  /** Verification. L'implementation DOIT etre a temps constant. */
  verify(plain: string, hash: string): Promise<boolean>;
  /**
   * true si le hash devrait etre re-calcule (algo/parametres obsoletes) : permet la
   * migration transparente (ex. bcrypt -> argon2) au prochain login reussi.
   */
  needsRehash(hash: string): boolean;
}

/** Enregistrement credential resolu depuis le stockage. [TRANSLOG] */
export interface CredentialRecord {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  /** Hash du mot de passe, ou null si le compte n'a pas de credential. */
  readonly passwordHash: string | null;
  readonly isActive: boolean;
  readonly mfaEnabled: boolean;
  readonly roles: readonly string[];
}

/** Recherche de credentials (implementee par la persistance de l'app). */
export interface CredentialStore {
  findByEmail(email: string, tenantId: TenantId): Promise<CredentialRecord | null>;
  findByEmailAcrossTenants(email: string): Promise<readonly CredentialRecord[]>;
}

/** MFA (TOTP + backup codes). [TRANSLOG crypto AES-256-GCM] + [ATRIUM twoFactor] */
export interface MfaService {
  enroll(userId: UserId): Promise<{ readonly secretUri: string; readonly qr: string }>;
  verify(challengeId: string, code: string): Promise<boolean>;
  challenge(userId: UserId): Promise<{ readonly challengeId: string }>;
}

/**
 * Coffre de secrets. [ATRIUM] — implemente par Vault chez TransLog.
 * Retourne `unknown` : le consommateur DOIT valider (aucune confiance aveugle).
 */
export interface SecretsPort {
  getSecretObject(path: string): Promise<unknown>;
}

/** Chiffrement enveloppe par tenant (secret MFA at-rest, etc.). [ATRIUM] + [TRANSLOG] */
export interface KeyManagementPort {
  encrypt(tenantId: TenantId, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(tenantId: TenantId, ciphertext: Uint8Array): Promise<Uint8Array>;
}

/**
 * Chiffrement au niveau CHAMP pour les données personnelles (PII : email, téléphone,
 * adresse...) stockées. [compliance-by-design] Entrée/sortie = chaîne (colonne texte),
 * isolation cryptographique par tenant. Sert le RGPD (protection at-rest, crypto-shredding
 * possible via révocation de clé tenant).
 */
export interface FieldCipherPort {
  encryptField(tenantId: TenantId, plaintext: string): Promise<string>;
  decryptField(tenantId: TenantId, ciphertext: string): Promise<string>;
}

/* ============================================================================
 * 3. PORTS AUTHZ (le coeur Zero Trust)
 * ========================================================================== */

/**
 * Point de decision central (PDP). Deny-by-default, evalue PAR REQUETE. [NOUVEAU]
 * Compose : RBAC (grants) x relation org x conditions ABAC (CEL) x conditional access.
 */
export interface PolicyDecisionPoint {
  check(request: AccessRequest): Promise<Decision>;
  /** Batch (listes) — evite le N+1 sur le filtrage de collections. */
  checkMany(requests: readonly AccessRequest[]): Promise<readonly Decision[]>;
}

/** Charge les grants d'un utilisateur (exclut expires, distingue provenance). [ATRIUM] */
export interface AuthorizationRepository {
  loadGrantsForUser(userId: UserId, tenantId: TenantId): Promise<readonly Grant[]>;
  loadRole(roleKey: string, tenantId: TenantId): Promise<Role | null>;
}

/** Resout la relation organisationnelle acteur-ressource. [ATRIUM] */
export interface RelationResolver {
  resolveRelation(principal: Principal, resource: ResourceRef): Promise<OrgRelation>;
}

export interface ExpressionContext {
  readonly principal: Principal;
  readonly resource: ResourceRef;
  readonly env: AuthContext & { readonly now: number };
  readonly tenant?: Readonly<Record<string, unknown>>;
}

/** Evaluateur de conditions declaratives (CEL). [ATRIUM expr-cel] — etendu a l'authz. */
export interface ExpressionEnginePort {
  evaluateBoolean(expression: string, ctx: ExpressionContext): boolean;
}

export interface PolicyRule {
  readonly effect: Effect;
  readonly scope?: Scope;
  /** Condition CEL optionnelle. Absence = toujours vrai. */
  readonly when?: string;
  readonly obligations?: readonly Obligation[];
  readonly reason?: string;
}

export interface Policy {
  readonly resource: string;
  readonly action: string;
  readonly rules: readonly PolicyRule[];
}

/**
 * Source des policies declaratives. [NOUVEAU]
 * Hybride possible : policies structurelles en fichiers versionnes (CI),
 * overrides tenant en base (hot-reload).
 */
export interface PolicyStore {
  loadPolicies(tenantId: TenantId): Promise<readonly Policy[]>;
}

/** Journal des decisions (observabilite ZTNA). [NOUVEAU] */
export interface DecisionLogSink {
  record(entry: {
    readonly request: AccessRequest;
    readonly decision: Decision;
    readonly at: number;
  }): Promise<void> | void;
}

/* ============================================================================
 * 4. PORT CONTEXTE / ZTNA
 * ========================================================================== */

/**
 * Fournit le contexte de connexion (geo/device/risque). [NOUVEAU]
 * Chaque app branche sa source (GeoIP, device fingerprint, risk engine).
 */
export interface ContextProvider {
  enrich(input: {
    readonly ip?: string;
    readonly userAgent?: string;
    readonly userId?: UserId;
  }): Promise<AuthContext>;
}

/* ============================================================================
 * 5. PORTS TENANCY (isolation multi-tenant)
 * ========================================================================== */

/** Contexte tenant courant (ALS). [ATRIUM tenancy] */
export interface TenantContextPort {
  run<T>(tenantId: TenantId, fn: () => Promise<T>): Promise<T>;
  require(): TenantId;
  current(): TenantId | null;
}

/** Unite de travail liant la connexion au tenant (RLS). [ATRIUM] + [TRANSLOG RLS] */
export interface UnitOfWork {
  withTenant<T>(tenantId: TenantId, fn: (repos: unknown) => Promise<T>): Promise<T>;
}

/* ============================================================================
 * 6. PORTS FEDERATION / ANNUAIRE (opt-in)
 * ========================================================================== */

/** Profil normalise, point de convergence des 6 sources IdP. [ATRIUM iam-mapping] */
export interface DirectoryProfile {
  readonly externalId: string;
  readonly email?: string;
  readonly displayName?: string;
  readonly groups: readonly string[];
  readonly attributes: Readonly<Record<string, unknown>>;
  readonly active: boolean;
  readonly source: 'oidc' | 'scim' | 'saml' | 'ldap' | 'graph' | 'google';
}

/** Une source d'annuaire (OIDC/SCIM/SAML/LDAP/Graph/Google). [ATRIUM] */
export interface DirectorySourcePort {
  fetchProfile(raw: unknown, tenantId: TenantId): Promise<DirectoryProfile>;
}

/** Persistance SCIM (Users + Groups). [ATRIUM scim] */
export interface ScimRepository {
  upsertUserByEmail(
    tenantId: TenantId,
    profile: DirectoryProfile,
  ): Promise<{ readonly id: string; readonly created: boolean }>;
  deactivateUser(tenantId: TenantId, id: string): Promise<void>;
}

/* ============================================================================
 * 7. PORTS TRANSVERSES
 * ========================================================================== */

/** Cache (grants, rate-limit). [TRANSLOG Redis] */
export interface CachePort {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown, ttlSec: number): Promise<void>;
  del(key: string): Promise<void>;
}

/** Audit metier/securite (distinct du DecisionLogSink). */
export interface AuditSink {
  emit(event: {
    readonly type: string;
    readonly tenantId: TenantId;
    readonly actor?: UserId;
    readonly data?: Readonly<Record<string, unknown>>;
  }): Promise<void> | void;
}

/** Horloge injectable (determinisme des tests + CEL). [ATRIUM] */
export interface Clock {
  now(): number;
}
