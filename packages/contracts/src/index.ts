/**
 * @kengela/contracts - The port contracts of the Kengela foundation.
 *
 * Project INVARIANT: the stable shape that core, adapters and apps depend on.
 *
 * DOCTRINE
 *  - This package contains ONLY types and interfaces. Zero implementation, zero vendor import.
 *  - The CORE depends on these ports; the ADAPTERS implement them; the APPS compose.
 *  - Zero Trust: the PDP is deny-by-default, evaluated PER REQUEST, with continuous context.
 *
 * PROVENANCE (tag on each port)
 *  - [ATRIUM]   : already exists in Atrium, we extract it.
 *  - [TRANSLOG] : the hardened muscle of TransLog to port into an adapter.
 *  - [NEW]      : to create (the Entra-like / ZTNA differentiator).
 */

/* ============================================================================
 * 1. CORE TYPES (the shared vocabulary)
 * ========================================================================== */

/** Opaque tenant identifier. The lib imposes no format. */
export type TenantId = string;
export type UserId = string;

/** Permission grammar common to Atrium + TransLog: plane.resource.action.scope */
export type PermissionString = string;

export type Plane = 'platform' | 'control' | 'data' | 'public';

/** Ordered scope: own subset unit subset subtree subset tenant subset global. [ATRIUM] */
export type Scope = 'own' | 'unit' | 'subtree' | 'tenant' | 'global';

/** Organizational actor-resource relation, resolved on the org chart. [ATRIUM] */
export type OrgRelation = 'self' | 'unit' | 'subtree' | 'tenant' | 'none';

/** ZTNA contextual signals, promoted from audit-only to decision inputs. [NEW] */
export interface AuthContext {
  readonly ip?: string;
  readonly geo?: { readonly country?: string; readonly lat?: number; readonly lng?: number };
  readonly device?: {
    readonly id?: string;
    readonly trusted?: boolean;
    readonly userAgent?: string;
  };
  /** Computed risk score (impossible travel, flagged IP, unknown device...). */
  readonly riskScore?: number;
  /** Authentication timestamp (session freshness). */
  readonly authTime: number;
}

/**
 * The authn-authz BRIDGE. The authn PRODUCES it, the authz CONSUMES it.
 * Holds everything a Zero Trust decision may require.
 */
export interface Principal {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  /** Multi-role (union of grants). [NEW vs TransLog mono-role] */
  readonly roles: readonly string[];
  readonly orgUnitId?: string;
  readonly agencyId?: string;
  readonly coverageUnits?: readonly string[];
  readonly activeStationId?: string;
  /** Authentication strength reached (for step-up). */
  readonly mfaLevel: 'none' | 'totp' | 'passkey';
  readonly authMethod:
    'credential' | 'passwordless' | 'oidc' | 'saml' | 'passkey' | 'impersonation';
  /** Connection context = inputs of the ZTNA conditional access. [NEW] */
  readonly ctx: AuthContext;
}

/** Reference to the target resource. Free attributes = the raw material of ABAC. */
export interface ResourceRef {
  readonly type: string;
  readonly id?: string;
  readonly tenantId: TenantId;
  /** Attributes evaluated by CEL conditions (agencyId, ownerId, amount...). */
  readonly attributes?: Readonly<Record<string, unknown>>;
}

/** An access request submitted to the PDP. */
export interface AccessRequest {
  readonly principal: Principal;
  readonly action: string;
  readonly resource: ResourceRef;
  /** Environmental context at the moment of the check. */
  readonly env?: Partial<AuthContext> & { readonly now?: number };
}

export type Effect = 'allow' | 'deny' | 'step_up';

export interface Obligation {
  readonly type: 'require_mfa' | 'require_passkey' | 'reauthenticate' | 'notify';
  readonly params?: Readonly<Record<string, unknown>>;
}

/** The result of a check. Never a plain boolean (ZTNA + obligations). [NEW] */
export interface Decision {
  readonly effect: Effect;
  /** Obligations to satisfy if effect = step_up. */
  readonly obligations?: readonly Obligation[];
  /** Policy/rule that decided (traceability). */
  readonly matchedPolicy?: string;
  /** Readable reason: "no_grant", "condition_failed", "outside_business_hours"... */
  readonly reason: string;
  /** Signals that influenced the decision (for the decision log). */
  readonly signals?: Readonly<Record<string, unknown>>;
}

/** A grant (right), with provenance and expiration. [ATRIUM] */
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
 * 2. AUTHN PORTS
 * ========================================================================== */

export type SessionStrategy = 'cookie' | 'bearer';

export interface SessionCredential {
  readonly strategy: SessionStrategy;
  readonly token: string;
}

/** Authentication boundary. Resolves a session proof into a Principal. [ATRIUM] */
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
 * Hardened opaque session storage. [TRANSLOG]
 * The native adapter carries: rotation at mid-TTL, FIFO cap, IP-binding, cleanup.
 */
export interface SessionStore {
  create(input: {
    readonly userId: UserId;
    readonly tenantId: TenantId;
    readonly ctx: AuthContext;
    readonly ttlMs: number;
  }): Promise<SessionHandle>;
  get(token: string): Promise<SessionHandle | null>;
  /** Rotation: issues a new token, invalidates the old one. */
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
 * Credential-based authentication. [TRANSLOG]
 * The implementation MUST be timing-safe (systematic compare, dummy hash).
 */
export interface CredentialAuthenticator {
  authenticate(input: {
    readonly email: string;
    readonly password: string;
    readonly tenantId: TenantId;
    readonly ctx: AuthContext;
  }): Promise<AuthOutcome>;
  /** Multi-tenant mobile login: may return a tenant choice. [TRANSLOG] */
  authenticateCrossTenant(input: {
    readonly email: string;
    readonly password: string;
    readonly ctx: AuthContext;
  }): Promise<AuthOutcome>;
}

/** Password hashing (argon2id recommended, bcrypt for compat). [TRANSLOG] */
export interface PasswordHasher {
  hash(plain: string): Promise<string>;
  /** Verification. The implementation MUST be constant-time. */
  verify(plain: string, hash: string): Promise<boolean>;
  /**
   * true if the hash should be re-computed (obsolete algo/parameters): enables
   * transparent migration (e.g. bcrypt -> argon2) at the next successful login.
   */
  needsRehash(hash: string): boolean;
}

/** Credential record resolved from storage. [TRANSLOG] */
export interface CredentialRecord {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  /** Password hash, or null if the account has no credential. */
  readonly passwordHash: string | null;
  readonly isActive: boolean;
  readonly mfaEnabled: boolean;
  readonly roles: readonly string[];
}

/** Credential lookup (implemented by the app's persistence). */
export interface CredentialStore {
  findByEmail(email: string, tenantId: TenantId): Promise<CredentialRecord | null>;
  findByEmailAcrossTenants(email: string): Promise<readonly CredentialRecord[]>;
}

/** MFA (TOTP + backup codes). [TRANSLOG crypto AES-256-GCM] + [ATRIUM twoFactor] */
export interface MfaService {
  enroll(input: {
    readonly tenantId: TenantId;
    readonly userId: UserId;
    readonly account: string;
    readonly issuer: string;
  }): Promise<{ readonly secretUri: string; readonly qr: string }>;
  challenge(input: {
    readonly tenantId: TenantId;
    readonly userId: UserId;
  }): Promise<{ readonly challengeId: string }>;
  verify(challengeId: string, code: string): Promise<boolean>;
}

/**
 * Persistence of the at-rest encrypted TOTP secret, isolated per tenant. [TRANSLOG]
 * The implementation (app) stores the already-encrypted secret; the port only knows its opacity.
 */
export interface MfaSecretStore {
  save(tenantId: TenantId, userId: UserId, encryptedSecret: string): Promise<void>;
  get(tenantId: TenantId, userId: UserId): Promise<string | null>;
}

/**
 * Issuance/consumption of one-shot MFA challenges (step-up). [TRANSLOG]
 * `issue` returns an opaque challengeId; `consume` is single-use (one-shot) and expiring.
 */
export interface MfaChallengeStore {
  /** Returns an opaque challengeId, valid for `ttlMs`. */
  issue(tenantId: TenantId, userId: UserId, ttlMs: number): Promise<string>;
  /** Resolves and invalidates the challenge (one-shot). null if unknown, consumed or expired. */
  consume(
    challengeId: string,
  ): Promise<{ readonly tenantId: TenantId; readonly userId: UserId } | null>;
}

/**
 * Secrets vault. [ATRIUM] - implemented by Vault at TransLog.
 * Returns `unknown`: the consumer MUST validate (no blind trust).
 */
export interface SecretsPort {
  getSecretObject(path: string): Promise<unknown>;
}

/** Per-tenant envelope encryption (at-rest MFA secret, etc.). [ATRIUM] + [TRANSLOG] */
export interface KeyManagementPort {
  encrypt(tenantId: TenantId, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(tenantId: TenantId, ciphertext: Uint8Array): Promise<Uint8Array>;
}

/**
 * FIELD-level encryption for stored personal data (PII: email, phone,
 * address...). [compliance-by-design] Input/output = string (text column),
 * cryptographic isolation per tenant. Serves the GDPR (at-rest protection, crypto-shredding
 * possible via tenant key revocation).
 */
export interface FieldCipherPort {
  encryptField(tenantId: TenantId, plaintext: string): Promise<string>;
  decryptField(tenantId: TenantId, ciphertext: string): Promise<string>;
}

/**
 * Personal-data access log (GDPR art. 30, auditability). [compliance-by-design]
 * Every PII read/export must be traceable: who, which subject, which fields, which purpose.
 */
export interface PiiAccessLogSink {
  record(entry: {
    readonly tenantId: TenantId;
    /** Data subject concerned. */
    readonly subjectId: string;
    /** Actor accessing (absent = system). */
    readonly actorId?: UserId;
    readonly fields: readonly string[];
    /** Processing purpose (GDPR). */
    readonly purpose: string;
    readonly at: number;
  }): Promise<void> | void;
}

/**
 * Storage of an encryption key PER SUBJECT (data subject). [compliance-by-design]
 * Basis of crypto-shredding: destroying a subject's key makes their encrypted PII
 * permanently unreadable - GDPR erasure (art. 17) without scanning every table.
 */
export interface SubjectKeyStore {
  getOrCreateKey(tenantId: TenantId, subjectId: string): Promise<Uint8Array>;
  getKey(tenantId: TenantId, subjectId: string): Promise<Uint8Array | null>;
  deleteKey(tenantId: TenantId, subjectId: string): Promise<void>;
}

/** Right to erasure (GDPR art. 17). Recommended implementation: crypto-shredding. */
export interface ErasurePort {
  eraseSubject(tenantId: TenantId, subjectId: string): Promise<void>;
}

/* ============================================================================
 * 3. AUTHZ PORTS (the Zero Trust core)
 * ========================================================================== */

/**
 * Central decision point (PDP). Deny-by-default, evaluated PER REQUEST. [NEW]
 * Composes: RBAC (grants) x org relation x ABAC conditions (CEL) x conditional access.
 */
export interface PolicyDecisionPoint {
  check(request: AccessRequest): Promise<Decision>;
  /** Batch (lists) - avoids the N+1 on collection filtering. */
  checkMany(requests: readonly AccessRequest[]): Promise<readonly Decision[]>;
}

/** Loads a user's grants (excludes expired, distinguishes provenance). [ATRIUM] */
export interface AuthorizationRepository {
  loadGrantsForUser(userId: UserId, tenantId: TenantId): Promise<readonly Grant[]>;
  loadRole(roleKey: string, tenantId: TenantId): Promise<Role | null>;
}

/** Resolves the organizational actor-resource relation. [ATRIUM] */
export interface RelationResolver {
  resolveRelation(principal: Principal, resource: ResourceRef): Promise<OrgRelation>;
}

export interface ExpressionContext {
  readonly principal: Principal;
  readonly resource: ResourceRef;
  readonly env: AuthContext & { readonly now: number };
  readonly tenant?: Readonly<Record<string, unknown>>;
}

/** Evaluator of declarative conditions (CEL). [ATRIUM expr-cel] - extended to authz. */
export interface ExpressionEnginePort {
  evaluateBoolean(expression: string, ctx: ExpressionContext): boolean;
}

export interface PolicyRule {
  readonly effect: Effect;
  readonly scope?: Scope;
  /** Optional CEL condition. Absence = always true. */
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
 * Source of declarative policies. [NEW]
 * Hybrid possible: structural policies in versioned files (CI),
 * tenant overrides in the database (hot-reload).
 */
export interface PolicyStore {
  loadPolicies(tenantId: TenantId): Promise<readonly Policy[]>;
}

/** Decision log (ZTNA observability). [NEW] */
export interface DecisionLogSink {
  record(entry: {
    readonly request: AccessRequest;
    readonly decision: Decision;
    readonly at: number;
  }): Promise<void> | void;
}

/* ============================================================================
 * 4. CONTEXT / ZTNA PORT
 * ========================================================================== */

/**
 * Provides the connection context (geo/device/risk). [NEW]
 * Each app wires its source (GeoIP, device fingerprint, risk engine).
 */
export interface ContextProvider {
  enrich(input: {
    readonly ip?: string;
    readonly userAgent?: string;
    readonly userId?: UserId;
  }): Promise<AuthContext>;
}

/* ============================================================================
 * 5. TENANCY PORTS (multi-tenant isolation)
 * ========================================================================== */

/** Current tenant context (ALS). [ATRIUM tenancy] */
export interface TenantContextPort {
  run<T>(tenantId: TenantId, fn: () => Promise<T>): Promise<T>;
  require(): TenantId;
  current(): TenantId | null;
}

/** Unit of work binding the connection to the tenant (RLS). [ATRIUM] + [TRANSLOG RLS] */
export interface UnitOfWork {
  withTenant<T>(tenantId: TenantId, fn: (repos: unknown) => Promise<T>): Promise<T>;
}

/* ============================================================================
 * 6. FEDERATION / DIRECTORY PORTS (opt-in)
 * ========================================================================== */

/** Normalized profile, convergence point of the 6 IdP sources. [ATRIUM iam-mapping] */
export interface DirectoryProfile {
  readonly externalId: string;
  readonly email?: string;
  readonly displayName?: string;
  readonly groups: readonly string[];
  readonly attributes: Readonly<Record<string, unknown>>;
  readonly active: boolean;
  readonly source: 'oidc' | 'scim' | 'saml' | 'ldap' | 'graph' | 'google';
}

/** A directory source (OIDC/SCIM/SAML/LDAP/Graph/Google). [ATRIUM] */
export interface DirectorySourcePort {
  fetchProfile(raw: unknown, tenantId: TenantId): Promise<DirectoryProfile>;
}

/** SCIM persistence (Users + Groups). [ATRIUM scim] */
export interface ScimRepository {
  upsertUserByEmail(
    tenantId: TenantId,
    profile: DirectoryProfile,
  ): Promise<{ readonly id: string; readonly created: boolean }>;
  deactivateUser(tenantId: TenantId, id: string): Promise<void>;
}

/* ============================================================================
 * 7. CROSS-CUTTING PORTS
 * ========================================================================== */

/** Cache (grants, rate-limit). [TRANSLOG Redis] */
export interface CachePort {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown, ttlSec: number): Promise<void>;
  del(key: string): Promise<void>;
}

/** Business/security audit (distinct from the DecisionLogSink). */
export interface AuditSink {
  emit(event: {
    readonly type: string;
    readonly tenantId: TenantId;
    readonly actor?: UserId;
    readonly data?: Readonly<Record<string, unknown>>;
  }): Promise<void> | void;
}

/** Injectable clock (test determinism + CEL). [ATRIUM] */
export interface Clock {
  now(): number;
}
