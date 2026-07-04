/**
 * PrismaLike - the NARROW surface this adapter depends on.
 *
 * DOCTRINE: the port is an airlock, not a hideout. We do NOT generate a Prisma
 * client here and we import NOTHING from `@prisma/client`. We describe exactly the
 * delegates and methods used, with explicit row types. A real `PrismaClient`
 * (generated from prisma/schema.prisma) is structurally compatible on the
 * application side: it fits wherever `PrismaLike` is expected.
 *
 * The union columns (scope, source, effect, ctx JSON) stay as `string` /
 * `unknown` on the database side: the fail-closed narrowing lives in mapping.ts.
 */
import type { TenantId, UserId } from '@kengela/contracts';

/** `Grant` row as stored (unions kept as `string`). */
export interface GrantRow {
  readonly permission: string;
  readonly scope: string;
  readonly source: string;
  readonly expiresAt: Date | null;
}

/** `Role` row with its joined grants. */
export interface RoleRow {
  readonly key: string;
  readonly tenantId: TenantId;
  readonly grants: readonly GrantRow[];
}

/** `Session` row. `ctx` is an opaque JSON column (`unknown`). */
export interface SessionRow {
  readonly token: string;
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly ctx: unknown;
}

/** Write payload for a session (same shape as the row). */
export interface SessionCreateData {
  readonly token: string;
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly ctx: unknown;
}

/** `PolicyRule` row (nested under a policy). */
export interface PolicyRuleRow {
  readonly effect: string;
  readonly scope: string | null;
  readonly when: string | null;
  readonly obligations: unknown;
  readonly reason: string | null;
}

/** `Policy` row with its joined rules. */
export interface PolicyRow {
  readonly resource: string;
  readonly action: string;
  readonly tenantId: TenantId;
  readonly rules: readonly PolicyRuleRow[];
}

export interface GrantDelegate {
  findMany(args: {
    readonly where: { readonly userId: UserId; readonly tenantId: TenantId };
  }): Promise<readonly GrantRow[]>;
}

export interface RoleDelegate {
  findFirst(args: {
    readonly where: { readonly key: string; readonly tenantId: TenantId };
    readonly include: { readonly grants: true };
  }): Promise<RoleRow | null>;
}

export interface SessionDelegate {
  create(args: { readonly data: SessionCreateData }): Promise<SessionRow>;
  findUnique(args: { readonly where: { readonly token: string } }): Promise<SessionRow | null>;
  delete(args: { readonly where: { readonly token: string } }): Promise<SessionRow>;
  deleteMany(args: {
    readonly where: { readonly token?: string; readonly userId?: UserId };
  }): Promise<{ readonly count: number }>;
  findMany(args: { readonly where: { readonly userId: UserId } }): Promise<readonly SessionRow[]>;
}

export interface PolicyDelegate {
  findMany(args: {
    readonly where: { readonly tenantId: TenantId };
    readonly include: { readonly rules: true };
  }): Promise<readonly PolicyRow[]>;
}

/**
 * The injected client. `$transaction` is OPTIONAL: the atomic operations
 * (session rotation) use it if the injected client provides it, otherwise they
 * degrade to sequential operations.
 */
export interface PrismaLike {
  readonly grant: GrantDelegate;
  readonly role: RoleDelegate;
  readonly session: SessionDelegate;
  readonly policy: PolicyDelegate;
  readonly $transaction?: (<T>(fn: (tx: PrismaLike) => Promise<T>) => Promise<T>) | undefined;
}

// ── MFA: encrypted at-rest secret + one-shot expiring challenges ─────────────

/** Row storing the encrypted TOTP secret (cleartext is never persisted). */
export interface MfaSecretRow {
  readonly secret: string;
}

export interface MfaSecretDelegate {
  findFirst(args: {
    readonly where: { readonly tenantId: TenantId; readonly userId: UserId };
  }): Promise<MfaSecretRow | null>;
  deleteMany(args: {
    readonly where: { readonly tenantId: TenantId; readonly userId: UserId };
  }): Promise<{ readonly count: number }>;
  create(args: {
    readonly data: {
      readonly tenantId: TenantId;
      readonly userId: UserId;
      readonly secret: string;
    };
  }): Promise<unknown>;
}

export interface MfaChallengeRow {
  readonly id: string;
  readonly tenantId: TenantId;
  readonly userId: UserId;
  readonly expiresAt: Date;
}

export interface MfaChallengeDelegate {
  create(args: {
    readonly data: {
      readonly id: string;
      readonly tenantId: TenantId;
      readonly userId: UserId;
      readonly expiresAt: Date;
    };
  }): Promise<unknown>;
  findUnique(args: { readonly where: { readonly id: string } }): Promise<MfaChallengeRow | null>;
  delete(args: { readonly where: { readonly id: string } }): Promise<unknown>;
}

// ── Credentials: password identity (Account) + account state (User) ──────────
//
// Reference schema (generic "better-auth-like" model):
//  - User    { id, tenantId, isActive, deletedAt?, mfaEnabled, roles String[] }
//  - Account { userId, tenantId, providerId, accountId, password? }
// The hash lives in `Account` (providerId='credential', accountId=email); the
// account state (active, mfa, roles) in `User`. A real `PrismaClient` (User/Account) is
// structurally compatible with the NARROW delegates below.

/** `Account` row - NARROW subset (the `password` hash is optional). */
export interface AccountRow {
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly password: string | null;
}

/** `User` row - NARROW subset read to resolve a `CredentialRecord`. */
export interface CredentialUserRow {
  readonly id: UserId;
  readonly tenantId: TenantId;
  readonly isActive: boolean;
  readonly deletedAt: Date | null;
  readonly mfaEnabled: boolean;
  /** The user's roles (list column, e.g. `roles String[]`). */
  readonly roles: readonly string[];
}

export interface AccountDelegate {
  findFirst(args: {
    readonly where: {
      readonly tenantId: TenantId;
      readonly providerId: string;
      readonly accountId: string;
    };
  }): Promise<AccountRow | null>;
  findMany(args: {
    readonly where: { readonly providerId: string; readonly accountId: string };
  }): Promise<readonly AccountRow[]>;
}

export interface CredentialUserDelegate {
  findFirst(args: {
    readonly where: { readonly id: UserId; readonly tenantId: TenantId };
  }): Promise<CredentialUserRow | null>;
  findMany(args: {
    readonly where: { readonly id: { readonly in: readonly UserId[] } };
  }): Promise<readonly CredentialUserRow[]>;
}

/** NARROW surface that `PrismaCredentialStore` needs (Account + User). */
export interface CredentialPrismaLike {
  readonly account: AccountDelegate;
  readonly user: CredentialUserDelegate;
}

// ── PII: PER-SUBJECT encryption key (crypto-shredding) + access log ──────────

/** Row storing a subject's key, serialized in base64 (encrypted-at-rest if KMS injected). */
export interface SubjectKeyRow {
  readonly key: string;
}

export interface SubjectKeyDelegate {
  findFirst(args: {
    readonly where: { readonly tenantId: TenantId; readonly subjectId: string };
  }): Promise<SubjectKeyRow | null>;
  create(args: {
    readonly data: {
      readonly tenantId: TenantId;
      readonly subjectId: string;
      readonly key: string;
    };
  }): Promise<unknown>;
  deleteMany(args: {
    readonly where: { readonly tenantId: TenantId; readonly subjectId: string };
  }): Promise<{ readonly count: number }>;
}

export interface PiiAccessLogDelegate {
  create(args: {
    readonly data: {
      readonly tenantId: TenantId;
      readonly subjectId: string;
      readonly actorId: UserId | null;
      readonly fields: readonly string[];
      readonly purpose: string;
      readonly at: Date;
    };
  }): Promise<unknown>;
}
