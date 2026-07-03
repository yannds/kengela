/**
 * PrismaLike — la surface NARROW dont cet adapter depend.
 *
 * DOCTRINE : le port est un sas, pas une planque. On ne genere PAS de client
 * Prisma ici et on n'importe RIEN de `@prisma/client`. On decrit exactement les
 * delegues et methodes utilises, avec des types de lignes explicites. Un vrai
 * `PrismaClient` (genere depuis prisma/schema.prisma) est structurellement
 * compatible cote application : il se passe la ou `PrismaLike` est attendu.
 *
 * Les colonnes d'union (scope, source, effect, ctx JSON) restent des `string` /
 * `unknown` cote base : le narrowing fail-closed vit dans mapping.ts.
 */
import type { TenantId, UserId } from '@kengela/contracts';

/** Ligne `Grant` telle que stockee (unions gardees en `string`). */
export interface GrantRow {
  readonly permission: string;
  readonly scope: string;
  readonly source: string;
  readonly expiresAt: Date | null;
}

/** Ligne `Role` avec ses grants joints. */
export interface RoleRow {
  readonly key: string;
  readonly tenantId: TenantId;
  readonly grants: readonly GrantRow[];
}

/** Ligne `Session`. `ctx` est une colonne JSON opaque (`unknown`). */
export interface SessionRow {
  readonly token: string;
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly ctx: unknown;
}

/** Payload d'ecriture d'une session (meme forme que la ligne). */
export interface SessionCreateData {
  readonly token: string;
  readonly userId: UserId;
  readonly tenantId: TenantId;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly ctx: unknown;
}

/** Ligne `PolicyRule` (imbriquee sous une policy). */
export interface PolicyRuleRow {
  readonly effect: string;
  readonly scope: string | null;
  readonly when: string | null;
  readonly obligations: unknown;
  readonly reason: string | null;
}

/** Ligne `Policy` avec ses regles jointes. */
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
 * Le client injecte. `$transaction` est OPTIONNEL : les operations atomiques
 * (rotation de session) l'utilisent si le client injecte le fournit, sinon
 * degradent en operations sequentielles.
 */
export interface PrismaLike {
  readonly grant: GrantDelegate;
  readonly role: RoleDelegate;
  readonly session: SessionDelegate;
  readonly policy: PolicyDelegate;
  readonly $transaction?: (<T>(fn: (tx: PrismaLike) => Promise<T>) => Promise<T>) | undefined;
}

// ── MFA : secret chiffre at-rest + defis one-shot expirants ──────────────────

/** Ligne stockant le secret TOTP chiffre (le clair n'est jamais persiste). */
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
