/**
 * Contrats du cœur SCIM 2.0 (RFC 7643/7644) - port `ScimStore` + formes de requête /
 * réponse. Framework-agnostique : aucune référence HTTP, aucune dépendance vendor.
 *
 * Le port est NARROW et orienté SCIM : il expose exactement ce dont les handlers ont
 * besoin (réconciliation par e-mail, pagination, désactivation ≠ suppression, membres de
 * groupe). Un adapter (Prisma, NestJS…) l'implémente ; les handlers le consomment.
 */
import type { TenantId } from '@kengela/contracts';

// ── Lignes de persistance (formes explicites) ────────────────────────────────
/** Utilisateur SCIM tel que stocké/relu. `userName` porte l'e-mail (clé de réconciliation). */
export interface ScimUserRow {
  readonly id: string;
  readonly userName: string;
  readonly externalId: string | null;
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly active: boolean;
  /** Horodatage ISO 8601 de création. */
  readonly createdAt: string;
  /** Horodatage ISO 8601 de dernière modification. */
  readonly lastModified: string;
}

/** Groupe SCIM tel que stocké/relu, avec ses membres (ids d'utilisateurs). */
export interface ScimGroupRow {
  readonly id: string;
  readonly displayName: string;
  readonly externalId: string | null;
  readonly memberIds: readonly string[];
  readonly createdAt: string;
  readonly lastModified: string;
}

// ── Entrées d'écriture ───────────────────────────────────────────────────────
/** Champs d'un utilisateur à créer (POST) ou remplacer intégralement (PUT). */
export interface ScimUserWriteInput {
  readonly userName: string;
  readonly externalId: string | null;
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly displayName: string | null;
  readonly active: boolean;
}

/**
 * Champs d'identité touchés par un PATCH. `undefined` = non touché ; `null` = effacé ;
 * chaîne = valeur posée (RFC 7644 §3.5.2, sémantique add/replace/remove).
 */
export interface ScimUserIdentityPatch {
  readonly firstName?: string | null;
  readonly lastName?: string | null;
  readonly displayName?: string | null;
}

/** PATCH utilisateur normalisé : activation + champs d'identité touchés. */
export interface ScimUserPatch {
  /** Nouvelle valeur d'`active`, ou `null` si le PATCH ne la touche pas. */
  readonly active: boolean | null;
  readonly identity: ScimUserIdentityPatch;
}

/** Champs d'un groupe à créer (POST) ou remplacer intégralement (PUT). */
export interface ScimGroupWriteInput {
  readonly displayName: string;
  readonly externalId: string | null;
  readonly memberIds: readonly string[];
}

/** Opération de membre de groupe normalisée depuis un PATCH SCIM (RFC 7644 §3.5.2). */
export type GroupMemberPatch =
  | { readonly kind: 'add'; readonly members: readonly string[] }
  | { readonly kind: 'remove'; readonly members: readonly string[] }
  | { readonly kind: 'replace'; readonly members: readonly string[] };

// ── Options de liste + page ──────────────────────────────────────────────────
/**
 * Options de `listUsers` : filtres `userName eq` / `externalId eq` optionnels (au moins l'un
 * des deux, jamais les deux à la fois) + pagination 1-based. `userName` s'égale de façon
 * INSENSIBLE À LA CASSE ; `externalId` est `caseExact` (comparaison exacte).
 */
export interface ScimUserListOptions {
  readonly userName?: string;
  readonly externalId?: string;
  readonly startIndex: number;
  readonly count: number;
}

/** Options de `listGroups` : filtre `displayName eq` optionnel + pagination 1-based. */
export interface ScimGroupListOptions {
  readonly displayName?: string;
  readonly startIndex: number;
  readonly count: number;
}

/**
 * Page de résultats renvoyée par le store. `totalResults` = total AVANT pagination ;
 * `resources` = tranche demandée ; `itemsPerPage` = taille de la tranche.
 */
export interface ScimListPage<TRow> {
  readonly resources: readonly TRow[];
  readonly totalResults: number;
  readonly startIndex: number;
  readonly itemsPerPage: number;
}

// ── Port de persistance ──────────────────────────────────────────────────────
/**
 * Port de persistance SCIM (Users + Groups). Toute opération est bornée au tenant.
 *
 * Invariants attendus de l'implémentation :
 *  - `findUserByEmail` : réconciliation INSENSIBLE À LA CASSE (idempotence du provisioning).
 *  - `deactivateUser` : DÉSACTIVE (active=false), ne SUPPRIME jamais (déprovisionnement RGPD-safe).
 *  - `listUsers`/`listGroups` : renvoient `totalResults` = total filtré AVANT pagination.
 */
export interface ScimStore {
  getUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null>;
  findUserByEmail(tenantId: TenantId, email: string): Promise<ScimUserRow | null>;
  listUsers(tenantId: TenantId, options: ScimUserListOptions): Promise<ScimListPage<ScimUserRow>>;
  createUser(tenantId: TenantId, input: ScimUserWriteInput): Promise<ScimUserRow>;
  replaceUser(
    tenantId: TenantId,
    id: string,
    input: ScimUserWriteInput,
  ): Promise<ScimUserRow | null>;
  patchUser(tenantId: TenantId, id: string, patch: ScimUserPatch): Promise<ScimUserRow | null>;
  deactivateUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null>;

  getGroup(tenantId: TenantId, id: string): Promise<ScimGroupRow | null>;
  listGroups(
    tenantId: TenantId,
    options: ScimGroupListOptions,
  ): Promise<ScimListPage<ScimGroupRow>>;
  createGroup(tenantId: TenantId, input: ScimGroupWriteInput): Promise<ScimGroupRow>;
  replaceGroup(
    tenantId: TenantId,
    id: string,
    input: ScimGroupWriteInput,
  ): Promise<ScimGroupRow | null>;
  patchGroup(
    tenantId: TenantId,
    id: string,
    ops: readonly GroupMemberPatch[],
  ): Promise<ScimGroupRow | null>;
  deleteGroup(tenantId: TenantId, id: string): Promise<boolean>;
}

// ── Requête / réponse des handlers purs ──────────────────────────────────────
/** Paramètres de requête SCIM déjà extraits par la couche HTTP (adapter). */
export interface ScimQuery {
  readonly filter?: string;
  readonly startIndex?: string | number;
  readonly count?: string | number;
}

/**
 * Requête SCIM parsée, indépendante du transport. `pathId` = segment `/:id` ; `body` =
 * JSON déjà désérialisé (validé par le handler) ; `query` = paramètres de liste.
 */
export interface ScimRequest {
  readonly tenantId: TenantId;
  readonly pathId?: string;
  readonly query?: ScimQuery;
  readonly body?: unknown;
}

/**
 * Réponse SCIM neutre : un statut HTTP + un corps JSON (absent pour 204). L'adapter la
 * sérialise en `application/scim+json`.
 */
export interface ScimResponse {
  readonly status: number;
  readonly body?: Readonly<Record<string, unknown>>;
}

/** Signature commune d'un handler SCIM pur : `(store, requête) → réponse`. */
export type ScimHandler = (store: ScimStore, request: ScimRequest) => Promise<ScimResponse>;
