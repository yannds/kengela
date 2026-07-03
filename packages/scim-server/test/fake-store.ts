/**
 * Fake `ScimStore` en mémoire pour des tests hermétiques (sans DB). Reproduit les
 * sémantiques du port : réconciliation par e-mail insensible à la casse, désactivation
 * (jamais de suppression), pagination `startIndex`/`count`, opérations de membres.
 */
import type { TenantId } from '@kengela/contracts';
import type {
  GroupMemberPatch,
  ScimGroupListOptions,
  ScimGroupRow,
  ScimGroupWriteInput,
  ScimListPage,
  ScimStore,
  ScimUserListOptions,
  ScimUserPatch,
  ScimUserRow,
  ScimUserWriteInput,
} from '../src/index.js';

interface MutableUser {
  id: string;
  userName: string;
  externalId: string | null;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
  active: boolean;
  createdAt: string;
  lastModified: string;
}

interface MutableGroup {
  id: string;
  displayName: string;
  externalId: string | null;
  memberIds: string[];
  createdAt: string;
  lastModified: string;
}

function toUserRow(user: MutableUser): ScimUserRow {
  return {
    id: user.id,
    userName: user.userName,
    externalId: user.externalId,
    firstName: user.firstName,
    lastName: user.lastName,
    displayName: user.displayName,
    active: user.active,
    createdAt: user.createdAt,
    lastModified: user.lastModified,
  };
}

function toGroupRow(group: MutableGroup): ScimGroupRow {
  return {
    id: group.id,
    displayName: group.displayName,
    externalId: group.externalId,
    memberIds: [...group.memberIds],
    createdAt: group.createdAt,
    lastModified: group.lastModified,
  };
}

function paginate<TRow>(
  rows: readonly TRow[],
  startIndex: number,
  count: number,
): ScimListPage<TRow> {
  const from = Math.max(0, startIndex - 1);
  const slice = rows.slice(from, from + count);
  return {
    resources: slice,
    totalResults: rows.length,
    startIndex,
    itemsPerPage: slice.length,
  };
}

export class FakeScimStore implements ScimStore {
  readonly #users = new Map<TenantId, MutableUser[]>();
  readonly #groups = new Map<TenantId, MutableGroup[]>();
  #seq = 0;
  #tick = 0;

  #nextId(prefix: string): string {
    this.#seq += 1;
    return `${prefix}-${String(this.#seq)}`;
  }

  #now(): string {
    this.#tick += 1;
    return new Date(1_700_000_000_000 + this.#tick * 1000).toISOString();
  }

  #usersOf(tenantId: TenantId): MutableUser[] {
    const existing = this.#users.get(tenantId);
    if (existing !== undefined) {
      return existing;
    }
    const created: MutableUser[] = [];
    this.#users.set(tenantId, created);
    return created;
  }

  #groupsOf(tenantId: TenantId): MutableGroup[] {
    const existing = this.#groups.get(tenantId);
    if (existing !== undefined) {
      return existing;
    }
    const created: MutableGroup[] = [];
    this.#groups.set(tenantId, created);
    return created;
  }

  public getUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null> {
    const user = this.#usersOf(tenantId).find((u) => u.id === id);
    return Promise.resolve(user === undefined ? null : toUserRow(user));
  }

  public findUserByEmail(tenantId: TenantId, email: string): Promise<ScimUserRow | null> {
    const needle = email.toLowerCase();
    const user = this.#usersOf(tenantId).find((u) => u.userName.toLowerCase() === needle);
    return Promise.resolve(user === undefined ? null : toUserRow(user));
  }

  public listUsers(
    tenantId: TenantId,
    options: ScimUserListOptions,
  ): Promise<ScimListPage<ScimUserRow>> {
    let rows = this.#usersOf(tenantId);
    if (options.userName !== undefined) {
      const needle = options.userName.toLowerCase();
      rows = rows.filter((u) => u.userName.toLowerCase() === needle);
    }
    if (options.externalId !== undefined) {
      const needle = options.externalId;
      rows = rows.filter((u) => u.externalId === needle);
    }
    const mapped = rows.map((u) => toUserRow(u));
    return Promise.resolve(paginate(mapped, options.startIndex, options.count));
  }

  public createUser(tenantId: TenantId, input: ScimUserWriteInput): Promise<ScimUserRow> {
    const stamp = this.#now();
    const user: MutableUser = {
      id: this.#nextId('usr'),
      userName: input.userName,
      externalId: input.externalId,
      firstName: input.firstName,
      lastName: input.lastName,
      displayName: input.displayName,
      active: input.active,
      createdAt: stamp,
      lastModified: stamp,
    };
    this.#usersOf(tenantId).push(user);
    return Promise.resolve(toUserRow(user));
  }

  public replaceUser(
    tenantId: TenantId,
    id: string,
    input: ScimUserWriteInput,
  ): Promise<ScimUserRow | null> {
    const user = this.#usersOf(tenantId).find((u) => u.id === id);
    if (user === undefined) {
      return Promise.resolve(null);
    }
    user.userName = input.userName;
    user.externalId = input.externalId;
    user.firstName = input.firstName;
    user.lastName = input.lastName;
    user.displayName = input.displayName;
    user.active = input.active;
    user.lastModified = this.#now();
    return Promise.resolve(toUserRow(user));
  }

  public patchUser(
    tenantId: TenantId,
    id: string,
    patch: ScimUserPatch,
  ): Promise<ScimUserRow | null> {
    const user = this.#usersOf(tenantId).find((u) => u.id === id);
    if (user === undefined) {
      return Promise.resolve(null);
    }
    if (patch.active !== null) {
      user.active = patch.active;
    }
    if (patch.identity.firstName !== undefined) {
      user.firstName = patch.identity.firstName;
    }
    if (patch.identity.lastName !== undefined) {
      user.lastName = patch.identity.lastName;
    }
    if (patch.identity.displayName !== undefined) {
      user.displayName = patch.identity.displayName;
    }
    user.lastModified = this.#now();
    return Promise.resolve(toUserRow(user));
  }

  public deactivateUser(tenantId: TenantId, id: string): Promise<ScimUserRow | null> {
    const user = this.#usersOf(tenantId).find((u) => u.id === id);
    if (user === undefined) {
      return Promise.resolve(null);
    }
    user.active = false;
    user.lastModified = this.#now();
    return Promise.resolve(toUserRow(user));
  }

  public getGroup(tenantId: TenantId, id: string): Promise<ScimGroupRow | null> {
    const group = this.#groupsOf(tenantId).find((g) => g.id === id);
    return Promise.resolve(group === undefined ? null : toGroupRow(group));
  }

  public listGroups(
    tenantId: TenantId,
    options: ScimGroupListOptions,
  ): Promise<ScimListPage<ScimGroupRow>> {
    let rows = this.#groupsOf(tenantId);
    if (options.displayName !== undefined) {
      rows = rows.filter((g) => g.displayName === options.displayName);
    }
    const mapped = rows.map((g) => toGroupRow(g));
    return Promise.resolve(paginate(mapped, options.startIndex, options.count));
  }

  public createGroup(tenantId: TenantId, input: ScimGroupWriteInput): Promise<ScimGroupRow> {
    const stamp = this.#now();
    const group: MutableGroup = {
      id: this.#nextId('grp'),
      displayName: input.displayName,
      externalId: input.externalId,
      memberIds: [...new Set(input.memberIds)],
      createdAt: stamp,
      lastModified: stamp,
    };
    this.#groupsOf(tenantId).push(group);
    return Promise.resolve(toGroupRow(group));
  }

  public replaceGroup(
    tenantId: TenantId,
    id: string,
    input: ScimGroupWriteInput,
  ): Promise<ScimGroupRow | null> {
    const group = this.#groupsOf(tenantId).find((g) => g.id === id);
    if (group === undefined) {
      return Promise.resolve(null);
    }
    group.displayName = input.displayName;
    group.externalId = input.externalId;
    group.memberIds = [...new Set(input.memberIds)];
    group.lastModified = this.#now();
    return Promise.resolve(toGroupRow(group));
  }

  public patchGroup(
    tenantId: TenantId,
    id: string,
    ops: readonly GroupMemberPatch[],
  ): Promise<ScimGroupRow | null> {
    const group = this.#groupsOf(tenantId).find((g) => g.id === id);
    if (group === undefined) {
      return Promise.resolve(null);
    }
    for (const op of ops) {
      if (op.kind === 'add') {
        group.memberIds = [...new Set([...group.memberIds, ...op.members])];
      } else if (op.kind === 'remove') {
        const removed = new Set(op.members);
        group.memberIds = group.memberIds.filter((m) => !removed.has(m));
      } else {
        group.memberIds = [...new Set(op.members)];
      }
    }
    group.lastModified = this.#now();
    return Promise.resolve(toGroupRow(group));
  }

  public deleteGroup(tenantId: TenantId, id: string): Promise<boolean> {
    const rows = this.#groupsOf(tenantId);
    const index = rows.findIndex((g) => g.id === id);
    if (index < 0) {
      return Promise.resolve(false);
    }
    rows.splice(index, 1);
    return Promise.resolve(true);
  }
}
