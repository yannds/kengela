/**
 * Kengela permission grammar: dotted string `plane.resource.action`, where
 * `resource` may span several segments (e.g. `data.cashier.register.read`).
 * Compatible with the Atrium and TransLog catalogs.
 *
 * Matching (`permissionCovers`):
 *  - non-terminal `*` segment  -> wildcard over exactly one segment.
 *  - terminal `*` segment      -> prefix wildcard (covers all remaining segments).
 *  - otherwise strict segment equality.
 *  - without a terminal wildcard, lengths must be equal.
 *
 * Examples:
 *  - `data.cashier.*`        covers `data.cashier.register.read`
 *  - `data.*.read`           covers `data.orders.read` (not `data.a.b.read`)
 *  - `data.cashier.read`     covers only `data.cashier.read`
 */

const SEGMENT = /^[a-z0-9*_-]+$/;

/** Validates a permission string (fail-closed). Throws if a segment is invalid. */
export function assertPermissionSyntax(permission: string): void {
  const segments = permission.split('.');
  if (segments.length < 2) {
    throw new PermissionSyntaxError(`Invalid permission (>= 2 segments): "${permission}".`);
  }
  for (const seg of segments) {
    if (!SEGMENT.test(seg)) {
      throw new PermissionSyntaxError(`Invalid segment: "${seg}" in "${permission}".`);
    }
  }
}

export class PermissionSyntaxError extends Error {
  public override readonly name = 'PermissionSyntaxError';
}

/** Does a grant pattern cover the required permission? */
export function permissionCovers(grantPermission: string, required: string): boolean {
  const grant = grantPermission.split('.');
  const req = required.split('.');
  for (const [i, seg] of grant.entries()) {
    if (seg === '*') {
      if (i === grant.length - 1) return true; // terminal wildcard = prefix
      if (i >= req.length) return false; // single wildcard with no segment to cover
      continue;
    }
    if (req[i] !== seg) return false; // equality (and handles grant longer than req)
  }
  return grant.length === req.length;
}
