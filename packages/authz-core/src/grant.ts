/**
 * Grammaire de permission Kengela : chaine pointee `plane.resource.action`, ou
 * `resource` peut compter plusieurs segments (ex. `data.cashier.register.read`).
 * Compatible avec les catalogues Atrium et TransLog.
 *
 * Correspondance (`permissionCovers`) :
 *  - segment `*` non terminal  -> joker sur exactement un segment.
 *  - segment `*` terminal      -> joker de prefixe (couvre tous les segments restants).
 *  - sinon egalite stricte de segment.
 *  - a defaut de joker terminal, les longueurs doivent etre egales.
 *
 * Exemples :
 *  - `data.cashier.*`        couvre `data.cashier.register.read`
 *  - `data.*.read`           couvre `data.orders.read` (pas `data.a.b.read`)
 *  - `data.cashier.read`     couvre uniquement `data.cashier.read`
 */

const SEGMENT = /^[a-z0-9*_-]+$/;

/** Valide une chaine de permission (fail-closed). Leve si un segment est invalide. */
export function assertPermissionSyntax(permission: string): void {
  const segments = permission.split('.');
  if (segments.length < 2) {
    throw new PermissionSyntaxError(`Permission invalide (>= 2 segments) : « ${permission} ».`);
  }
  for (const seg of segments) {
    if (!SEGMENT.test(seg)) {
      throw new PermissionSyntaxError(`Segment invalide : « ${seg} » dans « ${permission} ».`);
    }
  }
}

export class PermissionSyntaxError extends Error {
  public override readonly name = 'PermissionSyntaxError';
}

/** Le motif d'un grant couvre-t-il la permission requise ? */
export function permissionCovers(grantPermission: string, required: string): boolean {
  const grant = grantPermission.split('.');
  const req = required.split('.');
  for (const [i, seg] of grant.entries()) {
    if (seg === '*') {
      if (i === grant.length - 1) return true; // joker terminal = prefixe
      if (i >= req.length) return false; // joker simple sans segment a couvrir
      continue;
    }
    if (req[i] !== seg) return false; // egalite (et gere grant plus long que req)
  }
  return grant.length === req.length;
}
