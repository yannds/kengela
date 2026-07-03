import { SetMetadata } from '@nestjs/common';
import type { CustomDecorator } from '@nestjs/common';

export const KENGELA_PERMISSION = 'kengela:permission';
export const KENGELA_PUBLIC = 'kengela:public';

/** Acces requis par une route : type de ressource + action (permission = type.action). */
export interface RequiredAccess {
  readonly resourceType: string;
  readonly action: string;
}

/**
 * Declare l'acces requis par une route. La permission evaluee est `resourceType.action`.
 * Ex. `@RequirePermission('data.cashier.register', 'read')`.
 */
export function RequirePermission(resourceType: string, action: string): CustomDecorator {
  const access: RequiredAccess = { resourceType, action };
  return SetMetadata(KENGELA_PERMISSION, access);
}

/** Marque une route comme publique (le guard la laisse passer sans decision). */
export function PublicRoute(): CustomDecorator {
  return SetMetadata(KENGELA_PUBLIC, true);
}
