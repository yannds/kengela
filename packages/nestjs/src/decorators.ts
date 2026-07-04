import { SetMetadata } from '@nestjs/common';
import type { CustomDecorator } from '@nestjs/common';

export const KENGELA_PERMISSION = 'kengela:permission';
export const KENGELA_PUBLIC = 'kengela:public';

/** Access required by a route: resource type + action (permission = type.action). */
export interface RequiredAccess {
  readonly resourceType: string;
  readonly action: string;
}

/**
 * Declares the access required by a route. The evaluated permission is `resourceType.action`.
 * E.g. `@RequirePermission('data.cashier.register', 'read')`.
 */
export function RequirePermission(resourceType: string, action: string): CustomDecorator {
  const access: RequiredAccess = { resourceType, action };
  return SetMetadata(KENGELA_PERMISSION, access);
}

/** Marks a route as public (the guard lets it through without a decision). */
export function PublicRoute(): CustomDecorator {
  return SetMetadata(KENGELA_PUBLIC, true);
}
