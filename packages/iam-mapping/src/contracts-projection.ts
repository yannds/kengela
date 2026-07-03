/**
 * Projection `DirectoryProfile` RICHE (iam-mapping) → `DirectoryProfile` MINIMAL (contracts).
 *
 * DEUX types portent le même nom `DirectoryProfile` :
 *  - celui d'`iam-mapping` (ce paquet) est RICHE : identité éclatée (firstName/lastName/
 *    displayName), `attributes` typés (DirectoryAttributes), `claims` bruts. C'est la cible
 *    de normalisation des 6 sources IdP.
 *  - celui de `@kengela/contracts` (`ProfileForContracts` ci-dessous) est MINIMAL et STABLE :
 *    `externalId` (non-null), `email?`, `displayName?`, `groups`, `attributes` (record libre),
 *    `active`, `source`. C'est la forme que le port `ScimRepository` consomme.
 *
 * `toContractsProfile` est la fonction de projection PURE entre les deux. Deux champs du profil
 * contracts n'existent PAS dans le profil riche et doivent être fournis par l'appelant :
 *  - `active` : le profil riche ne porte pas l'état d'activation (il vient d'`accountActiveFrom*`
 *    ou de la sémantique du provisioning) ;
 *  - `source` : la source d'annuaire (`oidc`/`scim`/`saml`/`ldap`/`graph`/`google`), connue de
 *    l'adapter qui a produit le profil.
 *
 * PONT `ScimStore` (scim-server) ↔ `ScimRepository` (contracts)
 * -----------------------------------------------------------------
 * `ScimStore` (paquet `@kengela/scim-server`) est un port de persistance SCIM RICHE et orienté
 * CRUD (getUser/createUser/replaceUser/patchUser/listUsers + Groups), avec ses propres lignes
 * (`ScimUserRow`…). `ScimRepository` (contracts) est un port de fédération MINIMAL et orienté
 * réconciliation (`upsertUserByEmail(tenantId, DirectoryProfile) → {id, created}` +
 * `deactivateUser(tenantId, id)`). Les deux ne sont donc PAS interchangeables : le second est
 * une VUE de synchronisation par-dessus le premier.
 *
 * Un adaptateur `ScimStore → ScimRepository` n'est pas fourni ici À DESSEIN, pour trois raisons
 * de conception :
 *  1. Emplacement : il devrait dépendre à la fois de `@kengela/scim-server` (lignes SCIM) et de
 *     `@kengela/contracts`. `iam-mapping` est un paquet CŒUR (aucun vendor, et `scim-server`
 *     dépend DÉJÀ d'`iam-mapping` — l'inverse créerait un cycle). Sa place naturelle est donc un
 *     adapter/app de composition, pas ce cœur.
 *  2. Impédance : le `DirectoryProfile` contracts a `email` OPTIONNEL, alors que SCIM impose un
 *     `userName` (clé de réconciliation) ; et il n'a pas de `firstName`/`lastName` de premier plan
 *     (portés dans `attributes`). La conversion vers `ScimUserWriteInput` suppose donc des
 *     décisions applicatives (repli d'e-mail, extraction des noms depuis `attributes`).
 *  3. Le vrai point dur — projeter n'importe quelle source IdP vers une forme commune — est
 *     précisément ce que résout `toContractsProfile`. Une fois le profil contracts obtenu,
 *     `ScimRepository.upsertUserByEmail(tenantId, profile)` est un appel direct côté app.
 *
 * Esquisse de l'adaptateur (à écrire côté app, cf. guide) :
 *   const profile = toContractsProfile(profileFromScim(body), { source: 'scim', active });
 *   await scimRepository.upsertUserByEmail(tenantId, profile);
 */
import type { DirectoryProfile as ContractsDirectoryProfile } from '@kengela/contracts';
import type { DirectoryProfile } from './profile.js';

/** Métadonnées non portées par le profil riche, exigées par le profil contracts. */
export interface ContractsProfileMeta {
  readonly source: ContractsDirectoryProfile['source'];
  readonly active: boolean;
}

/** Chaîne non vide, ou `undefined` (respecte exactOptionalPropertyTypes). */
function nonEmpty(value: string | null | undefined): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * Projette un `DirectoryProfile` riche vers la forme MINIMALE de `@kengela/contracts`.
 *
 * - `externalId` (requis, non-null côté contracts) : `rich.externalId`, à défaut l'e-mail
 *   (repli stable) ; jamais vide grâce à ce repli (une source sans ni l'un ni l'autre est déjà
 *   pathologique et donnera une chaîne vide, à charge de l'appelant de rejeter).
 * - `email` / `displayName` : omis (et non `undefined`) s'ils sont absents.
 * - `attributes` : les attributs d'annuaire (department/title…) plus `firstName`/`lastName`
 *   reversés (le profil contracts n'a pas de champ nom dédié) afin de ne rien perdre.
 *   Les `claims` bruts ne sont PAS reportés (volume + PII potentielle).
 */
export function toContractsProfile(
  rich: DirectoryProfile,
  meta: ContractsProfileMeta,
): ContractsDirectoryProfile {
  const email = nonEmpty(rich.email);
  const displayName = nonEmpty(rich.displayName);
  const firstName = nonEmpty(rich.firstName);
  const lastName = nonEmpty(rich.lastName);

  const attributes: Record<string, unknown> = { ...rich.attributes };
  if (firstName !== undefined) {
    attributes['firstName'] = firstName;
  }
  if (lastName !== undefined) {
    attributes['lastName'] = lastName;
  }

  return {
    externalId: nonEmpty(rich.externalId) ?? rich.email,
    ...(email !== undefined ? { email } : {}),
    ...(displayName !== undefined ? { displayName } : {}),
    groups: [...rich.groups],
    attributes,
    active: meta.active,
    source: meta.source,
  };
}
