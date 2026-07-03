# @kengela/connector-translog

Connecteur **TransLog Pro** pour le socle Kengela. Il implemente les ports
`@kengela/contracts` (`CredentialStore`, `AuthorizationRepository`, `SessionStore`,
`PolicyStore`) contre le schema Prisma **reel** de TransLog Pro.

Paquet **prive** (`"private": true`, non publie). Il vit en **reference** dans le
monorepo Kengela : il prouve que les ports s'implementent sur le schema TransLog
existant. Une fois `@kengela/*` publie sur le registre, ce connecteur est destine a
etre **depose dans TransLog** (ou il remplacera l'authn/authz maison), en pointant
`@kengela/contracts` vers la version publiee.

## Surface NARROW

Le connecteur ne depend PAS de `@prisma/client`. Il decrit une surface NARROW,
`TranslogPrismaLike`, avec des types de lignes explicites (`UserRow`, `AccountRow`,
`SessionRow`, `RolePermissionRow`). Un vrai `PrismaClient` genere depuis le schema
TransLog est structurellement compatible : il se passe la ou `TranslogPrismaLike`
est attendu.

## Mapping (resume)

| Port Kengela                                | Source TransLog                                                    | Regle                                                                                                                                                                                                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CredentialStore.findByEmail`               | `Account` (providerId='credential', accountId=email) ⋈ `User`      | `passwordHash <- Account.password`, `isActive <- User.isActive && deletedAt==null`, `mfaEnabled <- User.mfaEnabled`, `roles <- User.roleId ? [roleId] : []`. `null` si absent.                                                                                |
| `CredentialStore.findByEmailAcrossTenants`  | tous les `Account` credential (tous tenants), Users charges en lot | idem, un enregistrement par compte.                                                                                                                                                                                                                           |
| `AuthorizationRepository.loadGrantsForUser` | `User.roleId` -> `RolePermission[]`                                | chaque `permission` `plane.module.action.SCOPE` : dernier segment = portee, reste = permission Kengela. `own->own`, `agency->unit`, `tenant->tenant`, `global->global`, jeton inconnu -> **fail-closed** (grant ignore). `source: 'MANUAL'`, sans expiration. |
| `AuthorizationRepository.loadRole`          | `RolePermission` (roleId=roleKey)                                  | meme split ; `null` si aucune permission.                                                                                                                                                                                                                     |
| `SessionStore`                              | `Session` (`token`, `ipAddress`, `userAgent`, ...)                 | token opaque `randomBytes(32).hex` ; `expiresAt = now + ttlMs` (Clock injectable) ; `ipAddress <- ctx.ip`, `userAgent <- ctx.device.userAgent`. Reconstitution du `ctx` **LOSSY** (voir DEBT.md).                                                             |
| `PolicyStore.loadPolicies`                  | —                                                                  | `[]` (TransLog n'a pas de table policy ; RBAC seul).                                                                                                                                                                                                          |

## Fail-closed

Toute portee inconnue ou permission malformee fait TOMBER le grant concerne :
jamais d'elargissement fantome. Un compte credential orphelin (User introuvable)
est ecarte.

## Dette

Voir [`DEBT.md`](./DEBT.md) : contexte de session lossy, mono-role, policies vides,
absence de tests d'integration DB live.

## Licence

Apache-2.0.
