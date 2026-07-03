# Guide Kengela

> **kokéngela** _(lingala)_ - veiller, garder, être vigilant.
> Kengela est un socle **identité & accès Zero Trust** pour applications **multi-tenant** en
> TypeScript : **authentification + autorisation + fédération d'identité + conformité**, composé de
> ports purs (`@kengela/contracts`), d'un cœur sans vendor et d'adapters interchangeables.

Ce guide couvre l'installation, l'utilisation et le développement du monorepo. **Tous les extraits
de code s'appuient sur les signatures réelles** des paquets `@kengela/*`, vérifiées dans le code
source. Chaque page est autonome (elle sert aussi de page de wiki GitHub).

## Table des matières

| #   | Page                                                         | Sujet                                                                                                                                 |
| --- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| 0   | [00-getting-started.md](./00-getting-started.md)             | Installer (dual ESM+CJS), composer un premier PDP, exécuter un `check()` de bout en bout : allow, deny, step-up.                      |
| 1   | [01-architecture.md](./01-architecture.md)                   | Les 3 anneaux, la doctrine « le port est un sas », le lint anti-vendor, le flux de décision Zero Trust, le pont `Principal`.          |
| 2   | [02-authorization.md](./02-authorization.md)                 | Grammaire des permissions, grants & relations, policies déclaratives (CEL), conditional access, obligations & step-up, decision logs. |
| 3   | [03-authentication.md](./03-authentication.md)               | Credential timing-safe (argon2id / bcrypt + `needsRehash`), sessions, MFA/TOTP complet, better-auth, crypto-shredding.                |
| 4   | [04-identity-federation.md](./04-identity-federation.md)     | `iam-mapping` (6 sources → `DirectoryProfile`), schéma SCIM Kengela, `scim-server` (découverte + validation + Entra), LDAP.           |
| 5   | [05-nestjs-integration.md](./05-nestjs-integration.md)       | `KengelaAuthzGuard`, décorateurs, jeton `KENGELA_PDP`, `StepUpRequiredException`, module d'exemple.                                   |
| 6   | [06-compliance-pii.md](./06-compliance-pii.md)               | Classification, minimisation, redaction, rétention, effacement (crypto-shredding), `PiiAccessLogSink`.                                |
| 7   | [07-developing-an-adapter.md](./07-developing-an-adapter.md) | Ajouter un adapter : implémenter un port, interface vendor NARROW, fake de test, `DEBT.md`, conventions strictes, dual build.         |
| 8   | [08-security.md](./08-security.md)                           | Posture Zero Trust, résumé de l'audit red/blue, et comment relancer l'audit adverse.                                                  |

## Les 12 paquets en un coup d'œil

| Paquet                                | Anneau      | Rôle                                                                                                     |
| ------------------------------------- | ----------- | -------------------------------------------------------------------------------------------------------- |
| `@kengela/contracts`                  | contracts   | Ports & types purs - l'invariant du projet, zéro vendor, zéro implémentation.                            |
| `@kengela/authz-core`                 | core        | Moteur d'autorisation : RBAC scopé + relation org + ABAC (CEL) + step-up ; deny-by-default, fail-closed. |
| `@kengela/iam-mapping`                | core        | Normalisation 6 sources IdP → `DirectoryProfile` + schéma SCIM canonique + moteur de règles.             |
| `@kengela/pii`                        | core        | Conformité RGPD : classification, minimisation, redaction, rétention.                                    |
| `@kengela/adapter-expr-cel`           | adapter     | Moteur CEL (conditions ABAC + fonctions de dates déterministes).                                         |
| `@kengela/adapter-authn-native`       | adapter     | Credential timing-safe, sessions, MFA/TOTP, AES-256-GCM, field cipher + crypto-shredding.                |
| `@kengela/adapter-authn-better-auth`  | adapter     | `IdentityPort` au-dessus de better-auth (peer dependency).                                               |
| `@kengela/adapter-persistence-prisma` | adapter     | `AuthorizationRepository` / `SessionStore` / `PolicyStore` / stores MFA via une interface Prisma narrow. |
| `@kengela/adapter-directory-ldap`     | adapter     | Connecteur AD / LDAP (ldapts) → `DirectoryProfile`.                                                      |
| `@kengela/scim-server`                | adapter     | Cœur SCIM 2.0 Users + Groups + découverte + conformité Entra + validation.                               |
| `@kengela/nestjs`                     | intégration | Guard deny-by-default + décorateurs + step-up.                                                           |
| `@kengela/connector-translog`         | connecteur  | Mapping du schéma TransLog Pro vers les ports Kengela (référence d'intégration).                         |

## Principes directeurs (à garder en tête)

1. **Zero Trust** : aucune confiance par défaut. Le point de décision (PDP) est **deny-by-default**,
   évalué **par requête**, avec rechargement des droits (anti-staleness).
2. **Fail-closed** : la moindre incertitude (condition inévaluable, session expirée, tenant non
   résoluble) se résout en **refus**, jamais en accès.
3. **Isolation multi-tenant au cœur** : la frontière tenant est vérifiée dans le PDP lui-même, pas
   déléguée aveuglément à l'app.
4. **Le port est un sas, pas une planque** : le cœur ne connaît aucun vendor ; chaque adapter
   enveloppe une techno derrière une interface NARROW, et trace sa dette dans `DEBT.md`.
5. **Composition à la carte** : une application n'installe que les paquets qu'elle utilise.

## Vérifier l'ensemble

```sh
pnpm install
pnpm -r build && pnpm -r test   # TS6 strict, ESLint strictTypeChecked, tout vert
pnpm lint:arch                  # garde-fou anti-vendor sur le cœur (dependency-cruiser)
```

Voir aussi [`PUBLISHING.md`](../../PUBLISHING.md) (publication & consommation npm) et
[`docs/SECURITY-AUDIT-REPORT.md`](../SECURITY-AUDIT-REPORT.md) (audit sécurité).
</content>
</invoke>
