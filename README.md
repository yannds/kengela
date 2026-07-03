# Kengela

> **kokéngela** (lingala) — veiller, garder, être vigilant. `Kengela!` = sois vigilant.
> Le veilleur : ne fait jamais confiance par défaut, vérifie en continu.

Kengela est un socle **identité & accès** (authentification + autorisation) **Zero Trust**,
pensé pour les applications **multi-tenant**. Il naît de la consolidation de deux bases réelles
(Atrium et TransLog Pro) en une librairie unique, maintenable et évolutive.

## Doctrine (non négociable)

- **Abstraction totale** : le CORE ne connait aucun vendor. Prisma, better-auth, LDAP, Redis,
  Vault, CEL ne sont que des **adapters interchangeables** derriere des **ports**.
- **Le port est un sas, pas une planque** : on enveloppe l'existant pour ne rien casser,
  mais tout ce qui est faible a une **cible de migration** tracee (voir `DEBT.md` par adapter).
- **Zero dette silencieuse** : aucun compromis cache, tout documente.
- **Zero Trust (ZTNA)** : autorisation deny-by-default, evaluee **par requete**, avec contexte
  continu (geo / heure / device / risque), obligations / step-up, et **decision logs**.

## Les 3 anneaux

```
contracts  ── types & ports purs, zero vendor          (@kengela/contracts)
core       ── logique pure : PDP, RBAC, ABAC, mapping   (@kengela/authz-core, ...)
adapters   ── le vendor vit ici, interchangeable        (@kengela/adapter-*)
```

Un lint d'architecture (`pnpm lint:arch`, dependency-cruiser) **casse la build** si un paquet
CORE importe un vendor.

## Paquets

| Paquet | Rôle |
|---|---|
| `@kengela/contracts` | Ports & types — l'invariant du projet, zéro vendor |
| `@kengela/authz-core` | Moteur d'autorisation : RBAC scopé + relation org + ABAC (CEL) + conditional access + step-up ; deny-by-default, **fail-closed**, decision logs |
| `@kengela/iam-mapping` | Normalisation **6 sources IdP** (OIDC/SCIM/SAML/LDAP/Graph/Google) + schéma **SCIM canonique** (superset Okta/Entra) + moteur de règles |
| `@kengela/adapter-expr-cel` | Moteur **CEL** (conditions ABAC + fonctions de dates déterministes) |
| `@kengela/adapter-authn-native` | Credential **timing-safe** (argon2id/bcrypt + `needsRehash`), sessions, **MFA/TOTP** complet, **AES-256-GCM**, field cipher + **crypto-shredding** (RGPD) |
| `@kengela/adapter-authn-better-auth` | `IdentityPort` au-dessus de **better-auth** (OIDC/OAuth/SSO) — better-auth en `peerDependency` |
| `@kengela/adapter-persistence-prisma` | Stockage (`AuthorizationRepository`/`SessionStore`/`PolicyStore`) via une interface Prisma narrow |
| `@kengela/adapter-directory-ldap` | Connecteur **AD/LDAP** (ldapts) → `DirectoryProfile` |
| `@kengela/scim-server` | Serveur **SCIM 2.0** Users+Groups + découverte (`/Schemas`, `/ServiceProviderConfig`, `/ResourceTypes`) + **conformité Entra** + validation de schéma |
| `@kengela/nestjs` | Intégration **NestJS** : guard deny-by-default + décorateurs + step-up |
| `@kengela/pii` | Conformité **RGPD** : classification, minimisation, redaction, rétention, effacement |
| `@kengela/connector-translog` | *(privé)* mapping du schéma TransLog Pro vers les ports Kengela (référence d'intégration) |

## Démarrage rapide

```sh
pnpm install
pnpm -r build && pnpm -r test   # tout vert, TS6 strict, ESLint strictTypeChecked
pnpm lint:arch                  # garde-fou anti-vendor sur le CORE
```

Une application n'installe que les paquets utiles :

```sh
npm add @kengela/authz-core @kengela/nestjs @kengela/adapter-persistence-prisma
# les adapters lourds (SAML, LDAP, better-auth) restent optionnels
```

Voir `PUBLISHING.md` pour publier/consommer, `docs/` pour le RFC et les études.

## Etat

Socle **fonctionnellement complet** (authn + authz + fédération d'identité + SCIM + conformité PII).
Chaque paquet a son `DEBT.md` (dettes ouvertes uniquement). Publication npm à venir (voir `PUBLISHING.md`).

## Licence

**Apache-2.0** (c) 2026 yannds. Voir `LICENSE` et `NOTICE`.
Licence permissive avec clause de brevet ; le detenteur du copyright conserve
la possibilite d'un double-licensing commercial ulterieur.

