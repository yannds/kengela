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

## Etat

Phase **fondations**. Premier paquet : `@kengela/contracts` (les ports, l'invariant du projet).
Voir `docs/` pour le RFC, l'etude detaillee et le plan d'action.

## Structure

```
packages/
  contracts/     @kengela/contracts   — ports & types (fait)
  authz-core/    — PDP + RBAC + relation + ABAC        (a venir)
  authn-core/    — orchestration sessions/MFA          (a venir)
  iam-mapping/   — normalisation 6 sources IdP          (a venir, depuis Atrium)
  adapter-*/     — better-auth, native, prisma, cel, ldap, ...
```

## Licence

**Apache-2.0** (c) 2026 yannds. Voir `LICENSE` et `NOTICE`.
Licence permissive avec clause de brevet ; le detenteur du copyright conserve
la possibilite d'un double-licensing commercial ulterieur.

