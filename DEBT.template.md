# DEBT.md — registre de dette (gabarit)

> A copier dans chaque ADAPTER. Le port est un sas, pas une planque :
> ce qu'on enveloppe et qui est faible DOIT figurer ici avec sa cible.

| #   | Ce qui est enveloppe        | Etat      | Probleme             | Cible de migration  | Prio |
| --- | --------------------------- | --------- | -------------------- | ------------------- | ---- |
| 1   | _ex: OAuth maison TransLog_ | enveloppe | id_token non verifie | OIDC verifie + PKCE | P2   |

Legende Etat : `enveloppe` (parite, non migre) · `en cours` · `migre` · `retire`.
