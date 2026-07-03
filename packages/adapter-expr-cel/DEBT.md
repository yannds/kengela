# DEBT.md — @kengela/adapter-expr-cel

> Le port est un sas, pas une planque. Ce qui est enveloppe et faible figure ici.

| # | Ce qui est enveloppe | Etat | Probleme | Cible de migration | Prio |
|---|----------------------|------|----------|--------------------|------|
| 1 | @marcbachmann/cel-js | enveloppe | Pas de fonctions de dates custom (business-hours) en v1 | Ajouter un Environment + registerFunction (now/daysUntil/businessDaysBetween) injecte via Clock, comme Atrium | P3 |

> Dette #2 (fail-closed sur erreur d'evaluation) RESOLUE le 2026-07-03 : le
> LayeredDecisionPoint (authz-core) catch toute erreur d'evaluation et REFUSE la
> requete (reason `condition_error`). Retiree de la liste.
