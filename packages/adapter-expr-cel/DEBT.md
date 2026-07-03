# DEBT.md — @kengela/adapter-expr-cel

> Le port est un sas, pas une planque. Ce qui est enveloppe et faible figure ici.

| # | Ce qui est enveloppe | Etat | Probleme | Cible de migration | Prio |
|---|----------------------|------|----------|--------------------|------|
| 1 | @marcbachmann/cel-js | enveloppe | Pas de fonctions de dates custom (business-hours) en v1 | Ajouter un Environment + registerFunction (now/daysUntil/businessDaysBetween) injecte via Clock, comme Atrium | P3 |
| 2 | evaluateBoolean | enveloppe | Une erreur d'evaluation (variable absente, non-booleen) est LEVEE, pas fail-closed | Wrapper PDP qui catch -> DENY (fail-closed Zero Trust) | P2 |
