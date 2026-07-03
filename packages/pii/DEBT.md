# DEBT.md — @kengela/pii

> Le port est un sas, pas une planque. Dettes tracées, retirées quand résolues.

| # | Sujet | Etat | Note | Cible | Prio |
|---|-------|------|------|-------|------|
| 2 | Redaction des attributs | scope | v1 masque l'identité (email/nom) ; les attributs PII (téléphone, adresse) ne sont pas encore masqués par `redactProfile`. | Étendre la redaction aux attributs classés `pii` | P3 |
| 3 | Classification par chemin SCIM | scope | Registre indexé sur les champs normalisés ; les chemins SCIM bruts (name.givenName, emails...) ne sont pas classés séparément. | Table de correspondance chemin SCIM -> sensibilité | P3 |
