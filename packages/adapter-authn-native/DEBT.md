# DEBT.md — @kengela/adapter-authn-native

> Le port est un sas, pas une planque. Dettes tracées, retirées quand résolues.

| # | Sujet | Etat | Note | Cible | Prio |
|---|-------|------|------|-------|------|
| 2 | Rotation de clé maître AES-GCM | assume | Pas de versioning `enc:vN` ni de rotation/rollover. | En-tête de version + re-chiffrement au rollover | P3 |
