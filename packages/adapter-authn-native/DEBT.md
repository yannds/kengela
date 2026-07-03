# DEBT.md — @kengela/adapter-authn-native

> Le port est un sas, pas une planque. Dettes tracées, retirées quand résolues.

| # | Sujet | Etat | Note | Cible | Prio |
|---|-------|------|------|-------|------|
| 1 | MfaService (cycle challenge/enroll) | scope | Ce paquet fournit `TotpVerifier` + le chiffrement du secret ; le cycle challengeId/enroll (persistance) reste à composer avec un store. | `MfaService` complet + `MfaSecretStore`/`MfaChallengeStore` | P3 |
| 2 | Rotation de clé maître AES-GCM | assume | Pas de versioning `enc:vN` ni de rotation/rollover. | En-tête de version + re-chiffrement au rollover | P3 |
