# DEBT.md - @kengela/adapter-authn-better-auth

> Le port est un sas, pas une planque. Dettes tracées, retirées quand résolues.

| #   | Sujet                      | Etat           | Note                                                                                                                                         | Cible                                                               | Prio |
| --- | -------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ---- |
| 1   | ctx (géo/device)           | par conception | better-auth ne fournit pas les signaux de connexion ; le `Principal.ctx` est minimal (authTime).                                             | Enrichissement via un ContextProvider côté app (conditional access) | P2   |
| 2   | mfaLevel                   | scope          | Toujours `none` ; l'état 2FA (plugin better-auth) n'est pas lu depuis la session.                                                            | Lire le facteur depuis la session/plugin twoFactor -> `mfaLevel`    | P3   |
| 3   | Compat surface better-auth | assume         | Interface NARROW `BetterAuthLike` (api.getSession) ; compat avec les types exacts de better-auth non prouvée par un test d'intégration réel. | Test d'intégration contre une vraie instance better-auth            | P3   |
