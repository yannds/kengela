# DEBT.md - @kengela/adapter-authn-better-auth

> The port is an airlock, not a hideout. Debts are tracked, removed when resolved.

| #   | Topic                      | State     | Note                                                                                                                               | Target                                                                | Prio |
| --- | -------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---- |
| 1   | ctx (geo/device)           | by design | better-auth does not provide the login signals; the `Principal.ctx` is minimal (authTime).                                         | Enrichment via a ContextProvider on the app side (conditional access) | P2   |
| 2   | mfaLevel                   | scope     | Always `none`; the 2FA state (better-auth plugin) is not read from the session.                                                    | Read the factor from the session/twoFactor plugin -> `mfaLevel`       | P3   |
| 3   | better-auth surface compat | assumed   | NARROW interface `BetterAuthLike` (api.getSession); compat with the exact better-auth types not proven by a real integration test. | Integration test against a real better-auth instance                  | P3   |
