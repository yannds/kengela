# 08 - Sécurité

Kengela est un socle de sécurité : sa propre posture doit être **prouvée**, pas affirmée. Cette page
résume la doctrine Zero Trust, les contrôles vérifiés par l'audit adverse red/blue, et explique
comment relancer cet audit.

## Posture Zero Trust (les invariants)

| Invariant | Où il est appliqué |
|-----------|--------------------|
| **Deny-by-default** | PDP (`RbacDecisionPoint` / `LayeredDecisionPoint`), guard NestJS (route non annotée = 403) |
| **Fail-closed** | condition CEL inévaluable → deny ; session expirée → `null` ; tenant non résoluble → refus ; narrowing d'union illisible → écarté |
| **Isolation multi-tenant au cœur** | `tenantScopedRelation()` : cross-tenant → relation `none` ; seul un grant `global` franchit |
| **Anti-staleness** | grants rechargés à chaque check (un droit révoqué cesse d'agir immédiatement) |
| **Timing-safe** | `verify` toujours effectué (hash leurre), pas de court-circuit cross-tenant (anti-énumération) |
| **Crypto authentifié** | AES-256-GCM, clé par tenant (HKDF) et par sujet ; toute altération → rejet |
| **Anti-ReDoS** | `matches` interdit dans CEL ; regex bornées dans `iam-mapping` ; filtres SCIM bornés |
| **Observabilité** | `DecisionLogSink` (autorisation), `AuditSink` (métier/sécurité), `PiiAccessLogSink` (RGPD art. 30) |

## Résumé de l'audit (red team / blue team)

Le rapport complet est dans [`docs/SECURITY-AUDIT-REPORT.md`](../SECURITY-AUDIT-REPORT.md). L'audit a
attaqué les 12 paquets de façon adverse (fakes en mémoire, aucun réseau/DB réel), puis prouvé les
contrôles et cartographié la conformité.

### Bilan

| Sévérité | Trouvées | Corrigées | Documentées (dette) |
|----------|----------|-----------|---------------------|
| Critical | 0 | 0 | 0 |
| High | 4 | 4 | 0 |
| Medium | 1 | 0 | 1 |
| Low | 1 | 0 | 1 |

**83 cas de test adverses** (`security-*.test.ts`), tous verts. Aucune API de port publique modifiée.

### Les 4 High corrigées

1. **Isolation multi-tenant défendue au cœur.** Le PDP déléguait toute l'isolation au
   `RelationResolver` de l'app. Correctif : `tenantScopedRelation()` ramène la relation à `none` en
   cross-tenant (fail-closed), câblé dans `pdp.ts` et `policy-pdp.ts`, avec un signal `crossTenant`
   au decision log.
2. **Guard NestJS fail-open.** Un `@PublicRoute` de **classe** neutralisait un `@RequirePermission`
   de **handler**. Correctif : précédence explicite handler > classe (voir
   [05-nestjs-integration.md](./05-nestjs-integration.md)).
3. **ReDoS via CEL `matches`.** cel-js compilait une `RegExp` non bornée (DoS du PDP). Correctif :
   `matches` **interdit à la compilation** (fail-closed) ; les conditions s'écrivent via `==`, `in`,
   `startsWith`, `contains`.
4. **Sessions expirées servies.** `get()` restituait une ligne expirée non encore purgée. Correctif :
   `get()` renvoie `null` dès `expiresAt <= now`, indépendamment du cron (Prisma + connector-translog).

### Les 2 dettes documentées

- **MEDIUM-1** — anti-rejeu du **code** TOTP (NIST 800-63B §5.1.4.2) : le défi est one-shot, mais un
  code déjà consommé pourrait être rejoué via un nouveau `challengeId` dans la fenêtre (~30 s). Cible :
  cache anti-rejeu (`adapter-authn-native/DEBT.md` #3).
- **LOW-1** — helper `escapeLdapFilterValue()` absent : l'adapter n'introduit aucune injection (filtre
  verbatim), mais n'outille pas l'appelant qui composerait un filtre depuis une entrée utilisateur
  (`adapter-directory-ldap/DEBT.md` #5).

## Contrôles prouvés (extrait blue team)

| Scénario attaqué | Contrôle prouvé |
|------------------|-----------------|
| Escalade par portée | `subtree` ne couvre pas `tenant` ; grant expiré inopérant ; seul `global` franchit un tenant |
| Fail-open / deny-wins | relation `none` sans grant global = deny ; `deny` explicite gagne ; condition qui lève = deny |
| Sandbox CEL | accès `process`/`globalThis`/`__proto__` → throw ; non-booléen → throw ; variable absente → throw |
| Énumération par timing | compare leurre toujours effectué (email inconnu, compte inactif) ; cross-tenant sans court-circuit |
| AES-256-GCM | iv/tag/ciphertext altéré → rejet ; tronqué → rejet ; mauvaise clé tenant → rejet ; nonce unique |
| Crypto-shredding | après `eraseSubject`, PII illisible ; clé d'un autre sujet ne déchiffre pas |
| Rejeu MFA | `challengeId` one-shot ; verify sans secret = false ; challengeId forgé = false |
| SCIM | filtres bornés ; injection non interprétée ; unicité 409 ; delete = désactivation ; 404 cross-tenant |
| Mapping IdP | safe-regex anti-ReDoS ; règle vide ne matche jamais ; SAML sans groupe ne fabrique aucun rôle |
| better-auth | session absente → null ; tenant non résoluble → null ; roles/mfa jamais hérités du payload |
| LDAP | filtre verbatim ; `unbind` garanti même en erreur ; plafond `max` appliqué ; secret non journalisé |
| Sessions | rotation invalide l'ancien token ; `revokeAllForUser` effectif ; token 256 bits sans collision |
| Guard NestJS | deny-by-default (403) ; principal absent = 401 ; précédence handler > classe |

## Cartographie de conformité

| Cadre | Couverture |
|-------|------------|
| **OWASP ASVS v4** | V2 authn (argon2id, anti-énumération), V3 session (expiration fail-closed, rotation, 256 bits), V4 access control (deny-by-default, `tenantScopedRelation`, deny-wins), V6 crypto (AES-256-GCM par tenant/sujet), V7 logging (decision log), V9 data protection (`pii`, `FieldCipherPort`) |
| **NIST SP 800-63B** | hashing argon2id memory-hard + `needsRehash` ; verifier temps constant ; MFA TOTP (RFC 6238) secret chiffré + défi one-shot ; anti-rejeu OTP = dette #3 |
| **RGPD** | minimisation, effacement art. 17 (crypto-shredding), journal d'accès art. 30, rétention, chiffrement at-rest, isolation cryptographique inter-tenant |
| **SCIM** | RFC 7643/7644 + validateur Microsoft Entra (schéma, filtre `eq` borné, PATCH, unicité 409, déprovisionnement = désactivation, isolation tenant) |

## Relancer l'audit adverse

Le prompt d'audit reproductible est dans
[`docs/SECURITY-AUDIT-PROMPT.md`](../SECURITY-AUDIT-PROMPT.md). Il confie à un agent (ou un pentester)
un accès lecture + écriture de **tests** au dépôt, avec pour mission de **casser** la lib (RED) puis
de **prouver** les contrôles (BLUE).

Cadre imposé :

- Vérifier d'abord que tout est vert :
  ```sh
  pnpm install && pnpm -r build && pnpm -r test && pnpm lint:arch
  ```
- Lire les ports (`packages/contracts/src/index.ts`), les implémentations (`packages/*/src`) et **tous
  les `DEBT.md`** (chaque dette = une hypothèse de faiblesse à confirmer/infirmer).
- Écrire des tests adverses `packages/*/test/security-*.test.ts` (hermétiques, fakes en mémoire).
- Corriger les Critical/High ; documenter les Medium/Low dans les `DEBT.md` (une dette résolue est
  **supprimée**).
- Re-vérifier build + test + `lint:arch` verts, sans régression, sans casser l'API publique des ports.

Livrables : le rapport `docs/SECURITY-AUDIT-REPORT.md` (findings par sévérité + mapping de conformité
+ correctifs appliqués vs recommandés) et les tests adverses ajoutés.

## Signaler une vulnérabilité

Kengela est sous licence Apache-2.0. Pour un signalement responsable, ouvrez un contact privé avec le
mainteneur plutôt qu'une issue publique tant que le correctif n'est pas disponible.
</content>
