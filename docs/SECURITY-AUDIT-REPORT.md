# Rapport d'audit sécurité & conformité — Kengela

> Audit adverse **RED team / BLUE team** du socle identité & accès Zero Trust Kengela
> (monorepo pnpm, TypeScript 6 strict, ESLint `strictTypeChecked`, Vitest).
> Objectif : casser la lib, prouver les contrôles, cartographier la conformité avant publication npm.
> Périmètre : les 12 paquets `packages/*`. Tests hermétiques (fakes en mémoire, aucun réseau/DB réel).

## Résumé exécutif

| Sévérité | Trouvées | Corrigées | Documentées (dette) |
| -------- | -------- | --------- | ------------------- |
| Critical | 0        | 0         | 0                   |
| High     | 4        | 4         | 0                   |
| Medium   | 1        | 0         | 1                   |
| Low      | 1        | 0         | 1                   |

- **83 cas de test adverses** ajoutés (10 fichiers `security-*.test.ts`, ~88 assertions exécutées avec l'`it.each`), tous verts.
- **4 failles High corrigées** (défense-en-profondeur multi-tenant, fail-open guard NestJS, ReDoS CEL, sessions expirées servies).
- État initial ET final : `pnpm -r build && pnpm -r test && pnpm exec eslint . && pnpm lint:arch && pnpm exec prettier --check` **tous VERTS**, aucune régression.

---

## 1. Findings

### [HIGH-1] Isolation multi-tenant non défendue au cœur du PDP (défense-en-profondeur)

- **Scénario** : cross-tenant / smuggling de `tenantId`. Un `Principal` du tenant A demande une ressource du tenant B.
- **Fichier** : `packages/authz-core/src/pdp.ts` (avant : ligne ~40) et `packages/authz-core/src/policy-pdp.ts` (avant : ligne ~62).
- **Preuve** : `packages/authz-core/test/security-authz.test.ts` → « un grant `tenant` du tenant A ne franchit PAS vers une ressource du tenant B, même si le résolveur ment ».
- **Analyse** : le PDP déléguait TOUTE l'isolation multi-tenant au `RelationResolver` injecté (adapté par l'app) et ne comparait jamais `resource.tenantId` à `principal.tenantId`. Un résolveur bogué ou compromis renvoyant `tenant` (relation la plus large) pour une ressource d'un AUTRE tenant faisait accorder un `allow` cross-tenant à un grant de portée `tenant` (non-plateforme). Fail-open silencieux sur l'invariant central de la lib.
- **Impact** : franchissement de frontière tenant (OWASP A01 Broken Access Control), fuite de données cross-tenant.
- **Remédiation (appliquée)** : nouvel helper `tenantScopedRelation()` (`engine.ts:25`), fail-closed : si `resource.tenantId !== principal.tenantId`, la relation est ramenée à `none` — seul un grant de portée `global` (plan plateforme) peut alors couvrir. Câblé dans `pdp.ts:45` et `policy-pdp.ts:65`. Un signal `crossTenant` est émis au decision log (`pdp.ts:57`). Les flux même-tenant légitimes sont inchangés (prouvé).

### [HIGH-2] Guard NestJS fail-open : `@PublicRoute` de classe neutralisait `@RequirePermission` de handler

- **Scénario** : intégration guard NestJS (deny-by-default).
- **Fichier** : `packages/nestjs/src/authz.guard.ts` (avant : `getAllAndOverride(KENGELA_PUBLIC, [handler, controller])` évalué en premier).
- **Preuve** : `packages/nestjs/test/security-guard.test.ts` → « handler protégé + classe publique => la décision PDP est bien évaluée (pas de bypass) ».
- **Analyse** : `getAllAndOverride` renvoyait `true` dès que le PUBLIC était posé au niveau HANDLER **ou** CLASSE. Un contrôleur annoté `@PublicRoute` rendait donc publiques TOUTES ses routes — y compris un handler portant un `@RequirePermission`, qui n'était jamais évalué. Fail-open classique (A01).
- **Impact** : exposition non authentifiée/non autorisée d'endpoints sensibles.
- **Remédiation (appliquée)** : précédence explicite HANDLER > CLASSE via `reflector.get` par cible (`authz.guard.ts:52-77`). Un `@RequirePermission` de handler est TOUJOURS évalué ; un `@PublicRoute` de handler reste un opt-out volontaire ; sinon deny-by-default.

### [HIGH-3] ReDoS via la fonction CEL `matches` (DoS du PDP)

- **Scénario** : sandbox CEL — consommation de ressources (ReDoS).
- **Fichier** : `packages/adapter-expr-cel/src/cel-expression-engine.ts` ; racine chez le vendor `@marcbachmann/cel-js/lib/functions.js:358` (`new RegExp(b).test(a)`, non borné).
- **Preuve** : `packages/adapter-expr-cel/test/security-cel-sandbox.test.ts` → « rejette IMMÉDIATEMENT une regex catastrophique ». Confirmé empiriquement : `"aaaa…(60)!".matches("(a+)+$")` ne rendait jamais la main (backtracking exponentiel).
- **Analyse** : cel-js compile `x.matches(p)` en une `RegExp` JS non bornée. Une condition de policy `champ.matches("(a+)+")` évaluée contre une valeur de contexte adverse (attribut de ressource, nom…) bloque le thread du PDP → déni de service tenant. Incohérent avec la doctrine « toute regex bornée » déjà appliquée dans `@kengela/iam-mapping` (safe-regex.ts).
- **Impact** : DoS du point de décision (OWASP A05/A06).
- **Remédiation (appliquée)** : `assertNoUnboundedRegex()` (`cel-expression-engine.ts:100`) interdit `matches` à la compilation (fail-closed → le PDP en fait un `deny condition_error`). Détection après neutralisation des chaînes littérales (`stripStringLiterals`, motif linéaire) pour éviter les faux positifs. Les conditions d'accès s'expriment via `==`, `in`, `startsWith`, `contains`. `Environment.registerFunction` ne peut pas surcharger `matches` (cel-js rejette les signatures chevauchantes), d'où l'interdiction plutôt qu'un remplacement borné.

### [HIGH-4] Sessions EXPIRÉES servies comme valides (fail-open en lecture)

- **Scénario** : sessions — expiration respectée.
- **Fichiers** : `packages/adapter-persistence-prisma/src/session-store.ts:60` et `packages/connector-translog/src/session-store.ts:63` (`get`).
- **Preuve** : `packages/adapter-persistence-prisma/test/security-session.test.ts` et `packages/connector-translog/test/security-session.test.ts` → « get(token) renvoie null une fois l'expiration passée, même si la ligne subsiste ».
- **Analyse** : `get` renvoyait la ligne quelle que soit `expiresAt`, déléguant le contrôle d'expiration au consommateur et au balayage différé (cleanup). Un store « durci » Zero Trust ne doit jamais restituer une session expirée comme valide.
- **Impact** : rejeu de session expirée avant purge (OWASP ASVS V3, session management).
- **Remédiation (appliquée)** : `get` renvoie `null` si `expiresAt <= clock.now()` (les deux stores). Fail-closed, indépendant du cron de nettoyage.

### [MEDIUM-1] Anti-rejeu du code TOTP absent (NIST 800-63B §5.1.4.2)

- **Fichier** : `packages/adapter-authn-native/src/totp-mfa-service.ts`.
- **Analyse** : le défi MFA (`MfaChallengeStore`) est bien one-shot (prouvé), mais le CODE TOTP lui-même n'est pas mémorisé. Dans la fenêtre de pas (~30 s), un code valide déjà consommé pourrait être rejoué via un NOUVEAU `challengeId`. NIST 800-63B exige que le vérificateur refuse un OTP déjà utilisé.
- **Impact** : fenêtre de rejeu OTP réduite (~30 s), sous condition d'interception du code.
- **Statut** : **documenté** — `packages/adapter-authn-native/DEBT.md` #3 (cible : cache anti-rejeu TTL = fenêtre TOTP dans `verify`). Non corrigé ici car nécessite un nouveau port de stockage ; risque résiduel faible (one-shot déjà en place).

### [LOW-1] Pas de helper d'échappement de filtre LDAP (RFC 4515)

- **Fichier** : `packages/adapter-directory-ldap/src/ldap-directory-source.ts`.
- **Analyse** : l'adapter transmet le `filter` VERBATIM au client — il n'introduit AUCUNE injection (prouvé : `security-ldap.test.ts`, le filtre est inchangé). Mais aucun helper d'échappement n'est exposé : une app qui composerait un filtre à partir d'entrée utilisateur non échappée resterait exposée à l'injection de filtre LDAP côté appelant.
- **Statut** : **documenté** — `packages/adapter-directory-ldap/DEBT.md` #5 (cible : `escapeLdapFilterValue()`).

---

## 2. Contrôles prouvés (BLUE team — aucune faille)

| #   | Scénario RED                   | Contrôle prouvé                                                                                                                                                                                           | Preuve (fichier)                                                                               |
| --- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| B1  | Escalade via portée            | `subtree` ne couvre pas `tenant` ; grant expiré inopérant ; seul `global` franchit un tenant                                                                                                              | `authz-core/test/security-authz.test.ts`                                                       |
| B2  | Fail-open / deny-wins          | relation `none` sans grant global = deny ; `deny` explicite gagne quel que soit l'ordre ; condition qui lève = `deny` ; gate ABAC positif                                                                 | `authz-core/test/security-authz.test.ts`, `adapter-expr-cel/test/security-cel-sandbox.test.ts` |
| B3  | Sandbox CEL                    | accès `process`/`globalThis`/`constructor`/`__proto__` → throw ; expression non booléenne → throw ; variable/champ absent → throw (fail-closed)                                                           | `adapter-expr-cel/test/security-cel-sandbox.test.ts`                                           |
| B4  | Énumération par timing         | compare bcrypt leurre TOUJOURS effectué (email inconnu, compte inactif) ; cross-tenant sans court-circuit (N compares pour N tenants)                                                                     | `adapter-authn-native/test/security-authn.test.ts`                                             |
| B5  | AES-256-GCM                    | IV/tag/ciphertext altéré → rejet ; tronqué → rejet ; mauvaise clé tenant → rejet ; nonce unique par chiffrement                                                                                           | `adapter-authn-native/test/security-authn.test.ts`                                             |
| B6  | Crypto-shredding (RGPD art.17) | après `eraseSubject`, PII illisible (null) ; clé d'un autre sujet ne déchiffre pas                                                                                                                        | `adapter-authn-native/test/security-authn.test.ts`                                             |
| B7  | Rejeu MFA                      | `challengeId` one-shot ; verify sans secret = false ; challengeId forgé = false                                                                                                                           | `adapter-authn-native/test/security-authn.test.ts`                                             |
| B8  | SCIM injection/ReDoS/PATCH     | filtres bornés (entrée géante rejetée vite) ; injection non interprétée ; op inconnue ignorée ; unicité 409 ; delete = désactivation ; isolation tenant (404 cross-tenant) ; validation de schéma stricte | `scim-server/test/security-scim.test.ts`                                                       |
| B9  | Mapping IdP                    | safe-regex anti-ReDoS ; règle vide ne matche jamais ; aucune élévation sans règle configurée ; SAML sans groupe ne fabrique aucun rôle                                                                    | `iam-mapping/test/security-mapping.test.ts`                                                    |
| B10 | better-auth                    | session absente → null ; tenant non résoluble / mauvais type → null ; roles/mfa jamais hérités du payload (l'authz recharge)                                                                              | `adapter-authn-better-auth/test/security-better-auth.test.ts`                                  |
| B11 | LDAP                           | filtre verbatim (aucune injection introduite) ; `unbind` garanti même en erreur ; plafond `max` appliqué ; `checkConnection` avale l'erreur sans fuiter le secret                                         | `adapter-directory-ldap/test/security-ldap.test.ts`                                            |
| B12 | Sessions                       | rotation invalide l'ancien token ; `revokeAllForUser` effectif ; token 32 octets aléatoires (64 hex) sans collision                                                                                       | `adapter-persistence-prisma/test/security-session.test.ts`                                     |
| B13 | Guard NestJS                   | deny-by-default (route non annotée = 403) ; principal absent = 401 ; précédence handler > classe                                                                                                          | `nestjs/test/security-guard.test.ts`                                                           |
| B14 | Decision log                   | `signals` capturent la relation + `crossTenant` ; raison lisible (`no_grant`, `condition_error`, `no_matching_allow`…) pour l'audit                                                                       | `authz-core/test/security-authz.test.ts`                                                       |

---

## 3. Cartographie de conformité (contrôle → statut → preuve)

### OWASP ASVS v4

| Contrôle                                                           | Statut     | Preuve                                                                                                                                          |
| ------------------------------------------------------------------ | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| V2 Authentication — hashing fort, anti-énumération                 | ✅         | argon2id (`argon2-password-hasher.ts`), compare systématique (`native-credential-authenticator.ts:47-54`) ; `security-authn.test.ts`            |
| V3 Session Management — expiration, rotation, révocation, entropie | ✅ (durci) | expiration fail-closed (`session-store.ts:67`), rotation atomique, token 256 bits ; `security-session.test.ts`                                  |
| V4 Access Control — deny-by-default, isolation, deny-wins          | ✅ (durci) | PDP deny-by-default + `tenantScopedRelation` (`pdp.ts:45`), guard (`authz.guard.ts:52-77`) ; `security-authz.test.ts`, `security-guard.test.ts` |
| V6 Cryptography — AES-256-GCM, clés par tenant/sujet, intégrité    | ✅         | `aes-gcm-key-management.ts` (HKDF par tenant), `subject-field-cipher.ts` ; `security-authn.test.ts`                                             |
| V7 Errors & Logging — decision log auditable                       | ✅         | `DecisionLogSink` + `signals`/`reason` ; `security-authz.test.ts`                                                                               |
| V9 Data Protection — chiffrement at-rest, minimisation, redaction  | ✅         | `pii/` (classify/minimize/redact/retention), `FieldCipherPort` ; tests `pii`                                                                    |

### NIST SP 800-63B

| Exigence                                                   | Statut     | Preuve                                                                             |
| ---------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------- |
| Password hashing (argon2id, memory-hard)                   | ✅         | `argon2-password-hasher.ts` (argon2id), `needsRehash` pour migration bcrypt→argon2 |
| Verifier — compare à temps constant, anti-énumération      | ✅         | `native-credential-authenticator.ts` ; `security-authn.test.ts`                    |
| MFA TOTP (RFC 6238), secret chiffré at-rest, défi one-shot | ✅         | `totp-mfa-service.ts` (secret chiffré par tenant, `MfaChallengeStore` one-shot)    |
| MFA — refus de réutilisation d'un OTP (§5.1.4.2)           | ⚠️ partiel | one-shot par défi OK ; anti-rejeu du code TOTP → **DEBT native #3** (MEDIUM-1)     |

### RGPD

| Exigence                                                  | Statut | Preuve                                                                          |
| --------------------------------------------------------- | ------ | ------------------------------------------------------------------------------- |
| Minimisation (art. 5.1.c)                                 | ✅     | `pii/minimize.ts` (n'expose que les champs autorisés)                           |
| Effacement / droit à l'oubli (art. 17) — crypto-shredding | ✅     | `subject-crypto-shredder.ts` ; `security-authn.test.ts` (illisible après erase) |
| Journal d'accès PII (art. 30)                             | ✅     | port `PiiAccessLogSink` (contracts)                                             |
| Rétention (art. 5.1.e)                                    | ✅     | `pii/retention.ts` (`retentionExpired`, défauts prudents)                       |
| Chiffrement at-rest                                       | ✅     | `AesGcmFieldCipher` / `SubjectFieldCipher` (AES-256-GCM par tenant/sujet)       |
| Isolation cryptographique inter-tenant                    | ✅     | HKDF `kengela:mfa:<tenantId>` ; `security-authn.test.ts` (mauvaise clé → rejet) |

### SCIM (RFC 7643/7644 + validateur Microsoft Entra)

| Exigence                                                    | Statut | Preuve                                                                        |
| ----------------------------------------------------------- | ------ | ----------------------------------------------------------------------------- |
| Schéma User/Group + validation (7643 §4, §7)                | ✅     | `validate.ts`, `discovery.ts` ; `security-scim.test.ts` (schéma forgé rejeté) |
| Filtre `eq` borné (7644 §3.4.2.2) anti-ReDoS                | ✅     | `serialize.ts:363-395` ; `security-scim.test.ts` (entrée géante rejetée)      |
| PATCH (7644 §3.5.2) — op inconnue ignorée, path forgé borné | ✅     | `serialize.ts:236-360` ; `security-scim.test.ts`                              |
| Unicité `userName` (409, 7644 §3.3)                         | ✅     | `handleUsersPostStrict` ; `security-scim.test.ts`                             |
| Déprovisionnement = désactivation (jamais suppression)      | ✅     | `handleUsersDelete` ; `security-scim.test.ts`                                 |
| Isolation multi-tenant                                      | ✅     | handlers bornés au `tenantId` ; `security-scim.test.ts` (404 cross-tenant)    |

---

## 4. Correctifs appliqués vs recommandés

**Appliqués (High, sécurité — feu vert implicite) :**

1. `tenantScopedRelation` défense-en-profondeur multi-tenant — `authz-core` (`engine.ts:25`, `pdp.ts:45`, `policy-pdp.ts:65`).
2. Précédence handler > classe dans le guard — `nestjs` (`authz.guard.ts:52-77`).
3. Interdiction de `matches` (ReDoS) dans CEL — `adapter-expr-cel` (`cel-expression-engine.ts:100`).
4. `get` de session fail-closed sur l'expiration — `adapter-persistence-prisma` (`session-store.ts:67`) + `connector-translog` (`session-store.ts:70`).

**Recommandés (documentés en dette) :**

- MEDIUM-1 : cache anti-rejeu OTP TOTP — `adapter-authn-native/DEBT.md` #3.
- LOW-1 : helper `escapeLdapFilterValue()` — `adapter-directory-ldap/DEBT.md` #5.

## 5. Vérification finale

```
pnpm -r build                         # ✅ 12 paquets
pnpm -r test                          # ✅ (dont 10 fichiers security-*.test.ts)
pnpm exec eslint .                    # ✅ strictTypeChecked, 0 erreur
pnpm lint:arch                        # ✅ core-no-vendor + no-circular
pnpm exec prettier --check "packages/**/*.ts"  # ✅
```

Aucune API de port publique modifiée. Aucune régression.
