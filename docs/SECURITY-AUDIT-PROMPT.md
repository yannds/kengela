# Prompt — Audit sécurité & conformité de Kengela (red team / blue team)

> À confier à un agent (ou à un pentester) disposant d'un accès **lecture + écriture de tests**
> au dépôt Kengela. L'objectif est de **casser** la lib de façon adverse, puis de **prouver**
> les contrôles et la conformité — avant toute publication npm.
>
> Copier tout ce qui suit comme prompt.

---

Tu réalises un **audit de sécurité et de conformité adverse** du monorepo Kengela
(`/Users/dsyann/kengela`), un socle identité & accès Zero Trust multi-tenant en TypeScript.
Tu joues **deux rôles** : **RED** (attaquer) puis **BLUE** (prouver/durcir). Tu ne modifies PAS
le code de production sans le signaler ; tu écris des **tests adverses** (Vitest) pour matérialiser
chaque hypothèse. AUCUNE mention de Claude/Anthropic nulle part.

## Cadre à respecter
- Conventions du repo : TS6 strict, ESLint strictTypeChecked, ESM/NodeNext, Prettier. Tests via Vitest.
- Vérifier d'abord : `pnpm install && pnpm -r build && pnpm -r test && pnpm lint:arch` (tout doit être vert).
- Lire les ports dans `packages/contracts/src/index.ts` et les implémentations dans chaque `packages/*/src`.
- Lire tous les `DEBT.md` : traiter chaque dette comme une **hypothèse de faiblesse** à confirmer/infirmer.

## RED TEAM — scénarios d'attaque à tenter (écris un test qui ÉCHOUE si la lib est vulnérable)
Isolation & autorisation :
1. **Cross-tenant** : un Principal du tenant A obtient-il une décision `allow` sur une ressource du
   tenant B ? (AccessRequest, RelationResolver, grants) — tenter le smuggling de tenantId.
2. **Escalade de privilège** : un grant `*.global` ou `platform.*` accordé à un tenant non-plateforme
   est-il honoré ? Le split de scope (`plane.resource.action.SCOPE`) peut-il être détourné (ex.
   `data.x.read.tenant` interprété plus large) ? Wildcards (`*`) trop permissifs ?
3. **Fail-open** : une requête sans policy / sans grant / avec relation `none` obtient-elle `allow` ?
   Une **condition CEL qui lève** doit donner `deny` (fail-closed) — le prouver, et tenter une
   expression qui contourne (variable absente, non-booléen, exception).
4. **deny-wins** : une règle `deny` peut-elle être court-circuitée par l'ordre d'évaluation ?
5. **Sandbox CEL** : tenter une évaluation CEL qui accède à des globals, boucle infinie, ReDoS,
   ou consomme des ressources (DoS). Vérifier l'isolement de `@kengela/adapter-expr-cel`.

Authentification & crypto :
6. **Timing** : `NativeCredentialAuthenticator` fait-il TOUJOURS un compare bcrypt/argon2 (même
   email inconnu) ? Mesurer/raisonner sur l'oracle d'énumération. Cross-tenant sans short-circuit ?
7. **AES-256-GCM** : altérer iv/tag/ciphertext → doit rejeter ; mauvaise clé tenant → rejeter ;
   nonce réutilisé ? Vérifier `AesGcmKeyManagement`, `AesGcmFieldCipher`, `SubjectFieldCipher`.
8. **Crypto-shredding** : après `eraseSubject`, une PII chiffrée est-elle réellement irrécupérable ?
   La clé est-elle vraiment détruite (pas dérivable) ?
9. **MFA** : rejouer un challengeId (one-shot ?), code TOTP hors fenêtre, deviner le secret, bypass
   via `verify` sans secret. `TotpMfaService` + stores.
10. **Sessions** : forger/rejouer un token opaque, expiration respectée, rotation invalide l'ancien,
    `revokeAll` effectif. `SessionStore` / `PrismaSessionStore` / `TranslogSessionStore`.

Fédération / SCIM :
11. **SCIM** : injection via filtre (`userName eq`), PATCH malveillant (op inconnue, path forgé),
    contournement de la désactivation (delete = deactivate), unicité `userName` (409) contournable,
    validation d'entrée `validateScimUser` bypassable, ReDoS des filtres/regex. `@kengela/scim-server`.
12. **LDAP** : injection de filtre LDAP, bind password loggé ? TLS désactivable ? `adapter-directory-ldap`.
13. **Mapping IdP** : `iam-mapping` — regex de règles ReDoS (`safe-regex`), profil malveillant
    (SAML non signé accepté ? gate emailVerified ?), élévation via mapping de groupes.

Intégration :
14. **Guard NestJS** : route non annotée = `deny` (deny-by-default) ? `@PublicRoute` sur une classe
    neutralise-t-il un `@RequirePermission` de handler de façon dangereuse ? Principal absent = 401.
15. **better-auth adapter** : session invalide/expirée acceptée ? tenant non résoluble = `null` ?

## BLUE TEAM — prouver les contrôles & la conformité
- Écris/complète les tests adverses ci-dessus qui **passent** (contrôle prouvé) ou **échouent**
  (faille trouvée → à corriger).
- **Mapping standards** (produire un tableau contrôle → statut → preuve/fichier:ligne) :
  - **OWASP ASVS v4** : V2 (authn), V3 (session), V4 (access control), V6 (crypto), V7 (logging), V9 (data protection).
  - **NIST SP 800-63B** : hashing (argon2id params), MFA (TOTP), verifier requirements.
  - **RGPD** : minimisation (`pii`), effacement art.17 (crypto-shredding), journal d'accès PII
    (`PiiAccessLogSink`), rétention (`retentionExpired`), chiffrement at-rest.
  - **SCIM** : RFC 7643 (schéma) / 7644 (protocole) + exigences du validateur Microsoft Entra.
- Vérifie que les **decision logs** capturent assez pour l'audit (allow/deny + raison + signaux).

## Livrables
1. **Rapport** `docs/SECURITY-AUDIT-REPORT.md` : findings classés par sévérité (Critical/High/Medium/Low),
   chacun avec : scénario, `fichier:ligne`, preuve (test), impact, remédiation. Puis le tableau de
   mapping standards. Puis la liste des correctifs appliqués vs recommandés.
2. **Tests adverses** ajoutés sous `packages/*/test/` (préfixe `security-*.test.ts`), tous exécutables.
3. Corriger les failles **Critical/High** (avec l'accord implicite : c'est de la sécurité), documenter
   les Medium/Low dans les `DEBT.md` concernés. Toute dette résolue est **supprimée** du `DEBT.md`.
4. Re-vérifier `pnpm -r build && pnpm -r test && pnpm lint:arch` verts. Aucune régression.

## Contraintes
- Ne casse pas l'API publique des ports sans le justifier dans le rapport.
- Reste hermétique (fakes en mémoire) — pas de vrai réseau/DB.
- Ne commit/push pas ; laisse l'orchestrateur committer après revue.
