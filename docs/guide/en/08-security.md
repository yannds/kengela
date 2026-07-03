# 08 - Security

Kengela is a security foundation: its own posture must be **proven**, not asserted. This page
summarizes the Zero Trust doctrine, the controls verified by the adversarial red/blue audit, and
explains how to re-run that audit.

## Zero Trust posture (the invariants)

| Invariant                              | Where it is enforced                                                                                                             |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Deny-by-default**                    | PDP (`RbacDecisionPoint` / `LayeredDecisionPoint`), NestJS guard (unannotated route = 403)                                       |
| **Fail-closed**                        | unevaluable CEL condition → deny; expired session → `null`; unresolvable tenant → refuse; unreadable union narrowing → discarded |
| **Multi-tenant isolation at the core** | `tenantScopedRelation()`: cross-tenant → `none` relation; only a `global` grant crosses                                          |
| **Anti-staleness**                     | grants reloaded on every check (a revoked right stops acting immediately)                                                        |
| **Timing-safe**                        | `verify` always performed (decoy hash), no cross-tenant short-circuit (anti-enumeration)                                         |
| **Authenticated crypto**               | AES-256-GCM, per-tenant (HKDF) and per-subject key; any tampering → reject                                                       |
| **Anti-ReDoS**                         | `matches` forbidden in CEL; bounded regexes in `iam-mapping`; bounded SCIM filters                                               |
| **Observability**                      | `DecisionLogSink` (authorization), `AuditSink` (business/security), `PiiAccessLogSink` (GDPR art. 30)                            |

## Audit summary (red team / blue team)

The full report is in [`docs/SECURITY-AUDIT-REPORT.md`](../SECURITY-AUDIT-REPORT.md). The audit
attacked the 12 packages adversarially (in-memory fakes, no real network/DB), then proved the
controls and mapped compliance.

### Tally

| Severity | Found | Fixed | Documented (debt) |
| -------- | ----- | ----- | ----------------- |
| Critical | 0     | 0     | 0                 |
| High     | 4     | 4     | 0                 |
| Medium   | 1     | 0     | 1                 |
| Low      | 1     | 0     | 1                 |

**83 adversarial test cases** (`security-*.test.ts`), all green. No public port API modified.

### The 4 fixed Highs

1. **Multi-tenant isolation defended at the core.** The PDP delegated all isolation to the app's
   `RelationResolver`. Fix: `tenantScopedRelation()` brings the relation back to `none` in
   cross-tenant (fail-closed), wired into `pdp.ts` and `policy-pdp.ts`, with a `crossTenant` signal
   on the decision log.
2. **Fail-open NestJS guard.** A **class-level** `@PublicRoute` neutralized a **handler-level**
   `@RequirePermission`. Fix: explicit handler > class precedence (see
   [05-nestjs-integration.md](./05-nestjs-integration.md)).
3. **ReDoS via CEL `matches`.** cel-js compiled an unbounded `RegExp` (DoS of the PDP). Fix:
   `matches` **forbidden at compile time** (fail-closed); conditions are written via `==`, `in`,
   `startsWith`, `contains`.
4. **Expired sessions served.** `get()` returned an expired row not yet purged. Fix: `get()` returns
   `null` as soon as `expiresAt <= now`, independently of the cron (Prisma + connector-translog).

### The 2 documented debts

- **MEDIUM-1** — anti-replay of the TOTP **code** (NIST 800-63B §5.1.4.2): the challenge is one-shot,
  but an already-consumed code could be replayed via a new `challengeId` within the window (~30 s).
  Target: anti-replay cache (`adapter-authn-native/DEBT.md` #3).
- **LOW-1** — `escapeLdapFilterValue()` helper missing: the adapter introduces no injection (verbatim
  filter), but does not tool the caller who would compose a filter from user input
  (`adapter-directory-ldap/DEBT.md` #5).

## Proven controls (blue team excerpt)

| Attacked scenario     | Proven control                                                                                       |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| Scope escalation      | `subtree` does not cover `tenant`; expired grant inoperative; only `global` crosses a tenant         |
| Fail-open / deny-wins | `none` relation without a global grant = deny; explicit `deny` wins; a condition that throws = deny  |
| CEL sandbox           | access to `process`/`globalThis`/`__proto__` → throw; non-boolean → throw; missing variable → throw  |
| Timing enumeration    | decoy compare always performed (unknown email, inactive account); cross-tenant without short-circuit |
| AES-256-GCM           | tampered iv/tag/ciphertext → reject; truncated → reject; wrong tenant key → reject; unique nonce     |
| Crypto-shredding      | after `eraseSubject`, PII unreadable; another subject's key does not decrypt                         |
| MFA replay            | `challengeId` one-shot; verify without secret = false; forged challengeId = false                    |
| SCIM                  | bounded filters; injection not interpreted; uniqueness 409; delete = deactivation; 404 cross-tenant  |
| IdP mapping           | safe-regex anti-ReDoS; empty rule never matches; SAML without a group builds no role                 |
| better-auth           | missing session → null; unresolvable tenant → null; roles/mfa never inherited from the payload       |
| LDAP                  | verbatim filter; `unbind` guaranteed even on error; `max` cap applied; secret not logged             |
| Sessions              | rotation invalidates the old token; `revokeAllForUser` effective; 256-bit token without collision    |
| NestJS guard          | deny-by-default (403); missing principal = 401; handler > class precedence                           |

## Compliance mapping

| Framework           | Coverage                                                                                                                                                                                                                                                                                     |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OWASP ASVS v4**   | V2 authn (argon2id, anti-enumeration), V3 session (fail-closed expiration, rotation, 256 bits), V4 access control (deny-by-default, `tenantScopedRelation`, deny-wins), V6 crypto (AES-256-GCM per tenant/subject), V7 logging (decision log), V9 data protection (`pii`, `FieldCipherPort`) |
| **NIST SP 800-63B** | argon2id memory-hard hashing + `needsRehash`; constant-time verifier; TOTP MFA (RFC 6238) encrypted secret + one-shot challenge; OTP anti-replay = debt #3                                                                                                                                   |
| **GDPR**            | minimization, erasure art. 17 (crypto-shredding), access log art. 30, retention, at-rest encryption, inter-tenant cryptographic isolation                                                                                                                                                    |
| **SCIM**            | RFC 7643/7644 + Microsoft Entra validator (schema, bounded `eq` filter, PATCH, uniqueness 409, deprovisioning = deactivation, tenant isolation)                                                                                                                                              |

## Re-running the adversarial audit

The reproducible audit prompt is in
[`docs/SECURITY-AUDIT-PROMPT.md`](../SECURITY-AUDIT-PROMPT.md). It gives an agent (or a pentester)
read access + **test** write access to the repository, with the mission to **break** the lib (RED)
then **prove** the controls (BLUE).

Imposed framework:

- First check that everything is green:
  ```sh
  pnpm install && pnpm -r build && pnpm -r test && pnpm lint:arch
  ```
- Read the ports (`packages/contracts/src/index.ts`), the implementations (`packages/*/src`) and **all
  the `DEBT.md` files** (each debt = a weakness hypothesis to confirm/refute).
- Write adversarial tests `packages/*/test/security-*.test.ts` (hermetic, in-memory fakes).
- Fix the Critical/High; document the Medium/Low in the `DEBT.md` files (a resolved debt is
  **deleted**).
- Re-check build + test + `lint:arch` green, without regression, without breaking the ports' public
  API.

Deliverables: the `docs/SECURITY-AUDIT-REPORT.md` report (findings by severity + compliance mapping

- applied vs recommended fixes) and the adversarial tests added.

## Reporting a vulnerability

Kengela is licensed under Apache-2.0. For responsible disclosure, open a private contact with the
maintainer rather than a public issue while the fix is not yet available.
