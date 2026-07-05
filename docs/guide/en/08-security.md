# 08 - Security

Kengela is a security foundation: its own posture must be **proven**, not asserted. This page
summarizes the Zero Trust doctrine and the controls verified by the adversarial test suite.

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

## Verified controls

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
| **NIST SP 800-63B** | argon2id memory-hard hashing + `needsRehash`; constant-time verifier; TOTP MFA (RFC 6238) encrypted secret + one-shot challenge                                                                                                                                                              |
| **GDPR**            | minimization, erasure art. 17 (crypto-shredding), access log art. 30, retention, at-rest encryption, inter-tenant cryptographic isolation                                                                                                                                                    |
| **SCIM**            | RFC 7643/7644 + Microsoft Entra validator (schema, bounded `eq` filter, PATCH, uniqueness 409, deprovisioning = deactivation, tenant isolation)                                                                                                                                              |

## Reporting a vulnerability

Kengela is licensed under Apache-2.0. For responsible disclosure, open a private contact with the
maintainer rather than a public issue while the fix is not yet available.
