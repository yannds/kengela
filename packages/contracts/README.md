# @kengela/contracts

> The stable port contracts (types and interfaces only) that the rest of Kengela depends on.

This package defines the shared vocabulary and the port interfaces of the framework: identities, principals, access requests, decisions, grants, and the ports for authentication, authorization, tenancy, directory federation, and compliance. It is the contracts ring: zero implementation and zero vendor imports, so the core depends on these ports, adapters implement them, and applications compose them.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/contracts
```

## Usage

```ts
import type { Principal, AccessRequest, Decision, PolicyDecisionPoint } from '@kengela/contracts';

// A PDP is deny-by-default and evaluated per request.
async function canAccess(pdp: PolicyDecisionPoint, request: AccessRequest): Promise<boolean> {
  const decision: Decision = await pdp.check(request);
  return decision.effect === 'allow';
}
```

## Key exports

- `Principal`, `AccessRequest`, `Decision` - the authn-authz bridge types.
- `Grant`, `Role`, `Scope`, `OrgRelation`, `Effect` - the RBAC and relation vocabulary.
- `AuthContext`, `Obligation` - Zero Trust context signals and step-up obligations.
- `PolicyDecisionPoint`, `AuthorizationRepository`, `RelationResolver` - authorization ports.
- `IdentityPort`, `CredentialAuthenticator`, `PasswordHasher`, `SessionStore`, `MfaService` - authentication ports.
- `ExpressionEnginePort`, `PolicyStore`, `Policy`, `PolicyRule` - policy evaluation ports.
- `FieldCipherPort`, `SubjectKeyStore`, `ErasurePort`, `PiiAccessLogSink` - compliance ports.
- `DirectoryProfile`, `DirectorySourcePort`, `ScimRepository` - directory federation ports.
- `TenantContextPort`, `UnitOfWork`, `CachePort`, `AuditSink`, `Clock` - cross-cutting ports.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
