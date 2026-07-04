# @kengela/iam-mapping

> Pure identity normalization from enterprise IdPs (OIDC, SAML, SCIM, LDAP, Microsoft Graph, Google) into a single directory profile, plus a role-mapping engine.

This package bridges enterprise identity (Entra, AD, ADFS, Okta, Google Workspace) and the internal role + org-unit model. It normalizes the six IdP sources into a `DirectoryProfile`, maps groups, claims, and attributes to roles and units, and compiles safe (anti-ReDoS, fail-closed) regexes. It is the core ring: everything is pure and testable outside infrastructure.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/iam-mapping
```

## Usage

```ts
import { profileFromOidcClaims, evaluateMappings } from '@kengela/iam-mapping';

const profile = profileFromOidcClaims(idTokenClaims);

const result = evaluateMappings(profile, [
  { source: 'group', match: { op: 'equals', value: 'Admins' }, roles: ['tenant-admin'] },
]);
// result.roles / result.orgUnitId
```

## Key exports

- `profileFromOidcClaims`, `profileFromScim`, `profileFromSaml`, `profileFromLdap`, `profileFromGraph`, `profileFromGoogle`, `profileFromParts` - the six IdP source normalizers.
- `evaluateMappings` - group/claim/attribute to role + unit mapping engine.
- `compileSafeRegex`, `safeRegexTest`, `SAFE_REGEX_LIMITS` - fail-closed regex evaluation.
- `toContractsProfile`, `projectScimUser` - projections to contracts and SCIM shapes.
- `DirectoryProfile`, `LdapEntryParts`, `SamlAssertionParts`, `GraphUserParts`, `GoogleDirectoryUserParts` - source part types.
- `SCIM_SCHEMA_CORE_USER`, `SCIM_SCHEMA_ENTERPRISE_USER`, `SCIM_SCHEMA_GROUP`, `KengelaScimUser` - canonical SCIM schema URNs and types.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
