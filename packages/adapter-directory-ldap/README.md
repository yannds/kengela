# @kengela/adapter-directory-ldap

> An AD/LDAP directory adapter: LDAP(S) bind, paginated search, and normalization into directory profiles.

This package connects to Active Directory or LDAP over LDAP(S), runs paginated searches, and normalizes entries into `LdapEntryParts` and `DirectoryProfile` (reusing the pure mappers from `@kengela/iam-mapping`). It is the adapter ring: it only speaks LDAP, while role mapping stays pure in `@kengela/iam-mapping`.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/adapter-directory-ldap
```

## Usage

```ts
import { LdapDirectorySource } from '@kengela/adapter-directory-ldap';

const source = new LdapDirectorySource({
  connection: {
    url: 'ldaps://ad.example.com',
    bindDN: 'CN=svc,OU=Service,DC=example,DC=com',
    bindPassword: process.env.LDAP_PASSWORD,
    baseDN: 'DC=example,DC=com',
  },
});

const profiles = await source.toProfiles(tenantId, { filter: '(objectClass=user)' });
```

## Key exports

- `LdapDirectorySource` - LDAP(S) bind, paginated search, health-check, and `toProfiles` / `toRecords`.
- `LDAP_SOURCE_DEFAULTS` - default source options.
- `LdapConnectionConfig`, `LdapDirectorySourceOptions`, `FetchEntriesOptions`, `DirectoryRecord` - configuration and result types.
- `LdapClientLike` and related types - the narrow client surface the real `ldapts` client satisfies.
- `profileFromLdap`, `accountActiveFromLdap`, `DirectoryProfile` - re-exports from `@kengela/iam-mapping` for composing without a second dependency.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
