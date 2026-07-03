import { describe, expect, it } from 'vitest';
import type { LdapSearchEntry } from '../src/ldap-client-like.js';
import type { LdapConnectionConfig } from '../src/ldap-directory-source.js';
import { LdapDirectorySource } from '../src/ldap-directory-source.js';
import { FakeLdapClient, fakeFactory } from './fake-ldap-client.js';

const CONFIG: LdapConnectionConfig = {
  url: 'ldaps://dc.corp.local:636',
  bindDN: 'CN=svc-read,OU=Service,DC=corp,DC=local',
  bindPassword: 's3cr3t',
  baseDN: 'OU=Users,DC=corp,DC=local',
};

/** Objet GUID binaire (4 octets) → base64 stable `AQIDBA==`. */
const OBJECT_GUID = Buffer.from([0x01, 0x02, 0x03, 0x04]);

const janeEntry: LdapSearchEntry = {
  dn: 'CN=Jane Doe,OU=Users,DC=corp,DC=local',
  mail: 'Jane.Doe@Corp.Local',
  givenName: 'Jane',
  sn: 'Doe',
  displayName: 'Jane Doe',
  department: 'Engineering',
  objectGUID: OBJECT_GUID,
  memberOf: ['CN=Admins,OU=Groups,DC=corp,DC=local', 'CN=Payroll,OU=Groups,DC=corp,DC=local'],
  userAccountControl: '512',
};

const disabledEntry: LdapSearchEntry = {
  dn: 'CN=Bob Gone,OU=Users,DC=corp,DC=local',
  mail: 'bob@corp.local',
  sn: 'Gone',
  userAccountControl: '514',
};

function sourceWith(client: FakeLdapClient): LdapDirectorySource {
  return new LdapDirectorySource(CONFIG, { clientFactory: fakeFactory(client) });
}

describe('LdapDirectorySource.fetchEntries', () => {
  it('se lie avec le DN et le mot de passe de service, puis se délie', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    await sourceWith(client).fetchEntries();

    expect(client.binds).toEqual([{ dn: CONFIG.bindDN, password: CONFIG.bindPassword }]);
    expect(client.unbindCount).toBe(1);
  });

  it('normalise le DN et les attributs mono-valués en chaînes', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    const [entry] = await sourceWith(client).fetchEntries();

    expect(entry?.dn).toBe('CN=Jane Doe,OU=Users,DC=corp,DC=local');
    expect(entry?.attributes['givenName']).toBe('Jane');
    expect(entry?.attributes['department']).toBe('Engineering');
  });

  it('préserve les attributs multi-valués (memberOf) en tableau', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    const [entry] = await sourceWith(client).fetchEntries();

    expect(entry?.attributes['memberOf']).toEqual([
      'CN=Admins,OU=Groups,DC=corp,DC=local',
      'CN=Payroll,OU=Groups,DC=corp,DC=local',
    ]);
  });

  it('convertit un attribut binaire (objectGUID) en base64 stable', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    const [entry] = await sourceWith(client).fetchEntries();

    expect(entry?.attributes['objectGUID']).toBe('AQIDBA==');
  });

  it('transmet la portée, le filtre, la pagination et le plafond au client', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    await sourceWith(client).fetchEntries();

    const search = client.searches[0];
    expect(search?.baseDN).toBe(CONFIG.baseDN);
    expect(search?.options.scope).toBe('sub');
    expect(search?.options.filter).toBe('(&(objectCategory=person)(objectClass=user))');
    expect(search?.options.paged).toEqual({ pageSize: 200 });
    expect(search?.options.sizeLimit).toBe(1000);
  });

  it('utilise le filtre fourni en argument', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    await sourceWith(client).fetchEntries('(objectClass=inetOrgPerson)');

    expect(client.searches[0]?.options.filter).toBe('(objectClass=inetOrgPerson)');
  });

  it('plafonne le nombre d’entrées via max', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry, disabledEntry] });
    const entries = await sourceWith(client).fetchEntries(undefined, { max: 1 });

    expect(entries).toHaveLength(1);
    expect(client.searches[0]?.options.sizeLimit).toBe(1);
  });

  it('se délie même quand le bind échoue', async () => {
    const client = new FakeLdapClient({ bindShouldFail: true });
    await expect(sourceWith(client).fetchEntries()).rejects.toThrow('bind failed');

    expect(client.unbindCount).toBe(1);
  });
});

describe('LdapDirectorySource.checkConnection', () => {
  it('renvoie true quand le bind réussit et se délie', async () => {
    const client = new FakeLdapClient();
    const ok = await sourceWith(client).checkConnection();

    expect(ok).toBe(true);
    expect(client.unbindCount).toBe(1);
  });

  it('renvoie false quand le bind échoue (aucune exception ne fuit)', async () => {
    const client = new FakeLdapClient({ bindShouldFail: true });
    const ok = await sourceWith(client).checkConnection();

    expect(ok).toBe(false);
    expect(client.unbindCount).toBe(1);
  });
});

describe('LdapDirectorySource.toProfiles', () => {
  it('projette une entrée en DirectoryProfile via profileFromLdap', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    const entries = await sourceWith(client).fetchEntries();
    const [profile] = LdapDirectorySource.toProfiles(entries);

    expect(profile?.email).toBe('jane.doe@corp.local');
    expect(profile?.externalId).toBe('AQIDBA==');
    expect(profile?.firstName).toBe('Jane');
    expect(profile?.lastName).toBe('Doe');
    expect(profile?.attributes.department).toBe('Engineering');
    expect(profile?.groups).toEqual(['Admins', 'Payroll']);
  });

  it('applique une carte d’attributs surchargée (OpenLDAP)', async () => {
    const openLdapEntry: LdapSearchEntry = {
      dn: 'uid=alice,ou=people,dc=corp,dc=local',
      mail: 'alice@corp.local',
      surname: 'Martin',
      groupMembership: ['cn=Ops,ou=groups,dc=corp,dc=local'],
    };
    const client = new FakeLdapClient({ entries: [openLdapEntry] });
    const entries = await sourceWith(client).fetchEntries();
    const [profile] = LdapDirectorySource.toProfiles(entries, {
      lastName: 'surname',
      groups: 'groupMembership',
    });

    expect(profile?.lastName).toBe('Martin');
    expect(profile?.groups).toEqual(['Ops']);
  });

  it('n’écrase pas la carte déjà portée par l’entrée', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    const entries = await sourceWith(client).fetchEntries(undefined, {
      attributeMap: { lastName: 'sn' },
    });
    const [profile] = LdapDirectorySource.toProfiles(entries, { lastName: 'givenName' });

    expect(profile?.lastName).toBe('Doe');
  });
});

describe('LdapDirectorySource.toRecords', () => {
  it('marque un compte normal comme actif', async () => {
    const client = new FakeLdapClient({ entries: [janeEntry] });
    const entries = await sourceWith(client).fetchEntries();
    const [record] = LdapDirectorySource.toRecords(entries);

    expect(record?.active).toBe(true);
    expect(record?.profile.email).toBe('jane.doe@corp.local');
  });

  it('détecte un compte désactivé (userAccountControl bit 0x2)', async () => {
    const client = new FakeLdapClient({ entries: [disabledEntry] });
    const entries = await sourceWith(client).fetchEntries();
    const [record] = LdapDirectorySource.toRecords(entries);

    expect(record?.active).toBe(false);
  });
});
