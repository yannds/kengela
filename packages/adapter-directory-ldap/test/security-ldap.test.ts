/**
 * RED TEAM — adapter LDAP (@kengela/adapter-directory-ldap).
 *
 * L'adapter ne construit JAMAIS de filtre a partir de fragments : il transmet le filtre
 * verbatim (pas d'injection introduite ici). Le `unbind` est garanti meme en erreur, le
 * plafond `sizeLimit`/`max` est applique, et `checkConnection` avale l'erreur sans fuiter
 * le mot de passe. Hermetique (fakes en memoire).
 */
import type { LdapClientLike, LdapSearchResult } from '../src/ldap-client-like.js';
import { describe, expect, it } from 'vitest';
import { LdapDirectorySource } from '../src/ldap-directory-source.js';
import { FakeLdapClient, fakeFactory } from './fake-ldap-client.js';

const CONFIG = {
  url: 'ldaps://dc.corp.local:636',
  bindDN: 'CN=svc,DC=corp',
  bindPassword: 'S3cr3t-bind-pw',
  baseDN: 'OU=Users,DC=corp',
} as const;

describe('RED — LDAP : filtre transmis verbatim (pas d’injection introduite)', () => {
  it('le filtre fourni par l’appelant est passe TEL QUEL au client (aucune concatenation)', async () => {
    const client = new FakeLdapClient({ entries: [{ dn: 'CN=a' }] });
    const source = new LdapDirectorySource(CONFIG, { clientFactory: fakeFactory(client) });
    const attackFilter = '(|(uid=*)(objectClass=*))'; // charge utile de test
    await source.fetchEntries(attackFilter);
    expect(client.searches).toHaveLength(1);
    expect(client.searches[0]?.options.filter).toBe(attackFilter); // inchange
  });

  it('sans filtre, applique le filtre par defaut (comptes personnes, exclut les machines)', async () => {
    const client = new FakeLdapClient({ entries: [] });
    const source = new LdapDirectorySource(CONFIG, { clientFactory: fakeFactory(client) });
    await source.fetchEntries();
    expect(client.searches[0]?.options.filter).toBe('(&(objectCategory=person)(objectClass=user))');
  });
});

describe('RED — LDAP : plafond et liberation de connexion', () => {
  it('plafonne le nombre d’entrees a `max` (anti-exhaustion memoire)', async () => {
    const many = Array.from({ length: 50 }, (_, i) => ({ dn: `CN=u${String(i)}` }));
    const client = new FakeLdapClient({ entries: many });
    const source = new LdapDirectorySource(CONFIG, { clientFactory: fakeFactory(client) });
    const entries = await source.fetchEntries(undefined, { max: 10 });
    expect(entries).toHaveLength(10);
  });

  it('unbind GARANTI meme si la recherche echoue (pas de fuite de connexion)', async () => {
    let unbinds = 0;
    const failing: LdapClientLike = {
      bind: () => Promise.resolve(),
      search: (): Promise<LdapSearchResult> => Promise.reject(new Error('search boom')),
      unbind: (): Promise<void> => {
        unbinds += 1;
        return Promise.resolve();
      },
    };
    const source = new LdapDirectorySource(CONFIG, { clientFactory: () => failing });
    await expect(source.fetchEntries()).rejects.toThrow('search boom');
    expect(unbinds).toBe(1);
  });
});

describe('RED — LDAP : checkConnection ne fuite pas le secret', () => {
  it('bind en echec => false, sans exception ni mot de passe propage', async () => {
    const client = new FakeLdapClient({ bindShouldFail: true });
    const source = new LdapDirectorySource(CONFIG, { clientFactory: fakeFactory(client) });
    const ok = await source.checkConnection();
    expect(ok).toBe(false);
    expect(client.unbindCount).toBe(1); // libere quand meme
  });

  it('le mot de passe de bind est transmis au client injecte, jamais reconstruit', async () => {
    const client = new FakeLdapClient({ entries: [] });
    const source = new LdapDirectorySource(CONFIG, { clientFactory: fakeFactory(client) });
    await source.checkConnection();
    expect(client.binds[0]).toEqual({ dn: CONFIG.bindDN, password: CONFIG.bindPassword });
  });
});

/** Garde-fou de non-regression : ce module source ne journalise rien (pas de fuite de secret via logs). */
describe('BLUE — LDAP : le module ne journalise aucun secret', () => {
  it('aucune option de recherche ne transporte le mot de passe de bind', async () => {
    const client = new FakeLdapClient({ entries: [] });
    const source = new LdapDirectorySource(CONFIG, { clientFactory: fakeFactory(client) });
    await source.fetchEntries();
    const serialized = JSON.stringify(client.searches);
    expect(serialized).not.toContain(CONFIG.bindPassword);
  });
});
