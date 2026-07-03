import { describe, expect, it } from 'vitest';
import {
  accountActiveFromGoogle,
  accountActiveFromLdap,
  profileFromGoogle,
  profileFromGraph,
  profileFromLdap,
  profileFromOidcClaims,
  profileFromParts,
  profileFromSaml,
  profileFromScim,
} from '../src/profile.js';

describe('profileFromOidcClaims', () => {
  it('normalise des claims OIDC nominaux (Entra/Okta)', () => {
    const p = profileFromOidcClaims({
      email: 'Alice@Corp.COM',
      given_name: 'Alice',
      family_name: 'Martin',
      name: 'Alice Martin',
      sub: 'oidc-123',
      jobTitle: 'Directrice',
      department: 'RH',
      groups: ['grp-rh', 'grp-admin'],
      roles: ['approver'],
    });
    expect(p.email).toBe('alice@corp.com');
    expect(p.externalId).toBe('oidc-123');
    expect(p.firstName).toBe('Alice');
    expect(p.lastName).toBe('Martin');
    expect(p.displayName).toBe('Alice Martin');
    expect(p.attributes.title).toBe('Directrice');
    expect(p.attributes.department).toBe('RH');
    // groups agrege groups + roles + wids
    expect([...p.groups].sort()).toEqual(['approver', 'grp-admin', 'grp-rh']);
    expect(p.claims['sub']).toBe('oidc-123');
  });

  it('respecte la surcharge attributeMap', () => {
    const p = profileFromOidcClaims(
      { mail_addr: 'bob@corp.com', dept: 'Finance' },
      { email: 'mail_addr', department: 'dept' },
    );
    expect(p.email).toBe('bob@corp.com');
    expect(p.attributes.department).toBe('Finance');
  });
});

describe('profileFromScim', () => {
  it('normalise une ressource SCIM 2.0 core + extension enterprise', () => {
    const p = profileFromScim({
      userName: 'carol@corp.com',
      name: { givenName: 'Carol', familyName: 'Nguyen' },
      externalId: 'scim-9',
      emails: [{ value: 'other@corp.com' }, { value: 'carol@corp.com', primary: true }],
      groups: [{ display: 'Engineering', value: 'g1' }, 'Ops'],
      'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': {
        department: 'R&D',
        employeeNumber: 'E-42',
        manager: { value: 'manager@corp.com' },
      },
    });
    expect(p.email).toBe('carol@corp.com');
    expect(p.externalId).toBe('scim-9');
    expect(p.firstName).toBe('Carol');
    expect(p.lastName).toBe('Nguyen');
    expect(p.displayName).toBe('Carol Nguyen');
    expect(p.attributes.department).toBe('R&D');
    expect(p.attributes.employeeNumber).toBe('E-42');
    expect(p.attributes.manager).toBe('manager@corp.com');
    expect(p.groups).toEqual(['Engineering', 'Ops']);
  });
});

describe('profileFromSaml', () => {
  it('normalise une assertion SAML (claims ADFS URI + nameID)', () => {
    const p = profileFromSaml({
      nameId: 'dave@corp.com',
      attributes: {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'Dave',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'Owusu',
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups': ['GRP-A', 'GRP-B'],
        title: 'Analyste',
      },
    });
    expect(p.email).toBe('dave@corp.com');
    expect(p.externalId).toBe('dave@corp.com');
    expect(p.firstName).toBe('Dave');
    expect(p.lastName).toBe('Owusu');
    expect(p.displayName).toBe('Dave Owusu');
    expect(p.attributes.title).toBe('Analyste');
    expect(p.groups).toEqual(['GRP-A', 'GRP-B']);
  });
});

describe('profileFromLdap', () => {
  it('normalise une entree Active Directory (memberOf => CN, defauts AD)', () => {
    const p = profileFromLdap({
      dn: 'CN=Eve Diallo,OU=Users,DC=corp',
      attributes: {
        mail: 'eve@corp.com',
        givenName: 'Eve',
        sn: 'Diallo',
        title: 'Manager',
        objectGUID: 'guid-1',
        manager: 'CN=Boss,OU=Users,DC=corp',
        memberOf: ['CN=Groupe RH,OU=Groupes,DC=corp', 'CN=Admins,DC=corp'],
      },
    });
    expect(p.email).toBe('eve@corp.com');
    expect(p.externalId).toBe('guid-1');
    expect(p.firstName).toBe('Eve');
    expect(p.lastName).toBe('Diallo');
    expect(p.attributes.title).toBe('Manager');
    expect(p.attributes.manager).toBe('Boss');
    expect(p.groups).toEqual(['Groupe RH', 'Admins']);
  });

  it('accountActiveFromLdap lit le bit ACCOUNTDISABLE (0x2)', () => {
    const base = { dn: 'CN=x', attributes: {} as Record<string, string> };
    expect(accountActiveFromLdap(base)).toBe(true); // absent => actif
    expect(accountActiveFromLdap({ ...base, attributes: { userAccountControl: '514' } })).toBe(
      false,
    );
    expect(accountActiveFromLdap({ ...base, attributes: { userAccountControl: '512' } })).toBe(
      true,
    );
  });
});

describe('profileFromGraph', () => {
  it('normalise un utilisateur Microsoft Graph', () => {
    const p = profileFromGraph({
      id: 'graph-1',
      mail: 'frank@corp.com',
      userPrincipalName: 'frank@corp.onmicrosoft.com',
      givenName: 'Frank',
      surname: 'Okoro',
      displayName: 'Frank Okoro',
      jobTitle: 'Lead',
      department: 'IT',
      employeeId: 'E-7',
      groups: ['G1', 'G1', 'G2'],
    });
    expect(p.email).toBe('frank@corp.com');
    expect(p.externalId).toBe('graph-1');
    expect(p.attributes.title).toBe('Lead');
    expect(p.attributes.employeeNumber).toBe('E-7');
    expect(p.groups).toEqual(['G1', 'G2']); // dedupe
  });
});

describe('profileFromGoogle', () => {
  it('normalise un utilisateur Google Workspace (org primaire + relation manager)', () => {
    const p = profileFromGoogle({
      id: 'g-1',
      primaryEmail: 'Grace@corp.com',
      name: { givenName: 'Grace', familyName: 'Kone', fullName: 'Grace Kone' },
      organizations: [
        { department: 'Sales', title: 'Rep', primary: false },
        { department: 'Direction', title: 'VP', primary: true },
      ],
      relations: [{ type: 'manager', value: 'ceo@corp.com' }],
      groups: ['sales-team'],
    });
    expect(p.email).toBe('grace@corp.com');
    expect(p.externalId).toBe('g-1');
    expect(p.displayName).toBe('Grace Kone');
    expect(p.attributes.department).toBe('Direction'); // org primaire
    expect(p.attributes.title).toBe('VP');
    expect(p.attributes.manager).toBe('ceo@corp.com');
    expect(p.groups).toEqual(['sales-team']);
  });

  it('accountActiveFromGoogle lit suspended', () => {
    expect(accountActiveFromGoogle({ suspended: true })).toBe(false);
    expect(accountActiveFromGoogle({ suspended: false })).toBe(true);
    expect(accountActiveFromGoogle({})).toBe(true);
  });
});

describe('profileFromParts', () => {
  it('reconstruit un profil depuis l etat persiste (dedupe groupes, email minuscule)', () => {
    const p = profileFromParts({
      email: 'Henry@corp.com',
      externalId: 'x-1',
      firstName: 'Henry',
      groups: ['a', 'a', 'b'],
    });
    expect(p.email).toBe('henry@corp.com');
    expect(p.externalId).toBe('x-1');
    expect(p.lastName).toBeNull();
    expect(p.groups).toEqual(['a', 'b']);
    expect(p.claims).toEqual({});
  });
});
