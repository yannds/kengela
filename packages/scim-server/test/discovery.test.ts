import { describe, expect, it } from 'vitest';
import {
  handleResourceTypes,
  handleSchemas,
  handleServiceProviderConfig,
  resourceTypes,
  schemaDefinitions,
  SCIM_SCHEMA_CORE_USER,
  SCIM_SCHEMA_ENTERPRISE_USER,
  SCIM_SCHEMA_GROUP,
  SCIM_SCHEMA_LIST_RESPONSE,
  SCIM_SCHEMA_RESOURCE_TYPE,
  SCIM_SCHEMA_SERVICE_PROVIDER_CONFIG,
  serviceProviderConfig,
} from '../src/index.js';

function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? (value as Record<string, unknown>[]) : [];
}

describe('handleServiceProviderConfig', () => {
  it('déclare les capacités réelles du cœur (patch on, bulk off, filter on, sort/etag off)', () => {
    const res = handleServiceProviderConfig();
    expect(res.status).toBe(200);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_SERVICE_PROVIDER_CONFIG]);

    const cfg = serviceProviderConfig();
    expect(cfg['patch']).toEqual({ supported: true });
    expect((cfg['bulk'] as Record<string, unknown>)['supported']).toBe(false);
    expect((cfg['filter'] as Record<string, unknown>)['supported']).toBe(true);
    expect((cfg['filter'] as Record<string, unknown>)['maxResults']).toBeGreaterThan(0);
    expect(cfg['changePassword']).toEqual({ supported: false });
    expect(cfg['sort']).toEqual({ supported: false });
    expect(cfg['etag']).toEqual({ supported: false });
  });

  it("expose un schéma d'authentification oauthbearertoken", () => {
    const schemes = records(serviceProviderConfig()['authenticationSchemes']);
    expect(schemes).toHaveLength(1);
    expect(schemes[0]?.['type']).toBe('oauthbearertoken');
    expect(schemes[0]?.['primary']).toBe(true);
  });

  it('porte un meta.resourceType ServiceProviderConfig', () => {
    const meta = serviceProviderConfig()['meta'] as Record<string, unknown>;
    expect(meta['resourceType']).toBe('ServiceProviderConfig');
  });
});

describe('handleResourceTypes', () => {
  it('renvoie un ListResponse avec User (/Users) et Group (/Groups)', () => {
    const res = handleResourceTypes();
    expect(res.status).toBe(200);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_LIST_RESPONSE]);

    const list = records(res.body?.['Resources']);
    const user = list.find((rt) => rt['id'] === 'User');
    const group = list.find((rt) => rt['id'] === 'Group');
    expect(user?.['endpoint']).toBe('/Users');
    expect(user?.['schema']).toBe(SCIM_SCHEMA_CORE_USER);
    expect(group?.['endpoint']).toBe('/Groups');
    expect(group?.['schema']).toBe(SCIM_SCHEMA_GROUP);
  });

  it("déclare l'extension enterprise sur le ResourceType User", () => {
    const user = resourceTypes().find((rt) => rt['id'] === 'User');
    const ext = records(user?.['schemaExtensions']);
    expect(ext[0]?.['schema']).toBe(SCIM_SCHEMA_ENTERPRISE_USER);
    expect(ext[0]?.['required']).toBe(false);
  });

  it('chaque ResourceType porte le bon urn de schéma', () => {
    for (const rt of resourceTypes()) {
      expect(rt['schemas']).toEqual([SCIM_SCHEMA_RESOURCE_TYPE]);
    }
  });

  it('renvoie une ressource unique par id (/ResourceTypes/User)', () => {
    const res = handleResourceTypes('User');
    expect(res.status).toBe(200);
    expect(res.body?.['id']).toBe('User');
  });

  it('renvoie 404 pour un id de ResourceType inconnu', () => {
    const res = handleResourceTypes('Ghost');
    expect(res.status).toBe(404);
    expect(res.body?.['status']).toBe('404');
  });
});

describe('handleSchemas', () => {
  it('renvoie un ListResponse contenant core User, enterprise et Group', () => {
    const res = handleSchemas();
    expect(res.status).toBe(200);
    expect(res.body?.['schemas']).toEqual([SCIM_SCHEMA_LIST_RESPONSE]);

    const ids = records(res.body?.['Resources']).map((s) => s['id']);
    expect(ids).toContain(SCIM_SCHEMA_CORE_USER);
    expect(ids).toContain(SCIM_SCHEMA_ENTERPRISE_USER);
    expect(ids).toContain(SCIM_SCHEMA_GROUP);
  });

  it('décrit userName comme requis, unique server, non caseExact (auto-description)', () => {
    const user = schemaDefinitions().find((s) => s['id'] === SCIM_SCHEMA_CORE_USER);
    const attrs = records(user?.['attributes']);
    const userName = attrs.find((a) => a['name'] === 'userName');
    expect(userName?.['required']).toBe(true);
    expect(userName?.['uniqueness']).toBe('server');
    expect(userName?.['caseExact']).toBe(false);
    expect(userName?.['mutability']).toBe('readWrite');
    expect(userName?.['returned']).toBe('default');
  });

  it('décrit active comme booléen et emails comme complexe multi-valué', () => {
    const user = schemaDefinitions().find((s) => s['id'] === SCIM_SCHEMA_CORE_USER);
    const attrs = records(user?.['attributes']);
    const active = attrs.find((a) => a['name'] === 'active');
    const emails = attrs.find((a) => a['name'] === 'emails');
    expect(active?.['type']).toBe('boolean');
    expect(emails?.['type']).toBe('complex');
    expect(emails?.['multiValued']).toBe(true);
    expect(records(emails?.['subAttributes']).map((s) => s['name'])).toContain('value');
  });

  it('décrit le schéma Group avec displayName requis et members multi-valué', () => {
    const group = schemaDefinitions().find((s) => s['id'] === SCIM_SCHEMA_GROUP);
    const attrs = records(group?.['attributes']);
    const displayName = attrs.find((a) => a['name'] === 'displayName');
    const members = attrs.find((a) => a['name'] === 'members');
    expect(displayName?.['required']).toBe(true);
    expect(members?.['multiValued']).toBe(true);
  });

  it('renvoie une définition unique par urn (/Schemas/:urn)', () => {
    const res = handleSchemas(SCIM_SCHEMA_GROUP);
    expect(res.status).toBe(200);
    expect(res.body?.['id']).toBe(SCIM_SCHEMA_GROUP);
  });

  it('renvoie 404 pour une urn de schéma inconnue', () => {
    const res = handleSchemas('urn:ietf:params:scim:schemas:core:2.0:Unknown');
    expect(res.status).toBe(404);
  });

  it('chaque attribut porte les métadonnées SCIM obligatoires', () => {
    for (const schema of schemaDefinitions()) {
      for (const attr of records(schema['attributes'])) {
        for (const key of [
          'name',
          'type',
          'multiValued',
          'required',
          'mutability',
          'returned',
          'uniqueness',
        ]) {
          expect(attr[key]).toBeDefined();
        }
      }
    }
  });
});
