/**
 * Kengela — garde-fou d'architecture (ESM).
 * Le port est un sas, pas une planque : le CORE ne connait aucun vendor.
 * @type {import('dependency-cruiser').IConfiguration}
 */
export default {
  forbidden: [
    {
      name: 'core-no-vendor',
      severity: 'error',
      comment:
        'Les paquets CORE (contracts, authz-core, authn-core, iam-mapping, policy) ne doivent ' +
        'importer AUCUN vendor npm. Doctrine: zero techno en direct, tout derriere un port.',
      from: { path: '^packages/(contracts|authz-core|authn-core|iam-mapping|policy)/src' },
      to: {
        dependencyTypes: ['npm', 'npm-dev', 'npm-optional', 'npm-peer'],
        pathNot: ['^packages/'],
      },
    },
    {
      name: 'no-circular',
      severity: 'error',
      comment: 'Pas de dependance circulaire entre paquets.',
      from: {},
      to: { circular: true },
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    tsPreCompilationDeps: true,
    tsConfig: { fileName: 'tsconfig.base.json' },
  },
};
