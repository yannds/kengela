# DEBT.md — @kengela/scim-server

> Le cœur est honnête sur ce qu'il ne fait pas encore. Ce qui manque ou est partiel figure ici.

| # | Sujet | Etat | Probleme | Cible de migration | Prio |
|---|-------|------|----------|--------------------|------|
| 1 | Endpoints de découverte (`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`) | ABSENT | RFC 7644 §4 les recommande pour l'auto-configuration des IdP (capacités : filtrage, tri, PATCH, bulk, pagination). Non fournis : un IdP strict qui les interroge n'obtient pas de métadonnées. | Ajouter des handlers purs statiques décrivant les capacités réelles de ce cœur. | P2 |
| 2 | Filtres SCIM | limité à `eq` | Seuls `userName eq "..."` (Users) et `displayName eq "..."` (Groups) sont interprétés, via regex bornées (anti-ReDoS). Les opérateurs riches (`co`, `sw`, `pr`, `and`/`or`, `[]` complexes) sont ignorés : un filtre non supporté renvoie une liste vide, jamais une erreur. | Parser de filtres SCIM complet (arbre AST borné) mappé vers le port. | P2 |
| 3 | Intégration HTTP réelle | ABSENT (par conception) | Le paquet est framework-agnostique : les handlers sont purs (`req parsée → réponse`). Aucun câblage transport (routes, `application/scim+json`, auth Bearer, dérivation du tenant). | Adapter NestJS (ou Express) qui résout tenant + parse le corps + sérialise `ScimResponse`. | P1 |
| 4 | Extension enterprise + attributs riches | NON PORTÉS dans le cœur | La sérialisation expose le core User (identité, e-mail, active, meta). L'extension enterprise (department/manager…), les adresses, téléphones, rôles — présents dans `KengelaScimUser` / `projectScimUser` — ne sont ni relus ni réémis par ce cœur. | Étendre `ScimUserRow` + `toScimUser` (round-trip Entra/Okta) une fois la persistance d'attributs câblée dans l'adapter. | P2 |
| 5 | Tri (`sortBy`/`sortOrder`) | ABSENT | La pagination est fournie ; l'ordre des résultats suit l'ordre d'insertion du store. RFC 7644 §3.4.2.3 (tri) non implémenté. | Ajouter des options de tri au port `ScimStore` + parsing des paramètres. | P3 |
| 6 | Bulk (`/Bulk`) et ETag/versioning (`meta.version`) | ABSENT | Opérations groupées (RFC 7644 §3.7) et concurrence optimiste (`If-Match`) non gérées. `meta.version` n'est pas émis. | À évaluer selon les IdP cibles ; non requis par Entra/Okta pour un provisioning basique. | P3 |
