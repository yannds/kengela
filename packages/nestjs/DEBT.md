# DEBT.md — @kengela/nestjs

> Le port est un sas, pas une planque. Frontieres de conception et dettes tracees.

| # | Sujet | Etat | Note | Cible | Prio |
|---|-------|------|------|-------|------|
| 1 | Scoping par attribut de ressource | par conception | Le guard fournit la ressource au niveau TYPE (+ tenant), pas ses attributs (agencyId d'une instance precise). Les conditions ABAC sur une ressource chargee se verifient au niveau service via `pdp.check(...)`. | Decorateur/extracteur optionnel qui lit un id de ressource depuis les params | P3 |
| 2 | tsconfig override | assume | experimentalDecorators + emitDecoratorMetadata, isolatedDeclarations/verbatimModuleSyntax off (exigence NestJS) | — | — |
