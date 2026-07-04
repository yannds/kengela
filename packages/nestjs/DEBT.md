# DEBT.md - @kengela/nestjs

> The port is an airlock, not a hideout. Design boundaries and tracked debts.

| #   | Topic                         | State     | Note                                                                                                                                                                                                            | Target                                                                | Prio |
| --- | ----------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---- |
| 1   | Scoping by resource attribute | by design | The guard provides the resource at the TYPE level (+ tenant), not its attributes (agencyId of a specific instance). ABAC conditions on a loaded resource are checked at the service level via `pdp.check(...)`. | Optional decorator/extractor that reads a resource id from the params | P3   |
| 2   | tsconfig override             | assumed   | experimentalDecorators + emitDecoratorMetadata, isolatedDeclarations/verbatimModuleSyntax off (NestJS requirement)                                                                                              | -                                                                     | -    |
