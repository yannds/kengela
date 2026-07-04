# @kengela/adapter-expr-cel

> An `ExpressionEnginePort` adapter that evaluates authorization conditions with CEL (Common Expression Language).

This package implements the `ExpressionEnginePort` contract using CEL, so declarative policy conditions (for example `resource.attributes.agencyId == principal.agencyId`) are evaluated safely against the expression context. It is the adapter ring, and also ships date helpers usable from CEL expressions.

Part of [Kengela](https://github.com/yannds/kengela), a Zero Trust identity and access foundation for multi-tenant TypeScript apps (authentication + authorization + identity federation + compliance).

## Install

```sh
npm install @kengela/adapter-expr-cel
```

## Usage

```ts
import { CelExpressionEngine } from '@kengela/adapter-expr-cel';
import type { ExpressionContext } from '@kengela/contracts';

const engine = new CelExpressionEngine();

const allowed = engine.evaluateBoolean(
  'resource.attributes.agencyId == principal.agencyId',
  ctx satisfies ExpressionContext,
);
```

## Key exports

- `CelExpressionEngine` - the `ExpressionEnginePort` implementation backed by CEL.
- `CelEvaluationError` - thrown on invalid or failing expression evaluation.
- `toEpochMs`, `daysBetween`, `businessDaysBetween` - date helpers for CEL conditions.

## Documentation

Guides and recipes: https://github.com/yannds/kengela/wiki

## License

Apache-2.0
