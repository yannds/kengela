// @ts-check
/**
 * write-dist-markers — pose les marqueurs de format de module dans les
 * sous-dossiers de build dual-package.
 *
 * Un paquet publie a `"type": "module"` a la racine. Le build ESM sort dans
 * `dist/esm` (herite donc de `type: module`) et le build CJS dans `dist/cjs`.
 * Pour que Node interprete `dist/cjs/*.js` comme du CommonJS, on ecrit un
 * `package.json` local `{"type":"commonjs"}` qui override la racine pour ce
 * sous-arbre (et symetriquement `{"type":"module"}` cote ESM par clarte).
 *
 * Usage : `node ../../scripts/write-dist-markers.mjs <distDir>`
 *   ou <distDir> est relatif au cwd du paquet (typiquement `dist`).
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const distArg = process.argv[2];
if (!distArg) {
  console.error('write-dist-markers: argument <distDir> manquant');
  process.exit(1);
}

const distDir = resolve(process.cwd(), distArg);

/** @type {ReadonlyArray<readonly [string, 'module' | 'commonjs']>} */
const markers = [
  ['esm', 'module'],
  ['cjs', 'commonjs'],
];

for (const [sub, type] of markers) {
  const dir = resolve(distDir, sub);
  mkdirSync(dir, { recursive: true });
  writeFileSync(resolve(dir, 'package.json'), `${JSON.stringify({ type }, null, 2)}\n`, 'utf8');
}
