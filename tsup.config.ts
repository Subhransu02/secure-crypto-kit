import { defineConfig } from 'tsup';

export default defineConfig([
  // ESM build — FE only (browser-safe, no node:crypto)
  {
    entry: {
      'index':    'src/index.ts',
      'fe/index': 'src/fe/index.ts',
    },
    format:    ['esm'],
    outDir:    'dist/esm',
    dts:       false,
    sourcemap: true,
    clean:     true,
    treeshake: true,
    target:    'es2022',
    platform:  'browser',
  },
  // CJS build — FE only
  {
    entry: {
      'index':    'src/index.ts',
      'fe/index': 'src/fe/index.ts',
    },
    format:    ['cjs'],
    outDir:    'dist/cjs',
    dts:       false,
    sourcemap: true,
    treeshake: true,
    target:    'es2022',
    platform:  'browser',
  },
  // Type declarations — FE only (BE uses hand-written .d.ts)
  {
    entry: {
      'index':    'src/index.ts',
      'fe/index': 'src/fe/index.ts',
    },
    format:  ['esm'],
    outDir:  'dist/types',
    dts:     { only: true },
    clean:   false,
  },
]);
