import { describe, expect, it } from 'vitest';

import {
  ARCHIVE_LIMITS,
  assertArchiveEntries,
  type BundleEntryInput,
} from './index.js';

const bytes = new TextEncoder().encode('synthetic');
const entry = (path: string, overrides: Partial<BundleEntryInput> = {}): BundleEntryInput => ({
  path,
  bytes,
  executable: false,
  ...overrides,
});

describe('migration archive admission policy', () => {
  it('admits NFC UTF-8 source paths and an explicitly requested shebang script', () => {
    expect(() =>
      assertArchiveEntries([
        entry('app/café/page.tsx'),
        entry('scripts/build.mjs', {
          bytes: new TextEncoder().encode('#!/usr/bin/env node\n'),
          executable: true,
        }),
        entry('empty.txt', { bytes: new Uint8Array() }),
      ]),
    ).not.toThrow();
  });

  it.each([
    '',
    '/absolute',
    'C:/drive.txt',
    '//server/share',
    '../escape',
    'app/./page.tsx',
    'app//page.tsx',
    'app\\page.tsx',
    'app/pa\nge.tsx',
    'cafe\u0301.txt',
    'verow/payload-index.json',
    '.env',
    '.env.production',
    '.dev.vars.local',
    '.git/config',
    'node_modules/pkg/index.js',
    '.pnpm-store/v3/index',
    '.next/server/app.js',
    '.wrangler/state.json',
    '.vite/cache.json',
    'coverage/lcov.info',
    'dist/index.js',
    'build/output.js',
    '.history/page.tsx',
    '.bash_history',
    '.DS_Store',
    '.npmrc',
    '.pypirc',
    'keys/id_rsa',
    'keys/private.pem',
    'state/main.tfstate',
    '.move-to-verow/receipt.json',
    'fixture.zip',
    'bundle.tar.gz',
    'native/addon.node',
    'bin/program.exe',
    '.netrc',
    'config/secrets.json',
    'config/api-token.txt',
    'config/api-key.txt',
    'config/access_token.json',
    'config/client-secret.yaml',
    'config/credentials.json',
    'config/token.json',
    'config/service-account.json',
    'config/service_account_key.json',
    'config/service-account-credentials.json',
  ])('rejects forbidden candidate path %s with a content-free code', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it('does not confuse ordinary source names with credential material', () => {
    expect(() =>
      assertArchiveEntries([
        entry('styles/design-tokens.css'),
        entry('lib/tokenizer.ts'),
        entry('people/secretary.ts'),
        entry('styles/keyframes.css'),
        entry('lib/api-client.ts'),
      ]),
    ).not.toThrow();
  });

  it('rejects normalized, case-folded, long, deep and duplicate path collisions', () => {
    for (const entries of [
      [entry('App/Page.tsx'), entry('app/page.tsx')],
      [entry('straße.ts'), entry('strasse.ts')],
      [entry('same.ts'), entry('same.ts')],
      [entry(`${'a'.repeat(91)}.tsx`)],
      [entry(`d/${'a'.repeat(81)}`)],
      [entry(`${Array.from({ length: ARCHIVE_LIMITS.maxPathDepth + 1 }, () => 'a').join('/')}.tsx`)],
    ]) {
      expect(() => assertArchiveEntries(entries)).toThrow(/^bundle_entry_forbidden$/u);
    }
  });

  it('rejects hostile entry shapes without invoking accessors', () => {
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'path', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'secret';
      },
    });
    const symbolEntry = entry('app/page.tsx') as BundleEntryInput & { [key: symbol]: boolean };
    symbolEntry[Symbol('hidden')] = true;
    const sparse = Array(1) as BundleEntryInput[];

    for (const entries of [new Proxy([], {}), sparse, [accessor], [symbolEntry]]) {
      expect(() => assertArchiveEntries(entries as BundleEntryInput[])).toThrow(
        /^bundle_input_invalid$/u,
      );
    }
    expect(getterCalls).toBe(0);
  });

  it('rejects unsafe modes, views, executable data and binary magic', () => {
    const backing = new Uint8Array([1, 2]);
    const shared = new Uint8Array(new SharedArrayBuffer(1));
    for (const invalid of [
      entry('app/page.tsx', { executable: true }),
      entry('scripts/run.mjs', { executable: true, bytes: new TextEncoder().encode('no shebang') }),
      entry('asset.dat', { bytes: new Uint8Array([0x7f, 0x45, 0x4c, 0x46]) }),
      entry('app/page.tsx', { bytes: backing.subarray(1) }),
      entry('app/page.tsx', { bytes: Buffer.from('buffer') as Uint8Array }),
      entry('app/page.tsx', { bytes: shared }),
    ]) {
      expect(() => assertArchiveEntries([invalid])).toThrow(/^bundle_(?:entry_forbidden|input_invalid)$/u);
    }
  });

  it('rejects renamed archive signatures independently of their extension', () => {
    const tarBytes = new Uint8Array(262);
    tarBytes.set(new TextEncoder().encode('ustar'), 257);
    for (const [path, content] of [
      ['renamed-zip.txt', new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2])],
      ['renamed-gzip.txt', new Uint8Array([0x1f, 0x8b, 8, 0, 1, 2])],
      ['renamed-7z.txt', new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])],
      ['renamed-xz.txt', new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])],
      ['renamed-tar.txt', tarBytes],
    ] as const) {
      expect(() => assertArchiveEntries([entry(path, { bytes: content })])).toThrow(
        /^bundle_entry_forbidden$/u,
      );
    }
  });

  it('applies entry and byte limits with safe arithmetic', () => {
    expect(() =>
      assertArchiveEntries([entry('a.ts'), entry('b.ts')], {
        ...ARCHIVE_LIMITS,
        maxCandidateEntries: 1,
      }),
    ).toThrow(/^bundle_limit_exceeded$/u);
    expect(() =>
      assertArchiveEntries([entry('a.ts')], {
        ...ARCHIVE_LIMITS,
        maxSingleBytes: 1,
      }),
    ).toThrow(/^bundle_limit_exceeded$/u);
    expect(() =>
      assertArchiveEntries([entry('a.ts')], {
        maxCandidateEntries: ARCHIVE_LIMITS.maxCandidateEntries + 1,
      }),
    ).toThrow(/^bundle_input_invalid$/u);
  });

  it('admits the exact frozen candidate-entry boundary', () => {
    const entries = Array.from({ length: ARCHIVE_LIMITS.maxCandidateEntries }, (_, index) =>
      entry(`f/${index.toString().padStart(3, '0')}.ts`, { bytes: new Uint8Array() }),
    );
    expect(() => assertArchiveEntries(entries)).not.toThrow();
  });

  it('rejects an over-limit array before enumerating descriptors or observed items', () => {
    const originalDescriptors = Object.getOwnPropertyDescriptors;
    let descriptorReads = 0;
    let itemTraps = 0;
    const observedItem = new Proxy(entry('private.ts'), {
      ownKeys() {
        itemTraps += 1;
        throw new Error('private item trap');
      },
    });
    const oversized = Array.from(
      { length: ARCHIVE_LIMITS.maxCandidateEntries + 1 },
      () => observedItem,
    );
    Object.getOwnPropertyDescriptors = ((value: object) => {
      if (value === oversized) descriptorReads += 1;
      return originalDescriptors(value);
    }) as typeof Object.getOwnPropertyDescriptors;
    try {
      expect(() => assertArchiveEntries(oversized)).toThrow(/^bundle_limit_exceeded$/u);
    } finally {
      Object.getOwnPropertyDescriptors = originalDescriptors;
    }
    expect(descriptorReads).toBe(0);
    expect(itemTraps).toBe(0);

    const sparse = Array(ARCHIVE_LIMITS.maxCandidateEntries + 1) as BundleEntryInput[];
    Object.defineProperty(sparse, 0, {
      enumerable: true,
      get() {
        throw new Error('private accessor');
      },
    });
    expect(() => assertArchiveEntries(sparse)).toThrow(/^bundle_limit_exceeded$/u);
  });
});
