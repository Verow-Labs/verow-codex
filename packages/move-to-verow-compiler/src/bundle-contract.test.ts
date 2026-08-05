import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import {
  bundleContractProvenance,
  canonicalDigest,
  canonicalDigestVectors,
  validateBundleDescriptor,
  validatePayloadIndex,
  verifyBundleContractArtifacts,
} from './bundle-contract.js';

const bundleSchemaBytes = readFileSync(
  new URL('../contracts/migration-bundle.schema.json', import.meta.url),
);
const bundleSchemaDigestBytes = readFileSync(
  new URL('../contracts/migration-bundle.schema.sha256', import.meta.url),
);
const canonicalVectorBytes = readFileSync(
  new URL('../contracts/canonical-digest-vectors.json', import.meta.url),
);

const validDescriptor = {
  version: 'move-to-verow.bundle.v1',
  migrationId: 'migration_01',
  websiteId: 'website_01',
  sourceDigest: `sha256:${'1'.repeat(64)}`,
  artifactDigest: `sha256:${'2'.repeat(64)}`,
  archiveFormat: 'tar_gzip_v1',
  sourceKind: 'codex_sites_local',
  framework: 'nextjs_app_router',
  fileCount: 2,
  totalBytes: 42,
  capabilityClaims: ['static_content'],
  privateManifestDigest: `sha256:${'3'.repeat(64)}`,
  evidenceDigest: `sha256:${'4'.repeat(64)}`,
};

const validPayloadIndex = {
  version: 'move-to-verow.payload-index.v1',
  entries: [
    {
      path: 'app/page.tsx',
      bytes: 20,
      digest: `sha256:${'5'.repeat(64)}`,
      mode: 0o644,
    },
    {
      path: 'public/logo.svg',
      bytes: 22,
      digest: `sha256:${'6'.repeat(64)}`,
      mode: 0o644,
    },
  ],
};

describe('reviewed webapp bundle contract', () => {
  it('uses the exact reviewed webapp bundle schema', () => {
    const digest = `sha256:${createHash('sha256').update(bundleSchemaBytes).digest('hex')}`;

    expect(digest).toBe(bundleContractProvenance.sha256);
    expect(bundleContractProvenance.sourceCommit).toMatch(/^[0-9a-f]{40}$/u);
    expect(validateBundleDescriptor(validDescriptor).valid).toBe(true);
    expect(
      validateBundleDescriptor({
        ...validDescriptor,
        artifactDigest: 'sha256:bad',
      }).valid,
    ).toBe(false);
    expect(validatePayloadIndex(validPayloadIndex).valid).toBe(true);
    expect(
      validatePayloadIndex({
        ...validPayloadIndex,
        entries: [...validPayloadIndex.entries].reverse(),
      }).valid,
    ).toBe(false);
    for (const vector of canonicalDigestVectors) {
      expect(canonicalDigest(vector.value)).toBe(vector.digest);
    }
  });

  it('matches the strict reviewed payload-index schema and canonical byte ordering', () => {
    expect(
      validatePayloadIndex({
        version: 'move-to-verow.payload-index.v1',
        entries: [],
      }).valid,
    ).toBe(true);
    expect(
      validatePayloadIndex({
        version: 'move-to-verow.payload-index.v1',
        entries: [
          {
            path: '\uE000.txt',
            bytes: 1,
            digest: `sha256:${'1'.repeat(64)}`,
            mode: 0o644,
          },
          {
            path: '\u{10000}.txt',
            bytes: 1,
            digest: `sha256:${'2'.repeat(64)}`,
            mode: 0o755,
          },
        ],
      }).valid,
    ).toBe(true);
    expect(
      validatePayloadIndex({
        version: 'move-to-verow.payload-index.v1',
        entries: [
          {
            path: 'cafe\u0301.txt',
            bytes: 1,
            digest: `sha256:${'1'.repeat(64)}`,
            mode: 0o644,
          },
          {
            path: 'café.txt',
            bytes: 1,
            digest: `sha256:${'2'.repeat(64)}`,
            mode: 0o644,
          },
        ],
      }).valid,
    ).toBe(false);
  });

  it.each([
    ['missing mode', { ...validPayloadIndex.entries[0], mode: undefined }],
    [
      'digest alias',
      {
        path: 'app/page.tsx',
        bytes: 20,
        sha256: `sha256:${'5'.repeat(64)}`,
        mode: 0o644,
      },
    ],
    ['extra entry key', { ...validPayloadIndex.entries[0], mediaType: 'text/plain' }],
    ['negative mode', { ...validPayloadIndex.entries[0], mode: -1 }],
    ['oversized mode', { ...validPayloadIndex.entries[0], mode: 0o10000 }],
    ['unsafe path', { ...validPayloadIndex.entries[0], path: 'app//page.tsx' }],
    ['dot segment', { ...validPayloadIndex.entries[0], path: 'app/./page.tsx' }],
    ['control character', { ...validPayloadIndex.entries[0], path: 'app/pa\nge.tsx' }],
    ['self entry', { ...validPayloadIndex.entries[0], path: 'verow/payload-index.json' }],
  ])('rejects payload entries with %s', (_label, entry) => {
    expect(
      validatePayloadIndex({
        version: 'move-to-verow.payload-index.v1',
        entries: [entry],
      }).valid,
    ).toBe(false);
  });

  it('rejects extra payload-index root keys', () => {
    expect(validatePayloadIndex({ ...validPayloadIndex, extra: true }).valid).toBe(false);
  });

  it('matches the reviewed canonical logical-value boundary without invoking accessors', () => {
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'secret', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'secret';
      },
    });
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    const withSymbol = { safe: true };
    Object.defineProperty(withSymbol, Symbol('hidden'), {
      value: true,
      enumerable: true,
    });
    const nonEnumerable = Object.defineProperty({}, 'hidden', {
      value: true,
      enumerable: false,
    });
    const extendedArray = [true] as unknown[] & { extra?: string };
    extendedArray.extra = 'not logical JSON';

    for (const invalid of [
      1.5,
      Number.MAX_SAFE_INTEGER + 1,
      new Proxy({}, {}),
      cycle,
      accessor,
      withSymbol,
      Array(1),
      extendedArray,
      nonEnumerable,
      new Date(0),
      new Uint8Array([1]),
    ]) {
      expect(() => canonicalDigest(invalid)).toThrow('logical canonical JSON');
    }
    expect(getterCalls).toBe(0);
  });

  it('verifies the schema digest file bytes against provenance', () => {
    expect(() =>
      verifyBundleContractArtifacts({
        schemaBytes: bundleSchemaBytes,
        schemaDigestBytes: bundleSchemaDigestBytes,
        vectorsBytes: canonicalVectorBytes,
        provenance: bundleContractProvenance,
      }),
    ).not.toThrow();
    expect(() =>
      verifyBundleContractArtifacts({
        schemaBytes: bundleSchemaBytes,
        schemaDigestBytes: Buffer.from(`${bundleSchemaDigestBytes.toString('utf8')} `),
        vectorsBytes: canonicalVectorBytes,
        provenance: bundleContractProvenance,
      }),
    ).toThrow('schema digest file provenance mismatch');
  });
});
