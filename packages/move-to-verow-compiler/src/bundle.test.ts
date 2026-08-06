import { createHash } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { brotliCompressSync, gunzipSync } from 'node:zlib';

import { extract, pack, type Pack } from 'tar-stream';
import { describe, expect, it } from 'vitest';

import { canonicalDigest, validateBundleDescriptor, validatePayloadIndex } from './bundle-contract.js';
import {
  ARCHIVE_FORMAT,
  BUNDLE_FORMAT,
  PAYLOAD_INDEX_FORMAT,
  createMigrationBundle,
  type CreateMigrationBundleInput,
} from './index.js';
import { createDeterministicTarGzip } from './bundle.js';
import { digestFileInventory, makeInventoriedFile } from './inventory.js';
import {
  compileMigrationArtifacts,
  type CompileMigrationArtifactsInput,
  type CompiledMigrationArtifacts,
} from './manifest.js';

const encoder = new TextEncoder();
const sha256 = (value: string | Uint8Array): `sha256:${string}` =>
  `sha256:${createHash('sha256').update(value).digest('hex')}`;
const websiteId = '11111111-1111-4111-8111-111111111111';
const migrationId = '22222222-2222-4222-8222-222222222222';
const validPng = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL7qQAAAABJRU5ErkJggg==',
  'base64',
);
const validPng2x2 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAAEUlEQVR4nGP4z8DwH4QZYAwAR8oH+WdZbrcAAAAASUVORK5CYII=',
  'base64',
);
function syntheticWoff(): Buffer {
  const bytes = Buffer.alloc(68);
  bytes.write('wOFF', 0, 'ascii');
  bytes.writeUInt32BE(0x0001_0000, 4);
  bytes.writeUInt32BE(bytes.byteLength, 8);
  bytes.writeUInt16BE(1, 12);
  bytes.writeUInt32BE(32, 16);
  bytes.write('name', 44, 'ascii');
  bytes.writeUInt32BE(64, 48);
  bytes.writeUInt32BE(4, 52);
  bytes.writeUInt32BE(4, 56);
  return bytes;
}

function syntheticWoff2Bomb(): Buffer {
  const body = brotliCompressSync(Buffer.alloc(4));
  const bytes = Buffer.alloc(50 + body.byteLength);
  bytes.write('wOF2', 0, 'ascii');
  bytes.writeUInt32BE(0x0001_0000, 4);
  bytes.writeUInt32BE(bytes.byteLength, 8);
  bytes.writeUInt16BE(1, 12);
  bytes.writeUInt32BE(10_000_004, 16);
  bytes.writeUInt32BE(body.byteLength, 20);
  bytes[48] = 5;
  bytes[49] = 4;
  body.copy(bytes, 50);
  return bytes;
}
const sourceFiles = [
  makeInventoriedFile('app/page.tsx', encoder.encode('original source\n')),
  makeInventoriedFile('.openai/hosting.json', encoder.encode('{"version":1}\n')),
];
const sourceInventory = {
  format: 'move-to-verow.source-inventory.v1' as const,
  files: sourceFiles.map(({ path, bytes, digest }) => ({ path, bytes, digest })),
};
const sourceDigest = digestFileInventory(
  [...sourceFiles].sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path))),
);

const baseCandidate = [
  { path: 'app/page.tsx', bytes: encoder.encode('export default function Page(){return null}\n'), executable: false },
  { path: 'package.json', bytes: encoder.encode('{"private":true}\n'), executable: false },
  { path: 'scripts/build.mjs', bytes: encoder.encode('#!/usr/bin/env node\n'), executable: true },
];

function candidateDigest(candidate: readonly { path: string; bytes: Uint8Array }[] = baseCandidate): `sha256:${string}` {
  return digestFileInventory(
    [...candidate]
      .sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)))
      .map(({ path, bytes }) => makeInventoriedFile(path, bytes)),
  );
}

function artifacts(
  candidate: readonly { path: string; bytes: Uint8Array; executable: boolean }[] = baseCandidate,
): { compiled: CompiledMigrationArtifacts; assetBytes: Uint8Array } {
  const assetBytes = new Uint8Array(validPng);
  const assetDigest = sha256(assetBytes);
  const identity = { key: 'page.home.hero.image', locale: 'en', variant: null } as const;
  const compileInput: CompileMigrationArtifactsInput = {
    websiteId,
    migrationId,
    sourceDigest,
    candidateDigest: candidateDigest(candidate),
    cmsNativeProtocol: {
      package: '@verow/cms-native',
      version: '1.0.0',
      contractDigest: sha256('protocol'),
    },
    extraction: {
      status: 'ready',
      targets: [{ ...identity, label: 'Private image label', sourceKind: 'jsx', valueType: 'image', routeId: 'home', sourcePath: 'private/source/page.tsx', sourceAnchor: 'ast:private-anchor', thirdPartyBoundary: null, owner: 'site_region', structuredFamily: null }],
      values: { 'page.home.hero.image\u0000en\u0000': { ...identity, value: assetDigest } },
      structuredFamilies: [], thirdPartyBoundaries: [], derived: [], structural: [], needsAttention: [],
    },
    assets: {
      status: 'ready',
      bundled: [{ digest: assetDigest, bytes: assetBytes.byteLength, bytesValue: assetBytes, mime: 'image/png', encodedWidth: 1, encodedHeight: 1, renderedWidth: 1, renderedHeight: 1, pageCount: 1, animated: false, references: [{ id: 'hero', sourcePath: 'public/hero.png', target: identity, classification: 'editorial_cms', provenance: { authority: 'source_local', sourcePath: 'public/hero.png' } }] }],
      structural: [], external: [], blockers: [],
    },
    routes: [{ routeId: 'home', path: '/', renderedSource: 'page.home' }],
    policy: { targets: [{ ...identity, required: true, cardinality: 'one', actions: ['edit'], liveVerification: 'route', imagePair: null, collection: null }], collectionPolicy: [] },
  };
  return { compiled: compileMigrationArtifacts(compileInput), assetBytes };
}

function collectionArtifacts(
  candidate: readonly { path: string; bytes: Uint8Array; executable: boolean }[] = baseCandidate,
): CompiledMigrationArtifacts {
  const target = (
    key: string,
    valueType: 'collection' | 'string',
  ) => ({
    key,
    locale: 'en',
    variant: null,
    label: `Private ${key}`,
    sourceKind: 'jsx' as const,
    valueType,
    routeId: 'home',
    sourcePath: 'private/source/page.tsx',
    sourceAnchor: `ast:${key}`,
    thirdPartyBoundary: null,
    owner: 'site_region' as const,
    structuredFamily: null,
  });
  const root = target('page.home.cards', 'collection');
  const alpha = target('page.home.cards.items.alphaCard.heading', 'string');
  const beta = target('page.home.cards.items.betaCard.heading', 'string');
  const policy = (key: string) => ({
    key,
    locale: 'en',
    variant: null,
    required: true,
    cardinality: 'one' as const,
    actions: ['edit' as const],
    liveVerification: 'route' as const,
    imagePair: null,
    collection: null,
  });
  return compileMigrationArtifacts({
    websiteId,
    migrationId,
    sourceDigest,
    candidateDigest: candidateDigest(candidate),
    cmsNativeProtocol: {
      package: '@verow/cms-native',
      version: '1.0.0',
      contractDigest: sha256('protocol'),
    },
    extraction: {
      status: 'ready',
      targets: [root, alpha, beta],
      values: {
        [`${root.key}\u0000en\u0000`]: { key: root.key, locale: 'en', variant: null, value: '["alpha-card","beta-card"]' },
        [`${alpha.key}\u0000en\u0000`]: { key: alpha.key, locale: 'en', variant: null, value: 'Alpha' },
        [`${beta.key}\u0000en\u0000`]: { key: beta.key, locale: 'en', variant: null, value: 'Beta' },
      },
      structuredFamilies: [],
      thirdPartyBoundaries: [],
      derived: [],
      structural: [],
      needsAttention: [],
    },
    assets: { status: 'ready', bundled: [], structural: [], external: [], blockers: [] },
    routes: [{ routeId: 'home', path: '/', renderedSource: 'page.home' }],
    policy: {
      targets: [policy(root.key), policy(alpha.key), policy(beta.key)],
      collectionPolicy: [{
        key: root.key,
        locale: 'en',
        variant: null,
        minimumItems: 1,
        maximumItems: 4,
        requiredItemIds: ['alpha-card'],
      }],
    },
  });
}

function pairedImageArtifacts(
  candidate: readonly { path: string; bytes: Uint8Array; executable: boolean }[] = baseCandidate,
): { compiled: CompiledMigrationArtifacts; assetBytes: Uint8Array } {
  const assetBytes = new Uint8Array(validPng);
  const assetDigest = sha256(assetBytes);
  const image = { key: 'page.home.hero.image', locale: 'en', variant: null } as const;
  const alt = { key: 'page.home.hero.alt', locale: 'en', variant: null } as const;
  const target = (identity: typeof image | typeof alt, valueType: 'image' | 'string') => ({
    ...identity,
    label: `Private ${identity.key}`,
    sourceKind: 'jsx' as const,
    valueType,
    routeId: 'home',
    sourcePath: 'private/source/page.tsx',
    sourceAnchor: `ast:${identity.key}`,
    thirdPartyBoundary: null,
    owner: 'site_region' as const,
    structuredFamily: null,
  });
  const policy = (identity: typeof image | typeof alt, role: 'image' | 'alt', pair: typeof image | typeof alt) => ({
    ...identity,
    required: true,
    cardinality: 'one' as const,
    actions: ['edit' as const],
    liveVerification: 'route' as const,
    imagePair: { role, target: pair },
    collection: null,
  });
  return {
    assetBytes,
    compiled: compileMigrationArtifacts({
      websiteId,
      migrationId,
      sourceDigest,
      candidateDigest: candidateDigest(candidate),
      cmsNativeProtocol: {
        package: '@verow/cms-native',
        version: '1.0.0',
        contractDigest: sha256('protocol'),
      },
      extraction: {
        status: 'ready',
        targets: [target(image, 'image'), target(alt, 'string')],
        values: {
          [`${image.key}\u0000en\u0000`]: { ...image, value: assetDigest },
          [`${alt.key}\u0000en\u0000`]: { ...alt, value: 'Synthetic alt' },
        },
        structuredFamilies: [],
        thirdPartyBoundaries: [],
        derived: [],
        structural: [],
        needsAttention: [],
      },
      assets: {
        status: 'ready',
        bundled: [{
          digest: assetDigest,
          bytes: assetBytes.byteLength,
          bytesValue: assetBytes,
          mime: 'image/png',
          encodedWidth: 1,
          encodedHeight: 1,
          renderedWidth: 1,
          renderedHeight: 1,
          pageCount: 1,
          animated: false,
          references: [{
            id: 'hero',
            sourcePath: 'public/hero.png',
            target: image,
            classification: 'editorial_cms',
            provenance: { authority: 'source_local', sourcePath: 'public/hero.png' },
          }],
        }],
        structural: [],
        external: [],
        blockers: [],
      },
      routes: [{ routeId: 'home', path: '/', renderedSource: 'page.home' }],
      policy: {
        targets: [policy(image, 'image', alt), policy(alt, 'alt', image)],
        collectionPolicy: [],
      },
    }),
  };
}

function input(overrides: Partial<CreateMigrationBundleInput> = {}): CreateMigrationBundleInput {
  const built = artifacts();
  return {
    websiteId,
    migrationId,
    sourceDigest: built.compiled.privateManifest.sourceDigest,
    sourceInventory: {
      format: sourceInventory.format,
      files: sourceInventory.files.map((file) => ({ ...file })),
    },
    candidate: baseCandidate.map((entry) => ({ ...entry, bytes: new Uint8Array(entry.bytes) })),
    artifacts: built.compiled,
    editorialAssets: [{
      digest: built.compiled.contentFixture.editorialAssets[0]!.digest,
      bytes: new Uint8Array(built.assetBytes),
    }],
    dependencyInventory: {
      version: 'move-to-verow.dependency-inventory.v1',
      dependencies: [
        { name: 'next', version: '16.0.0', integrity: `sha512-${Buffer.alloc(64).toString('base64')}` },
        { name: 'react', version: '19.0.0', integrity: `sha512-${Buffer.alloc(64, 1).toString('base64')}` },
      ],
    },
    evidence: [
      { name: 'accessibility', value: { violations: 0, checked: true } },
      { name: 'static-verification', value: { routes: ['/', '/about'], valid: true } },
    ],
    ...overrides,
  };
}

function relinkArtifactDigests(compiled: CompiledMigrationArtifacts): void {
  compiled.digests.contentFixture = canonicalDigest(compiled.contentFixture);
  compiled.digests.privateManifest = canonicalDigest(compiled.privateManifest);
  compiled.repositoryBinding.privateManifestDigest = compiled.digests.privateManifest;
  compiled.digests.repositoryBinding = canonicalDigest(compiled.repositoryBinding);
  compiled.runtimeExpectation.expectedPrivateManifestDigest = compiled.digests.privateManifest;
  compiled.runtimeExpectation.expectedRepositoryBindingDigest = compiled.digests.repositoryBinding;
  compiled.digests.runtimeExpectation = canonicalDigest(compiled.runtimeExpectation);
}

interface ReadEntry {
  path: string;
  bytes: Buffer;
  mode: number;
  mtime: Date;
  uid: number;
  gid: number;
  uname: string;
  gname: string;
  type: string;
}

interface PhysicalHeader {
  name: string;
  type: string;
  checksum: number;
  computedChecksum: number;
}

function parseOctal(field: Uint8Array): number {
  const text = Buffer.from(field).toString('ascii').replace(/\0.*$/u, '').trim();
  return text === '' ? 0 : Number.parseInt(text, 8);
}

function readPhysicalHeaders(bytes: Uint8Array): PhysicalHeader[] {
  const tar = gunzipSync(bytes);
  const headers: PhysicalHeader[] = [];
  let offset = 0;
  let terminalBlocks = 0;
  while (offset + 512 <= tar.byteLength) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((value) => value === 0)) {
      terminalBlocks += 1;
      offset += 512;
      continue;
    }
    expect(terminalBlocks).toBe(0);
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    const nul = header.indexOf(0);
    const nameBytes = header.subarray(0, nul === -1 || nul > 100 ? 100 : nul);
    const size = parseOctal(header.subarray(124, 136));
    headers.push({
      name: new TextDecoder('utf-8', { fatal: true }).decode(nameBytes),
      type: String.fromCharCode(header[156] ?? 0),
      checksum: parseOctal(header.subarray(148, 156)),
      computedChecksum: checksumHeader.reduce((total, value) => total + value, 0),
    });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  expect(offset).toBe(tar.byteLength);
  expect(terminalBlocks).toBe(2);
  return headers;
}

function terminalPack(kind: 'empty-end' | 'truncated-end' | 'close'): Pack {
  const stream = new PassThrough();
  const archive = stream as unknown as Pack;
  archive.entry = ((_header, _bytes, callback) => {
    callback();
  }) as Pack['entry'];
  archive.finalize = () => {
    if (kind === 'truncated-end') stream.write(Buffer.alloc(512));
    if (kind === 'close') stream.destroy();
    else stream.end();
  };
  return archive;
}

async function readArchive(bytes: Uint8Array): Promise<ReadEntry[]> {
  const entries: ReadEntry[] = [];
  const parser = extract();
  const complete = new Promise<void>((resolve, reject) => {
    parser.on('entry', (header, stream, next) => {
      const chunks: Buffer[] = [];
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('error', reject);
      stream.on('end', () => {
        entries.push({
          path: header.name,
          bytes: Buffer.concat(chunks),
          mode: header.mode ?? -1,
          mtime: header.mtime ?? new Date(-1),
          uid: header.uid ?? -1,
          gid: header.gid ?? -1,
          uname: header.uname ?? '',
          gname: header.gname ?? '',
          type: header.type ?? '',
        });
        next();
      });
      stream.resume();
    });
    parser.once('finish', resolve);
    parser.once('error', reject);
  });
  parser.end(gunzipSync(bytes));
  await complete;
  return entries;
}

describe('deterministic migration bundle', () => {
  it('produces identical bytes and valid adjacent/index contracts', async () => {
    const first = await createMigrationBundle(input());
    const second = await createMigrationBundle(input());

    expect(first.bytes).toEqual(second.bytes);
    expect(first.artifactDigest).toBe(second.artifactDigest);
    expect(first.artifactDigest).toBe(sha256(first.bytes));
    expect(first.manifest).toEqual(second.manifest);
    expect(first.manifest.version).toBe(BUNDLE_FORMAT);
    expect(first.manifest.archiveFormat).toBe(ARCHIVE_FORMAT);
    expect(first.manifest.capabilityClaims).toEqual(['inline_edit', 'preview']);
    expect(first.payloadIndex.version).toBe(PAYLOAD_INDEX_FORMAT);
    expect(validateBundleDescriptor(first.manifest)).toEqual({ valid: true, errors: [] });
    expect(validatePayloadIndex(first.payloadIndex)).toEqual({ valid: true, errors: [] });
  });

  it('canonicalizes every input collection and logical property order', async () => {
    const original = input();
    const reordered = input({
      candidate: [...original.candidate].reverse(),
      editorialAssets: [...original.editorialAssets].reverse(),
      evidence: [...original.evidence].reverse().map((item) => ({ value: { ...item.value as object }, name: item.name })),
      sourceInventory: {
        format: original.sourceInventory.format,
        files: [...original.sourceInventory.files].reverse(),
      },
      dependencyInventory: {
        dependencies: [...original.dependencyInventory.dependencies].reverse(),
        version: original.dependencyInventory.version,
      },
      artifacts: {
        ...original.artifacts,
        contentFixture: { ...original.artifacts.contentFixture, editorialAssets: [...original.artifacts.contentFixture.editorialAssets].reverse(), values: [...original.artifacts.contentFixture.values].reverse() },
      },
    });
    expect((await createMigrationBundle(reordered)).bytes).toEqual(
      (await createMigrationBundle(original)).bytes,
    );
  });

  it('writes only canonical regular-file entries and a fixed gzip header', async () => {
    const result = await createMigrationBundle(input());
    const entries = await readArchive(result.bytes);
    const paths = entries.map(({ path }) => path);
    expect(paths).toEqual([...paths].sort((a, b) => Buffer.from(a).compare(Buffer.from(b))));
    expect(result.bytes.slice(0, 10)).toEqual(new Uint8Array([31, 139, 8, 0, 0, 0, 0, 0, 2, 3]));
    for (const entry of entries) {
      expect(entry.type).toBe('file');
      expect(entry.mtime.getTime()).toBe(0);
      expect(entry.uid).toBe(0);
      expect(entry.gid).toBe(0);
      expect(entry.uname).toBe('');
      expect(entry.gname).toBe('');
      expect([0o644, 0o755]).toContain(entry.mode);
    }
    expect(paths.some((path) => path.endsWith('/'))).toBe(false);
    expect(paths.some((path) => path.includes('PaxHeader'))).toBe(false);
  });

  it('writes an NFC UTF-8 path directly in one checksummed USTAR header without PAX', async () => {
    const candidate = [
      ...baseCandidate,
      { path: 'public/café.txt', bytes: encoder.encode('bonjour\n'), executable: false },
    ];
    const result = await createMigrationBundle(
      input({ candidate, artifacts: artifacts(candidate).compiled }),
    );
    const physical = readPhysicalHeaders(result.bytes);
    const extracted = await readArchive(result.bytes);

    expect(physical.map(({ name }) => name)).toEqual(extracted.map(({ path }) => path));
    expect(physical).toHaveLength(result.payloadIndex.entries.length + 1);
    expect(physical.find(({ name }) => name === 'candidate/public/café.txt')).toBeDefined();
    expect(physical.some(({ type }) => ['x', 'g', 'L', 'K'].includes(type))).toBe(false);
    expect(physical.every(({ type }) => type === '0')).toBe(true);
    expect(physical.every(({ checksum, computedChecksum }) => checksum === computedChecksum)).toBe(true);
  });

  it('indexes every other uncompressed entry exactly once and keeps the outer descriptor adjacent', async () => {
    const result = await createMigrationBundle(input());
    const entries = await readArchive(result.bytes);
    const byPath = new Map(entries.map((entry) => [entry.path, entry]));
    expect(result.payloadIndex.entries).toHaveLength(entries.length - 1);
    expect(result.payloadIndex.entries.some(({ path }) => path === 'verow/payload-index.json')).toBe(false);
    for (const indexed of result.payloadIndex.entries) {
      const entry = byPath.get(indexed.path)!;
      expect(indexed.bytes).toBe(entry.bytes.byteLength);
      expect(indexed.digest).toBe(sha256(entry.bytes));
      expect(indexed.mode).toBe(entry.mode);
    }
    expect(result.manifest.fileCount).toBe(entries.length);
    expect(result.manifest.totalBytes).toBe(result.bytes.byteLength);
    const archiveText = entries.map(({ bytes }) => bytes.toString('utf8')).join('\n');
    expect(archiveText).not.toContain(result.artifactDigest);
    expect(archiveText).not.toContain(BUNDLE_FORMAT);
  });

  it('changes payload, archive and evidence claims only from admitted changes', async () => {
    const first = await createMigrationBundle(input());
    const changedCandidate = input({ candidate: baseCandidate.map((entry, index) => index === 0 ? { ...entry, bytes: encoder.encode('export default 1\n') } : entry) });
    changedCandidate.artifacts = artifacts(changedCandidate.candidate).compiled;
    changedCandidate.sourceDigest = changedCandidate.artifacts.privateManifest.sourceDigest;
    changedCandidate.editorialAssets = input().editorialAssets;
    const second = await createMigrationBundle(changedCandidate);
    const changedEvidence = await createMigrationBundle(input({ evidence: [{ name: 'accessibility', value: { violations: 1 } }] }));
    expect(second.artifactDigest).not.toBe(first.artifactDigest);
    expect(second.payloadIndex.entries.find(({ path }) => path === 'candidate/app/page.tsx')?.digest).not.toBe(
      first.payloadIndex.entries.find(({ path }) => path === 'candidate/app/page.tsx')?.digest,
    );
    expect(changedEvidence.manifest.evidenceDigest).not.toBe(first.manifest.evidenceDigest);
    expect(changedEvidence.artifactDigest).not.toBe(first.artifactDigest);
  });

  it('keeps candidate source separate from upload-only private material', async () => {
    const result = await createMigrationBundle(input());
    const entries = await readArchive(result.bytes);
    const paths = entries.map(({ path }) => path);
    expect(paths).toContain('verow/artifacts/content-fixture.json');
    expect(paths).toContain('verow/artifacts/private-manifest.json');
    expect(paths).toContain('verow/artifacts/capability-claims.json');
    expect(paths).toContain('verow/artifacts/evidence-index.json');
    expect(paths).toContain('verow/evidence/source-inventory.json');
    expect(paths).toContain('verow/assets/' + input().editorialAssets[0]!.digest.slice(7));
    const candidateText = entries.filter(({ path }) => path.startsWith('candidate/')).map(({ bytes }) => bytes.toString()).join('\n');
    for (const forbidden of ['Private image label', 'ast:private-anchor', 'private/source/page.tsx']) {
      expect(candidateText).not.toContain(forbidden);
    }
  });

  it.each([
    ['website id', (value: CreateMigrationBundleInput) => { value.artifacts.contentFixture.websiteId = 'SECRET_INVALID'; }],
    ['migration id', (value: CreateMigrationBundleInput) => { value.artifacts.contentFixture.migrationId = 'SECRET_INVALID'; }],
    ['source digest', (value: CreateMigrationBundleInput) => { value.sourceDigest = sha256('changed'); }],
    ['candidate digest', (value: CreateMigrationBundleInput) => { value.artifacts.privateManifest.candidateDigest = sha256('changed'); }],
    ['private link', (value: CreateMigrationBundleInput) => { value.artifacts.repositoryBinding.privateManifestDigest = sha256('changed'); }],
    ['runtime private link', (value: CreateMigrationBundleInput) => { value.artifacts.runtimeExpectation.expectedPrivateManifestDigest = sha256('changed'); }],
    ['runtime repository link', (value: CreateMigrationBundleInput) => { value.artifacts.runtimeExpectation.expectedRepositoryBindingDigest = sha256('changed'); }],
    ['content digest', (value: CreateMigrationBundleInput) => { value.artifacts.digests.contentFixture = sha256('changed'); }],
    ['private digest', (value: CreateMigrationBundleInput) => { value.artifacts.digests.privateManifest = sha256('changed'); }],
    ['repository digest', (value: CreateMigrationBundleInput) => { value.artifacts.digests.repositoryBinding = sha256('changed'); }],
    ['runtime digest', (value: CreateMigrationBundleInput) => { value.artifacts.digests.runtimeExpectation = sha256('changed'); }],
    ['protocol', (value: CreateMigrationBundleInput) => { value.artifacts.repositoryBinding.cmsNativeProtocol.version = '2.0.0'; }],
  ])('rejects cross-artifact mismatch: %s', async (_label, mutate) => {
    const invalid = structuredClone(input());
    mutate(invalid);
    await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_contract_invalid$/u);
  });

  it.each([
    ['fixture purpose', (value: CreateMigrationBundleInput) => {
      (value.artifacts.contentFixture as { purpose: string }).purpose = 'SYNTHETIC_PRIVATE_PURPOSE';
    }],
    ['binding kind', (value: CreateMigrationBundleInput) => {
      (value.artifacts.privateManifest.targets[0]!.binding as { kind: string }).kind = 'private_kind';
    }],
    ['binding key', (value: CreateMigrationBundleInput) => {
      value.artifacts.privateManifest.targets[0]!.binding.key = 'private.other.key';
    }],
    ['protocol package', (value: CreateMigrationBundleInput) => {
      for (const protocol of [
        value.artifacts.privateManifest.cmsNativeProtocol,
        value.artifacts.repositoryBinding.cmsNativeProtocol,
        value.artifacts.runtimeExpectation.cmsNativeProtocol,
      ]) {
        (protocol as { package: string }).package = '@private/forged';
      }
    }],
    ['numeric actions', (value: CreateMigrationBundleInput) => {
      value.artifacts.privateManifest.targets[0]!.actions = [1, 2] as never;
    }],
    ['runtime strategy', (value: CreateMigrationBundleInput) => {
      (value.artifacts.repositoryBinding.runtimeBinding as { strategy: string }).strategy = 'private_strategy';
    }],
    ['runtime identity version', (value: CreateMigrationBundleInput) => {
      (value.artifacts.repositoryBinding.runtimeBinding as { identityVersion: number }).identityVersion = 2;
    }],
    ['negative runtime count', (value: CreateMigrationBundleInput) => {
      value.artifacts.runtimeExpectation.counts.routes = -1;
    }],
    ['unused structured family', (value: CreateMigrationBundleInput) => {
      value.artifacts.privateManifest.structuredFamilies = ['blog'];
      value.artifacts.runtimeExpectation.counts.structuredFamilies = 1;
    }],
    ['collection policy on an image', (value: CreateMigrationBundleInput) => {
      value.artifacts.privateManifest.targets[0]!.collection = {
        minimumItems: 0,
        maximumItems: 1,
        requiredItemIds: [],
      };
    }],
    ['image value detached from its editorial digest', (value: CreateMigrationBundleInput) => {
      value.artifacts.contentFixture.values[0]!.value = sha256('private detached value');
    }],
  ])('rejects semantically forged Task 4 artifact fields: %s', async (_label, mutate) => {
    const invalid = structuredClone(input());
    mutate(invalid);
    relinkArtifactDigests(invalid.artifacts);
    try {
      await createMigrationBundle(invalid);
      throw new Error('expected rejection');
    } catch (error) {
      expect(String(error)).toBe('Error: bundle_contract_invalid');
      expect(String(error)).not.toContain('SYNTHETIC_PRIVATE');
    }
  });

  it('rejects a rehashed private or non-canonical external asset URL', async () => {
    const invalid = structuredClone(input());
    const target = invalid.artifacts.privateManifest.targets[0]!;
    const identity = { key: target.key, locale: target.locale, variant: target.variant };
    const privateUrl = 'https://localhost/private-image.png';
    invalid.artifacts.contentFixture.editorialAssets = [];
    invalid.artifacts.contentFixture.externalAssets = [{ target: identity, url: privateUrl }];
    invalid.artifacts.contentFixture.values[0]!.value = privateUrl;
    target.editorialAssetDigest = null;
    target.externalBoundary = 'private-test-boundary';
    target.externalUrl = privateUrl;
    invalid.editorialAssets = [];
    relinkArtifactDigests(invalid.artifacts);
    await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_contract_invalid$/u);
  });

  it('revalidates collection fixture JSON, policy bounds, and exact stable-id child closure', async () => {
    const compiled = collectionArtifacts();
    await expect(createMigrationBundle(input({ artifacts: compiled, editorialAssets: [] }))).resolves.toBeDefined();

    for (const rootValue of [
      'not-json',
      '[]',
      '["alpha-card","alpha-card"]',
      '["beta-card","alpha-card"]',
    ]) {
      const invalid = input({ artifacts: structuredClone(compiled), editorialAssets: [] });
      invalid.artifacts.contentFixture.values.find(({ key }) => key === 'page.home.cards')!.value = rootValue;
      relinkArtifactDigests(invalid.artifacts);
      await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_contract_invalid$/u);
    }

    const missingChild = input({ artifacts: structuredClone(compiled), editorialAssets: [] });
    const betaKey = 'page.home.cards.items.betaCard.heading';
    missingChild.artifacts.contentFixture.values = missingChild.artifacts.contentFixture.values.filter(
      ({ key }) => key !== betaKey,
    );
    missingChild.artifacts.privateManifest.targets = missingChild.artifacts.privateManifest.targets.filter(
      ({ key }) => key !== betaKey,
    );
    missingChild.artifacts.repositoryBinding.bindings = missingChild.artifacts.repositoryBinding.bindings.filter(
      ({ key }) => key !== betaKey,
    );
    missingChild.artifacts.runtimeExpectation.counts.editableTargets -= 1;
    relinkArtifactDigests(missingChild.artifacts);
    await expect(createMigrationBundle(missingChild)).rejects.toThrow(/^bundle_contract_invalid$/u);
  });

  it('requires inferred image and alt targets to retain reciprocal Task 4 pairing', async () => {
    const paired = pairedImageArtifacts();
    const valid = input({
      artifacts: paired.compiled,
      editorialAssets: [{
        digest: paired.compiled.contentFixture.editorialAssets[0]!.digest,
        bytes: paired.assetBytes,
      }],
    });
    await expect(createMigrationBundle(valid)).resolves.toBeDefined();

    const invalid = structuredClone(valid);
    for (const target of invalid.artifacts.privateManifest.targets) target.imagePair = null;
    relinkArtifactDigests(invalid.artifacts);
    await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_contract_invalid$/u);
  });

  it('rejects missing, extra, duplicate, mismatched, external and structural editorial blobs', async () => {
    const valid = input();
    const digest = valid.editorialAssets[0]!.digest;
    for (const editorialAssets of [
      [],
      [...valid.editorialAssets, { digest: sha256('extra'), bytes: encoder.encode('extra') }],
      [...valid.editorialAssets, valid.editorialAssets[0]!],
      [{ digest, bytes: encoder.encode('wrong') }],
    ]) {
      await expect(createMigrationBundle(input({ editorialAssets }))).rejects.toThrow(
        /^bundle_contract_invalid$/u,
      );
    }
    const structural = structuredClone(valid);
    structural.artifacts.privateManifest.structuralAssets = [{ digest, mime: 'image/png', references: [] }];
    structural.artifacts.digests.privateManifest = canonicalDigest(structural.artifacts.privateManifest);
    structural.artifacts.repositoryBinding.privateManifestDigest = structural.artifacts.digests.privateManifest;
    structural.artifacts.digests.repositoryBinding = canonicalDigest(structural.artifacts.repositoryBinding);
    structural.artifacts.runtimeExpectation.expectedPrivateManifestDigest = structural.artifacts.digests.privateManifest;
    structural.artifacts.runtimeExpectation.expectedRepositoryBindingDigest = structural.artifacts.digests.repositoryBinding;
    structural.artifacts.digests.runtimeExpectation = canonicalDigest(structural.artifacts.runtimeExpectation);
    await expect(createMigrationBundle(structural)).rejects.toThrow(/^bundle_contract_invalid$/u);
    await expect(
      createMigrationBundle(
        input({
          editorialAssets: [{ digest, bytes: new Uint8Array(25_000_001) }],
        }),
      ),
    ).rejects.toThrow(/^bundle_limit_exceeded$/u);
  });

  it('rejects dependency/evidence limits, limits and logical values', async () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    for (const invalid of [
      input({ evidence: [{ name: 'bad/name', value: true }] }),
      input({ evidence: [{ name: 'cycle', value: cycle as never }] }),
      input({ limits: { maxEntries: 0 } }),
      input({ limits: { maxEntries: Number.MAX_SAFE_INTEGER } }),
      input({ limits: { maxCapabilities: 1 } }),
      input({ limits: { maxEvidenceEntries: 2 } }),
      input({ dependencyInventory: { version: 'move-to-verow.dependency-inventory.v1', dependencies: [{ name: 'pkg', version: '1.0.0', integrity: 'bad' }] } }),
    ]) {
      await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_(?:input_invalid|limit_exceeded)$/u);
    }
  });

  it('recomputes and closes the original source inventory', async () => {
    const reordered = input({
      sourceInventory: { ...sourceInventory, files: [...sourceInventory.files].reverse() },
    });
    expect((await createMigrationBundle(reordered)).bytes).toEqual(
      (await createMigrationBundle(input())).bytes,
    );

    const missing = input({
      sourceInventory: { ...sourceInventory, files: sourceInventory.files.slice(1) },
    });
    const tampered = input({
      sourceInventory: {
        ...sourceInventory,
        files: sourceInventory.files.map((file, index) =>
          index === 0 ? { ...file, bytes: file.bytes + 1 } : file,
        ),
      },
    });
    const extra = input({
      sourceInventory: {
        ...sourceInventory,
        files: [...sourceInventory.files, { path: 'extra.ts', bytes: 0, digest: sha256('') }],
      },
    });
    for (const invalid of [missing, tampered, extra]) {
      await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_contract_invalid$/u);
    }

    const caseCollision = input({
      sourceInventory: {
        ...sourceInventory,
        files: [
          { path: 'App/Page.tsx', bytes: 1, digest: sha256('a') },
          { path: 'app/page.tsx', bytes: 1, digest: sha256('b') },
        ],
      },
    });
    await expect(createMigrationBundle(caseCollision)).rejects.toThrow(/^bundle_input_invalid$/u);
    const oversizedRecord = input({
      sourceInventory: {
        ...sourceInventory,
        files: [{ path: 'large.ts', bytes: 25_000_001, digest: sha256('large') }],
      },
    });
    await expect(createMigrationBundle(oversizedRecord)).rejects.toThrow(/^bundle_limit_exceeded$/u);
  });

  it('embeds exact server-recomputable capability and evidence declarations', async () => {
    const result = await createMigrationBundle(input({ evidence: [] }));
    const entries = await readArchive(result.bytes);
    const byPath = new Map(
      entries
        .filter(({ path }) => path.endsWith('.json') && !path.startsWith('candidate/'))
        .map(({ path, bytes }) => [path, JSON.parse(bytes.toString('utf8')) as unknown]),
    );
    expect(byPath.get('verow/artifacts/capability-claims.json')).toEqual({
      format: 'move-to-verow.capability-claims.v1',
      claims: ['inline_edit', 'preview'],
    });
    const evidenceIndex = byPath.get('verow/artifacts/evidence-index.json') as {
      format: string;
      entries: Array<{ path: string; bytes: number; digest: string }>;
    };
    expect(evidenceIndex.format).toBe('move-to-verow.evidence-index.v1');
    expect(evidenceIndex.entries.map(({ path }) => path)).toEqual([
      'verow/evidence/source-inventory.json',
    ]);
    expect(result.manifest.evidenceDigest).toBe(canonicalDigest(evidenceIndex));
    expect(JSON.stringify(evidenceIndex)).not.toContain(result.artifactDigest);
    expect(JSON.stringify(result.payloadIndex)).not.toContain(result.artifactDigest);
  });

  it('enforces compressed-size and expansion-ratio boundaries after archive creation', async () => {
    const baseline = await createMigrationBundle(input());
    await expect(
      createMigrationBundle(input({ limits: { maxCompressedBytes: baseline.bytes.byteLength } })),
    ).resolves.toBeDefined();
    await expect(
      createMigrationBundle(
        input({ limits: { maxCompressedBytes: baseline.bytes.byteLength - 1 } }),
      ),
    ).rejects.toThrow(/^bundle_limit_exceeded$/u);

    const bombCandidate = [
      ...baseCandidate,
      { path: 'public/repeated.txt', bytes: encoder.encode('a'.repeat(1_000_000)), executable: false },
    ];
    await expect(
      createMigrationBundle(
        input({ candidate: bombCandidate, artifacts: artifacts(bombCandidate).compiled }),
      ),
    ).rejects.toThrow(/^bundle_limit_exceeded$/u);
  });

  it('stores one editorial blob shared by target references and rejects duplicate blob inputs', async () => {
    const shared = structuredClone(input());
    const first = shared.artifacts.contentFixture.editorialAssets[0]!;
    const secondTarget = { key: 'page.about.hero.image', locale: 'en', variant: null };
    shared.artifacts.contentFixture.editorialAssets.push({ digest: first.digest, target: secondTarget });
    shared.artifacts.contentFixture.values.push({ ...secondTarget, value: first.digest });
    const privateTarget = structuredClone(shared.artifacts.privateManifest.targets[0]!);
    privateTarget.key = secondTarget.key;
    privateTarget.binding.key = secondTarget.key;
    privateTarget.editorialAssetDigest = first.digest;
    shared.artifacts.privateManifest.targets.push(privateTarget);
    shared.artifacts.repositoryBinding.bindings.push(secondTarget);
    shared.artifacts.runtimeExpectation.counts.editableTargets += 1;
    const compareIdentity = (left: { key: string; locale: string; variant: string | null }, right: { key: string; locale: string; variant: string | null }) =>
      Buffer.from(`${left.key}\u0000${left.locale}\u0000${left.variant ?? ''}`).compare(
        Buffer.from(`${right.key}\u0000${right.locale}\u0000${right.variant ?? ''}`),
      );
    shared.artifacts.contentFixture.values.sort(compareIdentity);
    shared.artifacts.contentFixture.editorialAssets.sort((left, right) =>
      compareIdentity(left.target, right.target),
    );
    shared.artifacts.privateManifest.targets.sort(compareIdentity);
    shared.artifacts.repositoryBinding.bindings.sort(compareIdentity);
    relinkArtifactDigests(shared.artifacts);

    const result = await createMigrationBundle(shared);
    expect(
      (await readArchive(result.bytes)).filter(({ path }) => path.startsWith('verow/assets/')),
    ).toHaveLength(1);
    await expect(
      createMigrationBundle({
        ...shared,
        editorialAssets: [shared.editorialAssets[0]!, shared.editorialAssets[0]!],
      }),
    ).rejects.toThrow(/^bundle_contract_invalid$/u);
  });

  it('requires structural references to close over exact candidate bytes', async () => {
    const structuralBytes = encoder.encode(
      '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>',
    );
    const structuralPath = 'public/mark.svg';
    const candidate = [
      ...baseCandidate,
      { path: structuralPath, bytes: structuralBytes, executable: false },
    ];
    const valid = input({ candidate, artifacts: artifacts(candidate).compiled });
    valid.artifacts.privateManifest.structuralAssets = [
      {
        digest: sha256(structuralBytes),
        mime: 'image/svg+xml',
        references: [{ id: 'mark', sourcePath: structuralPath }],
      },
    ];
    relinkArtifactDigests(valid.artifacts);
    await expect(createMigrationBundle(valid)).resolves.toBeDefined();

    const missing = structuredClone(valid);
    missing.artifacts.privateManifest.structuralAssets[0]!.references[0]!.sourcePath =
      'public/missing.svg';
    relinkArtifactDigests(missing.artifacts);
    await expect(createMigrationBundle(missing)).rejects.toThrow(/^bundle_contract_invalid$/u);

    const wrong = structuredClone(valid);
    wrong.candidate.find(({ path }) => path === structuralPath)!.bytes = encoder.encode('<svg/>');
    await expect(createMigrationBundle(wrong)).rejects.toThrow(/^bundle_contract_invalid$/u);

    const fontBytes = new Uint8Array(syntheticWoff());
    const fontPath = 'public/font.woff';
    const fontCandidate = [
      ...baseCandidate,
      { path: fontPath, bytes: fontBytes, executable: false },
    ];
    const unclosedFont = input({
      candidate: fontCandidate,
      artifacts: artifacts(fontCandidate).compiled,
    });
    await expect(createMigrationBundle(unclosedFont)).rejects.toThrow(/^bundle_contract_invalid$/u);
    unclosedFont.artifacts.privateManifest.structuralAssets = [
      {
        digest: sha256(fontBytes),
        mime: 'font/woff',
        references: [{ id: 'brand-font', sourcePath: fontPath }],
      },
    ];
    relinkArtifactDigests(unclosedFont.artifacts);
    await expect(createMigrationBundle(unclosedFont)).resolves.toBeDefined();
  });

  it('rejects renamed archive magic and opaque binary outside the Task 4 asset allowlist', async () => {
    const zipBytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3, 4]);
    const opaqueBytes = new Uint8Array([1, 2, 0, 0xff, 3, 4]);
    for (const [path, bytes] of [
      ['public/renamed-data.txt', zipBytes],
      ['public/opaque-data.txt', opaqueBytes],
    ] as const) {
      const candidate = [...baseCandidate, { path, bytes, executable: false }];
      await expect(
        createMigrationBundle(input({ candidate, artifacts: artifacts(candidate).compiled })),
      ).rejects.toThrow(/^bundle_entry_forbidden$/u);
    }

    const disguised = [...baseCandidate, {
      path: 'public/disguised.png',
      bytes: zipBytes,
      executable: false,
    }];
    const forged = input({ candidate: disguised, artifacts: artifacts(disguised).compiled });
    forged.artifacts.privateManifest.structuralAssets = [{
      digest: sha256(zipBytes),
      mime: 'image/png',
      references: [{ id: 'disguised', sourcePath: 'public/disguised.png' }],
    }];
    relinkArtifactDigests(forged.artifacts);
    await expect(createMigrationBundle(forged)).rejects.toThrow(/^bundle_entry_forbidden$/u);
  });

  it('allows inspected binary assets by Task 4 digest/mime and requires SVG structural closure', async () => {
    const pngBytes = new Uint8Array(validPng2x2);
    const binaryCandidate = [
      ...baseCandidate,
      { path: 'public/brand.data', bytes: pngBytes, executable: false },
    ];
    const allowed = input({
      candidate: binaryCandidate,
      artifacts: artifacts(binaryCandidate).compiled,
    });
    allowed.artifacts.privateManifest.structuralAssets = [{
      digest: sha256(pngBytes),
      mime: 'image/png',
      references: [{ id: 'brand', sourcePath: 'public/brand.data' }],
    }];
    relinkArtifactDigests(allowed.artifacts);
    await expect(createMigrationBundle(allowed)).resolves.toBeDefined();

    const svgBytes = encoder.encode(
      '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><path d="M0 0"/></svg>',
    );
    const svgCandidate = [
      ...baseCandidate,
      { path: 'public/decorative.svg', bytes: svgBytes, executable: false },
    ];
    const missing = input({ candidate: svgCandidate, artifacts: artifacts(svgCandidate).compiled });
    await expect(createMigrationBundle(missing)).rejects.toThrow(/^bundle_contract_invalid$/u);
    missing.artifacts.privateManifest.structuralAssets = [{
      digest: sha256(svgBytes),
      mime: 'image/svg+xml',
      references: [{ id: 'decorative', sourcePath: 'public/decorative.svg' }],
    }];
    relinkArtifactDigests(missing.artifacts);
    await expect(createMigrationBundle(missing)).resolves.toBeDefined();
  });

  it('requires exact structural closure for a renamed whole-document SVG', async () => {
    const svgBytes = encoder.encode(
      '\uFEFF<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>',
    );
    const structuralPath = 'public/renamed-vector.data';
    const candidate = [...baseCandidate, { path: structuralPath, bytes: svgBytes, executable: false }];
    const missing = input({ candidate, artifacts: artifacts(candidate).compiled });
    await expect(createMigrationBundle(missing)).rejects.toThrow(/^bundle_contract_invalid$/u);

    missing.artifacts.privateManifest.structuralAssets = [{
      digest: sha256(svgBytes),
      mime: 'image/svg+xml',
      references: [{ id: 'renamed-vector', sourcePath: structuralPath }],
    }];
    relinkArtifactDigests(missing.artifacts);
    await expect(createMigrationBundle(missing)).resolves.toBeDefined();
  });

  it('requires exact structural closure for namespace-prefixed whole-document SVG roots', async () => {
    for (const [name, prefix] of [
      ['ascii', 's'],
      ['unicode-latin', 'é'],
      ['unicode-cjk', '图'],
      ['dotted', 's.x'],
    ] as const) {
      const svgBytes = encoder.encode(
        `<${prefix}:svg xmlns:${prefix}="http://www.w3.org/2000/svg" width="1" height="1"><${prefix}:rect width="1" height="1"/></${prefix}:svg>`,
      );
      const structuralPath = `public/prefixed-vector-${name}.data`;
      const candidate = [...baseCandidate, { path: structuralPath, bytes: svgBytes, executable: false }];
      const missing = input({ candidate, artifacts: artifacts(candidate).compiled });
      await expect(createMigrationBundle(missing)).rejects.toThrow(/^bundle_contract_invalid$/u);

      missing.artifacts.privateManifest.structuralAssets = [{
        digest: sha256(svgBytes),
        mime: 'image/svg+xml',
        references: [{ id: `prefixed-vector-${name}`, sourcePath: structuralPath }],
      }];
      relinkArtifactDigests(missing.artifacts);
      await expect(createMigrationBundle(missing)).resolves.toBeDefined();
    }
  });

  it('blocks unsafe and namespace-invalid prefixed SVG roots outside structural closure', async () => {
    for (const [name, source] of [
      ['script', '<s:svg xmlns:s="http://www.w3.org/2000/svg"><s:script>alert(1)</s:script></s:svg>'],
      ['external', '<s:svg xmlns:s="http://www.w3.org/2000/svg"><s:use href="https://example.test/x.svg#x"/></s:svg>'],
      ['namespace', '<s:svg xmlns:s="https://example.test/not-svg"><s:path d="M0 0"/></s:svg>'],
      ['unresolved', '<s:svg><s:path d="M0 0"/></s:svg>'],
      ['unicode-script', '<é:svg xmlns:é="http://www.w3.org/2000/svg"><é:script>alert(1)</é:script></é:svg>'],
      ['unicode-external', '<图:svg xmlns:图="http://www.w3.org/2000/svg"><图:use href="https://example.test/x.svg#x"/></图:svg>'],
      ['xml-reserved', '<xml:svg xmlns:xml="http://www.w3.org/2000/svg"><xml:path d="M0 0"/></xml:svg>'],
      ['xmlns-reserved', '<xmlns:svg xmlns:xmlns="http://www.w3.org/2000/svg"><xmlns:path d="M0 0"/></xmlns:svg>'],
      ['multiple-colons', '<s:x:svg xmlns:s="http://www.w3.org/2000/svg"><s:path d="M0 0"/></s:x:svg>'],
      ['invalid-name', '<1s:svg xmlns:1s="http://www.w3.org/2000/svg"><1s:path d="M0 0"/></1s:svg>'],
      ['invalid-name-suffix', '<s:svg$ xmlns:s="http://www.w3.org/2000/svg"><s:path d="M0 0"/></s:svg$>'],
    ] as const) {
      const bytes = encoder.encode(source);
      const path = `public/prefixed-${name}.txt`;
      const candidate = [...baseCandidate, { path, bytes, executable: false }];
      await expect(
        createMigrationBundle(input({ candidate, artifacts: artifacts(candidate).compiled })),
      ).rejects.toThrow(/^bundle_contract_invalid$/u);
    }
  });

  it('rejects unsafe renamed SVG documents instead of admitting them as source text', async () => {
    for (const [name, source] of [
      ['script', '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'],
      ['external', '<svg xmlns="http://www.w3.org/2000/svg"><use href="https://example.test/x.svg#x"/></svg>'],
      ['doctype', '<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'],
      ['entity', '<!DOCTYPE svg [<!ENTITY x "unsafe">]><svg xmlns="http://www.w3.org/2000/svg"><title>&x;</title></svg>'],
      ['comment', '<!-- synthetic --><svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'],
      ['many-comments', `${'<!-- synthetic -->'.repeat(65)}<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>`],
      ['processing-instruction', '<?xml-stylesheet href="x.css"?><svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'],
    ] as const) {
      const bytes = encoder.encode(source);
      const path = `public/renamed-${name}.txt`;
      const candidate = [...baseCandidate, { path, bytes, executable: false }];
      await expect(
        createMigrationBundle(input({ candidate, artifacts: artifacts(candidate).compiled })),
      ).rejects.toThrow(/^bundle_contract_invalid$/u);
    }
  });

  it('does not confuse embedded SVG source or ordinary XML/HTML documents with SVG assets', async () => {
    const candidate = [
      ...baseCandidate,
      {
        path: 'components/icon.tsx',
        bytes: encoder.encode("export const icon = '<svg viewBox=\\\"0 0 1 1\\\"></svg>';\n"),
        executable: false,
      },
      {
        path: 'components/prefixed-icon.tsx',
        bytes: encoder.encode("export const icon = '<s:svg xmlns:s=\\\"http://www.w3.org/2000/svg\\\"></s:svg>';\n"),
        executable: false,
      },
      {
        path: 'components/unicode-prefixed-icon.tsx',
        bytes: encoder.encode("export const icon = '<é:svg xmlns:é=\\\"http://www.w3.org/2000/svg\\\"></é:svg><s.x:svg xmlns:s.x=\\\"http://www.w3.org/2000/svg\\\"></s.x:svg>';\n"),
        executable: false,
      },
      {
        path: 'config/feed.xml',
        bytes: encoder.encode('<?xml version="1.0"?><configuration><item/></configuration>'),
        executable: false,
      },
      {
        path: 'public/page.html',
        bytes: encoder.encode('<!doctype html><html><body><svg></svg><s:svg xmlns:s="http://www.w3.org/2000/svg"></s:svg></body></html>'),
        executable: false,
      },
    ];
    await expect(
      createMigrationBundle(input({ candidate, artifacts: artifacts(candidate).compiled })),
    ).resolves.toBeDefined();
  });

  it('rejects a PDF signature after a BOM/whitespace prefix end to end', async () => {
    const bytes = new Uint8Array([
      0xef, 0xbb, 0xbf, 0x20, 0x0a, 0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37,
    ]);
    const candidate = [...baseCandidate, {
      path: 'public/renamed-document.txt',
      bytes,
      executable: false,
    }];
    await expect(
      createMigrationBundle(input({ candidate, artifacts: artifacts(candidate).compiled })),
    ).rejects.toThrow(/^bundle_entry_forbidden$/u);
  });

  it('rejects editorial blobs that fail the exact Task 4 image-byte inspection', async () => {
    const malformedWoff = Buffer.alloc(68);
    malformedWoff.write('wOFF', 0, 'ascii');
    for (const bytes of [
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
      malformedWoff,
      syntheticWoff2Bomb(),
    ]) {
      const invalid = input();
      const digest = sha256(bytes);
      invalid.editorialAssets = [{ digest, bytes: new Uint8Array(bytes) }];
      invalid.artifacts.contentFixture.editorialAssets[0]!.digest = digest;
      invalid.artifacts.contentFixture.values[0]!.value = digest;
      invalid.artifacts.privateManifest.targets[0]!.editorialAssetDigest = digest;
      relinkArtifactDigests(invalid.artifacts);
      await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_contract_invalid$/u);
    }
  });

  it('rejects malformed structural raster, SVG, and font bytes through the Task 4 inspector', async () => {
    const malformedWoff = Buffer.alloc(68);
    malformedWoff.write('wOFF', 0, 'ascii');
    const cases = [
      ['public/malformed.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), 'image/png'],
      ['public/script.svg', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), 'image/svg+xml'],
      ['public/external.svg', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><use href="https://example.test/x.svg#x"/></svg>'), 'image/svg+xml'],
      ['public/malformed.woff', malformedWoff, 'font/woff'],
      ['public/bomb.woff2', syntheticWoff2Bomb(), 'font/woff2'],
      ['public/mime-mismatch.data', validPng2x2, 'image/jpeg'],
    ] as const;
    for (const [path, bytes, mime] of cases) {
      const candidate = [...baseCandidate, { path, bytes: new Uint8Array(bytes), executable: false }];
      const invalid = input({ candidate, artifacts: artifacts(candidate).compiled });
      invalid.artifacts.privateManifest.structuralAssets = [{
        digest: sha256(bytes),
        mime,
        references: [{ id: 'structural-test', sourcePath: path }],
      }];
      relinkArtifactDigests(invalid.artifacts);
      await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_contract_invalid$/u);
    }
  });

  it('allows legitimate third-party HTTPS text while preserving namespace separation', async () => {
    const candidate = [
      ...baseCandidate,
      {
        path: 'lib/provider.ts',
        bytes: encoder.encode("export const url = 'https://cdn.example.test/widget.js';\n"),
        executable: false,
      },
    ];
    const result = await createMigrationBundle(
      input({ candidate, artifacts: artifacts(candidate).compiled }),
    );
    const paths = (await readArchive(result.bytes)).map(({ path }) => path);
    expect(paths).toContain('candidate/lib/provider.ts');
    expect(paths.filter((path) => path.startsWith('candidate/verow/'))).toEqual([]);
    expect(paths.filter((path) => path.startsWith('verow/')).length).toBeGreaterThan(0);
  });

  it('rejects hostile roots, accessors, symbols, sparse arrays and unsafe byte views without reading getters', async () => {
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'websiteId', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'private';
      },
    });
    const symbolInput = input() as CreateMigrationBundleInput & { [key: symbol]: boolean };
    symbolInput[Symbol('hidden')] = true;
    const sparse = input();
    sparse.candidate = Array(1);
    const callerCapabilities = { ...input(), capabilityClaims: ['inline_edit', 'preview'] };
    const symbolValue = input();
    symbolValue.websiteId = Symbol('private') as never;
    const nestedExtra = structuredClone(input());
    Object.assign(nestedExtra.artifacts.contentFixture.values[0]!, { extra: true });
    relinkArtifactDigests(nestedExtra.artifacts);
    for (const invalid of [
      new Proxy(input(), {}),
      accessor,
      symbolInput,
      sparse,
      callerCapabilities,
      symbolValue,
      nestedExtra,
    ]) {
      await expect(createMigrationBundle(invalid as CreateMigrationBundleInput)).rejects.toThrow(
        /^bundle_input_invalid$/u,
      );
    }
    expect(getterCalls).toBe(0);
  });

  it('rejects accessor-bearing Task 4 scalar arrays without invoking the accessor', async () => {
    let getterCalls = 0;
    const invalid = input();
    const families = Array(1) as CompiledMigrationArtifacts['privateManifest']['structuredFamilies'];
    Object.defineProperty(families, 0, {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error('SYNTHETIC_PRIVATE_FAMILY_GETTER');
      },
    });
    invalid.artifacts.privateManifest.structuredFamilies = families;
    await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_input_invalid$/u);
    expect(getterCalls).toBe(0);
  });

  it('preflights every Task 4 scalar without coercing accessors, proxies, or exotic primitives', async () => {
    const secret = 'SYNTHETIC_PRIVATE_ARTIFACT_COERCION';
    let observerCalls = 0;
    const observer = {
      [Symbol.toPrimitive]() {
        observerCalls += 1;
        throw new Error(secret);
      },
    };
    const proxied = new Proxy({}, {
      get() {
        observerCalls += 1;
        throw new Error(secret);
      },
    });
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const accessor = Object.defineProperty({ path: 'private/source/page.tsx' }, 'anchor', {
      enumerable: true,
      get() {
        observerCalls += 1;
        throw new Error(secret);
      },
    });
    const invalid = [
      (() => {
        const value = input();
        value.artifacts.contentFixture.websiteId = Symbol(secret) as never;
        return value;
      })(),
      (() => {
        const value = input();
        value.artifacts.contentFixture.websiteId = 1n as never;
        return value;
      })(),
      (() => {
        const value = input();
        value.artifacts.privateManifest.targets[0]!.label = (() => secret) as never;
        return value;
      })(),
      (() => {
        const value = input();
        value.artifacts.contentFixture.websiteId = observer as never;
        return value;
      })(),
      (() => {
        const value = input();
        value.artifacts.contentFixture.websiteId = proxied as never;
        return value;
      })(),
      (() => {
        const value = input();
        value.artifacts.contentFixture.websiteId = revoked.proxy as never;
        return value;
      })(),
      (() => {
        const value = input();
        value.artifacts.privateManifest.targets[0]!.sourceEvidence = accessor as never;
        return value;
      })(),
    ];
    for (const value of invalid) {
      try {
        await createMigrationBundle(value);
        throw new Error('expected rejection');
      } catch (error) {
        expect(String(error)).toBe('Error: bundle_input_invalid');
        expect(String(error)).not.toContain(secret);
      }
    }
    expect(observerCalls).toBe(0);
  });

  it('copies every admitted byte before asynchronous work', async () => {
    const mutable = input();
    const expected = await createMigrationBundle(structuredClone(mutable));
    const promise = createMigrationBundle(mutable);
    mutable.candidate[0]!.bytes.fill(0);
    mutable.editorialAssets[0]!.bytes.fill(0);
    expect((await promise).bytes).toEqual(expected.bytes);
  });

  it('snapshots IDs and every mutable raw input before returning the promise', async () => {
    const expected = await createMigrationBundle(input());
    const mutable = input();
    const promise = createMigrationBundle(mutable);
    mutable.websiteId = '33333333-3333-4333-8333-333333333333';
    mutable.migrationId = '44444444-4444-4444-8444-444444444444';
    mutable.sourceDigest = sha256('mutated source');
    mutable.candidate.reverse();
    mutable.candidate[0]!.bytes.fill(0);
    mutable.sourceInventory.files.reverse();
    mutable.sourceInventory.files[0]!.path = 'private-mutated.ts';
    mutable.editorialAssets[0]!.bytes.fill(0);
    mutable.dependencyInventory.dependencies.reverse();
    mutable.evidence.reverse();
    mutable.artifacts.contentFixture.websiteId = mutable.websiteId;

    const actual = await promise;
    expect(actual.bytes).toEqual(expected.bytes);
    expect(actual.manifest).toEqual(expected.manifest);
    expect(actual.payloadIndex).toEqual(expected.payloadIndex);
  });

  it('rejects proxied and revoked byte arrays without triggering proxy traps or leaking errors', async () => {
    const secret = 'SYNTHETIC_PRIVATE_TYPED_ARRAY_TRAP';
    let trapCalls = 0;
    const proxied = new Proxy(new Uint8Array([1, 2, 3]), {
      getPrototypeOf() {
        trapCalls += 1;
        throw new Error(secret);
      },
      get() {
        trapCalls += 1;
        throw new Error(secret);
      },
    });
    const revocable = Proxy.revocable(new Uint8Array([1, 2, 3]), {});
    revocable.revoke();
    for (const bytes of [proxied, revocable.proxy]) {
      const invalid = input({
        candidate: baseCandidate.map((entry) => ({
          ...entry,
          bytes: new Uint8Array(entry.bytes),
        })),
      });
      invalid.candidate[0]!.bytes = bytes;
      try {
        await createMigrationBundle(invalid);
        throw new Error('expected rejection');
      } catch (error) {
        expect(String(error)).toBe('Error: bundle_input_invalid');
        expect(String(error)).not.toContain(secret);
      }
    }
    expect(trapCalls).toBe(0);
  });

  it('does not depend on current time, randomness or locale collation', async () => {
    const date = Date.now;
    const random = Math.random;
    const localeCompare = String.prototype.localeCompare;
    Date.now = () => { throw new Error('time reached'); };
    Math.random = () => { throw new Error('random reached'); };
    String.prototype.localeCompare = () => { throw new Error('locale reached'); };
    try {
      await expect(createMigrationBundle(input())).resolves.toBeDefined();
    } finally {
      Date.now = date;
      Math.random = random;
      String.prototype.localeCompare = localeCompare;
    }
  });

  it('normalizes archive implementation failures to one content-free code', async () => {
    await expect(
      createDeterministicTarGzip([], () => {
        throw new Error('synthetic private archive failure');
      }),
    ).rejects.toThrow(/^bundle_archive_failed$/u);
  });

  it('settles a pending entry write when the archive stream fails', async () => {
    const outcome = await Promise.race([
      createDeterministicTarGzip(
        [{ path: 'candidate/page.txt', bytes: encoder.encode('safe'), mode: 0o644 }],
        () => {
          const archive = pack();
          archive.entry = (() => {
            queueMicrotask(() => archive.emit('error', new Error('synthetic private stream failure')));
            return undefined;
          }) as unknown as typeof archive.entry;
          return archive;
        },
      ).then(
        () => 'partial-success',
        (error: unknown) => String(error),
      ),
      new Promise<string>((resolve) => setTimeout(() => resolve('hung'), 100)),
    ]);

    expect(outcome).toBe('Error: bundle_archive_failed');
  });

  it('normalizes repeated terminal error signals without an unhandled rejection', async () => {
    await expect(
      createDeterministicTarGzip(
        [{ path: 'candidate/page.txt', bytes: encoder.encode('safe'), mode: 0o644 }],
        () => {
          const archive = pack();
          archive.entry = (() => {
            queueMicrotask(() => {
              archive.emit('error', new Error('first private error'));
              archive.emit('error', new Error('second private error'));
            });
            return undefined;
          }) as unknown as typeof archive.entry;
          return archive;
        },
      ),
    ).rejects.toThrow(/^bundle_archive_failed$/u);
  });

  it.each(['empty-end', 'truncated-end'] as const)(
    'rejects %s archive output instead of returning a gzip success',
    async (kind) => {
      await expect(
        createDeterministicTarGzip(
          [{ path: 'candidate/page.txt', bytes: encoder.encode('safe'), mode: 0o644 }],
          () => terminalPack(kind),
        ),
      ).rejects.toThrow(/^bundle_archive_failed$/u);
    },
  );

  it('settles close-before-end archive output without hanging or partial success', async () => {
    const outcome = await Promise.race([
      createDeterministicTarGzip(
        [{ path: 'candidate/page.txt', bytes: encoder.encode('safe'), mode: 0o644 }],
        () => terminalPack('close'),
      ).then(
        () => 'partial-success',
        (error: unknown) => String(error),
      ),
      new Promise<string>((resolve) => setTimeout(() => resolve('hung'), 100)),
    ]);
    expect(outcome).toBe('Error: bundle_archive_failed');
  });

  it('never includes sensitive input values in descriptors or errors', async () => {
    const secret = 'SYNTHETIC_SECRET_CUSTOMER_TOKEN_9921';
    const valid = input({ evidence: [{ name: 'private-check', value: { detail: secret, url: `https://example.test/${secret}` } }] });
    expect(JSON.stringify((await createMigrationBundle(valid)).manifest)).not.toContain(secret);
    const invalid = input({ evidence: [{ name: `bad/${secret}`, value: secret }] });
    try {
      await createMigrationBundle(invalid);
      throw new Error('expected rejection');
    } catch (error) {
      expect(String(error)).not.toContain(secret);
      expect(String(error)).toMatch(/bundle_input_invalid/u);
    }
  });

  it('preserves canonical logical JSON text containing escaped line controls', async () => {
    const result = await createMigrationBundle(
      input({ evidence: [{ name: 'text-check', value: { detail: 'line one\nline two\tchecked' } }] }),
    );
    const entry = (await readArchive(result.bytes)).find(
      ({ path }) => path === 'verow/evidence/text-check.json',
    );
    expect(entry?.bytes.toString('utf8')).toBe('{"detail":"line one\\nline two\\tchecked"}');
  });

  it('rejects forged identity drift even when callers recompute artifact digests', async () => {
    const orphanValue = structuredClone(input());
    orphanValue.artifacts.contentFixture.values.push({
      key: 'page.orphan.heading',
      locale: 'en',
      variant: null,
      value: 'orphan',
    });
    orphanValue.artifacts.contentFixture.values.sort((left, right) =>
      Buffer.from(left.key).compare(Buffer.from(right.key)),
    );
    relinkArtifactDigests(orphanValue.artifacts);

    const missingBinding = structuredClone(input());
    missingBinding.artifacts.repositoryBinding.bindings = [];
    relinkArtifactDigests(missingBinding.artifacts);
    for (const invalid of [orphanValue, missingBinding]) {
      await expect(createMigrationBundle(invalid)).rejects.toThrow(/^bundle_contract_invalid$/u);
    }
  });
});
