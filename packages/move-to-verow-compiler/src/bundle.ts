import { createHash } from 'node:crypto';
import { types as nodeUtilTypes } from 'node:util';
import { gzipSync } from 'node:zlib';

import { pack, type Pack } from 'tar-stream';

import {
  assertArchiveEntries,
  assertSafeRelativePath,
  compareUtf8,
  copyArchiveEntries,
  isSafeByteArray,
  resolveArchiveLimits,
  type ArchiveLimits,
  type BundleEntryInput,
} from './archive-policy.js';
import {
  canonicalDigest,
  canonicalJsonBytes,
  validateBundleDescriptor,
  validatePayloadIndex,
} from './bundle-contract.js';
import { digestFileInventory, type InventoriedFile } from './inventory.js';
import {
  CONTENT_FIXTURE_FORMAT,
  PRIVATE_MANIFEST_FORMAT,
  REPOSITORY_BINDING_FORMAT,
  RUNTIME_EXPECTATION_FORMAT,
  type CompiledMigrationArtifacts,
  type MigrationContentIdentity,
} from './manifest.js';

export const ARCHIVE_FORMAT = 'tar_gzip_v1' as const;
export const BUNDLE_FORMAT = 'move-to-verow.bundle.v1' as const;
export const PAYLOAD_INDEX_FORMAT = 'move-to-verow.payload-index.v1' as const;
export const SOURCE_INVENTORY_FORMAT = 'move-to-verow.source-inventory.v1' as const;
export const DEPENDENCY_INVENTORY_FORMAT = 'move-to-verow.dependency-inventory.v1' as const;
export const CAPABILITY_CLAIMS_FORMAT = 'move-to-verow.capability-claims.v1' as const;
export const EVIDENCE_INDEX_FORMAT = 'move-to-verow.evidence-index.v1' as const;
export const BUNDLE_CAPABILITY_CLAIMS = Object.freeze(['inline_edit', 'preview'] as const);

type Digest = `sha256:${string}`;
export type BundleCapabilityClaim = (typeof BUNDLE_CAPABILITY_CLAIMS)[number];
export type BundleLogicalValue =
  | null
  | boolean
  | number
  | string
  | BundleLogicalValue[]
  | { [key: string]: BundleLogicalValue };

export interface SourceInventoryFileV1 {
  path: string;
  bytes: number;
  digest: Digest;
}

export interface SourceInventoryV1 {
  format: typeof SOURCE_INVENTORY_FORMAT;
  files: SourceInventoryFileV1[];
}

export interface DependencyInventoryRecordV1 {
  name: string;
  version: string;
  integrity: string;
}

export interface DependencyInventoryV1 {
  version: typeof DEPENDENCY_INVENTORY_FORMAT;
  dependencies: DependencyInventoryRecordV1[];
}

export interface BundleEvidenceInput {
  name: string;
  value: BundleLogicalValue;
}

export interface EditorialAssetBlobInput {
  digest: Digest;
  bytes: Uint8Array;
}

export interface CapabilityClaimsV1 {
  format: typeof CAPABILITY_CLAIMS_FORMAT;
  claims: BundleCapabilityClaim[];
}

export interface EvidenceIndexEntryV1 {
  path: string;
  bytes: number;
  digest: Digest;
}

export interface EvidenceIndexV1 {
  format: typeof EVIDENCE_INDEX_FORMAT;
  entries: EvidenceIndexEntryV1[];
}

export interface MigrationPayloadIndexEntryV1 {
  path: string;
  bytes: number;
  mode: number;
  digest: Digest;
}

export interface MigrationPayloadIndexV1 {
  version: typeof PAYLOAD_INDEX_FORMAT;
  entries: MigrationPayloadIndexEntryV1[];
}

export interface MigrationBundleManifestV1 {
  version: typeof BUNDLE_FORMAT;
  migrationId: string;
  websiteId: string;
  sourceDigest: Digest;
  artifactDigest: Digest;
  archiveFormat: typeof ARCHIVE_FORMAT;
  sourceKind: 'codex_sites_local';
  framework: 'nextjs_app_router';
  fileCount: number;
  totalBytes: number;
  capabilityClaims: BundleCapabilityClaim[];
  privateManifestDigest: Digest;
  evidenceDigest: Digest;
}

export type BundleLimits = Partial<ArchiveLimits>;

export interface CreateMigrationBundleInput {
  websiteId: string;
  migrationId: string;
  sourceDigest: Digest;
  sourceInventory: SourceInventoryV1;
  candidate: BundleEntryInput[];
  artifacts: CompiledMigrationArtifacts;
  editorialAssets: EditorialAssetBlobInput[];
  dependencyInventory: DependencyInventoryV1;
  evidence: BundleEvidenceInput[];
  limits?: BundleLimits;
}

export interface CreatedMigrationBundle {
  bytes: Uint8Array;
  artifactDigest: Digest;
  payloadIndex: MigrationPayloadIndexV1;
  manifest: MigrationBundleManifestV1;
  capabilityClaims: CapabilityClaimsV1;
  evidenceIndex: EvidenceIndexV1;
}

interface ArchiveEntry {
  path: string;
  bytes: Uint8Array;
  mode: 0o644 | 0o755;
}

interface EncodedArchive {
  bytes: Uint8Array;
  expandedBytes: number;
}

export type TarPackFactory = () => Pack;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const EVIDENCE_NAME_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const DEPENDENCY_NAME_PATTERN = /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/u;
const INPUT_KEYS = [
  'artifacts',
  'candidate',
  'dependencyInventory',
  'editorialAssets',
  'evidence',
  'migrationId',
  'sourceDigest',
  'sourceInventory',
  'websiteId',
] as const;
const INPUT_KEYS_WITH_LIMITS = [...INPUT_KEYS, 'limits'] as const;
const ARTIFACT_KEYS = [
  'contentFixture',
  'digests',
  'privateManifest',
  'repositoryBinding',
  'runtimeExpectation',
] as const;
const CONTENT_FIXTURE_KEYS = [
  'editorialAssets',
  'externalAssets',
  'format',
  'migrationId',
  'purpose',
  'values',
  'websiteId',
] as const;
const PRIVATE_MANIFEST_KEYS = [
  'candidateDigest',
  'cmsNativeProtocol',
  'derived',
  'format',
  'migrationId',
  'routes',
  'sourceDigest',
  'structural',
  'structuralAssets',
  'structuredFamilies',
  'targets',
  'thirdPartyBoundaries',
  'websiteId',
] as const;
const REPOSITORY_BINDING_KEYS = [
  'bindings',
  'candidateDigest',
  'cmsNativeProtocol',
  'format',
  'migrationId',
  'privateManifestDigest',
  'runtimeBinding',
  'sourceDigest',
  'websiteId',
] as const;
const RUNTIME_EXPECTATION_KEYS = [
  'cmsNativeProtocol',
  'counts',
  'expectedPrivateManifestDigest',
  'expectedRepositoryBindingDigest',
  'format',
  'migrationId',
  'websiteId',
] as const;
const DIGEST_KEYS = [
  'contentFixture',
  'privateManifest',
  'repositoryBinding',
  'runtimeExpectation',
] as const;
const IDENTITY_KEYS = ['key', 'locale', 'variant'] as const;
const PRIVATE_TARGET_KEYS = [
  'actions',
  'binding',
  'cardinality',
  'collection',
  'editorialAssetDigest',
  'externalBoundary',
  'externalUrl',
  'imagePair',
  'key',
  'label',
  'liveVerification',
  'locale',
  'owner',
  'required',
  'route',
  'routeId',
  'sourceEvidence',
  'sourceKind',
  'structuredFamily',
  'valueType',
  'variant',
] as const;

function fail(
  code:
    | 'bundle_archive_failed'
    | 'bundle_contract_invalid'
    | 'bundle_entry_forbidden'
    | 'bundle_input_invalid'
    | 'bundle_limit_exceeded',
): never {
  throw new Error(code);
}

function sha256(bytes: string | Uint8Array): Digest {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== 'object' ||
    nodeUtilTypes.isProxy(value) ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  ) {
    return false;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return Object.values(descriptors).every(
    (descriptor) => descriptor.enumerable && descriptor.get === undefined && descriptor.set === undefined,
  );
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function arrayLength(value: unknown): number | null {
  if (
    value === null ||
    typeof value !== 'object' ||
    nodeUtilTypes.isProxy(value) ||
    !Array.isArray(value)
  ) {
    return null;
  }
  return value.length;
}

function isPlainArray<T>(value: unknown, maximum: number): value is T[] {
  const length = arrayLength(value);
  if (
    length === null ||
    length > maximum ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  ) {
    return false;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).filter((key) => key !== 'length');
  return (
    keys.length === length &&
    keys.every((key) => {
      const descriptor = descriptors[key];
      return descriptor?.enumerable === true && descriptor.get === undefined && descriptor.set === undefined;
    })
  );
}

function safeString(value: unknown, maximum: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maximum &&
    value === value.normalize('NFC') &&
    !/\p{Cc}/u.test(value)
  );
}

function validDigest(value: unknown): value is Digest {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function assertLogicalShape(
  value: unknown,
  budget: { nodes: number; stringBytes: number },
  ancestors = new Set<object>(),
): void {
  budget.nodes -= 1;
  if (budget.nodes < 0) fail('bundle_limit_exceeded');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    budget.stringBytes -= Buffer.byteLength(value, 'utf8');
    if (budget.stringBytes < 0) fail('bundle_input_invalid');
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('bundle_input_invalid');
    return;
  }
  if (
    typeof value !== 'object' ||
    value === null ||
    nodeUtilTypes.isProxy(value) ||
    ancestors.has(value)
  ) {
    fail('bundle_input_invalid');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (!isPlainArray(value, 2_000)) fail('bundle_input_invalid');
      for (const item of value) assertLogicalShape(item, budget, ancestors);
      return;
    }
    if (!isPlainRecord(value)) fail('bundle_input_invalid');
    const keys = Object.keys(value);
    if (keys.length > 200) fail('bundle_limit_exceeded');
    for (const key of keys) {
      assertLogicalShape(key, budget, ancestors);
      assertLogicalShape(value[key], budget, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function canonicalCopy<T>(value: T, maximumBytes = 20_000_000): T {
  assertLogicalShape(value, { nodes: 50_000, stringBytes: maximumBytes });
  const bytes = canonicalJsonBytes(value);
  if (bytes.byteLength > maximumBytes) fail('bundle_limit_exceeded');
  return JSON.parse(Buffer.from(bytes).toString('utf8')) as T;
}

function requireExactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!isPlainRecord(value) || !exactKeys(value, keys)) fail('bundle_input_invalid');
  return value;
}

function requireExactItems(
  value: unknown,
  maximum: number,
  keys: readonly string[],
): Record<string, unknown>[] {
  if (!isPlainArray<Record<string, unknown>>(value, maximum)) fail('bundle_input_invalid');
  return value.map((item) => requireExactRecord(item, keys));
}

function requireIdentity(value: unknown): void {
  requireExactRecord(value, IDENTITY_KEYS);
}

function assertArtifactNestedShapes(input: CompiledMigrationArtifacts): void {
  const contentValues = requireExactItems(
    input.contentFixture.values,
    2_000,
    ['key', 'locale', 'value', 'variant'],
  );
  for (const value of contentValues) requireIdentity({ key: value.key, locale: value.locale, variant: value.variant });
  const editorial = requireExactItems(
    input.contentFixture.editorialAssets,
    2_000,
    ['digest', 'target'],
  );
  for (const item of editorial) requireIdentity(item.target);
  const external = requireExactItems(input.contentFixture.externalAssets, 2_000, ['target', 'url']);
  for (const item of external) requireIdentity(item.target);

  for (const protocol of [
    input.privateManifest.cmsNativeProtocol,
    input.repositoryBinding.cmsNativeProtocol,
    input.runtimeExpectation.cmsNativeProtocol,
  ]) {
    requireExactRecord(protocol, ['contractDigest', 'package', 'version']);
  }
  const routes = requireExactItems(input.privateManifest.routes, 500, [
    'path',
    'renderedSource',
    'routeId',
  ]);
  const targets = requireExactItems(input.privateManifest.targets, 500, PRIVATE_TARGET_KEYS);
  for (const target of targets) {
    if (!isPlainArray(target.actions, 4)) fail('bundle_input_invalid');
    requireExactRecord(target.binding, ['key', 'kind']);
    requireExactRecord(target.sourceEvidence, ['anchor', 'path']);
    if (target.route !== null) requireExactRecord(target.route, ['path', 'renderedSource', 'routeId']);
    if (target.imagePair !== null) {
      const pair = requireExactRecord(target.imagePair, ['role', 'target']);
      requireIdentity(pair.target);
    }
    if (target.collection !== null) {
      const collection = requireExactRecord(target.collection, [
        'maximumItems',
        'minimumItems',
        'requiredItemIds',
      ]);
      if (!isPlainArray(collection.requiredItemIds, 1_000)) fail('bundle_input_invalid');
    }
  }
  requireExactItems(input.privateManifest.thirdPartyBoundaries, 100, [
    'integration', 'key', 'locale', 'provider', 'renderedAnchor', 'sourceAnchor', 'sourcePath', 'variant',
  ]);
  requireExactItems(input.privateManifest.derived, 500, [
    'derivedFrom', 'key', 'locale', 'routeId', 'sourceAnchor', 'sourcePath', 'variant',
  ]);
  requireExactItems(input.privateManifest.structural, 500, [
    'key', 'locale', 'reason', 'routeId', 'sourceAnchor', 'sourcePath', 'variant',
  ]);
  const structuralAssets = requireExactItems(input.privateManifest.structuralAssets, 500, [
    'digest',
    'mime',
    'references',
  ]);
  for (const asset of structuralAssets) {
    requireExactItems(asset.references, 2_000, ['id', 'sourcePath']);
  }
  requireExactRecord(input.repositoryBinding.runtimeBinding, ['identityVersion', 'strategy']);
  const bindings = requireExactItems(input.repositoryBinding.bindings, 500, IDENTITY_KEYS);
  for (const binding of bindings) requireIdentity(binding);
  requireExactRecord(input.runtimeExpectation.counts, [
    'derivedDeclarations',
    'editableTargets',
    'routes',
    'structuralDeclarations',
    'structuredFamilies',
    'thirdPartyBoundaries',
  ]);
  if (routes.length !== input.privateManifest.routes.length) fail('bundle_input_invalid');
}

function identityKey(identity: MigrationContentIdentity): string {
  return `${identity.key}\u0000${identity.locale}\u0000${identity.variant ?? ''}`;
}

function sortIdentities<T extends MigrationContentIdentity>(items: T[]): void {
  items.sort((left, right) => compareUtf8(identityKey(left), identityKey(right)));
}

function normalizeArtifacts(input: CompiledMigrationArtifacts): CompiledMigrationArtifacts {
  if (
    !isPlainRecord(input) ||
    !exactKeys(input, ARTIFACT_KEYS) ||
    !isPlainRecord(input.contentFixture) ||
    !exactKeys(input.contentFixture, CONTENT_FIXTURE_KEYS) ||
    !isPlainRecord(input.privateManifest) ||
    !exactKeys(input.privateManifest, PRIVATE_MANIFEST_KEYS) ||
    !isPlainRecord(input.repositoryBinding) ||
    !exactKeys(input.repositoryBinding, REPOSITORY_BINDING_KEYS) ||
    !isPlainRecord(input.runtimeExpectation) ||
    !exactKeys(input.runtimeExpectation, RUNTIME_EXPECTATION_KEYS) ||
    !isPlainRecord(input.digests) ||
    !exactKeys(input.digests, DIGEST_KEYS)
  ) {
    fail('bundle_input_invalid');
  }
  for (const collection of [
    input.contentFixture.values,
    input.contentFixture.editorialAssets,
    input.contentFixture.externalAssets,
    input.privateManifest.structuredFamilies,
    input.privateManifest.routes,
    input.privateManifest.targets,
    input.privateManifest.thirdPartyBoundaries,
    input.privateManifest.derived,
    input.privateManifest.structural,
    input.privateManifest.structuralAssets,
    input.repositoryBinding.bindings,
  ]) {
    const length = arrayLength(collection);
    if (length === null) fail('bundle_input_invalid');
    if (length > 2_000) fail('bundle_limit_exceeded');
  }
  assertArtifactNestedShapes(input);

  const copy = canonicalCopy(input);
  sortIdentities(copy.contentFixture.values);
  copy.contentFixture.editorialAssets.sort((left, right) =>
    compareUtf8(identityKey(left.target), identityKey(right.target)),
  );
  copy.contentFixture.externalAssets.sort((left, right) =>
    compareUtf8(identityKey(left.target), identityKey(right.target)),
  );
  copy.privateManifest.structuredFamilies.sort(compareUtf8);
  copy.privateManifest.routes.sort((left, right) => compareUtf8(left.routeId, right.routeId));
  sortIdentities(copy.privateManifest.targets);
  Object.assign(copy.privateManifest, {
    thirdPartyBoundaries: [...copy.privateManifest.thirdPartyBoundaries].sort((left, right) =>
      compareUtf8(identityKey(left), identityKey(right)),
    ),
    derived: [...copy.privateManifest.derived].sort((left, right) =>
      compareUtf8(identityKey(left), identityKey(right)),
    ),
    structural: [...copy.privateManifest.structural].sort((left, right) =>
      compareUtf8(identityKey(left), identityKey(right)),
    ),
  });
  for (const target of copy.privateManifest.targets) {
    target.actions.sort(compareUtf8);
    target.collection?.requiredItemIds.sort(compareUtf8);
  }
  for (const asset of copy.privateManifest.structuralAssets) {
    asset.references.sort((left, right) =>
      compareUtf8(`${left.sourcePath}\u0000${left.id}`, `${right.sourcePath}\u0000${right.id}`),
    );
  }
  copy.privateManifest.structuralAssets.sort((left, right) => compareUtf8(left.digest, right.digest));
  sortIdentities(copy.repositoryBinding.bindings);
  return copy;
}

function assertInputRoot(value: unknown): asserts value is CreateMigrationBundleInput {
  if (!isPlainRecord(value)) fail('bundle_input_invalid');
  const expected = Object.hasOwn(value, 'limits') ? INPUT_KEYS_WITH_LIMITS : INPUT_KEYS;
  if (!exactKeys(value, expected)) fail('bundle_input_invalid');
  if (
    typeof value.websiteId !== 'string' ||
    typeof value.migrationId !== 'string' ||
    !UUID_PATTERN.test(value.websiteId) ||
    !UUID_PATTERN.test(value.migrationId)
  ) {
    fail('bundle_input_invalid');
  }
  if (!validDigest(value.sourceDigest)) fail('bundle_input_invalid');
}

function normalizedSourceInventory(
  value: unknown,
  limits: ArchiveLimits,
): { body: SourceInventoryV1; digest: Digest } {
  if (!isPlainRecord(value) || !exactKeys(value, ['files', 'format'])) fail('bundle_input_invalid');
  if (value.format !== SOURCE_INVENTORY_FORMAT) fail('bundle_input_invalid');
  const length = arrayLength(value.files);
  if (length === null) fail('bundle_input_invalid');
  if (length > limits.maxEntries) fail('bundle_limit_exceeded');
  if (!isPlainArray<SourceInventoryFileV1>(value.files, limits.maxEntries)) fail('bundle_input_invalid');
  const files: SourceInventoryFileV1[] = [];
  const paths = new Set<string>();
  const foldedPaths = new Set<string>();
  let total = 0;
  for (const item of value.files) {
    if (!isPlainRecord(item) || !exactKeys(item, ['bytes', 'digest', 'path'])) fail('bundle_input_invalid');
    assertSafeRelativePath(item.path, limits);
    const foldedPath = item.path.normalize('NFKC').toUpperCase().toLowerCase();
    if (
      paths.has(item.path) ||
      foldedPaths.has(foldedPath) ||
      !Number.isSafeInteger(item.bytes) ||
      item.bytes < 0 ||
      !validDigest(item.digest)
    ) {
      fail('bundle_input_invalid');
    }
    if (item.bytes > limits.maxSingleBytes) fail('bundle_limit_exceeded');
    paths.add(item.path);
    foldedPaths.add(foldedPath);
    if (!Number.isSafeInteger(total + item.bytes)) fail('bundle_limit_exceeded');
    total += item.bytes;
    if (total > limits.maxTotalBytes) fail('bundle_limit_exceeded');
    files.push({ path: item.path, bytes: item.bytes, digest: item.digest });
  }
  files.sort((left, right) => compareUtf8(left.path, right.path));
  const projected = files.map((file) => ({ ...file, content: new Uint8Array() })) as InventoriedFile[];
  return {
    body: { format: SOURCE_INVENTORY_FORMAT, files },
    digest: digestFileInventory(projected),
  };
}

function normalizedDependencies(value: unknown, limits: ArchiveLimits): DependencyInventoryV1 {
  if (!isPlainRecord(value) || !exactKeys(value, ['dependencies', 'version'])) fail('bundle_input_invalid');
  if (value.version !== DEPENDENCY_INVENTORY_FORMAT) fail('bundle_input_invalid');
  const length = arrayLength(value.dependencies);
  if (length === null) fail('bundle_input_invalid');
  if (length > limits.maxEntries) fail('bundle_limit_exceeded');
  if (!isPlainArray<DependencyInventoryRecordV1>(value.dependencies, limits.maxEntries)) {
    fail('bundle_input_invalid');
  }
  const dependencies: DependencyInventoryRecordV1[] = [];
  const identities = new Set<string>();
  for (const item of value.dependencies) {
    if (!isPlainRecord(item) || !exactKeys(item, ['integrity', 'name', 'version'])) {
      fail('bundle_input_invalid');
    }
    if (
      !safeString(item.name, 214) ||
      !DEPENDENCY_NAME_PATTERN.test(item.name) ||
      !safeString(item.version, 100) ||
      !VERSION_PATTERN.test(item.version) ||
      !safeString(item.integrity, 100) ||
      !/^sha512-[A-Za-z0-9+/]{86}==$/u.test(item.integrity)
    ) {
      fail('bundle_input_invalid');
    }
    const encoded = item.integrity.slice(7);
    if (Buffer.from(encoded, 'base64').toString('base64') !== encoded) fail('bundle_input_invalid');
    const identity = `${item.name}\u0000${item.version}\u0000${item.integrity}`;
    if (identities.has(identity)) fail('bundle_input_invalid');
    identities.add(identity);
    dependencies.push({ name: item.name, version: item.version, integrity: item.integrity });
  }
  dependencies.sort((left, right) =>
    compareUtf8(
      `${left.name}\u0000${left.version}\u0000${left.integrity}`,
      `${right.name}\u0000${right.version}\u0000${right.integrity}`,
    ),
  );
  const body = { version: DEPENDENCY_INVENTORY_FORMAT, dependencies };
  if (canonicalJsonBytes(body).byteLength > limits.maxDependencyBytes) fail('bundle_limit_exceeded');
  return body;
}

function normalizedEvidence(
  value: unknown,
  limits: ArchiveLimits,
): Array<{ name: string; bytes: Uint8Array }> {
  const length = arrayLength(value);
  if (length === null) fail('bundle_input_invalid');
  if (length > limits.maxEvidenceEntries) fail('bundle_limit_exceeded');
  if (!isPlainArray<BundleEvidenceInput>(value, limits.maxEvidenceEntries)) fail('bundle_input_invalid');
  const names = new Set<string>();
  let total = 0;
  const evidence: Array<{ name: string; bytes: Uint8Array }> = [];
  for (const item of value) {
    if (!isPlainRecord(item) || !exactKeys(item, ['name', 'value'])) fail('bundle_input_invalid');
    if (
      !safeString(item.name, 64) ||
      !EVIDENCE_NAME_PATTERN.test(item.name) ||
      item.name === 'source-inventory' ||
      names.has(item.name)
    ) {
      fail('bundle_input_invalid');
    }
    names.add(item.name);
    assertLogicalShape(item.value, {
      nodes: 10_000,
      stringBytes: limits.maxEvidenceBytes,
    });
    const bytes = canonicalJsonBytes(item.value);
    if (!Number.isSafeInteger(total + bytes.byteLength)) fail('bundle_limit_exceeded');
    total += bytes.byteLength;
    if (total > limits.maxEvidenceBytes) fail('bundle_limit_exceeded');
    evidence.push({ name: item.name, bytes });
  }
  evidence.sort((left, right) => compareUtf8(left.name, right.name));
  return evidence;
}

function normalizedEditorialAssets(
  value: unknown,
  limits: ArchiveLimits,
): EditorialAssetBlobInput[] {
  const length = arrayLength(value);
  if (length === null) fail('bundle_input_invalid');
  if (length > limits.maxEntries) fail('bundle_limit_exceeded');
  if (!isPlainArray<EditorialAssetBlobInput>(value, limits.maxEntries)) fail('bundle_input_invalid');
  const digests = new Set<string>();
  const assets: EditorialAssetBlobInput[] = [];
  let total = 0;
  for (const item of value) {
    if (!isPlainRecord(item) || !exactKeys(item, ['bytes', 'digest'])) fail('bundle_input_invalid');
    if (!validDigest(item.digest) || !isSafeByteArray(item.bytes) || digests.has(item.digest)) {
      fail('bundle_contract_invalid');
    }
    if (item.bytes.byteLength === 0) fail('bundle_contract_invalid');
    if (item.bytes.byteLength > limits.maxSingleBytes) fail('bundle_limit_exceeded');
    if (!Number.isSafeInteger(total + item.bytes.byteLength)) fail('bundle_limit_exceeded');
    total += item.bytes.byteLength;
    if (total > limits.maxTotalBytes) fail('bundle_limit_exceeded');
    digests.add(item.digest);
    assets.push({ digest: item.digest, bytes: new Uint8Array(item.bytes) });
  }
  assets.sort((left, right) => compareUtf8(left.digest, right.digest));
  return assets;
}

function assertArtifactContracts(
  artifacts: CompiledMigrationArtifacts,
  input: CreateMigrationBundleInput,
  candidateDigest: Digest,
  sourceDigest: Digest,
  candidateDigests: ReadonlyMap<string, Digest>,
  editorialAssets: readonly EditorialAssetBlobInput[],
): void {
  const { contentFixture, privateManifest, repositoryBinding, runtimeExpectation, digests } = artifacts;
  if (
    contentFixture.format !== CONTENT_FIXTURE_FORMAT ||
    privateManifest.format !== PRIVATE_MANIFEST_FORMAT ||
    repositoryBinding.format !== REPOSITORY_BINDING_FORMAT ||
    runtimeExpectation.format !== RUNTIME_EXPECTATION_FORMAT
  ) {
    fail('bundle_contract_invalid');
  }

  const identitySet = (values: readonly MigrationContentIdentity[]): Set<string> => {
    const identities = values.map(identityKey);
    if (new Set(identities).size !== identities.length) fail('bundle_contract_invalid');
    return new Set(identities);
  };
  const targetIdentities = identitySet(privateManifest.targets);
  const valueIdentities = identitySet(contentFixture.values);
  const bindingIdentities = identitySet(repositoryBinding.bindings);
  if (
    targetIdentities.size !== valueIdentities.size ||
    targetIdentities.size !== bindingIdentities.size ||
    [...targetIdentities].some(
      (identity) => !valueIdentities.has(identity) || !bindingIdentities.has(identity),
    )
  ) {
    fail('bundle_contract_invalid');
  }
  const editorialByTarget = new Map<string, Digest>();
  for (const item of contentFixture.editorialAssets) {
    const identity = identityKey(item.target);
    if (!targetIdentities.has(identity) || editorialByTarget.has(identity)) {
      fail('bundle_contract_invalid');
    }
    editorialByTarget.set(identity, item.digest);
  }
  const externalByTarget = new Map<string, string>();
  for (const item of contentFixture.externalAssets) {
    const identity = identityKey(item.target);
    if (
      !targetIdentities.has(identity) ||
      editorialByTarget.has(identity) ||
      externalByTarget.has(identity)
    ) {
      fail('bundle_contract_invalid');
    }
    externalByTarget.set(identity, item.url);
  }
  for (const target of privateManifest.targets) {
    const identity = identityKey(target);
    if (
      (target.editorialAssetDigest ?? null) !== (editorialByTarget.get(identity) ?? null) ||
      (target.externalUrl ?? null) !== (externalByTarget.get(identity) ?? null)
    ) {
      fail('bundle_contract_invalid');
    }
  }
  for (const artifact of [contentFixture, privateManifest, repositoryBinding, runtimeExpectation]) {
    if (artifact.websiteId !== input.websiteId || artifact.migrationId !== input.migrationId) {
      fail('bundle_contract_invalid');
    }
  }
  if (
    input.sourceDigest !== sourceDigest ||
    privateManifest.sourceDigest !== sourceDigest ||
    repositoryBinding.sourceDigest !== sourceDigest ||
    privateManifest.candidateDigest !== candidateDigest ||
    repositoryBinding.candidateDigest !== candidateDigest
  ) {
    fail('bundle_contract_invalid');
  }
  if (
    canonicalDigest(privateManifest.cmsNativeProtocol) !==
      canonicalDigest(repositoryBinding.cmsNativeProtocol) ||
    canonicalDigest(privateManifest.cmsNativeProtocol) !==
      canonicalDigest(runtimeExpectation.cmsNativeProtocol)
  ) {
    fail('bundle_contract_invalid');
  }
  const recomputed = {
    contentFixture: canonicalDigest(contentFixture),
    privateManifest: canonicalDigest(privateManifest),
    repositoryBinding: canonicalDigest(repositoryBinding),
    runtimeExpectation: canonicalDigest(runtimeExpectation),
  };
  for (const key of DIGEST_KEYS) {
    if (digests[key] !== recomputed[key]) fail('bundle_contract_invalid');
  }
  if (
    repositoryBinding.privateManifestDigest !== recomputed.privateManifest ||
    runtimeExpectation.expectedPrivateManifestDigest !== recomputed.privateManifest ||
    runtimeExpectation.expectedRepositoryBindingDigest !== recomputed.repositoryBinding
  ) {
    fail('bundle_contract_invalid');
  }
  if (
    runtimeExpectation.counts.editableTargets !== privateManifest.targets.length ||
    runtimeExpectation.counts.routes !== privateManifest.routes.length ||
    runtimeExpectation.counts.structuredFamilies !== privateManifest.structuredFamilies.length ||
    runtimeExpectation.counts.thirdPartyBoundaries !== privateManifest.thirdPartyBoundaries.length ||
    runtimeExpectation.counts.derivedDeclarations !== privateManifest.derived.length ||
    runtimeExpectation.counts.structuralDeclarations !== privateManifest.structural.length
  ) {
    fail('bundle_contract_invalid');
  }

  const expectedEditorial = new Set(contentFixture.editorialAssets.map(({ digest }) => digest));
  const actualEditorial = new Set(editorialAssets.map(({ digest }) => digest));
  if (
    expectedEditorial.size !== actualEditorial.size ||
    [...expectedEditorial].some((digest) => !actualEditorial.has(digest))
  ) {
    fail('bundle_contract_invalid');
  }
  for (const asset of editorialAssets) {
    if (sha256(asset.bytes) !== asset.digest) fail('bundle_contract_invalid');
  }
  const structuralDigests = new Set<string>();
  const structuralPaths = new Set<string>();
  for (const asset of privateManifest.structuralAssets) {
    if (asset.references.length === 0 || structuralDigests.has(asset.digest)) {
      fail('bundle_contract_invalid');
    }
    structuralDigests.add(asset.digest);
    if (expectedEditorial.has(asset.digest)) fail('bundle_contract_invalid');
    for (const reference of asset.references) {
      if (candidateDigests.get(reference.sourcePath) !== asset.digest) {
        fail('bundle_contract_invalid');
      }
      structuralPaths.add(reference.sourcePath);
    }
  }
  for (const path of candidateDigests.keys()) {
    if (/\.(?:avif|gif|jpe?g|png|webp|woff2?)$/iu.test(path) && !structuralPaths.has(path)) {
      fail('bundle_contract_invalid');
    }
  }
}

function candidateInventory(entries: readonly BundleEntryInput[]): {
  digest: Digest;
  digests: Map<string, Digest>;
} {
  const files = entries.map(({ path, bytes }) => ({
    path,
    bytes: bytes.byteLength,
    digest: sha256(bytes),
    content: bytes,
  }));
  const digests = new Map(files.map(({ path, digest }) => [path, digest]));
  return { digest: digestFileInventory(files), digests };
}

function payloadIndex(entries: readonly ArchiveEntry[]): MigrationPayloadIndexV1 {
  const value: MigrationPayloadIndexV1 = {
    version: PAYLOAD_INDEX_FORMAT,
    entries: entries.map(({ path, bytes, mode }) => ({
      path,
      bytes: bytes.byteLength,
      mode,
      digest: sha256(bytes),
    })),
  };
  if (!validatePayloadIndex(value).valid) fail('bundle_contract_invalid');
  return value;
}

function assertFinalEntries(entries: readonly ArchiveEntry[], limits: ArchiveLimits): void {
  if (entries.length > limits.maxEntries) fail('bundle_limit_exceeded');
  const paths = new Set<string>();
  let total = 0;
  for (const entry of entries) {
    if (paths.has(entry.path)) fail('bundle_contract_invalid');
    paths.add(entry.path);
    if (Buffer.byteLength(entry.path, 'utf8') > 100 || entry.path.split('/').length > limits.maxPathDepth) {
      fail('bundle_entry_forbidden');
    }
    if (entry.bytes.byteLength > limits.maxSingleBytes) fail('bundle_limit_exceeded');
    if (!Number.isSafeInteger(total + entry.bytes.byteLength)) fail('bundle_limit_exceeded');
    total += entry.bytes.byteLength;
    if (total > limits.maxTotalBytes) fail('bundle_limit_exceeded');
  }
}

async function encodeDeterministicArchive(
  entries: readonly ArchiveEntry[],
  packFactory: TarPackFactory,
): Promise<EncodedArchive> {
  try {
    const archive = packFactory();
    const chunks: Buffer[] = [];
    const archiveFailure = new Promise<never>((_resolve, reject) => {
      archive.once('error', reject);
    });
    const completion = new Promise<void>((resolve) => {
      archive.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      archive.once('end', resolve);
    });
    for (const entry of entries) {
      await Promise.race([
        new Promise<void>((resolve, reject) => {
          archive.entry(
            {
              name: entry.path,
              size: entry.bytes.byteLength,
              mode: entry.mode,
              type: 'file',
              mtime: new Date(0),
              uid: 0,
              gid: 0,
              uname: '',
              gname: '',
            },
            entry.bytes,
            (error) => (error ? reject(error) : resolve()),
          );
        }),
        archiveFailure,
      ]);
    }
    archive.finalize();
    await Promise.race([completion, archiveFailure]);
    const tarBytes = Buffer.concat(chunks);
    const gzipBytes = new Uint8Array(gzipSync(tarBytes, { level: 9 }));
    if (gzipBytes.byteLength < 10) fail('bundle_archive_failed');
    gzipBytes[9] = 3;
    return {
      bytes: gzipBytes,
      expandedBytes: tarBytes.byteLength,
    };
  } catch {
    fail('bundle_archive_failed');
  }
}

export async function createDeterministicTarGzip(
  entries: readonly ArchiveEntry[],
  packFactory: TarPackFactory = pack,
): Promise<Uint8Array> {
  return (await encodeDeterministicArchive(entries, packFactory)).bytes;
}

export async function createMigrationBundle(
  rawInput: CreateMigrationBundleInput,
): Promise<CreatedMigrationBundle> {
  assertInputRoot(rawInput);
  const limits = resolveArchiveLimits(rawInput.limits);
  if (BUNDLE_CAPABILITY_CLAIMS.length > limits.maxCapabilities) fail('bundle_limit_exceeded');
  assertArchiveEntries(rawInput.candidate, limits);
  const candidate = copyArchiveEntries(rawInput.candidate).sort((left, right) =>
    compareUtf8(left.path, right.path),
  );
  const editorialAssets = normalizedEditorialAssets(
    rawInput.editorialAssets,
    limits,
  );
  const candidateBytes = candidate.reduce((total, entry) => total + entry.bytes.byteLength, 0);
  const editorialBytes = editorialAssets.reduce((total, asset) => total + asset.bytes.byteLength, 0);
  if (
    !Number.isSafeInteger(candidateBytes + editorialBytes) ||
    candidateBytes + editorialBytes > limits.maxTotalBytes
  ) {
    fail('bundle_limit_exceeded');
  }
  const source = normalizedSourceInventory(rawInput.sourceInventory, limits);
  const dependencies = normalizedDependencies(rawInput.dependencyInventory, limits);
  const evidence = normalizedEvidence(rawInput.evidence, limits);
  if (evidence.length + 1 > limits.maxEvidenceEntries) fail('bundle_limit_exceeded');
  const sourceEvidenceBytes = canonicalJsonBytes(source.body).byteLength;
  const advisoryEvidenceBytes = evidence.reduce((total, item) => total + item.bytes.byteLength, 0);
  if (
    !Number.isSafeInteger(sourceEvidenceBytes + advisoryEvidenceBytes) ||
    sourceEvidenceBytes + advisoryEvidenceBytes > limits.maxEvidenceBytes
  ) {
    fail('bundle_limit_exceeded');
  }
  const artifacts = normalizeArtifacts(rawInput.artifacts);
  const candidateIdentity = candidateInventory(candidate);
  assertArtifactContracts(
    artifacts,
    rawInput,
    candidateIdentity.digest,
    source.digest,
    candidateIdentity.digests,
    editorialAssets,
  );

  const capabilityClaims: CapabilityClaimsV1 = {
    format: CAPABILITY_CLAIMS_FORMAT,
    claims: [...BUNDLE_CAPABILITY_CLAIMS],
  };
  const entries: ArchiveEntry[] = candidate.map(({ path, bytes, executable }) => ({
    path: `candidate/${path}`,
    bytes,
    mode: executable ? (0o755 as const) : (0o644 as const),
  }));
  const addJson = (path: string, value: unknown): void => {
    entries.push({ path, bytes: canonicalJsonBytes(value), mode: 0o644 });
  };
  addJson('verow/artifacts/content-fixture.json', artifacts.contentFixture);
  addJson('verow/artifacts/private-manifest.json', artifacts.privateManifest);
  addJson('verow/artifacts/repository-binding.json', artifacts.repositoryBinding);
  addJson('verow/artifacts/runtime-expectation.json', artifacts.runtimeExpectation);
  addJson('verow/artifacts/dependency-inventory.json', dependencies);
  addJson('verow/artifacts/capability-claims.json', capabilityClaims);

  const evidenceEntries: ArchiveEntry[] = [
    {
      path: 'verow/evidence/source-inventory.json',
      bytes: canonicalJsonBytes(source.body),
      mode: 0o644 as const,
    },
    ...evidence.map(({ name, bytes }) => ({
      path: `verow/evidence/${name}.json`,
      bytes,
      mode: 0o644 as const,
    })),
  ].sort((left, right) => compareUtf8(left.path, right.path));
  entries.push(...evidenceEntries);
  const evidenceIndex: EvidenceIndexV1 = {
    format: EVIDENCE_INDEX_FORMAT,
    entries: evidenceEntries.map(({ path, bytes }) => ({
      path,
      bytes: bytes.byteLength,
      digest: sha256(bytes),
    })),
  };
  addJson('verow/artifacts/evidence-index.json', evidenceIndex);
  for (const asset of editorialAssets) {
    entries.push({ path: `verow/assets/${asset.digest.slice(7)}`, bytes: asset.bytes, mode: 0o644 });
  }
  entries.sort((left, right) => compareUtf8(left.path, right.path));
  const index = payloadIndex(entries);
  entries.push({
    path: 'verow/payload-index.json',
    bytes: canonicalJsonBytes(index),
    mode: 0o644,
  });
  entries.sort((left, right) => compareUtf8(left.path, right.path));
  assertFinalEntries(entries, limits);

  const encoded = await encodeDeterministicArchive(entries, pack);
  if (encoded.bytes.byteLength > limits.maxCompressedBytes) fail('bundle_limit_exceeded');
  if (
    encoded.bytes.byteLength === 0 ||
    encoded.expandedBytes > encoded.bytes.byteLength * limits.maxExpansionRatio
  ) {
    fail('bundle_limit_exceeded');
  }
  const artifactDigest = sha256(encoded.bytes);
  const manifest: MigrationBundleManifestV1 = {
    version: BUNDLE_FORMAT,
    migrationId: rawInput.migrationId,
    websiteId: rawInput.websiteId,
    sourceDigest: source.digest,
    artifactDigest,
    archiveFormat: ARCHIVE_FORMAT,
    sourceKind: 'codex_sites_local',
    framework: 'nextjs_app_router',
    fileCount: entries.length,
    totalBytes: encoded.bytes.byteLength,
    capabilityClaims: [...BUNDLE_CAPABILITY_CLAIMS],
    privateManifestDigest: artifacts.digests.privateManifest,
    evidenceDigest: canonicalDigest(evidenceIndex),
  };
  if (!validateBundleDescriptor(manifest).valid) fail('bundle_contract_invalid');
  return {
    bytes: encoded.bytes,
    artifactDigest,
    payloadIndex: index,
    manifest,
    capabilityClaims,
    evidenceIndex,
  };
}
