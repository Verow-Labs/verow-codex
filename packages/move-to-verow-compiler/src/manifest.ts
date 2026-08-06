import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { types as nodeUtilTypes } from 'node:util';

import { canonicalDigest } from './bundle-contract.js';
import { normalizeSemanticSegment } from './content-key.js';
import type { AssetDigest, AssetInventoryResult, AssetTargetIdentity } from './asset-inventory.js';
import type {
  ContentExtractionResult,
  EditableContentCandidate,
  ManagedContentSourceKind,
  ManagedContentValueType,
  StructuredFamily,
} from './content-extractor.js';

export const PRIVATE_MANIFEST_FORMAT = 'move-to-verow.manifest.v1' as const;
export const CONTENT_FIXTURE_FORMAT = 'move-to-verow.content-fixture.v1' as const;
export const REPOSITORY_BINDING_FORMAT = 'move-to-verow.repository-binding.v1' as const;
export const RUNTIME_EXPECTATION_FORMAT = 'move-to-verow.runtime-expectation.v1' as const;

export interface MigrationContentIdentity {
  key: string;
  locale: string;
  variant: string | null;
}

export interface CmsNativeProtocolIdentityV1 {
  package: '@verow/cms-native';
  version: string;
  contractDigest: AssetDigest;
}

export interface MigrationRouteV1 {
  routeId: string;
  path: string;
  renderedSource: string;
}

export type MigrationActionV1 = 'edit' | 'create' | 'delete' | 'reorder';
export type MigrationCardinalityV1 = 'one' | 'many';
export type LiveVerificationIntentV1 = 'route' | 'global' | 'none';

export interface ImagePairPolicyV1 {
  role: 'image' | 'alt';
  target: MigrationContentIdentity;
}

export interface MigrationTargetPolicyV1 extends MigrationContentIdentity {
  required: boolean;
  cardinality: MigrationCardinalityV1;
  actions: MigrationActionV1[];
  liveVerification: LiveVerificationIntentV1;
  imagePair: ImagePairPolicyV1 | null;
  collection: null;
}

export interface CollectionPolicyV1 extends MigrationContentIdentity {
  minimumItems: number;
  maximumItems: number;
  requiredItemIds: string[];
}

export interface MigrationCompilePolicyV1 {
  targets: MigrationTargetPolicyV1[];
  collectionPolicy: CollectionPolicyV1[];
}

export interface CompileMigrationArtifactsInput {
  websiteId: string;
  migrationId: string;
  sourceDigest: AssetDigest;
  candidateDigest: AssetDigest;
  cmsNativeProtocol: CmsNativeProtocolIdentityV1;
  extraction: ContentExtractionResult;
  assets: AssetInventoryResult;
  routes: MigrationRouteV1[];
  policy: MigrationCompilePolicyV1;
}

export interface MigrationOnlyContentFixtureV1 {
  format: typeof CONTENT_FIXTURE_FORMAT;
  websiteId: string;
  migrationId: string;
  purpose: 'migration_upload_only';
  values: Array<MigrationContentIdentity & { value: string }>;
  editorialAssets: Array<{ digest: AssetDigest; target: MigrationContentIdentity }>;
  externalAssets: Array<{ target: MigrationContentIdentity; url: string }>;
}

export interface PrivateManifestTargetV1 extends MigrationContentIdentity {
  label: string;
  owner: 'site_region' | 'structured_family';
  structuredFamily: StructuredFamily | null;
  sourceKind: ManagedContentSourceKind;
  valueType: ManagedContentValueType;
  routeId: string;
  route: MigrationRouteV1 | null;
  sourceEvidence: { path: string; anchor: string };
  binding: { kind: 'logical_content_key'; key: string };
  required: boolean;
  cardinality: MigrationCardinalityV1;
  actions: MigrationActionV1[];
  liveVerification: LiveVerificationIntentV1;
  imagePair: ImagePairPolicyV1 | null;
  collection: Pick<CollectionPolicyV1, 'minimumItems' | 'maximumItems' | 'requiredItemIds'> | null;
  editorialAssetDigest: AssetDigest | null;
  externalBoundary: string | null;
  externalUrl: string | null;
}

export interface PrivateManifestSubmissionV1 {
  format: typeof PRIVATE_MANIFEST_FORMAT;
  websiteId: string;
  migrationId: string;
  sourceDigest: AssetDigest;
  candidateDigest: AssetDigest;
  cmsNativeProtocol: CmsNativeProtocolIdentityV1;
  structuredFamilies: StructuredFamily[];
  routes: MigrationRouteV1[];
  targets: PrivateManifestTargetV1[];
  thirdPartyBoundaries: ContentExtractionResult['thirdPartyBoundaries'];
  derived: ContentExtractionResult['derived'];
  structural: ContentExtractionResult['structural'];
  structuralAssets: Array<{
    digest: AssetDigest;
    mime: string;
    references: Array<{ id: string; sourcePath: string }>;
  }>;
}

export type RepositoryContentBindingV1 = MigrationContentIdentity;

export interface RepositoryBindingContractV1 {
  format: typeof REPOSITORY_BINDING_FORMAT;
  websiteId: string;
  migrationId: string;
  sourceDigest: AssetDigest;
  candidateDigest: AssetDigest;
  cmsNativeProtocol: CmsNativeProtocolIdentityV1;
  privateManifestDigest: AssetDigest;
  runtimeBinding: { strategy: 'canonical_content_identity'; identityVersion: 1 };
  bindings: RepositoryContentBindingV1[];
}

export interface RuntimeExpectationV1 {
  format: typeof RUNTIME_EXPECTATION_FORMAT;
  websiteId: string;
  migrationId: string;
  cmsNativeProtocol: CmsNativeProtocolIdentityV1;
  expectedPrivateManifestDigest: AssetDigest;
  expectedRepositoryBindingDigest: AssetDigest;
  counts: {
    editableTargets: number;
    routes: number;
    structuredFamilies: number;
    thirdPartyBoundaries: number;
    derivedDeclarations: number;
    structuralDeclarations: number;
  };
}

export interface MigrationArtifactDigestsV1 {
  contentFixture: AssetDigest;
  privateManifest: AssetDigest;
  repositoryBinding: AssetDigest;
  runtimeExpectation: AssetDigest;
}

export interface CompiledMigrationArtifacts {
  contentFixture: MigrationOnlyContentFixtureV1;
  privateManifest: PrivateManifestSubmissionV1;
  repositoryBinding: RepositoryBindingContractV1;
  runtimeExpectation: RuntimeExpectationV1;
  digests: MigrationArtifactDigestsV1;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const SEMVER_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/u;
const STRUCTURED_FAMILIES = new Set<StructuredFamily>(['blog', 'event', 'social', 'menu', 'faq']);
const ACTIONS = new Set<MigrationActionV1>(['edit', 'create', 'delete', 'reorder']);
const SOURCE_KINDS = new Set<ManagedContentSourceKind>(['jsx', 'json', 'typescript', 'css_content', 'aria', 'metadata']);
const VALUE_TYPES = new Set<ManagedContentValueType>(['string', 'rich_text', 'url', 'email', 'telephone', 'image', 'collection']);
const INPUT_KEYS = ['assets', 'candidateDigest', 'cmsNativeProtocol', 'extraction', 'migrationId', 'policy', 'routes', 'sourceDigest', 'websiteId'];
const MAX_TARGETS = 500;
const MAX_STRING = 2_000;
const MAX_COLLECTION_ITEMS = 1_000;
const EXTRACTION_KEYS = ['derived', 'needsAttention', 'status', 'structural', 'structuredFamilies', 'targets', 'thirdPartyBoundaries', 'values'];
const ASSET_INVENTORY_KEYS = ['blockers', 'bundled', 'external', 'status', 'structural'];
const TARGET_KEYS = ['key', 'label', 'locale', 'owner', 'routeId', 'sourceAnchor', 'sourceKind', 'sourcePath', 'structuredFamily', 'thirdPartyBoundary', 'valueType', 'variant'];

function fail(code: string): never {
  throw new Error(code);
}

function compareStrings(left: string, right: string): number {
  return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'));
}

function compareIdentities(left: MigrationContentIdentity, right: MigrationContentIdentity): number {
  return compareStrings(identityKey(left), identityKey(right));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || nodeUtilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length > 0) return false;
  return Object.values(Object.getOwnPropertyDescriptors(value)).every((descriptor) => descriptor.enumerable && descriptor.get === undefined && descriptor.set === undefined);
}

function isPlainArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || nodeUtilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length > 0) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).filter((key) => key !== 'length');
  return keys.length === value.length && keys.every((key) => descriptors[key]?.get === undefined && descriptors[key]?.set === undefined);
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareStrings);
  const sortedExpected = [...expected].sort(compareStrings);
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function safeString(value: unknown, maximum = MAX_STRING): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum && value === value.normalize('NFC') && !/\p{Cc}/u.test(value);
}

function validIdentity(value: unknown): value is MigrationContentIdentity {
  if (!isRecord(value)) return false;
  const variant = value.variant;
  return safeString(value.key, 500) && safeString(value.locale, 100) && (variant === null || safeString(variant, 100));
}

function identityKey(identity: MigrationContentIdentity): string {
  return `${identity.key}\u0000${identity.locale}\u0000${identity.variant ?? ''}`;
}

function copyIdentity(identity: MigrationContentIdentity): MigrationContentIdentity {
  return { key: identity.key, locale: identity.locale, variant: identity.variant };
}

function validDigest(value: unknown): value is AssetDigest {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function validProtocol(value: unknown): value is CmsNativeProtocolIdentityV1 {
  return isRecord(value) && exactKeys(value, ['contractDigest', 'package', 'version']) && safeString(value.package, 200) &&
    value.package === '@verow/cms-native' && safeString(value.version, 100) && SEMVER_PATTERN.test(value.version) && validDigest(value.contractDigest);
}

function validRoute(route: unknown): route is MigrationRouteV1 {
  if (!isRecord(route) || !exactKeys(route, ['path', 'renderedSource', 'routeId'])) return false;
  if (!safeString(route.routeId, 200) || route.routeId === 'global' || !safeString(route.renderedSource, 500)) return false;
  if (typeof route.path !== 'string' || route.path !== route.path.normalize('NFC') || !route.path.startsWith('/') || route.path.includes('?') || route.path.includes('#') || route.path.includes('\\') || /\p{Cc}/u.test(route.path)) return false;
  return !route.path.split('/').some((segment, index) => index > 0 && (segment === '' || segment === '.' || segment === '..')) || route.path === '/';
}

function isPublicIpAddress(address: string): boolean {
  const normalized = address.toLowerCase().replace(/^\[|\]$/gu, '');
  const version = isIP(normalized);
  if (version === 4) {
    const octets = normalized.split('.').map(Number);
    const [a, b] = octets;
    if (a === undefined || b === undefined) return false;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 0 || b === 168)) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0));
  }
  if (version === 6) return /^[23]/u.test(normalized) && !normalized.startsWith('2001:db8:') && !normalized.startsWith('2001:0db8:');
  return false;
}

function canonicalPublicHttpsUrl(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length > MAX_STRING) return null;
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || parsed.port) return null;
    const hostname = parsed.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname.endsWith('.localhost')) return null;
    if (isIP(hostname.replace(/^\[|\]$/gu, '')) !== 0 && !isPublicIpAddress(hostname)) return null;
    parsed.hostname = hostname;
    return parsed.toString() === raw ? raw : null;
  } catch {
    return null;
  }
}

function validateRoot(input: CompileMigrationArtifactsInput): void {
  if (!isRecord(input) || !exactKeys(input, INPUT_KEYS) || !UUID_PATTERN.test(input.websiteId) || !UUID_PATTERN.test(input.migrationId) ||
      !validDigest(input.sourceDigest) || !validDigest(input.candidateDigest) || !validProtocol(input.cmsNativeProtocol)) fail('manifest_input_invalid');
  if (!isPlainArray(input.routes) || !isRecord(input.extraction) || !isRecord(input.assets) || !isRecord(input.policy)) fail('manifest_input_invalid');
  if (!exactKeys(input.extraction, EXTRACTION_KEYS) || !isPlainArray(input.extraction.targets) || !isRecord(input.extraction.values) ||
      !isPlainArray(input.extraction.structuredFamilies) || !isPlainArray(input.extraction.thirdPartyBoundaries) ||
      !isPlainArray(input.extraction.derived) || !isPlainArray(input.extraction.structural) || !isPlainArray(input.extraction.needsAttention)) fail('manifest_input_invalid');
  if (!exactKeys(input.assets, ASSET_INVENTORY_KEYS) || !isPlainArray(input.assets.bundled) || !isPlainArray(input.assets.structural) ||
      !isPlainArray(input.assets.external) || !isPlainArray(input.assets.blockers)) fail('manifest_input_invalid');
}

function routeMap(input: CompileMigrationArtifactsInput): Map<string, MigrationRouteV1> {
  const routes = new Map<string, MigrationRouteV1>();
  for (const route of input.routes) {
    if (!validRoute(route) || routes.has(route.routeId) || [...routes.values()].some(({ path }) => path === route.path)) fail('manifest_route_invalid');
    routes.set(route.routeId, { routeId: route.routeId, path: route.path, renderedSource: route.renderedSource });
  }
  return routes;
}

function validateCandidate(target: EditableContentCandidate, routes: ReadonlyMap<string, MigrationRouteV1>): void {
  if (!validIdentity(target) || !exactKeys(target, TARGET_KEYS) || !safeString(target.label) || !safeString(target.sourceKind, 100) || !safeString(target.valueType, 100) ||
      !safeString(target.routeId, 200) || !safeString(target.sourcePath) || !safeString(target.sourceAnchor) || target.thirdPartyBoundary !== null) fail('manifest_input_invalid');
  if (!SOURCE_KINDS.has(target.sourceKind) || !VALUE_TYPES.has(target.valueType)) fail('manifest_input_invalid');
  if (target.routeId !== 'global' && !routes.has(target.routeId)) fail('manifest_route_invalid');
  if (target.owner === 'site_region') {
    if (target.structuredFamily !== null) fail('manifest_input_invalid');
  } else if (target.owner !== 'structured_family' || target.structuredFamily === null || !STRUCTURED_FAMILIES.has(target.structuredFamily)) {
    fail('manifest_input_invalid');
  }
}

function extractionIdentities(input: CompileMigrationArtifactsInput, routes: ReadonlyMap<string, MigrationRouteV1>): Map<string, EditableContentCandidate> {
  if (input.extraction.status !== 'ready' || input.extraction.needsAttention.length > 0) fail('manifest_extraction_blocked');
  if (!isPlainArray(input.extraction.targets) || input.extraction.targets.length > MAX_TARGETS || !isRecord(input.extraction.values)) fail(input.extraction.targets.length > MAX_TARGETS ? 'manifest_target_limit_exceeded' : 'manifest_input_invalid');
  const targets = new Map<string, EditableContentCandidate>();
  for (const target of input.extraction.targets) {
    validateCandidate(target, routes);
    const id = identityKey(target);
    if (targets.has(id)) fail('manifest_identity_bijection');
    targets.set(id, target);
  }
  const valueIds = Object.keys(input.extraction.values);
  if (valueIds.length !== targets.size) fail('manifest_identity_bijection');
  for (const [mapIdentity, managedValue] of Object.entries(input.extraction.values)) {
    if (!validIdentity(managedValue) || !exactKeys(managedValue, ['key', 'locale', 'value', 'variant']) || typeof managedValue.value !== 'string') fail('manifest_input_invalid');
    if (mapIdentity !== identityKey(managedValue) || !targets.has(mapIdentity)) fail('manifest_identity_bijection');
  }
  return targets;
}

function policyMap(input: CompileMigrationArtifactsInput, targets: ReadonlyMap<string, EditableContentCandidate>): Map<string, MigrationTargetPolicyV1> {
  if (!isRecord(input.policy) || !exactKeys(input.policy, ['collectionPolicy', 'targets']) || !isPlainArray(input.policy.targets) || !isPlainArray(input.policy.collectionPolicy)) fail('manifest_policy_invalid');
  const policies = new Map<string, MigrationTargetPolicyV1>();
  for (const policy of input.policy.targets) {
    if (!isRecord(policy) || !exactKeys(policy, ['actions', 'cardinality', 'collection', 'imagePair', 'key', 'liveVerification', 'locale', 'required', 'variant']) || !validIdentity(policy) ||
        typeof policy.required !== 'boolean' || !['one', 'many'].includes(policy.cardinality) || !['route', 'global', 'none'].includes(policy.liveVerification) || policy.collection !== null ||
        !isPlainArray(policy.actions) || policy.actions.length === 0 || policy.actions.some((action) => !ACTIONS.has(action as MigrationActionV1)) || new Set(policy.actions).size !== policy.actions.length) fail('manifest_policy_invalid');
    if (policy.imagePair !== null && (!isRecord(policy.imagePair) || !exactKeys(policy.imagePair, ['role', 'target']) || !['image', 'alt'].includes(policy.imagePair.role) || !validIdentity(policy.imagePair.target))) fail('manifest_policy_invalid');
    const id = identityKey(policy);
    if (policies.has(id)) fail('manifest_policy_bijection');
    policies.set(id, policy);
  }
  if (policies.size !== targets.size || [...targets.keys()].some((id) => !policies.has(id))) fail('manifest_policy_bijection');
  return policies;
}

interface CollectionDetails {
  byRoot: Map<string, Pick<CollectionPolicyV1, 'minimumItems' | 'maximumItems' | 'requiredItemIds'>>;
}

function collectionDetails(input: CompileMigrationArtifactsInput, targets: ReadonlyMap<string, EditableContentCandidate>): CollectionDetails {
  const roots = [...targets.values()].filter(({ valueType }) => valueType === 'collection');
  const policies = new Map<string, CollectionPolicyV1>();
  for (const policy of input.policy.collectionPolicy) {
    if (!isRecord(policy) || !exactKeys(policy, ['key', 'locale', 'maximumItems', 'minimumItems', 'requiredItemIds', 'variant']) || !validIdentity(policy) ||
        !Number.isSafeInteger(policy.minimumItems) || !Number.isSafeInteger(policy.maximumItems) || policy.minimumItems < 0 || policy.maximumItems < policy.minimumItems || policy.maximumItems > MAX_COLLECTION_ITEMS ||
        !isPlainArray(policy.requiredItemIds) || policy.requiredItemIds.some((id) => !safeString(id, 200)) || new Set(policy.requiredItemIds).size !== policy.requiredItemIds.length) fail('manifest_collection_invalid');
    const id = identityKey(policy);
    if (policies.has(id)) fail('manifest_collection_invalid');
    policies.set(id, policy);
  }
  if (roots.length !== policies.size || roots.some((root) => !policies.has(identityKey(root)))) {
    if (roots.length > 0 || policies.size > 0) fail('manifest_collection_invalid');
  }
  const byRoot = new Map<string, Pick<CollectionPolicyV1, 'minimumItems' | 'maximumItems' | 'requiredItemIds'>>();
  const claimedItemTargets = new Set<string>();
  for (const root of roots) {
    const id = identityKey(root);
    const policy = policies.get(id);
    if (policy === undefined) fail('manifest_collection_invalid');
    const rawValue = input.extraction.values[id]?.value;
    let stableIds: unknown;
    try { stableIds = JSON.parse(rawValue ?? ''); } catch { fail('manifest_collection_invalid'); }
    if (!isPlainArray(stableIds) || stableIds.some((item) => !safeString(item, 200)) || new Set(stableIds).size !== stableIds.length) fail('manifest_collection_invalid');
    const rawIds = stableIds as string[];
    if (rawIds.some((item, index) => index > 0 && compareStrings(rawIds[index - 1] as string, item) >= 0)) fail('manifest_collection_invalid');
    if (rawIds.length < policy.minimumItems || rawIds.length > policy.maximumItems || policy.requiredItemIds.some((required) => !rawIds.includes(required))) fail('manifest_collection_invalid');
    const normalizedIds = new Map<string, string>();
    try {
      for (const rawId of rawIds) {
        const normalized = normalizeSemanticSegment(rawId);
        if (normalizedIds.has(normalized)) fail('manifest_collection_invalid');
        normalizedIds.set(normalized, rawId);
      }
    } catch { fail('manifest_collection_invalid'); }
    const prefix = `${root.key}.items.`;
    const found = new Set<string>();
    for (const target of targets.values()) {
      if (target.locale !== root.locale || target.variant !== root.variant || !target.key.startsWith(prefix)) continue;
      const remainder = target.key.slice(prefix.length);
      const itemId = remainder.split('.')[0] ?? '';
      if (!normalizedIds.has(itemId) || remainder === itemId) fail('manifest_collection_invalid');
      found.add(itemId);
      claimedItemTargets.add(identityKey(target));
    }
    if ([...normalizedIds.keys()].some((itemId) => !found.has(itemId))) fail('manifest_collection_invalid');
    byRoot.set(id, {
      minimumItems: policy.minimumItems,
      maximumItems: policy.maximumItems,
      requiredItemIds: [...policy.requiredItemIds].sort(compareStrings),
    });
  }
  for (const target of targets.values()) {
    if (target.key.includes('.items.') && target.valueType !== 'collection' && !claimedItemTargets.has(identityKey(target))) fail('manifest_collection_invalid');
  }
  return { byRoot };
}

function validateFamilies(input: CompileMigrationArtifactsInput, targets: ReadonlyMap<string, EditableContentCandidate>): StructuredFamily[] {
  if (!isPlainArray(input.extraction.structuredFamilies) || input.extraction.structuredFamilies.some((family) => !STRUCTURED_FAMILIES.has(family as StructuredFamily)) || new Set(input.extraction.structuredFamilies).size !== input.extraction.structuredFamilies.length) fail('manifest_input_invalid');
  const declared = [...input.extraction.structuredFamilies].sort(compareStrings);
  const used = [...new Set([...targets.values()].flatMap((target) => target.structuredFamily === null ? [] : [target.structuredFamily]))].sort(compareStrings);
  if (JSON.stringify(declared) !== JSON.stringify(used)) fail('manifest_input_invalid');
  return declared;
}

interface AssetBindings {
  editorial: Map<string, AssetDigest>;
  external: Map<string, { url: string; boundary: string }>;
}

function validAssetReference(reference: unknown, classification: 'editorial_cms' | 'structural_git'): reference is Record<string, unknown> & { target?: MigrationContentIdentity } {
  if (!isRecord(reference) || !exactKeys(reference, classification === 'editorial_cms'
    ? ['classification', 'id', 'provenance', 'sourcePath', 'target']
    : ['classification', 'id', 'provenance', 'sourcePath'])) return false;
  if (reference.classification !== classification || !safeString(reference.id, 500) || !safeString(reference.sourcePath) || !isRecord(reference.provenance)) return false;
  const provenance = reference.provenance;
  if (provenance.authority === 'source_local') {
    if (!exactKeys(provenance, ['authority', 'sourcePath']) || provenance.sourcePath !== reference.sourcePath) return false;
  } else if (provenance.authority === 'hosted_source_capture') {
    if (!exactKeys(provenance, ['authority', 'finalUrl', 'originalUrl', 'receiptPolicyVersion', 'sourcePath']) ||
        provenance.receiptPolicyVersion !== 'move-to-verow.capture-receipt.v1' || provenance.sourcePath !== reference.sourcePath ||
        canonicalPublicHttpsUrl(provenance.originalUrl) === null || canonicalPublicHttpsUrl(provenance.finalUrl) === null) return false;
  } else return false;
  return classification === 'structural_git' || validIdentity(reference.target);
}

function validInventoriedAsset(asset: unknown, classification: 'editorial_cms' | 'structural_git'): asset is Record<string, unknown> & { bytesValue: Uint8Array; references: unknown[] } {
  if (!isRecord(asset)) return false;
  const optional = [...(Object.hasOwn(asset, 'fontLicense') ? ['fontLicense'] : []), ...(Object.hasOwn(asset, 'sanitizerPolicy') ? ['sanitizerPolicy'] : [])];
  if (!exactKeys(asset, ['animated', 'bytes', 'bytesValue', 'digest', 'encodedHeight', 'encodedWidth', 'mime', 'pageCount', 'references', 'renderedHeight', 'renderedWidth', ...optional]) ||
      !validDigest(asset.digest) || !(asset.bytesValue instanceof Uint8Array) || nodeUtilTypes.isProxy(asset.bytesValue) || asset.bytes !== asset.bytesValue.byteLength || digestBytes(asset.bytesValue) !== asset.digest ||
      !safeString(asset.mime, 100) || typeof asset.animated !== 'boolean' || !isPlainArray(asset.references) || asset.references.length === 0 ||
      ![asset.encodedWidth, asset.encodedHeight, asset.renderedWidth, asset.renderedHeight, asset.pageCount].every(Number.isSafeInteger)) return false;
  if (asset.references.some((reference) => !validAssetReference(reference, classification))) return false;
  if (asset.sanitizerPolicy !== undefined && (!isRecord(asset.sanitizerPolicy) || !exactKeys(asset.sanitizerPolicy, ['digest', 'version']) || asset.sanitizerPolicy.version !== 'move-to-verow.svg-safety.v1' || !validDigest(asset.sanitizerPolicy.digest))) return false;
  if (asset.fontLicense !== undefined && (!isRecord(asset.fontLicense) || !exactKeys(asset.fontLicense, ['notice', 'spdxId']) || !safeString(asset.fontLicense.notice) || !['OFL-1.1', 'Apache-2.0', 'MIT', 'BSD-3-Clause'].includes(asset.fontLicense.spdxId as string))) return false;
  return true;
}

function validateReadyAssetInventory(input: CompileMigrationArtifactsInput): void {
  if (input.assets.status !== 'ready' || input.assets.blockers.length > 0) fail('manifest_assets_blocked');
  if (input.assets.bundled.some((asset) => !validInventoriedAsset(asset, 'editorial_cms')) ||
      input.assets.structural.some((asset) => !validInventoriedAsset(asset, 'structural_git'))) fail('manifest_input_invalid');
  for (const asset of input.assets.external) {
    if (!isRecord(asset) || !exactKeys(asset, ['privateBoundary', 'provenance', 'reference', 'url']) || !safeString(asset.privateBoundary) ||
        canonicalPublicHttpsUrl(asset.url) === null || !isRecord(asset.reference) || !exactKeys(asset.reference, ['id', 'sourcePath', 'target']) ||
        !safeString(asset.reference.id, 500) || !safeString(asset.reference.sourcePath) || !validIdentity(asset.reference.target) ||
        !isRecord(asset.provenance) || !exactKeys(asset.provenance, ['authority', 'privateBoundary', 'url']) || asset.provenance.authority !== 'declared_external' ||
        asset.provenance.url !== asset.url || asset.provenance.privateBoundary !== asset.privateBoundary) fail('manifest_input_invalid');
  }
}

function digestBytes(bytes: Uint8Array): AssetDigest {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function assetBindings(input: CompileMigrationArtifactsInput, targets: ReadonlyMap<string, EditableContentCandidate>): AssetBindings {
  validateReadyAssetInventory(input);
  const editorial = new Map<string, AssetDigest>();
  const external = new Map<string, { url: string; boundary: string }>();
  for (const asset of input.assets.bundled) {
    if (!validDigest(asset.digest) || !(asset.bytesValue instanceof Uint8Array) || asset.bytes !== asset.bytesValue.byteLength || digestBytes(asset.bytesValue) !== asset.digest) fail('manifest_image_binding_invalid');
    for (const reference of asset.references) {
      if (reference.target === undefined || reference.classification !== 'editorial_cms') fail('manifest_image_binding_invalid');
      const id = identityKey(reference.target as MigrationContentIdentity);
      if (editorial.has(id) || external.has(id) || targets.get(id)?.valueType !== 'image') fail('manifest_image_binding_invalid');
      editorial.set(id, asset.digest);
    }
  }
  for (const asset of input.assets.external) {
    const target = asset.reference.target as AssetTargetIdentity;
    if (!validIdentity(target) || !safeString(asset.privateBoundary) || typeof asset.url !== 'string') fail('manifest_image_binding_invalid');
    let url: URL;
    try { url = new URL(asset.url); } catch { fail('manifest_image_binding_invalid'); }
    if (url.protocol !== 'https:' || url.href !== asset.url || url.username || url.password || url.hash) fail('manifest_image_binding_invalid');
    const id = identityKey(target as MigrationContentIdentity);
    if (editorial.has(id) || external.has(id) || targets.get(id)?.valueType !== 'image') fail('manifest_image_binding_invalid');
    external.set(id, { url: asset.url, boundary: asset.privateBoundary });
  }
  for (const [id, target] of targets) {
    const bound = Number(editorial.has(id)) + Number(external.has(id));
    if (target.valueType === 'image') {
      if (bound !== 1) fail('manifest_image_binding_invalid');
      const expectedValue = editorial.get(id) ?? external.get(id)?.url;
      if (input.extraction.values[id]?.value !== expectedValue) fail('manifest_image_binding_invalid');
    } else if (bound !== 0) fail('manifest_image_binding_invalid');
  }
  return { editorial, external };
}

function validateImagePairs(targets: ReadonlyMap<string, EditableContentCandidate>, policies: ReadonlyMap<string, MigrationTargetPolicyV1>): void {
  for (const [id, policy] of policies) {
    const target = targets.get(id) as EditableContentCandidate;
    const pair = policy.imagePair;
    if (pair !== null) {
      const pairId = identityKey(pair.target);
      const pairedPolicy = policies.get(pairId);
      const pairedTarget = targets.get(pairId);
      if (pairedPolicy?.imagePair === null || pairedPolicy?.imagePair === undefined || pairedTarget === undefined || identityKey(pairedPolicy.imagePair.target) !== id || pairedPolicy.imagePair.role === pair.role) fail('manifest_image_pair_invalid');
      if (target.locale !== pairedTarget.locale || target.variant !== pairedTarget.variant) fail('manifest_image_pair_invalid');
      if ((pair.role === 'image' && (target.valueType !== 'image' || pairedTarget.valueType !== 'string')) ||
          (pair.role === 'alt' && (target.valueType !== 'string' || pairedTarget.valueType !== 'image'))) fail('manifest_image_pair_invalid');
    }
    if (target.valueType === 'image') {
      const suffix = target.key.endsWith('.src') ? '.src' : target.key.endsWith('.image') ? '.image' : null;
      const altKey = suffix === null ? null : `${target.key.slice(0, -suffix.length)}.alt`;
      const hasAlt = altKey !== null && targets.has(identityKey({ key: altKey, locale: target.locale, variant: target.variant }));
      if (hasAlt && pair === null) fail('manifest_image_pair_invalid');
    }
  }
}

function validatePrivateDeclarations(input: CompileMigrationArtifactsInput, routes: ReadonlyMap<string, MigrationRouteV1>, targets: ReadonlyMap<string, EditableContentCandidate>): void {
  const editable = new Set(targets.keys());
  const declarationIds = new Set<string>();
  const declarations = [
    { list: input.extraction.thirdPartyBoundaries, keys: ['integration', 'key', 'locale', 'provider', 'renderedAnchor', 'sourceAnchor', 'sourcePath', 'variant'] },
    { list: input.extraction.derived, keys: ['derivedFrom', 'key', 'locale', 'routeId', 'sourceAnchor', 'sourcePath', 'variant'] },
    { list: input.extraction.structural, keys: ['key', 'locale', 'reason', 'routeId', 'sourceAnchor', 'sourcePath', 'variant'] },
  ] as const;
  for (const { list, keys } of declarations) {
    if (!isPlainArray(list)) fail('manifest_input_invalid');
    for (const declaration of list) {
      if (!validIdentity(declaration) || !exactKeys(declaration, keys)) fail('manifest_input_invalid');
      const record = declaration as unknown as Record<string, unknown> & MigrationContentIdentity;
      if (!safeString(record.sourcePath) || !safeString(record.sourceAnchor)) fail('manifest_input_invalid');
      const id = identityKey(declaration);
      if (editable.has(id) || declarationIds.has(id)) fail('manifest_boundary_invalid');
      declarationIds.add(id);
      if ('routeId' in record && (!safeString(record.routeId, 200) || (record.routeId !== 'global' && !routes.has(record.routeId)))) fail('manifest_route_invalid');
      if ('provider' in record && (!safeString(record.provider) || !safeString(record.integration) || !safeString(record.renderedAnchor))) fail('manifest_boundary_invalid');
      if ('derivedFrom' in record && !safeString(record.derivedFrom, 500)) fail('manifest_input_invalid');
      if ('reason' in record && !['aria_hidden_decorative_asset', 'explicit_structural_annotation'].includes(record.reason as string)) fail('manifest_input_invalid');
    }
  }
}

function sortedReadonlyCopies<T extends object & MigrationContentIdentity>(values: readonly T[]): T[] {
  return values.map((value) => ({ ...value })).sort(compareIdentities);
}

export function compileMigrationArtifacts(input: CompileMigrationArtifactsInput): CompiledMigrationArtifacts {
  validateRoot(input);
  const routes = routeMap(input);
  const targets = extractionIdentities(input, routes);
  const policies = policyMap(input, targets);
  const collections = collectionDetails(input, targets);
  const structuredFamilies = validateFamilies(input, targets);
  const assets = assetBindings(input, targets);
  validateImagePairs(targets, policies);
  validatePrivateDeclarations(input, routes, targets);

  const sortedTargets = [...targets.values()].sort(compareIdentities);
  const sortedRoutes = [...routes.values()].sort((left, right) => compareStrings(left.routeId, right.routeId));
  const contentFixture: MigrationOnlyContentFixtureV1 = {
    format: CONTENT_FIXTURE_FORMAT,
    websiteId: input.websiteId,
    migrationId: input.migrationId,
    purpose: 'migration_upload_only',
    values: sortedTargets.map((target) => ({ ...copyIdentity(target), value: input.extraction.values[identityKey(target)]?.value as string })),
    editorialAssets: [...assets.editorial].map(([id, digest]) => ({ digest, target: copyIdentity(targets.get(id) as EditableContentCandidate) })).sort((left, right) => compareIdentities(left.target, right.target)),
    externalAssets: [...assets.external].map(([id, external]) => ({ target: copyIdentity(targets.get(id) as EditableContentCandidate), url: external.url })).sort((left, right) => compareIdentities(left.target, right.target)),
  };

  const privateManifest: PrivateManifestSubmissionV1 = {
    format: PRIVATE_MANIFEST_FORMAT,
    websiteId: input.websiteId,
    migrationId: input.migrationId,
    sourceDigest: input.sourceDigest,
    candidateDigest: input.candidateDigest,
    cmsNativeProtocol: { ...input.cmsNativeProtocol },
    structuredFamilies,
    routes: sortedRoutes,
    targets: sortedTargets.map((target) => {
      const id = identityKey(target);
      const policy = policies.get(id) as MigrationTargetPolicyV1;
      const external = assets.external.get(id);
      return {
        ...copyIdentity(target),
        label: target.label,
        owner: target.owner,
        structuredFamily: target.structuredFamily,
        sourceKind: target.sourceKind,
        valueType: target.valueType,
        routeId: target.routeId,
        route: target.routeId === 'global' ? null : { ...(routes.get(target.routeId) as MigrationRouteV1) },
        sourceEvidence: { path: target.sourcePath, anchor: target.sourceAnchor },
        binding: { kind: 'logical_content_key', key: target.key },
        required: policy.required,
        cardinality: policy.cardinality,
        actions: [...policy.actions].sort(compareStrings),
        liveVerification: policy.liveVerification,
        imagePair: policy.imagePair === null ? null : { role: policy.imagePair.role, target: copyIdentity(policy.imagePair.target) },
        collection: collections.byRoot.get(id) ?? null,
        editorialAssetDigest: assets.editorial.get(id) ?? null,
        externalBoundary: external?.boundary ?? null,
        externalUrl: external?.url ?? null,
      };
    }),
    thirdPartyBoundaries: sortedReadonlyCopies(input.extraction.thirdPartyBoundaries),
    derived: sortedReadonlyCopies(input.extraction.derived),
    structural: sortedReadonlyCopies(input.extraction.structural),
    structuralAssets: input.assets.structural.map((asset) => ({
      digest: asset.digest,
      mime: asset.mime,
      references: asset.references.map(({ id, sourcePath }) => ({ id, sourcePath })).sort((left, right) => compareStrings(`${left.sourcePath}\u0000${left.id}`, `${right.sourcePath}\u0000${right.id}`)),
    })).sort((left, right) => compareStrings(left.digest, right.digest)),
  };

  const privateManifestDigest = canonicalDigest(privateManifest);
  const repositoryBinding: RepositoryBindingContractV1 = {
    format: REPOSITORY_BINDING_FORMAT,
    websiteId: input.websiteId,
    migrationId: input.migrationId,
    sourceDigest: input.sourceDigest,
    candidateDigest: input.candidateDigest,
    cmsNativeProtocol: { ...input.cmsNativeProtocol },
    privateManifestDigest,
    runtimeBinding: { strategy: 'canonical_content_identity', identityVersion: 1 },
    bindings: sortedTargets.map(copyIdentity),
  };
  const repositoryBindingDigest = canonicalDigest(repositoryBinding);
  const runtimeExpectation: RuntimeExpectationV1 = {
    format: RUNTIME_EXPECTATION_FORMAT,
    websiteId: input.websiteId,
    migrationId: input.migrationId,
    cmsNativeProtocol: { ...input.cmsNativeProtocol },
    expectedPrivateManifestDigest: privateManifestDigest,
    expectedRepositoryBindingDigest: repositoryBindingDigest,
    counts: {
      editableTargets: sortedTargets.length,
      routes: sortedRoutes.length,
      structuredFamilies: structuredFamilies.length,
      thirdPartyBoundaries: privateManifest.thirdPartyBoundaries.length,
      derivedDeclarations: privateManifest.derived.length,
      structuralDeclarations: privateManifest.structural.length,
    },
  };
  return {
    contentFixture,
    privateManifest,
    repositoryBinding,
    runtimeExpectation,
    digests: {
      contentFixture: canonicalDigest(contentFixture),
      privateManifest: privateManifestDigest,
      repositoryBinding: repositoryBindingDigest,
      runtimeExpectation: canonicalDigest(runtimeExpectation),
    },
  };
}
