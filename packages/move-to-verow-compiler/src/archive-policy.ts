import { types as nodeUtilTypes } from 'node:util';

export interface BundleEntryInput {
  path: string;
  bytes: Uint8Array;
  executable: boolean;
}

export interface ArchiveLimits {
  maxEntries: number;
  maxCandidateEntries: number;
  maxEvidenceEntries: number;
  maxTotalBytes: number;
  maxSingleBytes: number;
  maxPathBytes: number;
  maxSegmentBytes: number;
  maxPathDepth: number;
  maxCapabilities: number;
  maxDependencyBytes: number;
  maxEvidenceBytes: number;
  maxCompressedBytes: number;
  maxExpansionRatio: number;
}

export const ARCHIVE_LIMITS: Readonly<ArchiveLimits> = Object.freeze({
  maxEntries: 1_000,
  maxCandidateEntries: 750,
  maxEvidenceEntries: 100,
  maxTotalBytes: 200_000_000,
  maxSingleBytes: 25_000_000,
  maxPathBytes: 90,
  maxSegmentBytes: 80,
  maxPathDepth: 16,
  maxCapabilities: 16,
  maxDependencyBytes: 1_000_000,
  maxEvidenceBytes: 1_000_000,
  maxCompressedBytes: 250 * 1024 * 1024,
  maxExpansionRatio: 100,
});

const ENTRY_KEYS = ['bytes', 'executable', 'path'] as const;
const LIMIT_KEYS = Object.keys(ARCHIVE_LIMITS).sort(compareUtf8);
const FORBIDDEN_SEGMENTS = new Set([
  '.cache',
  '.cloudflare',
  '.git',
  '.history',
  '.local-history',
  '.move-to-verow',
  '.netlify',
  '.next',
  '.npm',
  '.parcel-cache',
  '.pnpm-store',
  '.firebase',
  '.amplify',
  '.sanity',
  '.ssh',
  '.sst',
  '.superpowers',
  '.turbo',
  '.vercel',
  '.vite',
  '.wrangler',
  '.yarn',
  'build',
  'coverage',
  'dist',
  'node_modules',
]);
const FORBIDDEN_NAMES = new Set([
  '.bash_history',
  '.ds_store',
  '.git-credentials',
  '.netrc',
  '.npmrc',
  '.pypirc',
  '.shell_history',
  '.zsh_history',
  'credentials',
  'credentials.json',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'id_rsa',
  'token.json',
]);
const STANDARD_CREDENTIAL_PATHS = [
  '.azure/accesstokens.json',
  '.cargo/credentials.toml',
  '.config/gcloud/credentials.db',
  '.config/gh/hosts.yml',
  '.docker/config.json',
  '.kube/config',
  'composer/auth.json',
] as const;
const CREDENTIAL_DATA_EXTENSIONS = new Set([
  '',
  'db',
  'env',
  'ini',
  'json',
  'toml',
  'txt',
  'yaml',
  'yml',
]);
const CREDENTIAL_SINGLETON_TOKENS = new Set([
  'auth',
  'credential',
  'credentials',
  'secret',
  'secrets',
  'token',
  'tokens',
]);
const CREDENTIAL_TOKEN_PAIRS = new Set([
  'access:credential',
  'access:credentials',
  'access:key',
  'access:secret',
  'access:secrets',
  'access:token',
  'access:tokens',
  'api:credential',
  'api:credentials',
  'api:key',
  'api:secret',
  'api:secrets',
  'api:token',
  'api:tokens',
  'client:credential',
  'client:credentials',
  'client:key',
  'client:secret',
  'client:secrets',
  'client:token',
  'client:tokens',
  'private:credential',
  'private:credentials',
  'private:key',
  'private:secret',
  'private:secrets',
  'private:token',
  'private:tokens',
  'refresh:token',
  'refresh:tokens',
  'service:account',
  'service:credential',
  'service:credentials',
  'service:key',
  'service:secret',
  'service:secrets',
  'service:token',
  'service:tokens',
]);
const CREDENTIAL_PROVIDER_TOKENS = new Set([
  'aws',
  'azure',
  'cloudflare',
  'firebase',
  'github',
  'gitlab',
  'google',
  'netlify',
  'openai',
  'sendgrid',
  'stripe',
  'supabase',
  'vercel',
]);
const CREDENTIAL_SENSITIVE_TOKENS = new Set([
  'credential',
  'credentials',
  'key',
  'secret',
  'secrets',
  'token',
  'tokens',
]);
const CREDENTIAL_AUTH_CONTEXT_TOKENS = new Set(['auth', 'refresh']);
const PDF_PREFIX_WHITESPACE = new Set([0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20]);
interface BlockedFormat {
  extensions: readonly string[];
  signatures: readonly { offset: number; bytes: readonly number[] }[];
}

// Finite formats that are never admitted as candidate source, by either name or bytes.
const BLOCKED_FORMATS: readonly BlockedFormat[] = [
  { extensions: ['.zip', '.jar', '.war'], signatures: [
    { offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
    { offset: 0, bytes: [0x50, 0x4b, 0x05, 0x06] },
    { offset: 0, bytes: [0x50, 0x4b, 0x07, 0x08] },
  ] },
  { extensions: ['.gz', '.tgz', '.tar.gz'], signatures: [{ offset: 0, bytes: [0x1f, 0x8b] }] },
  { extensions: ['.7z'], signatures: [{ offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] }] },
  { extensions: ['.rar'], signatures: [
    { offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00] },
    { offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00] },
  ] },
  { extensions: ['.bz2', '.tar.bz2'], signatures: [{ offset: 0, bytes: [0x42, 0x5a, 0x68] }] },
  { extensions: ['.xz', '.tar.xz'], signatures: [{ offset: 0, bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] }] },
  { extensions: ['.tar'], signatures: [{ offset: 257, bytes: [0x75, 0x73, 0x74, 0x61, 0x72] }] },
  { extensions: ['.zst', '.zstd', '.tar.zst', '.tar.zstd'], signatures: [
    { offset: 0, bytes: [0x28, 0xb5, 0x2f, 0xfd] },
    ...Array.from({ length: 16 }, (_, index) => ({
      offset: 0,
      bytes: [0x50 + index, 0x2a, 0x4d, 0x18],
    })),
  ] },
  { extensions: ['.lz4', '.tar.lz4'], signatures: [
    { offset: 0, bytes: [0x04, 0x22, 0x4d, 0x18] },
    { offset: 0, bytes: [0x02, 0x21, 0x4c, 0x18] },
  ] },
  { extensions: ['.cab'], signatures: [{ offset: 0, bytes: [0x4d, 0x53, 0x43, 0x46] }] },
  { extensions: ['.a', '.ar'], signatures: [
    { offset: 0, bytes: [0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e, 0x0a] },
    { offset: 0, bytes: [0x21, 0x3c, 0x74, 0x68, 0x69, 0x6e, 0x3e, 0x0a] },
  ] },
  { extensions: ['.cpio'], signatures: [
    { offset: 0, bytes: [0x30, 0x37, 0x30, 0x37, 0x30, 0x31] },
    { offset: 0, bytes: [0x30, 0x37, 0x30, 0x37, 0x30, 0x32] },
    { offset: 0, bytes: [0x30, 0x37, 0x30, 0x37, 0x30, 0x37] },
    { offset: 0, bytes: [0x71, 0xc7] },
    { offset: 0, bytes: [0xc7, 0x71] },
  ] },
  { extensions: ['.pdf'], signatures: [{ offset: 0, bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] }] },
];
const UNSAFE_BINARY_PATTERN = /(?:\.bin|\.class|\.com|\.dll|\.dylib|\.exe|\.msi|\.node|\.so|\.wasm)$/iu;
const EXECUTABLE_EXTENSIONS = new Set(['.cjs', '.js', '.mjs', '.sh', '.ts']);

function fail(code: 'bundle_entry_forbidden' | 'bundle_input_invalid' | 'bundle_limit_exceeded'): never {
  throw new Error(code);
}

export function compareUtf8(left: string, right: string): number {
  return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'));
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

function plainArray<T>(value: unknown): value is T[] {
  if (
    value === null ||
    typeof value !== 'object' ||
    nodeUtilTypes.isProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  ) {
    return false;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).filter((key) => key !== 'length');
  return (
    keys.length === value.length &&
    keys.every((key) => {
      const descriptor = descriptors[key];
      return descriptor?.enumerable === true && descriptor.get === undefined && descriptor.set === undefined;
    })
  );
}

function plainArrayLength(value: unknown): number | null {
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

export function isSafeByteArray(value: unknown): value is Uint8Array {
  if (value === null || typeof value !== 'object' || nodeUtilTypes.isProxy(value)) return false;
  try {
    if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype) {
      return false;
    }
    if (!(value.buffer instanceof ArrayBuffer) || value.byteOffset !== 0) return false;
    return value.byteLength === value.buffer.byteLength;
  } catch {
    return false;
  }
}

function extension(path: string): string {
  const name = path.slice(path.lastIndexOf('/') + 1);
  const dot = name.lastIndexOf('.');
  return dot < 0 ? '' : name.slice(dot).toLowerCase();
}

function hasPathSuffix(path: string, suffix: string): boolean {
  return path === suffix || path.endsWith(`/${suffix}`);
}

function credentialBasenameTokens(name: string): { extension: string; tokens: string[] } {
  const compatibilityName = name.normalize('NFKC');
  const dot = compatibilityName.lastIndexOf('.');
  const extension = dot > 0 ? compatibilityName.slice(dot + 1).toLowerCase() : '';
  const stem = dot > 0 ? compatibilityName.slice(0, dot) : compatibilityName;
  const canonical = stem
    .replace(/([a-z0-9])([A-Z])/gu, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1 $2')
    .toLowerCase();
  return {
    extension,
    tokens: canonical.split(/[._\-\s]+/u).filter(Boolean),
  };
}

function hasCredentialBasename(name: string): boolean {
  const { extension, tokens } = credentialBasenameTokens(name);
  if (!CREDENTIAL_DATA_EXTENSIONS.has(extension) || tokens.length === 0) return false;
  if (tokens.length === 1 && CREDENTIAL_SINGLETON_TOKENS.has(tokens[0] as string)) {
    return true;
  }
  const hasSensitiveToken = tokens.some((token) => CREDENTIAL_SENSITIVE_TOKENS.has(token));
  if (
    hasSensitiveToken &&
    (tokens.some((token) => CREDENTIAL_PROVIDER_TOKENS.has(token)) ||
      tokens.some((token) => CREDENTIAL_AUTH_CONTEXT_TOKENS.has(token)))
  ) {
    return true;
  }
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    const pair = `${tokens[index]}:${tokens[index + 1]}`;
    if (CREDENTIAL_TOKEN_PAIRS.has(pair)) return true;
  }
  return false;
}

function forbiddenName(path: string): boolean {
  const segments = path.split('/');
  const lower = segments.map((segment) => segment.toLowerCase());
  const lowerPath = lower.join('/');
  const rawName = segments.at(-1) ?? '';
  const name = lower.at(-1) ?? '';
  if (lower.some((segment) => FORBIDDEN_SEGMENTS.has(segment))) return true;
  if (STANDARD_CREDENTIAL_PATHS.some((suffix) => hasPathSuffix(lowerPath, suffix))) return true;
  if (FORBIDDEN_NAMES.has(name)) return true;
  if (name === '.env' || name.startsWith('.env.') || name === '.dev.vars' || name.startsWith('.dev.vars.')) return true;
  if (name.endsWith('.pem') || name.endsWith('.key') || name.endsWith('.p12') || name.endsWith('.pfx')) return true;
  if (name.endsWith('.tfstate') || name.endsWith('.tfstate.backup')) return true;
  if (/^(?:task-|compiler-).*(?:receipt|report).*\.json$/u.test(name)) return true;
  if (hasCredentialBasename(rawName)) return true;
  return BLOCKED_FORMATS.some(({ extensions }) => extensions.some((suffix) => name.endsWith(suffix))) ||
    UNSAFE_BINARY_PATTERN.test(name);
}

export function assertSafeRelativePath(path: unknown, limits: ArchiveLimits): asserts path is string {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path !== path.normalize('NFC') ||
    path.startsWith('/') ||
    path.startsWith('//') ||
    /^[A-Za-z]:/u.test(path) ||
    path.includes('\\') ||
    /\p{Cc}/u.test(path)
  ) {
    fail('bundle_entry_forbidden');
  }
  const segments = path.split('/');
  if (
    segments.length > limits.maxPathDepth ||
    segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..') ||
    Buffer.byteLength(path, 'utf8') > limits.maxPathBytes ||
    segments.some((segment) => Buffer.byteLength(segment, 'utf8') > limits.maxSegmentBytes) ||
    segments[0]?.toLowerCase() === 'verow' ||
    forbiddenName(path)
  ) {
    fail('bundle_entry_forbidden');
  }
}

function assertExecutable(entry: BundleEntryInput): void {
  if (!entry.executable) return;
  if (
    !EXECUTABLE_EXTENSIONS.has(extension(entry.path)) ||
    entry.bytes.byteLength < 2 ||
    entry.bytes[0] !== 0x23 ||
    entry.bytes[1] !== 0x21
  ) {
    fail('bundle_entry_forbidden');
  }
}

function hasUnsafeBinaryMagic(bytes: Uint8Array): boolean {
  if (BLOCKED_FORMATS.some(({ signatures }) => signatures.some((signature) =>
    signature.offset + signature.bytes.length <= bytes.byteLength &&
    signature.bytes.every((byte, index) => bytes[signature.offset + index] === byte),
  ))) {
    return true;
  }
  if (bytes.byteLength >= 4) {
    const signature = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if (
      (signature[0] === 0x7f && signature[1] === 0x45 && signature[2] === 0x4c && signature[3] === 0x46) ||
      (signature[0] === 0x00 && signature[1] === 0x61 && signature[2] === 0x73 && signature[3] === 0x6d) ||
      (signature[0] === 0xfe && signature[1] === 0xed && signature[2] === 0xfa && (signature[3] === 0xce || signature[3] === 0xcf)) ||
      ((signature[0] === 0xce || signature[0] === 0xcf) && signature[1] === 0xfa && signature[2] === 0xed && signature[3] === 0xfe) ||
      (signature[0] === 0xca && signature[1] === 0xfe && signature[2] === 0xba && signature[3] === 0xbe)
    ) {
      return true;
    }
  }
  let pdfOffset = 0;
  if (bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    pdfOffset = 3;
  }
  const pdfPrefixLimit = Math.min(bytes.byteLength, pdfOffset + 256);
  while (
    pdfOffset < pdfPrefixLimit &&
    PDF_PREFIX_WHITESPACE.has(bytes[pdfOffset] as number)
  ) {
    pdfOffset += 1;
  }
  if (
    pdfOffset + 5 <= bytes.byteLength &&
    [0x25, 0x50, 0x44, 0x46, 0x2d].every((byte, index) => bytes[pdfOffset + index] === byte)
  ) {
    return true;
  }
  return bytes.byteLength >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
}

function caseFold(path: string): string {
  return path.normalize('NFKC').toUpperCase().toLowerCase();
}

export function resolveArchiveLimits(overrides?: Partial<ArchiveLimits>): ArchiveLimits {
  if (overrides === undefined) return { ...ARCHIVE_LIMITS };
  if (!isPlainRecord(overrides) || !exactKeys(overrides, Object.keys(overrides))) {
    fail('bundle_input_invalid');
  }
  for (const key of Object.keys(overrides)) {
    if (!LIMIT_KEYS.includes(key)) fail('bundle_input_invalid');
    const value = overrides[key as keyof ArchiveLimits];
    const maximum = ARCHIVE_LIMITS[key as keyof ArchiveLimits];
    if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
      fail('bundle_input_invalid');
    }
  }
  return { ...ARCHIVE_LIMITS, ...overrides };
}

export function assertArchiveEntries(
  entries: readonly BundleEntryInput[],
  overrides?: Partial<ArchiveLimits>,
): void {
  const limits = resolveArchiveLimits(overrides);
  const length = plainArrayLength(entries);
  if (length === null) fail('bundle_input_invalid');
  if (length > limits.maxCandidateEntries || length > limits.maxEntries) {
    fail('bundle_limit_exceeded');
  }
  if (!plainArray<BundleEntryInput>(entries)) fail('bundle_input_invalid');
  const paths = new Set<string>();
  const folded = new Set<string>();
  let total = 0;
  for (const value of entries) {
    if (!isPlainRecord(value) || !exactKeys(value, ENTRY_KEYS)) fail('bundle_input_invalid');
    const entry = value as unknown as BundleEntryInput;
    if (typeof entry.executable !== 'boolean' || !isSafeByteArray(entry.bytes)) {
      fail('bundle_input_invalid');
    }
    assertSafeRelativePath(entry.path, limits);
    if (paths.has(entry.path) || folded.has(caseFold(entry.path))) fail('bundle_entry_forbidden');
    paths.add(entry.path);
    folded.add(caseFold(entry.path));
    if (entry.bytes.byteLength > limits.maxSingleBytes) fail('bundle_limit_exceeded');
    if (hasUnsafeBinaryMagic(entry.bytes)) fail('bundle_entry_forbidden');
    if (!Number.isSafeInteger(total + entry.bytes.byteLength)) fail('bundle_limit_exceeded');
    total += entry.bytes.byteLength;
    if (total > limits.maxTotalBytes) fail('bundle_limit_exceeded');
    assertExecutable(entry);
  }
}

export function copyArchiveEntries(entries: readonly BundleEntryInput[]): BundleEntryInput[] {
  return entries.map((entry) => ({
    path: entry.path,
    bytes: new Uint8Array(entry.bytes),
    executable: entry.executable,
  }));
}
