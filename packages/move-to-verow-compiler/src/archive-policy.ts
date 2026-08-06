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
  '.next',
  '.npm',
  '.parcel-cache',
  '.pnpm-store',
  '.sanity',
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
  '.netrc',
  '.npmrc',
  '.pypirc',
  '.shell_history',
  '.zsh_history',
  'credentials',
  'credentials.json',
  'id_ed25519',
  'id_rsa',
  'token.json',
]);
const NESTED_ARCHIVE_PATTERN = /(?:\.7z|\.bz2|\.gz|\.jar|\.rar|\.tar|\.tar\.(?:bz2|gz|xz)|\.tgz|\.war|\.xz|\.zip)$/iu;
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

function forbiddenName(path: string): boolean {
  const segments = path.split('/');
  const lower = segments.map((segment) => segment.toLowerCase());
  const name = lower.at(-1) ?? '';
  if (lower.some((segment) => FORBIDDEN_SEGMENTS.has(segment))) return true;
  if (FORBIDDEN_NAMES.has(name)) return true;
  if (name === '.env' || name.startsWith('.env.') || name === '.dev.vars' || name.startsWith('.dev.vars.')) return true;
  if (name.endsWith('.pem') || name.endsWith('.key') || name.endsWith('.p12') || name.endsWith('.pfx')) return true;
  if (name.endsWith('.tfstate') || name.endsWith('.tfstate.backup')) return true;
  if (/^(?:task-|compiler-).*(?:receipt|report).*\.json$/u.test(name)) return true;
  if (/^secrets?\.(?:ini|json|toml|txt|ya?ml)$/u.test(name)) return true;
  if (/^(?:access|api|auth|client|refresh)[._-](?:credentials?|key|secret|token)(?:[._-][a-z0-9-]+)*\.(?:ini|json|toml|txt|ya?ml)$/u.test(name)) return true;
  if (/^service[._-]account(?:[._-](?:credentials?|key|secret|token))?(?:[._-][a-z0-9-]+)*\.(?:ini|json|toml|txt|ya?ml)$/u.test(name)) return true;
  return NESTED_ARCHIVE_PATTERN.test(name) || UNSAFE_BINARY_PATTERN.test(name);
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
  if (bytes.byteLength >= 6) {
    const prefix = Buffer.from(bytes.subarray(0, 6)).toString('hex');
    if (
      prefix.startsWith('504b0304') ||
      prefix.startsWith('504b0506') ||
      prefix.startsWith('504b0708') ||
      prefix.startsWith('1f8b') ||
      prefix === '377abcaf271c' ||
      prefix.startsWith('526172211a07') ||
      prefix.startsWith('425a68') ||
      prefix === 'fd377a585a00'
    ) {
      return true;
    }
  }
  if (
    bytes.byteLength >= 262 &&
    Buffer.from(bytes.subarray(257, 262)).toString('ascii') === 'ustar'
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
