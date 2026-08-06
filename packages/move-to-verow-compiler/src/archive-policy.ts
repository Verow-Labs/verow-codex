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
// V1 emits a Next.js web repository. Only executable JS/TS modules, React source,
// web styles, HTML, and Markdown are treated as source; data, config, extensionless,
// and unknown formats remain fail-closed for credential-like basenames.
const CREDENTIAL_SOURCE_EXTENSIONS = new Set([
  'cjs',
  'css',
  'html',
  'js',
  'jsx',
  'less',
  'md',
  'mdx',
  'mjs',
  'sass',
  'scss',
  'ts',
  'tsx',
]);
const CREDENTIAL_INNER_RISK_EXTENSIONS = new Set([
  'cer',
  'cert',
  'cfg',
  'cnf',
  'conf',
  'config',
  'crt',
  'csv',
  'db',
  'der',
  'env',
  'ini',
  'jks',
  'json',
  'jsonc',
  'key',
  'keystore',
  'npmrc',
  'p12',
  'pem',
  'pfx',
  'properties',
  'pypirc',
  'sql',
  'sqlite',
  'sqlite3',
  'tfstate',
  'toml',
  'tsv',
  'txt',
  'xml',
  'yaml',
  'yml',
]);
const CREDENTIAL_SINGLETON_TOKENS = new Set([
  'auth',
  'credential',
  'credentials',
  'key',
  'keys',
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
const CREDENTIAL_CONNECTION_COORDINATE_PAIRS = new Set([
  'connection:string',
  'connection:uri',
  'connection:url',
  'database:string',
  'database:uri',
  'database:url',
]);
const CREDENTIAL_SENSITIVE_TOKENS = new Set([
  'credential',
  'credentials',
  'key',
  'keys',
  'passphrase',
  'passphrases',
  'password',
  'passwords',
  'secret',
  'secrets',
  'token',
  'tokens',
]);
const CREDENTIAL_COMPOUND_PREFIXES = [
  'access',
  'admin',
  'api',
  'application',
  'auth',
  'authentication',
  'authorization',
  'aws',
  'azure',
  'base',
  'bearer',
  'beta',
  'bucket',
  'certificate',
  'client',
  'cloudflare',
  'connection',
  'count',
  'cookie',
  'database',
  'db',
  'dev',
  'development',
  'encryption',
  'elasticsearch',
  'firebase',
  'github',
  'gitlab',
  'google',
  'jwt',
  'keystore',
  'live',
  'local',
  'master',
  'mariadb',
  'mongo',
  'mongodb',
  'mysql',
  'netlify',
  'npm',
  'oauth',
  'openai',
  'private',
  'prod',
  'production',
  'postgres',
  'postgresql',
  'rabbitmq',
  'redis',
  'refresh',
  'release',
  'root',
  'santa',
  'sanity',
  'sendgrid',
  'service',
  'session',
  'signing',
  'smtp',
  'ssl',
  'ssh',
  'stage',
  'staging',
  'string',
  'stripe',
  'supabase',
  'test',
  'testing',
  'tls',
  'truststore',
  'uri',
  'user',
  'url',
  'vercel',
  'webhook',
] as const;
const CREDENTIAL_COMPOUND_WORDS = [...new Set([
  ...CREDENTIAL_COMPOUND_PREFIXES,
  ...CREDENTIAL_SENSITIVE_TOKENS,
  'account',
  'design',
  'id',
])].sort((left, right) => right.length - left.length || compareUtf8(left, right));
const MAX_CREDENTIAL_COMPOUND_CHARACTERS = ARCHIVE_LIMITS.maxSegmentBytes;
const MAX_CREDENTIAL_COMPOUND_WORDS = 8;
const SUPPORTED_CANDIDATE_ASSET_MIMES = Object.freeze({
  avif: 'image/avif',
  gif: 'image/gif',
  jpeg: 'image/jpeg',
  jpg: 'image/jpeg',
  png: 'image/png',
  svg: 'image/svg+xml',
  webp: 'image/webp',
  woff: 'font/woff',
  woff2: 'font/woff2',
} as const);
const UNSUPPORTED_CANDIDATE_ASSET_SUFFIXES = new Set([
  '3g2',
  '3gp',
  'aac',
  'aif',
  'aiff',
  'apng',
  'avi',
  'bmp',
  'eot',
  'flac',
  'heic',
  'heif',
  'ico',
  'jpe',
  'jfif',
  'jxl',
  'm4a',
  'm4v',
  'mkv',
  'mov',
  'mp3',
  'mp4',
  'mpeg',
  'mpg',
  'oga',
  'ogg',
  'ogv',
  'opus',
  'otf',
  'svgz',
  'tif',
  'tiff',
  'ttc',
  'ttf',
  'wav',
  'webm',
  'wma',
  'wmv',
]);
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

export interface SupportedCandidateAssetClassification {
  suffix: keyof typeof SUPPORTED_CANDIDATE_ASSET_MIMES;
  mime: (typeof SUPPORTED_CANDIDATE_ASSET_MIMES)[keyof typeof SUPPORTED_CANDIDATE_ASSET_MIMES];
}

interface CanonicalCandidatePath {
  path: string;
  segments: readonly string[];
  basename: string;
  suffix: string;
}

type CredentialCompoundSegmentation =
  | { kind: 'opaque' }
  | { kind: 'over_bound' }
  | { kind: 'parsed'; words: readonly string[] };

interface CredentialBasenameTokens {
  tokens: readonly string[];
  hasOverBoundCompound: boolean;
}

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

function canonicalCandidatePath(path: string): CanonicalCandidatePath {
  const canonicalPath = path.normalize('NFKC').toLowerCase();
  const segments = canonicalPath.split('/');
  const basename = segments.at(-1) ?? '';
  const dot = basename.lastIndexOf('.');
  return {
    path: canonicalPath,
    segments,
    basename,
    suffix: dot < 0 ? '' : basename.slice(dot + 1),
  };
}

function classifySupportedCanonicalCandidateAsset(
  path: CanonicalCandidatePath,
): SupportedCandidateAssetClassification | null {
  const suffix = path.suffix;
  if (!Object.hasOwn(SUPPORTED_CANDIDATE_ASSET_MIMES, suffix)) return null;
  const supportedSuffix = suffix as keyof typeof SUPPORTED_CANDIDATE_ASSET_MIMES;
  return { suffix: supportedSuffix, mime: SUPPORTED_CANDIDATE_ASSET_MIMES[supportedSuffix] };
}

export function classifySupportedCandidateAsset(
  path: string,
): SupportedCandidateAssetClassification | null {
  return classifySupportedCanonicalCandidateAsset(canonicalCandidatePath(path));
}

function hasPathSuffix(path: string, suffix: string): boolean {
  return path === suffix || path.endsWith(`/${suffix}`);
}

function segmentCredentialCompound(token: string): CredentialCompoundSegmentation {
  if (token.length === 0 || token.length > MAX_CREDENTIAL_COMPOUND_CHARACTERS) {
    return { kind: 'opaque' };
  }
  const shortestAtOffset: Array<readonly string[] | undefined> = Array.from(
    { length: token.length + 1 },
    () => undefined,
  );
  shortestAtOffset[0] = [];
  for (let offset = 0; offset < token.length; offset += 1) {
    const prefix = shortestAtOffset[offset];
    if (prefix === undefined) continue;
    for (const word of CREDENTIAL_COMPOUND_WORDS) {
      if (!token.startsWith(word, offset)) continue;
      const nextOffset = offset + word.length;
      const existing = shortestAtOffset[nextOffset];
      if (existing === undefined || prefix.length + 1 < existing.length) {
        shortestAtOffset[nextOffset] = [...prefix, word];
      }
    }
  }
  const words = shortestAtOffset[token.length];
  if (words === undefined) return { kind: 'opaque' };
  if (words.length > MAX_CREDENTIAL_COMPOUND_WORDS) return { kind: 'over_bound' };
  return { kind: 'parsed', words };
}

function tokenizeCanonicalCredentialBasename(name: string): CredentialBasenameTokens {
  const tokens: string[] = [];
  let hasOverBoundCompound = false;
  for (const token of name.split(/[\p{P}\p{Z}\s]+/u).filter(Boolean)) {
    const segmentation = segmentCredentialCompound(token);
    if (segmentation.kind === 'parsed') {
      tokens.push(...segmentation.words);
    } else {
      tokens.push(token);
      hasOverBoundCompound ||= segmentation.kind === 'over_bound';
    }
  }
  return { tokens, hasOverBoundCompound };
}

function consumedBenignCredentialTokens(tokens: readonly string[]): Set<number> {
  const consumed = new Set<number>();
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    const current = tokens[index];
    const next = tokens[index + 1];
    if (current === 'design' && (next === 'token' || next === 'tokens')) {
      consumed.add(index + 1);
    } else if (current === 'token' && (next === 'bucket' || next === 'count')) {
      consumed.add(index);
    } else if (current === 'secret' && next === 'santa') {
      consumed.add(index);
    }
  }
  return consumed;
}

function hasCredentialBasename(name: string): boolean {
  const dot = name.lastIndexOf('.');
  const finalExtension = dot > 0 ? name.slice(dot + 1) : '';
  let classifiedName = name;
  if (CREDENTIAL_SOURCE_EXTENSIONS.has(finalExtension)) {
    const preSourceName = name.slice(0, dot);
    const hasRiskyInnerExtension = preSourceName
      .split('.')
      .slice(1)
      .some((suffix) => CREDENTIAL_INNER_RISK_EXTENSIONS.has(suffix));
    if (!hasRiskyInnerExtension) return false;
    classifiedName = preSourceName;
  }
  const tokenized = tokenizeCanonicalCredentialBasename(classifiedName);
  if (tokenized.hasOverBoundCompound) return true;
  const tokens = tokenized.tokens;
  if (tokens.length === 0) return false;
  const classifiedDot = classifiedName.lastIndexOf('.');
  const tokenizedBasename = tokenizeCanonicalCredentialBasename(
    classifiedDot > 0 ? classifiedName.slice(0, classifiedDot) : classifiedName,
  );
  if (tokenizedBasename.hasOverBoundCompound) return true;
  const basenameTokens = tokenizedBasename.tokens;
  if (
    basenameTokens.length === 1 &&
    CREDENTIAL_SINGLETON_TOKENS.has(basenameTokens[0] as string)
  ) {
    return true;
  }
  if (tokens.length === 1 && CREDENTIAL_SINGLETON_TOKENS.has(tokens[0] as string)) {
    return true;
  }
  const consumed = consumedBenignCredentialTokens(tokens);
  const hasUnconsumedSensitiveToken = tokens.some(
    (token, index) => CREDENTIAL_SENSITIVE_TOKENS.has(token) && !consumed.has(index),
  );
  if (hasUnconsumedSensitiveToken) return true;
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    const pair = `${tokens[index]}:${tokens[index + 1]}`;
    if (CREDENTIAL_CONNECTION_COORDINATE_PAIRS.has(pair)) return true;
    if (
      CREDENTIAL_TOKEN_PAIRS.has(pair) &&
      (pair === 'service:account' ||
        (CREDENTIAL_SENSITIVE_TOKENS.has(tokens[index] as string) && !consumed.has(index)) ||
        (CREDENTIAL_SENSITIVE_TOKENS.has(tokens[index + 1] as string) && !consumed.has(index + 1)))
    ) {
      return true;
    }
  }
  return false;
}

function exactCredentialPathCandidates(path: CanonicalCandidatePath): readonly string[] {
  const dot = path.basename.lastIndexOf('.');
  const finalExtension = dot > 0 ? path.basename.slice(dot + 1) : '';
  if (!CREDENTIAL_SOURCE_EXTENSIONS.has(finalExtension)) return [path.path];
  const directory = path.path.slice(0, path.path.length - path.basename.length);
  const candidates = [path.path];
  let stem = path.basename.slice(0, dot);
  while (stem.length > 0) {
    candidates.push(`${directory}${stem}`);
    const previousDot = stem.lastIndexOf('.');
    if (previousDot <= 0) break;
    stem = stem.slice(0, previousDot);
  }
  return candidates;
}

function hasExactCredentialPath(path: CanonicalCandidatePath): boolean {
  return exactCredentialPathCandidates(path).some((candidate) => {
    const basename = candidate.slice(candidate.lastIndexOf('/') + 1);
    return FORBIDDEN_NAMES.has(basename) ||
      STANDARD_CREDENTIAL_PATHS.some((suffix) => hasPathSuffix(candidate, suffix));
  });
}

function forbiddenName(path: string): boolean {
  const canonical = canonicalCandidatePath(path);
  const name = canonical.basename;
  if (canonical.segments.some((segment) => FORBIDDEN_SEGMENTS.has(segment))) return true;
  if (hasExactCredentialPath(canonical)) return true;
  if (UNSUPPORTED_CANDIDATE_ASSET_SUFFIXES.has(canonical.suffix)) return true;
  if (name === '.env' || name.startsWith('.env.') || name === '.dev.vars' || name.startsWith('.dev.vars.')) return true;
  if (name.endsWith('.pem') || name.endsWith('.key') || name.endsWith('.p12') || name.endsWith('.pfx')) return true;
  if (name.endsWith('.tfstate') || name.endsWith('.tfstate.backup')) return true;
  if (/^(?:task-|compiler-).*(?:receipt|report).*\.json$/u.test(name)) return true;
  if (
    classifySupportedCanonicalCandidateAsset(canonical) === null &&
    hasCredentialBasename(name)
  ) return true;
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
