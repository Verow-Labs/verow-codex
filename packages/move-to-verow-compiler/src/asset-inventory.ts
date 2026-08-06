import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { types as nodeUtilTypes } from 'node:util';
import { brotliDecompressSync, inflateSync } from 'node:zlib';

import sharp, { type Metadata } from 'sharp';

export type AssetDigest = `sha256:${string}`;

export interface AssetTargetIdentity {
  key: string;
  locale: string | null;
  variant: string | null;
}

export interface AssetReference {
  id: string;
  sourcePath: string;
  target?: AssetTargetIdentity;
}

export interface CaptureReceiptV1 {
  policyVersion: 'move-to-verow.capture-receipt.v1';
  originalUrl: string;
  finalUrl: string;
  redirects: string[];
  resolvedAddresses: Array<{ host: string; address: string; public: true }>;
  cookiesStripped: true;
  authorizationStripped: true;
  byteLimit: number;
  byteCount: number;
  sniffedMime: string;
  digest: AssetDigest;
}

export interface StructuralFontLicense {
  spdxId: 'OFL-1.1' | 'Apache-2.0' | 'MIT' | 'BSD-3-Clause';
  notice: string;
}

interface ByteAssetInput {
  classification: 'editorial_cms' | 'structural_git';
  reference: AssetReference;
  bytes: Uint8Array;
  digest: AssetDigest;
  structuralKind?: 'font' | 'image';
  fontLicense?: StructuralFontLicense;
}

export interface SourceLocalAssetInput extends ByteAssetInput {
  authority: 'source_local';
}

export interface HostedSourceCaptureAssetInput extends ByteAssetInput {
  authority: 'hosted_source_capture';
  captureReceipt: CaptureReceiptV1;
}

export interface DeclaredExternalAssetInput {
  authority: 'declared_external';
  classification: 'declared_external';
  reference: AssetReference & { target: AssetTargetIdentity };
  externalUrl: string;
  privateBoundary: string;
}

export type AssetInput = SourceLocalAssetInput | HostedSourceCaptureAssetInput | DeclaredExternalAssetInput;

export interface AssetInventoryLimits {
  maxAssets: number;
  maxSingleBytes: number;
  maxTotalBytes: number;
  maxPixels: number;
  maxDimension: number;
  maxSvgBytes: number;
  maxFrames: number;
  maxFonts: number;
  maxFontBytes: number;
  maxReferences: number;
  maxBlockers: number;
}

export type AssetInventoryBlockerCode =
  | 'asset_authority_conflict'
  | 'asset_digest_mismatch'
  | 'asset_input_invalid'
  | 'asset_limit_invalid'
  | 'asset_policy_blocked'
  | 'asset_target_conflict'
  | 'capture_receipt_invalid'
  | 'external_url_invalid';

export interface AssetInventoryBlocker {
  code: AssetInventoryBlockerCode;
}

export type AssetProvenance =
  | { authority: 'source_local'; sourcePath: string }
  | {
      authority: 'hosted_source_capture';
      sourcePath: string;
      receiptPolicyVersion: 'move-to-verow.capture-receipt.v1';
      originalUrl: string;
      finalUrl: string;
    };

export interface InventoriedAssetReference extends AssetReference {
  classification: 'editorial_cms' | 'structural_git';
  provenance: AssetProvenance;
}

export interface InventoriedAsset {
  digest: AssetDigest;
  bytes: number;
  bytesValue: Uint8Array;
  mime: string;
  encodedWidth: number;
  encodedHeight: number;
  renderedWidth: number;
  renderedHeight: number;
  pageCount: number;
  animated: boolean;
  sanitizerPolicy?: { version: 'move-to-verow.svg-safety.v1'; digest: AssetDigest };
  fontLicense?: StructuralFontLicense;
  references: InventoriedAssetReference[];
}

export interface DeclaredExternalAsset {
  url: string;
  privateBoundary: string;
  reference: AssetReference & { target: AssetTargetIdentity };
  provenance: { authority: 'declared_external'; url: string; privateBoundary: string };
}

export interface AssetInventoryResult {
  status: 'ready' | 'needs_attention';
  bundled: InventoriedAsset[];
  structural: InventoriedAsset[];
  external: DeclaredExternalAsset[];
  blockers: AssetInventoryBlocker[];
}

export interface AssetInventoryInput {
  assets: AssetInput[];
  limits?: Partial<AssetInventoryLimits>;
}

export type InspectedMigrationAssetBytes =
  | { mime: 'font/woff' | 'font/woff2' }
  | {
      mime: string;
      encodedWidth: number;
      encodedHeight: number;
      renderedWidth: number;
      renderedHeight: number;
      pageCount: number;
      animated: boolean;
      sanitizerPolicy?: { version: 'move-to-verow.svg-safety.v1'; digest: AssetDigest };
    };

const DEFAULT_LIMITS: Readonly<AssetInventoryLimits> = {
  maxAssets: 500,
  maxSingleBytes: 20_000_000,
  maxTotalBytes: 100_000_000,
  maxPixels: 40_000_000,
  maxDimension: 16_384,
  maxSvgBytes: 1_000_000,
  maxFrames: 256,
  maxFonts: 32,
  maxFontBytes: 10_000_000,
  maxReferences: 2_000,
  maxBlockers: 100,
};

const SVG_POLICY_VERSION = 'move-to-verow.svg-safety.v1' as const;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const MIME_BY_FORMAT: Readonly<Record<string, string>> = {
  avif: 'image/avif',
  gif: 'image/gif',
  jpeg: 'image/jpeg',
  png: 'image/png',
  svg: 'image/svg+xml',
  webp: 'image/webp',
};

function digestBytes(bytes: Uint8Array): AssetDigest {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function contentFreeResult(code: AssetInventoryBlockerCode): AssetInventoryResult {
  return { status: 'needs_attention', bundled: [], structural: [], external: [], blockers: [{ code }] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || nodeUtilTypes.isProxy(value) || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length > 0) return false;
  return Object.values(Object.getOwnPropertyDescriptors(value)).every((descriptor) => descriptor.enumerable && descriptor.get === undefined && descriptor.set === undefined);
}

function plainArrayLength(value: unknown): number | null {
  if (value === null || typeof value !== 'object' || nodeUtilTypes.isProxy(value) || !Array.isArray(value)) return null;
  return value.length;
}

function isPlainArray(value: unknown): value is unknown[] {
  const length = plainArrayLength(value);
  if (length === null || Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length > 0) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).filter((key) => key !== 'length');
  return keys.length === length && keys.every((key) => descriptors[key]?.enumerable && descriptors[key]?.get === undefined && descriptors[key]?.set === undefined);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function resolveLimits(overrides: Partial<AssetInventoryLimits> | undefined): AssetInventoryLimits | null {
  if (overrides === undefined) return { ...DEFAULT_LIMITS };
  if (!isRecord(overrides)) return null;
  const known = new Set(Object.keys(DEFAULT_LIMITS));
  for (const [key, value] of Object.entries(overrides)) {
    const maximum = DEFAULT_LIMITS[key as keyof AssetInventoryLimits];
    if (!known.has(key) || !Number.isSafeInteger(value) || value <= 0 || value > maximum) return null;
  }
  return { ...DEFAULT_LIMITS, ...overrides };
}

function hasControlCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || codePoint === 0x7f) return true;
  }
  return false;
}

function safePath(value: string): boolean {
  if (!value || value !== value.normalize('NFC') || value.startsWith('/') || value.includes('\\') || hasControlCharacters(value)) return false;
  const parts = value.split('/');
  return parts.every((part) => part.length > 0 && part !== '.' && part !== '..');
}

function safeToken(value: string | null | undefined): boolean {
  return value === null || (typeof value === 'string' && value.length > 0 && value.length <= 500 && value === value.normalize('NFC') && !hasControlCharacters(value));
}

function validTarget(target: AssetTargetIdentity | undefined): target is AssetTargetIdentity {
  if (!isRecord(target) || !exactKeys(target, ['key', 'locale', 'variant']) || !safeToken(target.key) || typeof target.key !== 'string') return false;
  return safeToken(target.locale) && safeToken(target.variant);
}

function targetKey(target: AssetTargetIdentity): string {
  return JSON.stringify([target.key, target.locale, target.variant]);
}

function referenceKey(reference: AssetReference): string {
  return JSON.stringify([reference.id, reference.sourcePath, reference.target === undefined ? null : targetKey(reference.target)]);
}

function validReference(reference: AssetReference): boolean {
  if (!isRecord(reference) || !exactKeys(reference, reference.target === undefined ? ['id', 'sourcePath'] : ['id', 'sourcePath', 'target'])) return false;
  return safeToken(reference.id) && typeof reference.id === 'string' && safePath(reference.sourcePath) && (reference.target === undefined || validTarget(reference.target));
}

function validFontLicense(value: unknown): value is StructuralFontLicense {
  return isRecord(value) && exactKeys(value, ['notice', 'spdxId']) &&
    ['OFL-1.1', 'Apache-2.0', 'MIT', 'BSD-3-Clause'].includes(value.spdxId as string) && typeof value.notice === 'string' && safeToken(value.notice);
}

function validAssetInput(value: unknown): value is AssetInput {
  if (!isRecord(value)) return false;
  if (value.authority === 'declared_external') {
    return exactKeys(value, ['authority', 'classification', 'externalUrl', 'privateBoundary', 'reference']) &&
      value.classification === 'declared_external' && validReference(value.reference as AssetReference) &&
      typeof value.externalUrl === 'string' && typeof value.privateBoundary === 'string';
  }
  if (value.authority !== 'source_local' && value.authority !== 'hosted_source_capture') return false;
  const optional = [
    ...(Object.hasOwn(value, 'structuralKind') ? ['structuralKind'] : []),
    ...(Object.hasOwn(value, 'fontLicense') ? ['fontLicense'] : []),
    ...(Object.hasOwn(value, 'captureReceipt') ? ['captureReceipt'] : []),
  ];
  if (!exactKeys(value, ['authority', 'bytes', 'classification', 'digest', 'reference', ...optional])) return false;
  if (!['editorial_cms', 'structural_git'].includes(value.classification as string) || !validReference(value.reference as AssetReference) ||
      !(value.bytes instanceof Uint8Array) || nodeUtilTypes.isProxy(value.bytes) || typeof value.digest !== 'string' ||
      (value.structuralKind !== undefined && !['font', 'image'].includes(value.structuralKind as string)) ||
      (value.fontLicense !== undefined && !validFontLicense(value.fontLicense))) return false;
  return value.authority === 'source_local' ? !Object.hasOwn(value, 'captureReceipt') : value.captureReceipt === undefined || isRecord(value.captureReceipt);
}

function ipv6Integer(address: string): bigint | null {
  const normalized = address.toLowerCase().replace(/^\[|\]$/gu, '');
  if (isIP(normalized) !== 6 || normalized.includes('.')) return null;
  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] === '' ? [] : (halves[0] as string).split(':');
  const right = halves.length === 1 || halves[1] === '' ? [] : (halves[1] as string).split(':');
  const omitted = 8 - left.length - right.length;
  if ((halves.length === 1 && omitted !== 0) || (halves.length === 2 && omitted < 1)) return null;
  const groups = [...left, ...Array.from({ length: omitted }, () => '0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/u.test(group))) return null;
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n);
}

function inIpv6Range(value: bigint, prefix: string, bits: number): boolean {
  const prefixValue = ipv6Integer(prefix);
  return prefixValue !== null && (value >> BigInt(128 - bits)) === (prefixValue >> BigInt(128 - bits));
}

function isPublicIpAddress(address: string): boolean {
  const normalized = address.toLowerCase().replace(/^\[|\]$/gu, '');
  const version = isIP(normalized);
  if (version === 4) {
    const octets = normalized.split('.').map(Number);
    const [a, b] = octets;
    if (a === undefined || b === undefined) return false;
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 0 || b === 168)) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) ||
      (a === 203 && b === 0)
    );
  }
  if (version === 6) {
    const value = ipv6Integer(normalized);
    if (value === null || !inIpv6Range(value, '2000::', 3)) return false;
    return ![
      ['2001::', 23],
      ['2001:db8::', 32],
      ['2002::', 16],
      ['2620:4f:8000::', 48],
      ['3fff::', 20],
    ].some(([prefix, bits]) => inIpv6Range(value, prefix as string, bits as number));
  }
  return false;
}

function canonicalHttpsUrl(raw: string): string | null {
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || parsed.port) return null;
    const hostname = parsed.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname.endsWith('.localhost')) return null;
    if (isIP(hostname.replace(/^\[|\]$/gu, '')) !== 0 && !isPublicIpAddress(hostname)) return null;
    parsed.hostname = hostname;
    return parsed.toString();
  } catch {
    return null;
  }
}

function exactObjectKeys(value: object, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index]);
}

function validCaptureReceiptPreflight(receipt: unknown, limits: AssetInventoryLimits): receipt is CaptureReceiptV1 {
  if (!isRecord(receipt) || !exactObjectKeys(receipt, [
    'authorizationStripped', 'byteCount', 'byteLimit', 'cookiesStripped', 'digest', 'finalUrl', 'originalUrl',
    'policyVersion', 'redirects', 'resolvedAddresses', 'sniffedMime',
  ])) return false;
  const candidate = receipt as Record<string, unknown>;
  if (candidate.policyVersion !== 'move-to-verow.capture-receipt.v1' || candidate.cookiesStripped !== true || candidate.authorizationStripped !== true) return false;
  if (!Number.isSafeInteger(candidate.byteLimit) || !Number.isSafeInteger(candidate.byteCount) || (candidate.byteLimit as number) <= 0 || (candidate.byteLimit as number) > limits.maxSingleBytes) return false;
  if ((candidate.byteCount as number) <= 0 || (candidate.byteCount as number) > (candidate.byteLimit as number) || typeof candidate.digest !== 'string' || !SHA256_PATTERN.test(candidate.digest) || typeof candidate.sniffedMime !== 'string' || !safeToken(candidate.sniffedMime)) return false;
  const redirectCount = plainArrayLength(candidate.redirects);
  if (redirectCount === null || redirectCount > 32 || !isPlainArray(candidate.redirects) || !candidate.redirects.every((url) => typeof url === 'string')) return false;
  const urls = [candidate.originalUrl, ...candidate.redirects, candidate.finalUrl];
  if (!urls.every((url) => typeof url === 'string')) return false;
  const canonical = urls.map((url) => canonicalHttpsUrl(url as string));
  if (canonical.some((url, index) => url === null || url !== urls[index])) return false;
  const hosts = canonical.map((url) => new URL(url as string).hostname);
  if (!hosts.every((host) => host === hosts[0])) return false;
  const resolvedAddressCount = plainArrayLength(candidate.resolvedAddresses);
  if (resolvedAddressCount === null || resolvedAddressCount === 0 || resolvedAddressCount > 128 || !isPlainArray(candidate.resolvedAddresses)) return false;
  const receipts = candidate.resolvedAddresses;
  if (!receipts.every((entry) => {
    if (!isRecord(entry) || !exactObjectKeys(entry, ['address', 'host', 'public'])) return false;
    const resolved = entry as Record<string, unknown>;
    return resolved.public === true && typeof resolved.host === 'string' && hosts.includes(resolved.host) && typeof resolved.address === 'string' && isPublicIpAddress(resolved.address);
  })) return false;
  return [...new Set(hosts)].every((host) => receipts.some((entry) => (entry as { host?: unknown }).host === host));
}

function validCaptureReceiptLinkage(receipt: CaptureReceiptV1, bytes: Uint8Array, digest: AssetDigest, mime: string): boolean {
  return receipt.byteCount === bytes.byteLength && receipt.byteLimit >= bytes.byteLength && receipt.digest === digest && receipt.sniffedMime === mime;
}

const SVG_DOCUMENT_PREFIX_BYTES = 65_536;
const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
const XLINK_NAMESPACE = 'http://www.w3.org/1999/xlink';
const XML_QNAME_MAX_CODE_POINTS = 256;

interface XmlQName {
  raw: string;
  prefix: string | null;
  local: string;
  end: number;
}

function inCodePointRange(value: number, start: number, end: number): boolean {
  return value >= start && value <= end;
}

function isXmlNcNameStart(value: number): boolean {
  return value === 0x5f ||
    inCodePointRange(value, 0x41, 0x5a) ||
    inCodePointRange(value, 0x61, 0x7a) ||
    inCodePointRange(value, 0xc0, 0xd6) ||
    inCodePointRange(value, 0xd8, 0xf6) ||
    inCodePointRange(value, 0xf8, 0x2ff) ||
    inCodePointRange(value, 0x370, 0x37d) ||
    inCodePointRange(value, 0x37f, 0x1fff) ||
    inCodePointRange(value, 0x200c, 0x200d) ||
    inCodePointRange(value, 0x2070, 0x218f) ||
    inCodePointRange(value, 0x2c00, 0x2fef) ||
    inCodePointRange(value, 0x3001, 0xd7ff) ||
    inCodePointRange(value, 0xf900, 0xfdcf) ||
    inCodePointRange(value, 0xfdf0, 0xfffd) ||
    inCodePointRange(value, 0x10000, 0xeffff);
}

function isXmlNcNameChar(value: number): boolean {
  return isXmlNcNameStart(value) ||
    value === 0x2d ||
    value === 0x2e ||
    inCodePointRange(value, 0x30, 0x39) ||
    value === 0xb7 ||
    inCodePointRange(value, 0x300, 0x36f) ||
    inCodePointRange(value, 0x203f, 0x2040);
}

function readXmlNcName(source: string, start: number): { value: string; end: number } | null {
  const first = source.codePointAt(start);
  if (first === undefined || !isXmlNcNameStart(first)) return null;
  let cursor = start;
  let count = 0;
  while (cursor < source.length) {
    const value = source.codePointAt(cursor);
    if (value === undefined || !isXmlNcNameChar(value)) break;
    count += 1;
    if (count > XML_QNAME_MAX_CODE_POINTS) return null;
    cursor += value > 0xffff ? 2 : 1;
  }
  return { value: source.slice(start, cursor), end: cursor };
}

function readXmlQName(source: string, start: number): XmlQName | null {
  const first = readXmlNcName(source, start);
  if (first === null) return null;
  if (source[first.end] !== ':') {
    return { raw: first.value, prefix: null, local: first.value, end: first.end };
  }
  const second = readXmlNcName(source, first.end + 1);
  if (
    second === null ||
    source[second.end] === ':' ||
    Array.from(source.slice(start, second.end)).length > XML_QNAME_MAX_CODE_POINTS
  ) return null;
  return {
    raw: source.slice(start, second.end),
    prefix: first.value,
    local: second.value,
    end: second.end,
  };
}

function readMarkupNameCandidate(
  source: string,
  start: number,
): { raw: string; end: number; overflow: boolean } {
  let cursor = start;
  let count = 0;
  while (cursor < source.length && !/[\t\n\f\r />]/u.test(source[cursor] as string)) {
    const value = source.codePointAt(cursor) as number;
    count += 1;
    if (count > XML_QNAME_MAX_CODE_POINTS) return { raw: '', end: cursor, overflow: true };
    cursor += value > 0xffff ? 2 : 1;
  }
  return { raw: source.slice(start, cursor), end: cursor, overflow: false };
}

function parseExactXmlQName(raw: string): XmlQName | null {
  const parsed = readXmlQName(raw, 0);
  return parsed !== null && parsed.end === raw.length ? parsed : null;
}

function isPotentialSvgQName(candidate: { raw: string; overflow: boolean }): boolean {
  if (candidate.overflow) return true;
  const parsed = parseExactXmlQName(candidate.raw);
  if (parsed !== null) return parsed.local.toLowerCase() === 'svg';
  const parts = candidate.raw.split(':');
  const local = parts.at(-1) ?? '';
  if (local.toLowerCase() === 'svg' || (parts.length > 2 && parts.some((part) => part.toLowerCase() === 'svg'))) {
    return true;
  }
  const partialLocal = readXmlNcName(local, 0);
  return partialLocal?.value.toLowerCase() === 'svg' && partialLocal.end < local.length;
}

function isReservedXmlPrefix(prefix: string): boolean {
  const lower = prefix.toLowerCase();
  return lower === 'xml' || lower === 'xmlns';
}

function skipXmlWhitespace(source: string, start: number): number {
  let cursor = start;
  while (cursor < source.length && /[\t\n\r ]/u.test(source[cursor] as string)) cursor += 1;
  return cursor;
}

function skipAsciiWhitespace(source: string, start: number): number {
  let cursor = start;
  while (cursor < source.length && /[\t\n\v\f\r ]/u.test(source[cursor] as string)) cursor += 1;
  return cursor;
}

function markupDeclarationEnd(source: string, start: number): number | null {
  let quote: '"' | "'" | null = null;
  let subsetDepth = 0;
  for (let cursor = start; cursor < source.length; cursor += 1) {
    const character = source[cursor];
    if (quote !== null) {
      if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
    } else if (character === '[') {
      subsetDepth += 1;
    } else if (character === ']' && subsetDepth > 0) {
      subsetDepth -= 1;
    } else if (character === '>' && subsetDepth === 0) {
      return cursor + 1;
    }
  }
  return null;
}

export function hasMigrationSvgDocumentStart(bytes: Uint8Array): boolean {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) return false;
  const truncated = bytes.byteLength > SVG_DOCUMENT_PREFIX_BYTES;
  const source = new TextDecoder('utf-8', { fatal: false }).decode(
    bytes.subarray(0, Math.min(bytes.byteLength, SVG_DOCUMENT_PREFIX_BYTES)),
  );
  let cursor = source.startsWith('\uFEFF') ? 1 : 0;
  while (cursor <= source.length) {
    cursor = skipAsciiWhitespace(source, cursor);
    if (cursor === source.length) return truncated;
    if (source.startsWith('<!--', cursor)) {
      const end = source.indexOf('-->', cursor + 4);
      if (end < 0) return truncated;
      cursor = end + 3;
      continue;
    }
    if (source.startsWith('<?', cursor)) {
      const end = source.indexOf('?>', cursor + 2);
      if (end < 0) return truncated;
      cursor = end + 2;
      continue;
    }
    if (source.slice(cursor, cursor + 9).toLowerCase() === '<!doctype') {
      const nameStart = skipAsciiWhitespace(source, cursor + 9);
      if (isPotentialSvgQName(readMarkupNameCandidate(source, nameStart))) return true;
      const end = markupDeclarationEnd(source, nameStart);
      if (end === null) return truncated;
      cursor = end;
      continue;
    }
    if (source[cursor] !== '<') return false;
    const nameStart = skipAsciiWhitespace(source, cursor + 1);
    return isPotentialSvgQName(readMarkupNameCandidate(source, nameStart));
  }
  return truncated;
}

function stripSvgXmlDeclaration(source: string): string | null {
  let cursor = source.startsWith('\uFEFF') ? 1 : 0;
  cursor = skipAsciiWhitespace(source, cursor);
  if (!source.startsWith('<?xml', cursor)) return source.slice(cursor);
  const declaration = /^<\?xml\s+[^<>&?]*\?>/iu.exec(source.slice(cursor));
  if (declaration === null) return null;
  const rootStart = skipAsciiWhitespace(source, cursor + declaration[0].length);
  return source.slice(rootStart);
}

interface SvgElementFrame { id?: string; qname: string }

interface ParsedXmlAttribute {
  qname: XmlQName;
  value: string;
}

interface ParsedXmlTag {
  attributes: ParsedXmlAttribute[];
  closing: boolean;
  end: number;
  qname: XmlQName;
  selfClosing: boolean;
}

function parseXmlTag(source: string, start: number): ParsedXmlTag | null {
  if (source[start] !== '<') return null;
  let cursor = start + 1;
  const closing = source[cursor] === '/';
  if (closing) cursor += 1;
  const qname = readXmlQName(source, cursor);
  if (qname === null) return null;
  cursor = qname.end;
  if (closing) {
    cursor = skipXmlWhitespace(source, cursor);
    return source[cursor] === '>'
      ? { attributes: [], closing: true, end: cursor + 1, qname, selfClosing: false }
      : null;
  }
  const attributes: ParsedXmlAttribute[] = [];
  while (cursor < source.length) {
    const beforeWhitespace = cursor;
    cursor = skipXmlWhitespace(source, cursor);
    if (source.startsWith('/>', cursor)) {
      return { attributes, closing: false, end: cursor + 2, qname, selfClosing: true };
    }
    if (source[cursor] === '>') {
      return { attributes, closing: false, end: cursor + 1, qname, selfClosing: false };
    }
    if (cursor === beforeWhitespace || attributes.length >= 256) return null;
    const attributeQName = readXmlQName(source, cursor);
    if (attributeQName === null) return null;
    cursor = skipXmlWhitespace(source, attributeQName.end);
    if (source[cursor] !== '=') return null;
    cursor = skipXmlWhitespace(source, cursor + 1);
    const quote = source[cursor];
    if (quote !== '"' && quote !== "'") return null;
    const valueStart = cursor + 1;
    const valueEnd = source.indexOf(quote, valueStart);
    if (valueEnd < 0) return null;
    const value = source.slice(valueStart, valueEnd);
    if (value.includes('<')) return null;
    attributes.push({ qname: attributeQName, value });
    cursor = valueEnd + 1;
  }
  return null;
}

function svgRootQName(source: string): XmlQName | null {
  if (source[0] !== '<') return null;
  const qname = readXmlQName(source, 1);
  if (
    qname === null ||
    qname.local !== 'svg' ||
    !/[\t\n\r />]/u.test(source[qname.end] ?? '')
  ) return null;
  return qname;
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function svgBytesForMetadata(bytes: Uint8Array): Uint8Array | null {
  let source: string;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  const declarationFreeSource = stripSvgXmlDeclaration(source);
  if (declarationFreeSource === null) return null;
  const rootQName = svgRootQName(declarationFreeSource);
  if (rootQName === null || rootQName.prefix === null) return rootQName === null ? null : bytes;
  const prefix = rootQName.prefix;
  const namespacePattern = new RegExp(
    `\\s+xmlns:${escapeRegularExpression(prefix)}\\s*=\\s*(["'])${SVG_NAMESPACE}\\1`,
    'u',
  );
  const metadataSource = source
    .replaceAll(`<${prefix}:`, '<')
    .replaceAll(`</${prefix}:`, '</')
    .replace(namespacePattern, ` xmlns="${SVG_NAMESPACE}"`);
  return Buffer.from(metadataSource, 'utf8');
}

function validateSafeSvg(bytes: Uint8Array, limits: AssetInventoryLimits): boolean {
  if (bytes.byteLength > limits.maxSvgBytes) return false;
  let source: string;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return false;
  }
  const declarationFreeSource = stripSvgXmlDeclaration(source);
  if (declarationFreeSource === null) return false;
  source = declarationFreeSource;
  const rootQName = svgRootQName(source);
  if (rootQName === null || (rootQName.prefix !== null && isReservedXmlPrefix(rootQName.prefix))) {
    return false;
  }
  if (hasControlCharacters(source) || /<!DOCTYPE|<!ENTITY|<!\[CDATA|<!--|<\?(?!xml\s)|&/iu.test(source)) return false;
  if (/\son[a-z][\w:-]*\s*=|\sstyle\s*=|@import|url\s*\(/iu.test(source)) return false;
  const allowedTags = new Set(['svg', 'g', 'defs', 'symbol', 'use', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon', 'path', 'title', 'desc']);
  const allowedAttributes = new Set([
    'id', 'href', 'xlink:href', 'width', 'height', 'viewbox', 'x', 'y', 'x1', 'x2', 'y1', 'y2',
    'cx', 'cy', 'r', 'rx', 'ry', 'd', 'points', 'fill', 'fill-rule', 'stroke', 'stroke-width', 'stroke-linecap',
    'stroke-linejoin', 'opacity', 'transform', 'preserveaspectratio', 'role', 'aria-label',
  ]);
  const stack: SvgElementFrame[] = [];
  const namespaces = new Map<string, string>();
  const ids = new Set<string>();
  const edges = new Map<string, Set<string>>();
  const referenced = new Set<string>();
  let cursor = 0;
  let rootSeen = false;
  let rootClosed = false;
  let referenceCount = 0;
  while (cursor < source.length) {
    const tagStart = source.indexOf('<', cursor);
    if (tagStart < 0) {
      const trailing = source.slice(cursor);
      if (trailing.includes('>') || (stack.length === 0 && trailing.trim().length > 0)) return false;
      cursor = source.length;
      break;
    }
    const between = source.slice(cursor, tagStart);
    if (between.includes('>') || (stack.length === 0 && between.trim().length > 0)) return false;
    const parsed = parseXmlTag(source, tagStart);
    if (parsed === null) return false;
    cursor = parsed.end;
    if (parsed.closing) {
      if (stack.at(-1)?.qname !== parsed.qname.raw) return false;
      stack.pop();
      if (stack.length === 0) rootClosed = true;
      continue;
    }
    const isRoot = !rootSeen;
    if (isRoot) {
      if (parsed.qname.raw !== rootQName.raw) return false;
      rootSeen = true;
    } else if (rootClosed || stack.length === 0) {
      return false;
    }
    for (const attribute of parsed.attributes) {
      const declaration = attribute.qname.prefix === 'xmlns'
        ? attribute.qname.local
        : attribute.qname.prefix === null && attribute.qname.local === 'xmlns'
          ? ''
          : null;
      if (declaration === null) continue;
      if (!isRoot || (declaration !== '' && isReservedXmlPrefix(declaration)) || namespaces.has(declaration)) {
        return false;
      }
      if (declaration === '') {
        if (attribute.value !== SVG_NAMESPACE) return false;
      } else if (declaration === rootQName.prefix) {
        if (attribute.value !== SVG_NAMESPACE) return false;
      } else if (declaration === 'xlink') {
        if (attribute.value !== XLINK_NAMESPACE) return false;
      } else {
        return false;
      }
      namespaces.set(declaration, attribute.value);
    }
    const elementNamespace = parsed.qname.prefix === null
      ? namespaces.get('') ?? (rootQName.prefix === null ? SVG_NAMESPACE : null)
      : namespaces.get(parsed.qname.prefix);
    if (elementNamespace !== SVG_NAMESPACE || !allowedTags.has(parsed.qname.local)) return false;
    const attributes = new Map<string, string>();
    for (const attribute of parsed.attributes) {
      const declaration = attribute.qname.prefix === 'xmlns' ||
        (attribute.qname.prefix === null && attribute.qname.local === 'xmlns');
      if (declaration) continue;
      let name: string;
      if (attribute.qname.prefix === null) {
        name = attribute.qname.local.toLowerCase();
      } else if (
        attribute.qname.prefix === 'xlink' &&
        attribute.qname.local === 'href' &&
        namespaces.get('xlink') === XLINK_NAMESPACE
      ) {
        name = 'xlink:href';
      } else {
        return false;
      }
      if (!allowedAttributes.has(name) || attributes.has(name) || hasControlCharacters(attribute.value)) {
        return false;
      }
      attributes.set(name, attribute.value);
    }
    const id = attributes.get('id');
    if (id !== undefined) {
      if (!/^[A-Za-z_][\w.-]{0,127}$/u.test(id) || ids.has(id)) return false;
      ids.add(id);
    }
    for (const name of ['href', 'xlink:href']) {
      const href = attributes.get(name);
      if (href === undefined) continue;
      referenceCount += 1;
      if (referenceCount > limits.maxReferences) return false;
      if (!/^#[A-Za-z_][\w.-]{0,127}$/u.test(href)) return false;
      const target = href.slice(1);
      referenced.add(target);
      const owner = id ?? [...stack].reverse().find((frame) => frame.id !== undefined)?.id;
      if (owner !== undefined) {
        const outgoing = edges.get(owner) ?? new Set<string>();
        outgoing.add(target);
        edges.set(owner, outgoing);
      }
    }
    if (!parsed.selfClosing) {
      stack.push({ qname: parsed.qname.raw, ...(id === undefined ? {} : { id }) });
      if (stack.length > 256) return false;
    } else if (isRoot) {
      rootClosed = true;
    }
  }
  if (!rootSeen || !rootClosed || stack.length > 0 || [...referenced].some((id) => !ids.has(id))) return false;
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const cyclic = (node: string): boolean => {
    if (visiting.has(node)) return true;
    if (visited.has(node)) return false;
    visiting.add(node);
    for (const next of edges.get(node) ?? []) if (cyclic(next)) return true;
    visiting.delete(node);
    visited.add(node);
    return false;
  };
  return ![...ids].some(cyclic);
}

function validRasterContainer(bytes: Uint8Array): boolean {
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    let offset = 8;
    let ended = false;
    while (offset + 12 <= buffer.length) {
      const length = buffer.readUInt32BE(offset);
      if (length > buffer.length - offset - 12) return false;
      const type = buffer.toString('ascii', offset + 4, offset + 8);
      offset += 12 + length;
      if (type === 'IEND') { ended = true; break; }
    }
    return ended && offset === buffer.length;
  }
  if (buffer[0] === 0xff && buffer[1] === 0xd8) return buffer.at(-2) === 0xff && buffer.at(-1) === 0xd9;
  const signature = buffer.toString('ascii', 0, 6);
  if (signature === 'GIF87a' || signature === 'GIF89a') return buffer.at(-1) === 0x3b;
  if (buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') return buffer.length >= 12 && buffer.readUInt32LE(4) + 8 === buffer.length;
  return buffer.length >= 16 && buffer.toString('ascii', 4, 8) === 'ftyp' && /avif|avis/u.test(buffer.toString('ascii', 8, 16));
}

function align4(value: number): number {
  return value + ((4 - (value % 4)) % 4);
}

function zeroPadding(buffer: Buffer, start: number, end: number): boolean {
  return end >= start && end <= buffer.length && buffer.subarray(start, end).every((byte) => byte === 0);
}

function validOptionalBlock(offset: number, length: number, originalLength: number | null, maximum: number): boolean {
  if (offset === 0) return length === 0 && (originalLength === null || originalLength === 0);
  return offset % 4 === 0 && length > 0 && length <= maximum && (originalLength === null || (originalLength > 0 && originalLength <= maximum));
}

function inspectWoff(buffer: Buffer, limits: AssetInventoryLimits): boolean {
  if (buffer.length < 64 || buffer.readUInt32BE(8) !== buffer.length) return false;
  const count = buffer.readUInt16BE(12);
  const totalSfntSize = buffer.readUInt32BE(16);
  const directoryEnd = 44 + count * 20;
  if (buffer.readUInt32BE(4) === 0 || count < 1 || count > 64 || buffer.readUInt16BE(14) !== 0 || directoryEnd > buffer.length || totalSfntSize === 0 || totalSfntSize % 4 !== 0 || totalSfntSize > limits.maxFontBytes) return false;
  const metaOffset = buffer.readUInt32BE(24);
  const metaLength = buffer.readUInt32BE(28);
  const metaOrigLength = buffer.readUInt32BE(32);
  const privateOffset = buffer.readUInt32BE(36);
  const privateLength = buffer.readUInt32BE(40);
  if (!validOptionalBlock(metaOffset, metaLength, metaOrigLength, limits.maxFontBytes) || !validOptionalBlock(privateOffset, privateLength, null, limits.maxFontBytes)) return false;

  const tables: Array<{ compressed: number; offset: number; original: number }> = [];
  let expectedSfntSize = 12 + count * 16;
  let previousTag = -1;
  for (let index = 0; index < count; index += 1) {
    const entry = 44 + index * 20;
    const tag = buffer.readUInt32BE(entry);
    const offset = buffer.readUInt32BE(entry + 4);
    const compressed = buffer.readUInt32BE(entry + 8);
    const original = buffer.readUInt32BE(entry + 12);
    if (tag <= previousTag || offset % 4 !== 0 || compressed === 0 || original === 0 || compressed > original || offset > buffer.length - compressed) return false;
    previousTag = tag;
    expectedSfntSize += align4(original);
    if (!Number.isSafeInteger(expectedSfntSize) || expectedSfntSize > limits.maxFontBytes) return false;
    tables.push({ compressed, offset, original });
  }
  if (expectedSfntSize !== totalSfntSize) return false;
  tables.sort((left, right) => left.offset - right.offset);
  let cursor = align4(directoryEnd);
  if (!zeroPadding(buffer, directoryEnd, cursor)) return false;
  for (const table of tables) {
    if (table.offset !== cursor) return false;
    const body = buffer.subarray(table.offset, table.offset + table.compressed);
    if (table.compressed < table.original) {
      try {
        if (inflateSync(body, { maxOutputLength: table.original }).byteLength !== table.original) return false;
      } catch { return false; }
    }
    cursor = align4(table.offset + table.compressed);
    if (!zeroPadding(buffer, table.offset + table.compressed, cursor)) return false;
  }
  if (metaOffset !== 0) {
    if (metaOffset !== cursor || metaOffset > buffer.length - metaLength) return false;
    try {
      if (inflateSync(buffer.subarray(metaOffset, metaOffset + metaLength), { maxOutputLength: metaOrigLength }).byteLength !== metaOrigLength) return false;
    } catch { return false; }
    cursor = align4(metaOffset + metaLength);
    if (!zeroPadding(buffer, metaOffset + metaLength, cursor)) return false;
  }
  if (privateOffset !== 0) {
    if (privateOffset !== cursor || privateOffset > buffer.length - privateLength) return false;
    cursor = privateOffset + privateLength;
  }
  return cursor === buffer.length;
}

function readUIntBase128(buffer: Buffer, start: number): { next: number; value: number } | null {
  let value = 0;
  for (let index = 0; index < 5; index += 1) {
    const byte = buffer[start + index];
    if (byte === undefined || (index === 0 && byte === 0x80) || value > 0x01ff_ffff) return null;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) return { next: start + index + 1, value };
  }
  return null;
}

function inspectWoff2(buffer: Buffer, limits: AssetInventoryLimits): boolean {
  if (buffer.length < 50 || buffer.readUInt32BE(8) !== buffer.length) return false;
  const flavor = buffer.readUInt32BE(4);
  const count = buffer.readUInt16BE(12);
  const totalSfntSize = buffer.readUInt32BE(16);
  const totalCompressedSize = buffer.readUInt32BE(20);
  if (flavor === 0 || flavor === 0x7474_6366 || count < 1 || count > 64 || buffer.readUInt16BE(14) !== 0 || totalSfntSize === 0 || totalSfntSize > limits.maxFontBytes || totalCompressedSize === 0 || totalCompressedSize > limits.maxFontBytes) return false;
  const metaOffset = buffer.readUInt32BE(28);
  const metaLength = buffer.readUInt32BE(32);
  const metaOrigLength = buffer.readUInt32BE(36);
  const privateOffset = buffer.readUInt32BE(40);
  const privateLength = buffer.readUInt32BE(44);
  if (!validOptionalBlock(metaOffset, metaLength, metaOrigLength, limits.maxFontBytes) || !validOptionalBlock(privateOffset, privateLength, null, limits.maxFontBytes)) return false;

  const knownTags = ['cmap', 'head', 'hhea', 'hmtx', 'maxp', 'name', 'OS/2', 'post', 'cvt ', 'fpgm', 'glyf', 'loca', 'prep', 'CFF ', 'VORG', 'EBDT', 'EBLC', 'gasp', 'hdmx', 'kern', 'LTSH', 'PCLT', 'VDMX', 'vhea', 'vmtx', 'BASE', 'GDEF', 'GPOS', 'GSUB', 'EBSC', 'JSTF', 'MATH', 'CBDT', 'CBLC', 'COLR', 'CPAL', 'SVG ', 'sbix', 'acnt', 'avar', 'bdat', 'bloc', 'bsln', 'cvar', 'fdsc', 'feat', 'fmtx', 'fvar', 'gvar', 'hsty', 'just', 'lcar', 'mort', 'morx', 'opbd', 'prop', 'trak', 'Zapf', 'Silf', 'Glat', 'Gloc', 'Feat', 'Sill'];
  const tags = new Set<string>();
  let cursor = 48;
  let decompressedSize = 0;
  let expectedSfntSize = 12 + count * 16;
  let glyf: { index: number; storedLength: number; transformed: boolean } | undefined;
  let loca: { index: number; storedLength: number; transformed: boolean } | undefined;
  for (let index = 0; index < count; index += 1) {
    const flags = buffer[cursor];
    if (flags === undefined) return false;
    cursor += 1;
    const tagIndex = flags & 0x3f;
    let tag: string;
    if (tagIndex === 63) {
      if (cursor > buffer.length - 4) return false;
      tag = buffer.toString('ascii', cursor, cursor + 4);
      if (!/^[\x20-\x7e]{4}$/u.test(tag)) return false;
      cursor += 4;
    } else {
      tag = knownTags[tagIndex] as string;
    }
    if (tags.has(tag)) return false;
    tags.add(tag);
    const original = readUIntBase128(buffer, cursor);
    if (original === null || original.value === 0) return false;
    cursor = original.next;
    expectedSfntSize += align4(original.value);
    if (!Number.isSafeInteger(expectedSfntSize) || expectedSfntSize > limits.maxFontBytes) return false;
    const transformVersion = flags >>> 6;
    const transformed = (tag === 'glyf' || tag === 'loca') && transformVersion === 0;
    if ((tag === 'glyf' || tag === 'loca') ? transformVersion === 1 || transformVersion === 2 : transformVersion !== 0) return false;
    let storedLength = original.value;
    if (transformed) {
      const transform = readUIntBase128(buffer, cursor);
      if (transform === null || (tag !== 'loca' && transform.value === 0)) return false;
      cursor = transform.next;
      storedLength = transform.value;
    }
    if (tag === 'glyf') glyf = { index, storedLength, transformed };
    if (tag === 'loca') loca = { index, storedLength, transformed };
    decompressedSize += storedLength;
    if (!Number.isSafeInteger(decompressedSize) || decompressedSize > limits.maxFontBytes) return false;
  }
  if ((glyf === undefined) !== (loca === undefined)) return false;
  if (glyf !== undefined && loca !== undefined && (glyf.index >= loca.index || glyf.transformed !== loca.transformed || (loca.transformed && loca.storedLength !== 0))) return false;
  if (expectedSfntSize !== totalSfntSize) return false;
  if (cursor > buffer.length - totalCompressedSize) return false;
  try {
    if (brotliDecompressSync(buffer.subarray(cursor, cursor + totalCompressedSize), { maxOutputLength: decompressedSize }).byteLength !== decompressedSize) return false;
  } catch { return false; }
  cursor += totalCompressedSize;
  if (metaOffset !== 0) {
    const aligned = align4(cursor);
    if (metaOffset !== aligned || !zeroPadding(buffer, cursor, aligned) || metaOffset > buffer.length - metaLength) return false;
    try {
      if (brotliDecompressSync(buffer.subarray(metaOffset, metaOffset + metaLength), { maxOutputLength: metaOrigLength }).byteLength !== metaOrigLength) return false;
    } catch { return false; }
    cursor = metaOffset + metaLength;
  }
  if (privateOffset !== 0) {
    const aligned = align4(cursor);
    if (privateOffset !== aligned || !zeroPadding(buffer, cursor, aligned) || privateOffset > buffer.length - privateLength) return false;
    cursor = privateOffset + privateLength;
  }
  return cursor === buffer.length;
}

function inspectFontBytes(bytes: Uint8Array, limits: AssetInventoryLimits): { mime: 'font/woff' | 'font/woff2' } | null {
  if (bytes.byteLength > limits.maxFontBytes) return null;
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const signature = buffer.toString('ascii', 0, 4);
  if (signature === 'wOFF') {
    return inspectWoff(buffer, limits) ? { mime: 'font/woff' } : null;
  }
  if (signature === 'wOF2') {
    return inspectWoff2(buffer, limits) ? { mime: 'font/woff2' } : null;
  }
  return null;
}

async function inspectImage(bytes: Uint8Array, limits: AssetInventoryLimits): Promise<Omit<InventoriedAsset, 'digest' | 'bytes' | 'bytesValue' | 'references'> | null> {
  const svg = hasMigrationSvgDocumentStart(bytes);
  if (svg ? !validateSafeSvg(bytes, limits) : !validRasterContainer(bytes)) return null;
  const inspectionBytes = svg ? svgBytesForMetadata(bytes) : bytes;
  if (inspectionBytes === null) return null;
  try {
    const metadata: Metadata = await sharp(inspectionBytes, { animated: true, failOn: 'error', limitInputPixels: limits.maxPixels, sequentialRead: true }).metadata();
    const format = metadata.format;
    const mime = format === undefined ? undefined : MIME_BY_FORMAT[format];
    const encodedWidth = metadata.width;
    const encodedHeight = metadata.pageHeight ?? metadata.height;
    const pageCount = metadata.pages ?? 1;
    const renderedWidth = metadata.autoOrient.width;
    const renderedHeight = pageCount > 1 && metadata.pageHeight !== undefined ? metadata.pageHeight : metadata.autoOrient.height;
    const numbers = [encodedWidth, encodedHeight, pageCount, renderedWidth, renderedHeight];
    if (mime === undefined || numbers.some((value) => !Number.isSafeInteger(value) || (value as number) < 0)) return null;
    if ((encodedWidth as number) === 0 || (encodedHeight as number) === 0 || (renderedWidth as number) === 0 || (renderedHeight as number) === 0) return null;
    if ((encodedWidth as number) > limits.maxDimension || (encodedHeight as number) > limits.maxDimension || (renderedWidth as number) > limits.maxDimension || (renderedHeight as number) > limits.maxDimension) return null;
    if ((renderedWidth as number) * (renderedHeight as number) > limits.maxPixels || pageCount > limits.maxFrames) return null;
    return {
      mime,
      encodedWidth: encodedWidth as number,
      encodedHeight: encodedHeight as number,
      renderedWidth: renderedWidth as number,
      renderedHeight: renderedHeight as number,
      pageCount,
      animated: pageCount > 1,
      ...(svg ? { sanitizerPolicy: { version: SVG_POLICY_VERSION, digest: digestBytes(Buffer.from(SVG_POLICY_VERSION)) } } : {}),
    };
  } catch {
    return null;
  }
}

async function inspectMigrationAssetBytesWithLimits(
  bytes: Uint8Array,
  limits: AssetInventoryLimits,
): Promise<InspectedMigrationAssetBytes | null> {
  if (bytes === null || typeof bytes !== 'object' || nodeUtilTypes.isProxy(bytes)) return null;
  try {
    if (
      !(bytes instanceof Uint8Array) ||
      bytes.byteLength === 0 ||
      bytes.byteLength > limits.maxSingleBytes
    ) {
      return null;
    }
    const signature = Buffer.from(
      bytes.buffer,
      bytes.byteOffset,
      Math.min(bytes.byteLength, 4),
    ).toString('ascii');
    if (signature === 'wOFF' || signature === 'wOF2') {
      return inspectFontBytes(bytes, limits);
    }
    return await inspectImage(bytes, limits);
  } catch {
    return null;
  }
}

export async function inspectMigrationAssetBytes(
  bytes: Uint8Array,
): Promise<InspectedMigrationAssetBytes | null> {
  return await inspectMigrationAssetBytesWithLimits(bytes, DEFAULT_LIMITS);
}

function compareReferences(left: InventoriedAssetReference, right: InventoriedAssetReference): number {
  return compareUtf8(JSON.stringify([left.sourcePath, left.id, left.target ?? null, left.provenance]), JSON.stringify([right.sourcePath, right.id, right.target ?? null, right.provenance]));
}

function compareUtf8(left: string, right: string): number {
  return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'));
}

function sortInput(left: AssetInput, right: AssetInput): number {
  return compareUtf8(JSON.stringify([left.reference.sourcePath, left.reference.id, left.reference.target ?? null, left.authority, left.classification]),
    JSON.stringify([right.reference.sourcePath, right.reference.id, right.reference.target ?? null, right.authority, right.classification]),
  );
}

export async function inventoryMigrationAssets(input: AssetInventoryInput): Promise<AssetInventoryResult> {
  if (!isRecord(input) || !exactKeys(input, input.limits === undefined ? ['assets'] : ['assets', 'limits'])) {
    return contentFreeResult('asset_input_invalid');
  }
  const limits = resolveLimits(input.limits);
  if (limits === null) return contentFreeResult('asset_limit_invalid');
  const assetCount = plainArrayLength(input.assets);
  if (assetCount === null) return contentFreeResult('asset_input_invalid');
  if (assetCount > limits.maxAssets || assetCount > limits.maxReferences) return contentFreeResult('asset_policy_blocked');
  if (!isPlainArray(input.assets) || input.assets.some((asset) => !validAssetInput(asset))) return contentFreeResult('asset_input_invalid');
  for (const asset of input.assets) {
    if (asset.authority === 'hosted_source_capture' && !validCaptureReceiptPreflight(asset.captureReceipt, limits)) return contentFreeResult('capture_receipt_invalid');
  }
  let attemptedBytes = 0;
  for (const asset of input.assets) {
    if (asset.authority === 'declared_external') continue;
    const byteCount = asset.bytes.byteLength;
    if (byteCount > limits.maxSingleBytes) return contentFreeResult('asset_policy_blocked');
    attemptedBytes += byteCount;
    if (!Number.isSafeInteger(attemptedBytes) || attemptedBytes > limits.maxTotalBytes) return contentFreeResult('asset_policy_blocked');
  }
  const blockerCodes = new Set<AssetInventoryBlockerCode>();
  const block = (code: AssetInventoryBlockerCode): void => {
    if (blockerCodes.size < limits.maxBlockers) blockerCodes.add(code);
  };
  const bundled = new Map<string, InventoriedAsset>();
  const structural = new Map<string, InventoriedAsset>();
  const external: DeclaredExternalAsset[] = [];
  const targetOwners = new Map<string, 'editorial_cms' | 'structural_git' | 'declared_external'>();
  const referenceOwners = new Map<string, { authority: AssetInput['authority']; classification: AssetInput['classification']; digest?: AssetDigest }>();
  const sourceOwners = new Map<string, string>();
  const groupAuthorities = new Map<string, AssetInput['authority']>();
  let fontCount = 0;

  for (const asset of [...input.assets].sort(sortInput)) {
    if (!validReference(asset.reference)) { block('asset_input_invalid'); continue; }
    const refKey = referenceKey(asset.reference);
    const previousReference = referenceOwners.get(refKey);
    const currentDigest = asset.authority === 'declared_external' ? undefined : asset.digest;
    if (previousReference !== undefined && (previousReference.authority !== asset.authority || previousReference.classification !== asset.classification || previousReference.digest !== currentDigest)) {
      block('asset_authority_conflict');
      continue;
    }
    referenceOwners.set(refKey, { authority: asset.authority, classification: asset.classification, ...(currentDigest === undefined ? {} : { digest: currentDigest }) });

    if (asset.authority === 'declared_external') {
      const url = canonicalHttpsUrl(asset.externalUrl);
      if (url === null) { block('external_url_invalid'); continue; }
      if (!safeToken(asset.privateBoundary) || !validTarget(asset.reference.target)) { block('asset_input_invalid'); continue; }
      const sourceOwner = `${asset.authority}:${asset.classification}:${url}:${asset.privateBoundary}`;
      const previousSourceOwner = sourceOwners.get(asset.reference.sourcePath);
      if (previousSourceOwner !== undefined && previousSourceOwner !== sourceOwner) { block('asset_authority_conflict'); continue; }
      sourceOwners.set(asset.reference.sourcePath, sourceOwner);
      const identity = targetKey(asset.reference.target);
      if (targetOwners.has(identity)) { block('asset_target_conflict'); continue; }
      targetOwners.set(identity, 'declared_external');
      external.push({
        url,
        privateBoundary: asset.privateBoundary,
        reference: asset.reference,
        provenance: { authority: 'declared_external', url, privateBoundary: asset.privateBoundary },
      });
      continue;
    }

    if (!(asset.bytes instanceof Uint8Array) || asset.bytes.byteLength === 0 || !SHA256_PATTERN.test(asset.digest)) { block('asset_input_invalid'); continue; }
    if (asset.bytes.byteLength > limits.maxSingleBytes) { block('asset_policy_blocked'); continue; }
    const actualDigest = digestBytes(asset.bytes);
    if (actualDigest !== asset.digest) { block('asset_digest_mismatch'); continue; }
    const sourceOwner = `${asset.authority}:${asset.classification}:${actualDigest}`;
    const previousSourceOwner = sourceOwners.get(asset.reference.sourcePath);
    if (previousSourceOwner !== undefined && previousSourceOwner !== sourceOwner) { block('asset_authority_conflict'); continue; }
    sourceOwners.set(asset.reference.sourcePath, sourceOwner);
    if (asset.classification === 'editorial_cms' ? !validTarget(asset.reference.target) : asset.reference.target !== undefined) {
      block('asset_authority_conflict');
      continue;
    }
    if (asset.reference.target !== undefined) {
      const identity = targetKey(asset.reference.target);
      const previousOwner = targetOwners.get(identity);
      if (previousOwner !== undefined) { block(previousOwner === asset.classification ? 'asset_target_conflict' : 'asset_authority_conflict'); continue; }
      targetOwners.set(identity, asset.classification);
    }
    const groupKey = `${asset.classification}:${actualDigest}`;
    const previousAuthority = groupAuthorities.get(groupKey);
    if (previousAuthority !== undefined && previousAuthority !== asset.authority) { block('asset_authority_conflict'); continue; }
    groupAuthorities.set(groupKey, asset.authority);

    const inspectedBytes = await inspectMigrationAssetBytesWithLimits(asset.bytes, limits);
    const font = inspectedBytes?.mime === 'font/woff' || inspectedBytes?.mime === 'font/woff2';
    let inspected: Omit<InventoriedAsset, 'digest' | 'bytes' | 'bytesValue' | 'references'> | null;
    if (font) {
      fontCount += 1;
      inspected = asset.classification !== 'structural_git' || !validFontLicense(asset.fontLicense)
        ? null
        : {
            mime: inspectedBytes.mime,
            encodedWidth: 0,
            encodedHeight: 0,
            renderedWidth: 0,
            renderedHeight: 0,
            pageCount: 0,
            animated: false,
            fontLicense: asset.fontLicense as StructuralFontLicense,
          };
    } else {
      inspected =
        asset.structuralKind === 'font' ||
        inspectedBytes === null ||
        !('encodedWidth' in inspectedBytes)
          ? null
          : inspectedBytes;
    }
    if (fontCount > limits.maxFonts || inspected === null) { block('asset_policy_blocked'); continue; }
    if (asset.authority === 'hosted_source_capture' && !validCaptureReceiptLinkage(asset.captureReceipt, asset.bytes, actualDigest, inspected.mime)) {
      block('capture_receipt_invalid');
      continue;
    }
    const provenance: AssetProvenance = asset.authority === 'source_local'
      ? { authority: 'source_local', sourcePath: asset.reference.sourcePath }
      : {
          authority: 'hosted_source_capture', sourcePath: asset.reference.sourcePath,
          receiptPolicyVersion: asset.captureReceipt.policyVersion,
          originalUrl: asset.captureReceipt.originalUrl,
          finalUrl: asset.captureReceipt.finalUrl,
        };
    const reference: InventoriedAssetReference = { ...asset.reference, classification: asset.classification, provenance };
    const destination = asset.classification === 'editorial_cms' ? bundled : structural;
    const existing = destination.get(actualDigest);
    if (existing === undefined) {
      destination.set(actualDigest, { digest: actualDigest, bytes: asset.bytes.byteLength, bytesValue: asset.bytes, ...inspected, references: [reference] });
    } else if (!existing.references.some((item) => referenceKey(item) === referenceKey(reference))) {
      existing.references.push(reference);
    }
  }

  const sortedAssets = (values: Iterable<InventoriedAsset>): InventoriedAsset[] => [...values].map((asset) => ({ ...asset, references: [...asset.references].sort(compareReferences) })).sort((left, right) => compareUtf8(left.digest, right.digest));
  external.sort((left, right) => compareUtf8(JSON.stringify([left.reference.target, left.url, left.privateBoundary]), JSON.stringify([right.reference.target, right.url, right.privateBoundary])));
  const blockers = [...blockerCodes].sort().map((code) => ({ code }));
  return {
    status: blockers.length === 0 ? 'ready' : 'needs_attention',
    bundled: sortedAssets(bundled.values()),
    structural: sortedAssets(structural.values()),
    external,
    blockers,
  };
}
