export type ContentKeyScope = 'page' | 'global';

export interface CompileContentKeyInput {
  scope?: ContentKeyScope;
  pageId?: string;
  componentRole: string | readonly string[];
  fieldRole: string;
  itemId?: string;
}

export interface CompileCollectionContentKeyInput {
  scope?: ContentKeyScope;
  pageId?: string;
  componentRole: string | readonly string[];
}

const reservedSegments = new Set([
  '__proto__',
  'constructor',
  'global',
  'items',
  'page',
  'prototype',
]);

export const contentKeyConfusablesProvenance = {
  source: 'https://www.unicode.org/Public/security/latest/confusables.txt',
  unicodeVersion: '17.0.0',
  sourceDate: '2025-07-22',
  sha256: '091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a',
  profile: 'ASCII semantic segments [A-Za-z0-9]',
} as const;

function unsafeSegment(): never {
  throw new TypeError('unsafe_semantic_segment');
}

export function normalizeSemanticSegment(input: string): string {
  const canonical = input.normalize('NFC').trim();
  if (
    canonical === '' ||
    reservedSegments.has(canonical.toLowerCase()) ||
    canonical.includes('.') ||
    /[/:\\\p{Cc}\p{Cf}]/u.test(canonical)
  ) {
    return unsafeSegment();
  }

  const words = canonical.split(/[\p{Zs}_-]+/u).filter(Boolean);
  if (words.length === 0) return unsafeSegment();
  const [first, ...rest] = words;
  if (!first) return unsafeSegment();
  const firstPoint = [...first][0];
  if (!firstPoint) return unsafeSegment();
  const firstWord = words.length > 1 || /^\p{Lu}{2,}$/u.test(first)
    ? first.toLowerCase()
    : `${firstPoint.toLowerCase()}${first.slice(firstPoint.length)}`;
  const normalized = `${firstWord}${rest
    .map((word) => {
      const lowered = word.toLowerCase();
      const point = [...lowered][0];
      return point ? `${point.toUpperCase()}${lowered.slice(point.length)}` : '';
    })
    .join('')}`.normalize('NFC');

  if (
    normalized !== normalized.normalize('NFKC') ||
    !/^[a-z][A-Za-z0-9]*$/u.test(normalized) ||
    reservedSegments.has(normalized) ||
    /^\p{N}+$/u.test(normalized) ||
    !/^\p{ID_Start}\p{ID_Continue}*$/u.test(normalized)
  ) {
    return unsafeSegment();
  }
  return normalized;
}

export function semanticConfusableSkeleton(input: string): string {
  return [...input]
    .map((character) => {
      if (character === '0') return 'O';
      if (character === '1' || character === 'I') return 'l';
      if (character === 'm') return 'rn';
      return character;
    })
    .join('');
}

export function compileContentKey(input: CompileContentKeyInput): string {
  const scope = input.scope ?? 'page';
  const roles = typeof input.componentRole === 'string'
    ? [input.componentRole]
    : [...input.componentRole];
  if (roles.length === 0) return unsafeSegment();

  const segments = scope === 'global'
    ? ['global']
    : ['page', normalizeSemanticSegment(input.pageId ?? '')];
  segments.push(...roles.map(normalizeSemanticSegment));
  if (input.itemId !== undefined) {
    segments.push('items', normalizeSemanticSegment(input.itemId));
  }
  segments.push(normalizeSemanticSegment(input.fieldRole));
  return segments.join('.');
}

export function compileCollectionContentKey(input: CompileCollectionContentKeyInput): string {
  const scope = input.scope ?? 'page';
  const roles = typeof input.componentRole === 'string'
    ? [input.componentRole]
    : [...input.componentRole];
  if (roles.length === 0) return unsafeSegment();
  const segments = scope === 'global'
    ? ['global']
    : ['page', normalizeSemanticSegment(input.pageId ?? '')];
  segments.push(...roles.map(normalizeSemanticSegment));
  return segments.join('.');
}

export function contentValueIdentity(
  key: string,
  locale: string,
  variant: string | null,
): string {
  return `${key}\u0000${locale}\u0000${variant ?? ''}`;
}
