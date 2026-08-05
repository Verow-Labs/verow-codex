import { createHash } from 'node:crypto';
import { extname } from 'node:path';

export type ContentSourceKind = 'jsx' | 'json' | 'css_content' | 'aria';

export interface ContentCandidate {
  path: string;
  sourceKind: ContentSourceKind;
  value: string;
  locator: string;
}

export interface InventoriedFile {
  path: string;
  bytes: number;
  digest: `sha256:${string}`;
  content: Uint8Array;
}

export interface ProjectedFile {
  path: string;
  bytes: number;
  digest: string;
}

const textExtensions = new Set([
  '.css',
  '.html',
  '.js',
  '.json',
  '.jsx',
  '.md',
  '.mdx',
  '.mjs',
  '.ts',
  '.tsx',
  '.txt',
  '.yaml',
  '.yml',
]);

function sha256(bytes: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function makeInventoriedFile(path: string, content: Uint8Array): InventoriedFile {
  return {
    path,
    bytes: content.byteLength,
    digest: sha256(content),
    content,
  };
}

export function projectFile(file: InventoriedFile): ProjectedFile {
  return { path: file.path, bytes: file.bytes, digest: file.digest };
}

export function digestFileInventory(files: readonly InventoriedFile[]): `sha256:${string}` {
  const inventory = files
    .map(({ path, bytes, digest }) => `${path}\0${bytes}\0${digest}\n`)
    .join('');
  return sha256(inventory);
}

function decodeText(file: InventoriedFile): string | null {
  if (!textExtensions.has(extname(file.path).toLowerCase())) return null;
  return new TextDecoder('utf-8', { fatal: false }).decode(file.content);
}

function routeSegment(segment: string): string | null {
  if (segment.startsWith('(') && segment.endsWith(')')) return null;
  if (segment.startsWith('@')) return null;
  if (segment.startsWith('[[...') && segment.endsWith(']]')) {
    return `:${segment.slice(5, -2)}*`;
  }
  if (segment.startsWith('[...') && segment.endsWith(']')) {
    return `:${segment.slice(4, -1)}*`;
  }
  if (segment.startsWith('[') && segment.endsWith(']')) {
    return `:${segment.slice(1, -1)}`;
  }
  return segment;
}

export function discoverAppRoutes(files: readonly InventoriedFile[]): readonly string[] {
  const routes = new Set<string>();
  for (const file of files) {
    const match = /^app\/(.*\/)?(?:page|route)\.(?:[cm]?[jt]sx?)$/u.exec(file.path);
    if (!match) continue;
    const segments = (match[1] ?? '')
      .split('/')
      .filter(Boolean)
      .map(routeSegment)
      .filter((segment): segment is string => segment !== null);
    routes.add(`/${segments.join('/')}`);
  }
  return [...routes].sort();
}

function addJsonCandidates(
  candidates: ContentCandidate[],
  path: string,
  value: unknown,
  locator = '',
): void {
  if (typeof value === 'string' && value.trim() !== '') {
    candidates.push({ path, sourceKind: 'json', value, locator: locator || '/' });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => addJsonCandidates(candidates, path, item, `${locator}/${index}`));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      const escaped = key.replaceAll('~', '~0').replaceAll('/', '~1');
      addJsonCandidates(candidates, path, item, `${locator}/${escaped}`);
    }
  }
}

export function collectContentCandidates(
  files: readonly InventoriedFile[],
): readonly ContentCandidate[] {
  const candidates: ContentCandidate[] = [];
  for (const file of files) {
    const text = decodeText(file);
    if (text === null) continue;
    const extension = extname(file.path).toLowerCase();
    if (extension === '.json' && !file.path.endsWith('package.json')) {
      try {
        addJsonCandidates(candidates, file.path, JSON.parse(text));
      } catch {
        // Malformed JSON is not treated as human-facing content.
      }
    }
    if (extension === '.css') {
      for (const match of text.matchAll(/\bcontent\s*:\s*(["'])(.*?)\1/gu)) {
        candidates.push({
          path: file.path,
          sourceKind: 'css_content',
          value: match[2] ?? '',
          locator: `offset:${match.index}`,
        });
      }
    }
    if (/\.[jt]sx$/u.test(extension)) {
      for (const match of text.matchAll(/\baria-(?:label|description)\s*=\s*(["'])(.*?)\1/gu)) {
        candidates.push({
          path: file.path,
          sourceKind: 'aria',
          value: match[2] ?? '',
          locator: `offset:${match.index}`,
        });
      }
      for (const match of text.matchAll(/>([^<>{}\n][^<>{}]*)</gu)) {
        const value = (match[1] ?? '').trim();
        if (value !== '') {
          candidates.push({
            path: file.path,
            sourceKind: 'jsx',
            value,
            locator: `offset:${match.index}`,
          });
        }
      }
    }
  }
  return candidates.sort((left, right) =>
    `${left.path}\0${left.locator}\0${left.sourceKind}`.localeCompare(
      `${right.path}\0${right.locator}\0${right.sourceKind}`,
    ),
  );
}

export function detectIntegrations(files: readonly InventoriedFile[]): readonly string[] {
  const packageFile = files.find(({ path }) => path === 'package.json');
  if (!packageFile) return [];
  try {
    const packageJson = JSON.parse(new TextDecoder().decode(packageFile.content)) as {
      dependencies?: Record<string, unknown>;
      devDependencies?: Record<string, unknown>;
    };
    const names = [
      ...Object.keys(packageJson.dependencies ?? {}),
      ...Object.keys(packageJson.devDependencies ?? {}),
    ];
    return [...new Set(names.filter((name) =>
      /(?:stripe|sentry|analytics|supabase|firebase|contentful|sanity)/iu.test(name),
    ))].sort();
  } catch {
    return [];
  }
}

export function textOf(file: InventoriedFile): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(file.content);
}
