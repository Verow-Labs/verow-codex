import { isAbsolute, join, relative, resolve, sep } from 'node:path';

import {
  collectContentCandidates,
  detectIntegrations,
  digestFileInventory,
  discoverAppRoutes,
  makeInventoriedFile,
  projectFile,
  textOf,
  type ContentCandidate,
  type InventoriedFile,
} from './inventory.js';

export type SourceBlockerCode =
  | 'not_codex_sites'
  | 'not_app_router'
  | 'unsafe_path'
  | 'secret_file'
  | 'd1_binding'
  | 'r2_binding'
  | 'sites_auth'
  | 'worker_runtime'
  | 'durable_state'
  | 'unsupported_dependency_source';

export interface SitesSourceAnalysis {
  sourceDigest: `sha256:${string}`;
  admissible: boolean;
  blockers: readonly { code: SourceBlockerCode; path: string | null }[];
  routes: readonly string[];
  files: readonly { path: string; bytes: number; digest: string }[];
  integrations: readonly string[];
  contentCandidates: readonly ContentCandidate[];
}

export interface WorkspaceEntry {
  name: string;
  kind: 'file' | 'directory' | 'symlink' | 'other';
}

export interface WorkspaceReader {
  realpath(path: string): Promise<string>;
  readDirectory(path: string): Promise<readonly WorkspaceEntry[]>;
  readFile(path: string): Promise<Uint8Array>;
}

const ignoredDirectories = new Set([
  '.git',
  '.next',
  '.wrangler',
  'coverage',
  'dist',
  'node_modules',
]);

const blockerOrder: readonly SourceBlockerCode[] = [
  'not_codex_sites',
  'not_app_router',
  'unsafe_path',
  'secret_file',
  'd1_binding',
  'r2_binding',
  'sites_auth',
  'worker_runtime',
  'durable_state',
  'unsupported_dependency_source',
];

function isSecretName(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower === '.env' ||
    lower.startsWith('.env.') ||
    lower === '.npmrc' ||
    lower === '.pypirc' ||
    lower === 'credentials' ||
    lower === 'id_rsa' ||
    lower === 'id_ed25519' ||
    lower.endsWith('.pem') ||
    lower.endsWith('.key')
  );
}

function isSafeEntryName(name: string): boolean {
  return (
    name !== '' &&
    name !== '.' &&
    name !== '..' &&
    !name.includes('/') &&
    !name.includes('\\') &&
    !name.includes('\0')
  );
}

function workspacePath(root: string, absolutePath: string): string {
  return relative(root, absolutePath).split(sep).join('/');
}

async function enumerateSafeFiles(input: {
  root: string;
  reader: WorkspaceReader;
}): Promise<{
  files: InventoriedFile[];
  blockers: { code: SourceBlockerCode; path: string | null }[];
}> {
  const files: InventoriedFile[] = [];
  const blockers: { code: SourceBlockerCode; path: string | null }[] = [];
  const canonicalRoot = await input.reader.realpath(resolve(input.root));

  async function visit(directory: string): Promise<void> {
    const entries = [...(await input.reader.readDirectory(directory))].sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (!isSafeEntryName(entry.name)) {
        blockers.push({ code: 'unsafe_path', path: workspacePath(canonicalRoot, directory) || null });
        continue;
      }
      const absolutePath = join(directory, entry.name);
      const path = workspacePath(canonicalRoot, absolutePath);
      if (absolutePath !== canonicalRoot && !absolutePath.startsWith(`${canonicalRoot}${sep}`)) {
        blockers.push({ code: 'unsafe_path', path });
        continue;
      }
      if (entry.kind === 'directory') {
        if (!ignoredDirectories.has(entry.name)) await visit(absolutePath);
        continue;
      }
      if (entry.kind !== 'file') {
        blockers.push({ code: 'unsafe_path', path });
        continue;
      }
      if (isSecretName(entry.name)) {
        blockers.push({ code: 'secret_file', path });
        continue;
      }
      files.push(makeInventoriedFile(path, await input.reader.readFile(absolutePath)));
    }
  }

  await visit(canonicalRoot);
  files.sort((left, right) => left.path.localeCompare(right.path));
  return { files, blockers };
}

function parseJson(file: InventoriedFile | undefined): Record<string, unknown> | null {
  if (!file) return null;
  try {
    const value: unknown = JSON.parse(textOf(file));
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function hasConfiguredValue(value: unknown): boolean {
  return value !== null && value !== undefined && value !== false && value !== '';
}

function hasUnsupportedDependencySource(files: readonly InventoriedFile[]): boolean {
  const packageJson = parseJson(files.find(({ path }) => path === 'package.json'));
  if (!packageJson) return false;
  const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const section of sections) {
    const dependencies = packageJson[section];
    if (dependencies === null || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
      continue;
    }
    for (const source of Object.values(dependencies)) {
      if (
        typeof source !== 'string' ||
        /^(?:https?:|git(?:\+|:)|github:|gitlab:|bitbucket:|file:|link:|workspace:|portal:|patch:)/iu.test(
          source.trim(),
        )
      ) {
        return true;
      }
    }
  }
  return false;
}

function detectUnsupportedCapabilities(
  files: readonly InventoriedFile[],
  initial: readonly { code: SourceBlockerCode; path: string | null }[],
): readonly { code: SourceBlockerCode; path: string | null }[] {
  const blockers = [...initial];
  const hostingFile = files.find(({ path }) => path === '.openai/hosting.json');
  const hosting = parseJson(hostingFile);
  const packageJson = parseJson(files.find(({ path }) => path === 'package.json'));
  const allText = files
    .filter(({ path }) => /\.(?:[cm]?[jt]sx?|json)$/u.test(path))
    .map(textOf)
    .join('\n');

  if (!hosting) blockers.push({ code: 'not_codex_sites', path: '.openai/hosting.json' });
  if (discoverAppRoutes(files).length === 0) blockers.push({ code: 'not_app_router', path: null });
  if (hosting && hasConfiguredValue(hosting.d1)) {
    blockers.push({ code: 'd1_binding', path: '.openai/hosting.json' });
  }
  if (hosting && hasConfiguredValue(hosting.r2)) {
    blockers.push({ code: 'r2_binding', path: '.openai/hosting.json' });
  }
  const dependencyNames = packageJson && typeof packageJson.dependencies === 'object'
    ? Object.keys(packageJson.dependencies as Record<string, unknown>)
    : [];
  if (
    (hosting && (hasConfiguredValue(hosting.auth) || hasConfiguredValue(hosting.accessPolicy))) ||
    dependencyNames.some((name) => name === 'next-auth' || name.startsWith('@auth/')) ||
    /(?:next-auth|@auth\/|sitesAuth)/u.test(allText)
  ) {
    blockers.push({ code: 'sites_auth', path: hostingFile?.path ?? null });
  }
  const workerFile = files.find(
    ({ path }) =>
      path.startsWith('worker/') ||
      /^wrangler\.(?:toml|jsonc?)$/u.test(path) ||
      /(?:^|\/)worker\.[cm]?[jt]s$/u.test(path),
  );
  if (workerFile || /cloudflare:workers|\bWorkerEntrypoint\b/u.test(allText)) {
    blockers.push({ code: 'worker_runtime', path: workerFile?.path ?? null });
  }
  if (
    (hosting && hasConfiguredValue(hosting.durableObjects)) ||
    /\bDurableObject(?:Namespace|State)?\b/u.test(allText)
  ) {
    blockers.push({ code: 'durable_state', path: hostingFile?.path ?? null });
  }
  if (hasUnsupportedDependencySource(files)) {
    blockers.push({ code: 'unsupported_dependency_source', path: 'package.json' });
  }

  const unique = new Map<string, { code: SourceBlockerCode; path: string | null }>();
  for (const blocker of blockers) unique.set(`${blocker.code}\0${blocker.path ?? ''}`, blocker);
  return [...unique.values()].sort((left, right) => {
    const codeOrder = blockerOrder.indexOf(left.code) - blockerOrder.indexOf(right.code);
    return codeOrder || (left.path ?? '').localeCompare(right.path ?? '');
  });
}

export async function analyzeSitesSource(input: {
  root: string;
  reader: WorkspaceReader;
}): Promise<SitesSourceAnalysis> {
  if (!isAbsolute(input.root)) throw new TypeError('workspace root must be absolute');
  const { files, blockers: filesystemBlockers } = await enumerateSafeFiles(input);
  const blockers = detectUnsupportedCapabilities(files, filesystemBlockers);
  return {
    sourceDigest: digestFileInventory(files),
    admissible: blockers.length === 0,
    blockers,
    routes: discoverAppRoutes(files),
    files: files.map(projectFile),
    integrations: detectIntegrations(files),
    contentCandidates: collectContentCandidates(files),
  };
}
