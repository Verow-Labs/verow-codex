import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { satisfies, valid, validRange } from 'semver';

import type { SitesSourceAnalysis } from './admission.js';
import {
  compareCodePointStrings,
  digestFileInventory,
  makeInventoriedFile,
  type InventoriedFile,
} from './inventory.js';
import { classifySitesHostingShim } from './hosting-shims.js';

type Sha256Digest = `sha256:${string}`;

export interface ConvertToNativeNextInput {
  analysis: SitesSourceAnalysis;
  sourceRoot: string;
  outputRoot: string;
}

export interface NativeNextMutation {
  path: string;
  action: 'copied' | 'rewritten' | 'removed';
  beforeDigest: Sha256Digest;
  afterDigest?: Sha256Digest;
}

export interface NativeNextCandidate {
  packageJson: Readonly<Record<string, unknown>>;
  outputPaths: readonly string[];
  preservedDigests: Readonly<Record<string, Sha256Digest>>;
  mutations: readonly NativeNextMutation[];
}

const ignoredDirectories = new Set([
  '.git',
  '.next',
  '.wrangler',
  'coverage',
  'dist',
  'node_modules',
]);

const dependencySections = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
] as const;

const rootLockManifestFields = [
  'name',
  'version',
  'license',
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
  'peerDependenciesMeta',
  'bundleDependencies',
  'bin',
  'engines',
  'os',
  'cpu',
  'workspaces',
] as const;

const removedHostingPackages = new Set([
  '@cloudflare/next-on-pages',
  '@cloudflare/vinext',
  '@cloudflare/vite-plugin',
  '@cloudflare/workers-types',
  '@opennextjs/cloudflare',
  'vinext',
  'vite',
  'vite-tsconfig-paths',
  'wrangler',
]);

const removedHostingBinaries = new Set([
  'next-on-pages',
  'opennextjs-cloudflare',
  'vinext',
  'vite',
  'wrangler',
]);

const hostingOnlyPaths = new Set([
  '.openai/hosting.json',
  'wrangler.json',
  'wrangler.jsonc',
  'wrangler.toml',
]);

function sha256(bytes: string | Uint8Array): Sha256Digest {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function canonicalJson(value: unknown): Uint8Array {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function isSecretName(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower === '.env' ||
    lower.startsWith('.env.') ||
    lower === '.dev.vars' ||
    lower.startsWith('.dev.vars.') ||
    lower === '.npmrc' ||
    lower === '.pypirc' ||
    lower === 'credentials' ||
    lower === 'id_rsa' ||
    lower === 'id_ed25519' ||
    lower.endsWith('.pem') ||
    lower.endsWith('.key')
  );
}

function assertSafeRelativePath(path: string): void {
  const segments = path.split('/');
  if (
    path === '' ||
    path.includes('\\') ||
    path.includes('\0') ||
    isAbsolute(path) ||
    segments.some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new Error(`unsafe source or output path: ${path}`);
  }
}

function isNested(parent: string, child: string): boolean {
  const path = relative(parent, child);
  return path !== '' && path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

async function assertRoots(input: ConvertToNativeNextInput): Promise<{
  sourceRoot: string;
  outputRoot: string;
}> {
  if (!isAbsolute(input.sourceRoot) || !isAbsolute(input.outputRoot)) {
    throw new TypeError('source and output roots must be absolute');
  }
  const requestedSourceRoot = resolve(input.sourceRoot);
  const requestedOutputRoot = resolve(input.outputRoot);

  const [sourceStat, outputStat] = await Promise.all([
    lstat(requestedSourceRoot),
    lstat(requestedOutputRoot),
  ]);
  if (sourceStat.isSymbolicLink() || outputStat.isSymbolicLink()) {
    throw new Error('source and output roots must not be symlinks');
  }
  if (!sourceStat.isDirectory() || !outputStat.isDirectory()) {
    throw new Error('source and output roots must be directories');
  }
  const [sourceRoot, outputRoot] = await Promise.all([
    realpath(requestedSourceRoot),
    realpath(requestedOutputRoot),
  ]);
  if (sourceRoot === outputRoot) {
    throw new Error('canonical source and output roots must be distinct');
  }
  if (isNested(sourceRoot, outputRoot) || isNested(outputRoot, sourceRoot)) {
    throw new Error('canonical source and output roots must not be nested');
  }
  if ((await readdir(outputRoot)).length !== 0) {
    throw new Error('compiler-owned output root must be empty');
  }
  return { sourceRoot, outputRoot };
}

async function enumerateAuthorizedSource(root: string): Promise<readonly string[]> {
  const paths: string[] = [];

  async function visit(directory: string, prefix: string): Promise<void> {
    const entries = [...(await readdir(directory, { withFileTypes: true }))].sort((left, right) =>
      compareCodePointStrings(left.name, right.name),
    );
    for (const entry of entries) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      assertSafeRelativePath(path);
      if (entry.isSymbolicLink()) throw new Error(`source symlink is not authorized: ${path}`);
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(join(directory, entry.name), path);
        continue;
      }
      if (!entry.isFile()) throw new Error(`unsafe source entry is not authorized: ${path}`);
      if (isSecretName(entry.name)) {
        throw new Error(`source authorization drift includes excluded file: ${path}`);
      }
      paths.push(path);
    }
  }

  await visit(root, '');
  return paths;
}

async function readWithoutSymlinks(root: string, path: string): Promise<Uint8Array> {
  let current = root;
  const segments = path.split('/');
  for (let index = 0; index < segments.length - 1; index += 1) {
    current = join(current, segments[index] ?? '');
    const stat = await lstat(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(`source symlink or non-directory ancestor: ${path}`);
    }
  }
  const absolutePath = join(root, ...segments);
  const handle = await open(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error(`source path is not a regular file: ${path}`);
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function verifyAuthorizationSnapshot(
  root: string,
  analysis: SitesSourceAnalysis,
): Promise<readonly InventoriedFile[]> {
  if (!analysis.admissible || analysis.blockers.length !== 0) {
    throw new Error('source analysis must be admissible and blocker-free');
  }
  const analysisPaths = analysis.files.map(({ path }) => path);
  const uniquePaths = new Set<string>();
  for (const path of analysisPaths) {
    assertSafeRelativePath(path);
    if (uniquePaths.has(path)) throw new Error(`duplicate authorization path: ${path}`);
    uniquePaths.add(path);
  }

  const actualPaths = await enumerateAuthorizedSource(root);
  const sortedAnalysisPaths = [...analysisPaths].sort(compareCodePointStrings);
  if (
    actualPaths.length !== sortedAnalysisPaths.length ||
    actualPaths.some((path, index) => path !== sortedAnalysisPaths[index])
  ) {
    throw new Error('source files do not match the analysis authorization snapshot');
  }

  const projectedByPath = new Map(analysis.files.map((file) => [file.path, file]));
  const files: InventoriedFile[] = [];
  for (const path of actualPaths) {
    const projected = projectedByPath.get(path);
    if (!projected) throw new Error(`source file is missing from authorization: ${path}`);
    const bytes = await readWithoutSymlinks(root, path);
    const file = makeInventoriedFile(path, bytes);
    if (file.bytes !== projected.bytes) {
      throw new Error(`source digest or byte count mismatch: ${path}`);
    }
    if (file.digest !== projected.digest) throw new Error(`source digest mismatch: ${path}`);
    files.push(file);
  }
  if (digestFileInventory(files) !== analysis.sourceDigest) {
    throw new Error('source inventory digest mismatch');
  }
  return files;
}

function isRemovedHostingPackage(name: string): boolean {
  return (
    removedHostingPackages.has(name) ||
    name.startsWith('@vitejs/') ||
    name.startsWith('vite-plugin-') ||
    name.endsWith('/vite-plugin')
  );
}

interface NpmAliasSpecifier {
  target: string;
  range: string;
}

function parseNpmAliasSpecifier(specifier: string): NpmAliasSpecifier | null {
  if (!specifier.startsWith('npm:')) return null;
  const alias = specifier.slice(4);
  const separator = alias.startsWith('@') ? alias.lastIndexOf('@') : alias.indexOf('@');
  const target = separator > 0 ? alias.slice(0, separator) : alias;
  const range = separator > 0 ? alias.slice(separator + 1) : '*';
  if (
    target === '' ||
    range === '' ||
    !(target.startsWith('@') ? /^@[^/\s]+\/[^/\s]+$/u : /^[^/@\s]+$/u.test(target))
  ) {
    throw new Error(`unsupported npm alias specifier: ${specifier}`);
  }
  return { target, range };
}

function dependencyTargetsRemovedHostingPackage(name: string, specifier: unknown): boolean {
  if (isRemovedHostingPackage(name)) return true;
  if (typeof specifier !== 'string') return false;
  const alias = parseNpmAliasSpecifier(specifier);
  return alias !== null && isRemovedHostingPackage(alias.target);
}

function invokesRemovedTool(command: string, removedScriptNames: ReadonlySet<string>): boolean {
  const tokens = command.match(/[^\s;&|()'"`]+/gu) ?? [];
  for (const originalToken of tokens) {
    const token = originalToken.replace(/,+$/u, '').replaceAll('\\', '/');
    if (isRemovedHostingPackage(token) || removedHostingBinaries.has(token)) return true;
    const binaryName = token.split('/').at(-1) ?? '';
    if (removedHostingBinaries.has(binaryName)) return true;
    if (token.startsWith('vite-plugin-') || token.startsWith('@vitejs/')) return true;
    const nodeModulesIndex = token.lastIndexOf('node_modules/');
    if (nodeModulesIndex >= 0) {
      const packagePath = token.slice(nodeModulesIndex + 'node_modules/'.length);
      const withoutBin = packagePath.startsWith('.bin/') ? packagePath.slice(5) : packagePath;
      const segments = withoutBin.split('/');
      const packageName = withoutBin.startsWith('@')
        ? segments.slice(0, 2).join('/')
        : (segments[0] ?? '');
      if (isRemovedHostingPackage(packageName)) return true;
    }
  }
  for (const name of removedScriptNames) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
    if (new RegExp(`(?:npm|pnpm|yarn|bun)\\s+(?:run\\s+)?${escaped}(?=$|[\\s;&|()])`, 'u').test(command)) {
      return true;
    }
  }
  return false;
}

function parseManifest(bytes: Uint8Array): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error('package.json is malformed');
  }
  if (!isPlainObject(value)) throw new Error('package.json must contain an object');
  return value;
}

function rewritePackageJson(bytes: Uint8Array): {
  packageJson: Record<string, unknown>;
  bytes: Uint8Array;
} {
  const packageJson = parseManifest(bytes);
  for (const sectionName of dependencySections) {
    const section = packageJson[sectionName];
    if (section === undefined) continue;
    if (!isPlainObject(section)) throw new Error(`package.json ${sectionName} must be an object`);
    for (const name of Object.keys(section)) {
      if (dependencyTargetsRemovedHostingPackage(name, section[name])) delete section[name];
    }
  }

  const dependencies = packageJson.dependencies;
  if (!isPlainObject(dependencies)) {
    throw new Error('package.json dependencies must contain native Next framework packages');
  }
  for (const name of ['next', 'react', 'react-dom']) {
    if (typeof dependencies[name] !== 'string' || dependencies[name] === '') {
      throw new Error(`package.json must preserve the existing ${name} version`);
    }
  }

  const scripts = packageJson.scripts;
  if (scripts !== undefined && !isPlainObject(scripts)) {
    throw new Error('package.json scripts must be an object');
  }
  const rewrittenScripts = scripts ?? {};
  const removedScriptNames = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, command] of Object.entries(rewrittenScripts)) {
      if (['dev', 'build', 'start'].includes(name) || removedScriptNames.has(name)) continue;
      if (typeof command !== 'string') throw new Error(`package.json script ${name} must be a string`);
      if (invokesRemovedTool(command, removedScriptNames)) {
        removedScriptNames.add(name);
        changed = true;
      }
    }
  }
  for (const name of removedScriptNames) delete rewrittenScripts[name];
  rewrittenScripts.dev = 'next dev';
  rewrittenScripts.build = 'next build';
  rewrittenScripts.start = 'next start';
  packageJson.scripts = rewrittenScripts;
  return { packageJson, bytes: canonicalJson(packageJson) };
}

function parentLockPackagePath(path: string): string | null {
  const match = /(?:^|\/)node_modules\/(?:@[^/]+\/)?[^/]+$/u.exec(path);
  if (!match) return null;
  return path.slice(0, match.index);
}

function resolveLockDependency(
  packages: Readonly<Record<string, unknown>>,
  fromPath: string,
  dependencyName: string,
): string | null {
  let current: string | null = fromPath;
  while (current !== null) {
    const candidate = current === ''
      ? `node_modules/${dependencyName}`
      : `${current}/node_modules/${dependencyName}`;
    if (candidate in packages) return candidate;
    current = parentLockPackagePath(current);
  }
  return null;
}

function dependencyMap(entry: Record<string, unknown>, section: string): Record<string, string> {
  const value = entry[section];
  if (value === undefined) return {};
  if (!isPlainObject(value)) throw new Error(`package-lock ${section} must be an object`);
  const result: Record<string, string> = {};
  for (const [name, source] of Object.entries(value)) {
    if (typeof source !== 'string') throw new Error(`package-lock ${section} value is malformed`);
    result[name] = source;
  }
  return result;
}

function isOptionalPeer(entry: Record<string, unknown>, name: string): boolean {
  const metadata = entry.peerDependenciesMeta;
  if (metadata === undefined) return false;
  if (!isPlainObject(metadata)) throw new Error('package-lock peerDependenciesMeta must be an object');
  const peer = metadata[name];
  if (peer === undefined) return false;
  if (!isPlainObject(peer)) throw new Error(`package-lock peer metadata is malformed: ${name}`);
  return peer.optional === true;
}

function registryPackageIdentity(resolved: string): string | null {
  try {
    const url = new URL(resolved);
    if (url.origin !== 'https://registry.npmjs.org') return null;
    const marker = url.pathname.indexOf('/-/');
    if (marker < 0) return null;
    const encoded = url.pathname.slice(1, marker);
    if (url.pathname.slice(marker + 3) === '') return null;
    const identity = decodeURIComponent(encoded);
    if (
      !(identity.startsWith('@')
        ? /^@[^/\s]+\/[^/\s]+$/u.test(identity)
        : /^[^/@\s]+$/u.test(identity))
    ) {
      return null;
    }
    return identity;
  } catch {
    return null;
  }
}

function lockedPackageIdentity(path: string, entry: Record<string, unknown>): string {
  if (typeof entry.resolved !== 'string') {
    throw new Error(`reachable package-lock entry is not from the public npm registry: ${path}`);
  }
  const registryIdentity = registryPackageIdentity(entry.resolved);
  if (registryIdentity === null) {
    throw new Error(`reachable package-lock entry is not from the public npm registry: ${path}`);
  }
  if (entry.name !== undefined && entry.name !== registryIdentity) {
    throw new Error(
      `package-lock name disagrees with registry identity for ${path}: ${String(entry.name)}`,
    );
  }
  return registryIdentity;
}

function specifierRange(specifier: string): { range: string; aliasTarget: string | null } {
  const alias = parseNpmAliasSpecifier(specifier);
  return alias === null
    ? { range: specifier, aliasTarget: null }
    : { range: alias.range, aliasTarget: alias.target };
}

function versionSatisfiesSpecifier(version: string, specifier: string): boolean {
  if (valid(version, { loose: false }) === null) {
    throw new Error(`package-lock entry lacks a concrete semantic version: ${version}`);
  }
  const { range } = specifierRange(specifier);
  if (range === '' || range !== range.trim() || range === '.' || range === '..') {
    throw new Error(`unsupported npm registry selector: ${specifier}`);
  }
  const semanticRange = validRange(range, { loose: false });
  if (semanticRange !== null) {
    return satisfies(version, semanticRange, { includePrerelease: false, loose: false });
  }
  if (encodeURIComponent(range) === range) return true;
  throw new Error(`unsupported npm registry selector: ${specifier}`);
}

function assertSafeLockPackagePath(path: string): void {
  if (
    path !== '' &&
    !/^node_modules\/(?:@[^/]+\/)?[^/]+(?:\/node_modules\/(?:@[^/]+\/)?[^/]+)*$/u.test(path)
  ) {
    throw new Error(`package-lock contains an unsafe package path: ${path}`);
  }
}

function rewritePackageLock(
  bytes: Uint8Array,
  packageJson: Record<string, unknown>,
): Uint8Array {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error('package-lock.json is malformed');
  }
  if (!isPlainObject(parsed) || parsed.lockfileVersion !== 3 || !isPlainObject(parsed.packages)) {
    throw new Error('package-lock.json must be an npm v3 lockfile');
  }
  const lock = parsed;
  const packages = lock.packages as Record<string, unknown>;
  for (const path of Object.keys(packages)) assertSafeLockPackagePath(path);
  const rootEntry = packages[''];
  if (!isPlainObject(rootEntry)) throw new Error('package-lock.json is missing its root package');
  for (const field of rootLockManifestFields) {
    if (packageJson[field] === undefined) delete rootEntry[field];
    else rootEntry[field] = cloneJson(packageJson[field]);
  }

  const reachable = new Set<string>(['']);
  const queue: string[] = [''];
  while (queue.length > 0) {
    const path = queue.shift();
    if (path === undefined) break;
    const entry = packages[path];
    if (!isPlainObject(entry)) throw new Error(`package-lock entry is malformed: ${path}`);
    if (path !== '') {
      if (
        typeof entry.version !== 'string' ||
        typeof entry.integrity !== 'string' ||
        !/^sha(?:256|384|512)-[A-Za-z0-9+/=]+(?:\s+sha(?:256|384|512)-[A-Za-z0-9+/=]+)*$/u.test(
          entry.integrity,
        )
      ) {
        throw new Error(`reachable package-lock entry lacks version or integrity: ${path}`);
      }
      if (
        typeof entry.resolved !== 'string' ||
        registryPackageIdentity(entry.resolved) === null
      ) {
        throw new Error(`reachable package-lock entry is not from the public npm registry: ${path}`);
      }
      const packageName = lockedPackageIdentity(path, entry);
      if (isRemovedHostingPackage(packageName)) {
        throw new Error(`removed hosting tool remains reachable in package-lock: ${packageName}`);
      }
    }

    const requiredDependencies = {
      ...dependencyMap(entry, 'dependencies'),
      ...(path === '' ? dependencyMap(entry, 'devDependencies') : {}),
    };
    const optionalDependencies = dependencyMap(entry, 'optionalDependencies');
    const peerDependencies = dependencyMap(entry, 'peerDependencies');
    const edges = [
      ...Object.entries(requiredDependencies).map(([name, specifier]) => ({
        name,
        specifier,
        optional: false,
        peer: false,
      })),
      ...Object.entries(optionalDependencies).map(([name, specifier]) => ({
        name,
        specifier,
        optional: true,
        peer: false,
      })),
      ...Object.entries(peerDependencies).map(([name, specifier]) => ({
        name,
        specifier,
        optional: isOptionalPeer(entry, name),
        peer: true,
      })),
    ].sort((left, right) => compareCodePointStrings(left.name, right.name));
    for (const edge of edges) {
      const alias = specifierRange(edge.specifier);
      if (alias.aliasTarget !== null && isRemovedHostingPackage(alias.aliasTarget)) {
        throw new Error(`removed hosting tool remains reachable through npm alias: ${alias.aliasTarget}`);
      }
      const dependencyPath = resolveLockDependency(packages, path, edge.name);
      if (dependencyPath === null) {
        if (!edge.optional) {
          const kind = edge.peer ? 'required peer' : 'required dependency';
          throw new Error(`package-lock is missing ${kind} ${edge.name} from ${path}`);
        }
        continue;
      }
      const dependencyEntry = packages[dependencyPath];
      if (!isPlainObject(dependencyEntry) || typeof dependencyEntry.version !== 'string') {
        throw new Error(`package-lock dependency entry is malformed: ${dependencyPath}`);
      }
      if (!versionSatisfiesSpecifier(dependencyEntry.version, edge.specifier)) {
        throw new Error(
          `${dependencyPath} version ${dependencyEntry.version} does not satisfy ${edge.specifier}`,
        );
      }
      const actualIdentity = lockedPackageIdentity(dependencyPath, dependencyEntry);
      if (isRemovedHostingPackage(actualIdentity)) {
        throw new Error(`removed hosting tool remains reachable: ${actualIdentity}`);
      }
      const declaredIdentity = alias.aliasTarget ?? edge.name;
      if (actualIdentity !== declaredIdentity) {
        throw new Error(
          `package-lock dependency ${edge.name} resolves ${actualIdentity} instead of ${declaredIdentity}`,
        );
      }
      if (!reachable.has(dependencyPath)) {
        reachable.add(dependencyPath);
        queue.push(dependencyPath);
      }
    }
  }

  const retainedPackages: Record<string, unknown> = {};
  for (const path of [...reachable].sort(compareCodePointStrings)) {
    retainedPackages[path] = packages[path];
  }
  lock.packages = retainedPackages;
  return canonicalJson(lock);
}

function isHostingOnlyFile(file: InventoriedFile): boolean {
  return (
    hostingOnlyPaths.has(file.path) ||
    /^vite\.config\.(?:[cm]?[jt]s)$/u.test(file.path) ||
    classifySitesHostingShim(file.path, file.content) === 'known_shim'
  );
}

async function assertCanonicalOutputDirectory(
  outputRoot: string,
  directory: string,
): Promise<void> {
  const stat = await lstat(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`output parent must remain a real directory: ${directory}`);
  }
  const canonical = await realpath(directory);
  if (canonical !== outputRoot && !isNested(outputRoot, canonical)) {
    throw new Error(`output parent escaped canonical output root: ${directory}`);
  }
}

async function createOutputParent(outputRoot: string, path: string): Promise<string> {
  await assertCanonicalOutputDirectory(outputRoot, outputRoot);
  const segments = path.split('/').slice(0, -1);
  let directory = outputRoot;
  for (const segment of segments) {
    directory = join(directory, segment);
    try {
      await mkdir(directory);
    } catch (error) {
      if (!isPlainObject(error) || error.code !== 'EEXIST') throw error;
    }
    await assertCanonicalOutputDirectory(outputRoot, directory);
  }
  return directory;
}

/** @internal */
export async function writeOutputFiles(
  outputRoot: string,
  files: ReadonlyMap<string, Uint8Array>,
): Promise<void> {
  for (const path of [...files.keys()].sort(compareCodePointStrings)) {
    const absolutePath = join(outputRoot, ...path.split('/'));
    const parent = await createOutputParent(outputRoot, path);
    const handle = await open(
      absolutePath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await assertCanonicalOutputDirectory(outputRoot, parent);
      const canonicalFile = await realpath(absolutePath);
      if (!isNested(outputRoot, canonicalFile)) {
        throw new Error(`output file escaped canonical output root: ${path}`);
      }
      await handle.writeFile(files.get(path) ?? new Uint8Array());
    } finally {
      await handle.close();
    }
  }
}

export async function convertToNativeNext(
  input: ConvertToNativeNextInput,
): Promise<NativeNextCandidate> {
  const { sourceRoot, outputRoot } = await assertRoots(input);
  const sourceFiles = await verifyAuthorizationSnapshot(sourceRoot, input.analysis);
  for (const file of sourceFiles) {
    const shim = classifySitesHostingShim(file.path, file.content);
    const workerPath =
      file.path.startsWith('worker/') || /(?:^|\/)worker\.[cm]?[jt]s$/u.test(file.path);
    if (shim === 'unsafe_shim' || (workerPath && shim !== 'known_shim')) {
      throw new Error(`source analysis contains unsupported Worker behavior: ${file.path}`);
    }
  }
  const sourceByPath = new Map(sourceFiles.map((file) => [file.path, file]));
  const packageFile = sourceByPath.get('package.json');
  const lockFile = sourceByPath.get('package-lock.json');
  if (!packageFile) throw new Error('package.json is required for native Next conversion');
  if (!lockFile) throw new Error('package-lock.json is required for offline native Next conversion');

  const rewrittenPackage = rewritePackageJson(packageFile.content);
  const rewrittenLock = rewritePackageLock(lockFile.content, rewrittenPackage.packageJson);
  const outputFiles = new Map<string, Uint8Array>();
  const preservedDigests: Record<string, Sha256Digest> = {};
  const mutations: NativeNextMutation[] = [];

  for (const file of sourceFiles) {
    if (isHostingOnlyFile(file)) {
      mutations.push({ path: file.path, action: 'removed', beforeDigest: file.digest });
      continue;
    }
    if (file.path === 'package.json' || file.path === 'package-lock.json') {
      const outputBytes = file.path === 'package.json' ? rewrittenPackage.bytes : rewrittenLock;
      outputFiles.set(file.path, outputBytes);
      mutations.push({
        path: file.path,
        action: 'rewritten',
        beforeDigest: file.digest,
        afterDigest: sha256(outputBytes),
      });
      continue;
    }
    outputFiles.set(file.path, file.content);
    preservedDigests[file.path] = file.digest;
    mutations.push({
      path: file.path,
      action: 'copied',
      beforeDigest: file.digest,
      afterDigest: file.digest,
    });
  }

  mutations.sort((left, right) => compareCodePointStrings(left.path, right.path));
  await writeOutputFiles(outputRoot, outputFiles);
  return {
    packageJson: rewrittenPackage.packageJson,
    outputPaths: [...outputFiles.keys()].sort(compareCodePointStrings),
    preservedDigests,
    mutations,
  };
}
