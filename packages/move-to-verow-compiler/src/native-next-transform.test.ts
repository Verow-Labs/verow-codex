import { createHash } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';

import {
  analyzeSitesSource,
  type SitesSourceAnalysis,
  type WorkspaceReader,
} from './admission.js';
import { compareCodePointStrings } from './inventory.js';
import { convertToNativeNext } from './native-next-transform.js';

const execFile = promisify(execFileCallback);
const fixtureRoot = resolve(import.meta.dirname, '..', 'fixtures', 'sites-multi-route');
const temporaryRoots = new Set<string>();

const nodeReader: WorkspaceReader = {
  async readDirectory(path) {
    return (await readdir(path, { withFileTypes: true })).map((entry) => ({
      name: entry.name,
      kind: entry.isFile()
        ? 'file'
        : entry.isDirectory()
          ? 'directory'
          : entry.isSymbolicLink()
            ? 'symlink'
            : 'other',
    }));
  },
  readFile,
  realpath,
};

afterEach(async () => {
  await Promise.all([...temporaryRoots].map((path) => rm(path, { recursive: true, force: true })));
  temporaryRoots.clear();
});

function sha256(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function emptyOutputRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'verow-native-output-'));
  temporaryRoots.add(root);
  return root;
}

async function fixtureCopy(): Promise<string> {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'verow-native-source-'));
  temporaryRoots.add(temporaryRoot);
  const sourceRoot = join(temporaryRoot, 'source');
  await cp(fixtureRoot, sourceRoot, { recursive: true });
  return sourceRoot;
}

async function analyze(root = fixtureRoot): Promise<SitesSourceAnalysis> {
  return analyzeSitesSource({ root, reader: nodeReader });
}

async function convertFixture(options: {
  sourceRoot?: string;
  analysis?: SitesSourceAnalysis;
  outputRoot?: string;
} = {}) {
  const sourceRoot = options.sourceRoot ?? fixtureRoot;
  const analysis = options.analysis ?? (await analyze(sourceRoot));
  const outputRoot = options.outputRoot ?? (await emptyOutputRoot());
  const candidate = await convertToNativeNext({ analysis, sourceRoot, outputRoot });
  return { analysis, candidate, outputRoot, sourceRoot };
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

function packageSections(packageJson: Record<string, unknown>) {
  return Object.fromEntries(
    ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']
      .filter((key) => key in packageJson)
      .map((key) => [key, packageJson[key]]),
  );
}

function lockPackageName(path: string): string {
  const parts = path.split('/node_modules/');
  const leaf = parts.at(-1) ?? '';
  const segments = leaf.split('/');
  return leaf.startsWith('@') ? segments.slice(0, 2).join('/') : (segments[0] ?? '');
}

describe('native Next hosting-toolchain conversion', () => {
  it('preserves app code and framework versions while removing Sites runtime tooling', async () => {
    const { analysis, candidate, outputRoot } = await convertFixture();
    const packageJson = candidate.packageJson as {
      dependencies: Record<string, string>;
      scripts: Record<string, string>;
    };

    expect(analysis.admissible).toBe(true);
    expect(packageJson.scripts).toMatchObject({
      dev: 'next dev',
      build: 'next build',
      start: 'next start',
    });
    expect(packageJson.dependencies.next).toBe('16.2.6');
    expect(packageJson.dependencies.react).toBe('19.2.3');
    expect(packageJson.dependencies['react-dom']).toBe('19.2.3');
    expect(candidate.outputPaths).not.toContain('.openai/hosting.json');
    expect(candidate.outputPaths).not.toContain('vite.config.ts');
    expect(candidate.outputPaths).not.toContain('wrangler.jsonc');
    expect(candidate.preservedDigests['app/page.tsx']).toBeDefined();
    expect(await lstat(join(outputRoot, 'app/page.tsx'))).toMatchObject({});
  });

  it('keeps application, asset, metadata, config, and unrelated manifest bytes unchanged', async () => {
    const { candidate, outputRoot } = await convertFixture();
    const preservedPaths = [
      'app/about/page.tsx',
      'app/globals.css',
      'app/layout.tsx',
      'app/page.tsx',
      'components/navigation.tsx',
      'fonts/fixture-license.txt',
      'next-env.d.ts',
      'public/fixture-mark.svg',
      'tsconfig.json',
    ];

    for (const path of preservedPaths) {
      const sourceBytes = await readFile(join(fixtureRoot, path));
      expect(await readFile(join(outputRoot, path))).toEqual(sourceBytes);
      expect(candidate.preservedDigests[path]).toBe(sha256(sourceBytes));
    }

    const sourcePackage = JSON.parse(await readFile(join(fixtureRoot, 'package.json'), 'utf8')) as {
      description: string;
      fixtureMetadata: unknown;
    };
    expect(candidate.packageJson).toMatchObject({
      description: sourcePackage.description,
      fixtureMetadata: sourcePackage.fixtureMetadata,
    });
  });

  it('removes hosting dependencies from every section and all direct or chained tool scripts', async () => {
    const { candidate } = await convertFixture();
    const packageJson = candidate.packageJson as Record<string, unknown> & {
      scripts: Record<string, string>;
    };
    const dependencyNames = Object.values(packageSections(packageJson)).flatMap((section) =>
      Object.keys(section as Record<string, string>),
    );

    expect(dependencyNames).not.toEqual(
      expect.arrayContaining([
        '@cloudflare/vite-plugin',
        '@vitejs/plugin-react',
        'vinext',
        'vite',
        'vite-plugin-inspect',
        'wrangler',
      ]),
    );
    expect(packageJson.scripts).toEqual({
      dev: 'next dev',
      build: 'next build',
      start: 'next start',
      lint: 'eslint .',
    });
  });

  it('emits sorted output paths, stable preserved digests, and a content-free ordered receipt', async () => {
    const { analysis, candidate } = await convertFixture();
    const receiptPaths = candidate.mutations.map(({ path }) => path);

    expect(candidate.outputPaths).toEqual(
      [...candidate.outputPaths].sort(compareCodePointStrings),
    );
    expect(Object.keys(candidate.preservedDigests)).toEqual(
      Object.keys(candidate.preservedDigests).sort(compareCodePointStrings),
    );
    expect(receiptPaths).toEqual(receiptPaths.toSorted(compareCodePointStrings));
    expect(candidate.mutations).toHaveLength(analysis.files.length);
    expect(candidate.mutations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: 'app/page.tsx', action: 'copied' }),
        expect.objectContaining({ path: 'package-lock.json', action: 'rewritten' }),
        expect.objectContaining({ path: 'package.json', action: 'rewritten' }),
        expect.objectContaining({ path: 'vite.config.ts', action: 'removed' }),
        expect.objectContaining({ path: 'wrangler.jsonc', action: 'removed' }),
      ]),
    );
    for (const mutation of candidate.mutations) {
      expect(mutation.beforeDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      if (mutation.action === 'removed') expect(mutation.afterDigest).toBeUndefined();
      else expect(mutation.afterDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(mutation).not.toHaveProperty('content');
    }
  });

  it('rejects invalid roots, non-empty outputs, and inadmissible analyses', async () => {
    const analysis = await analyze();
    const outputRoot = await emptyOutputRoot();
    const nestedOutput = join(fixtureRoot, 'nested-output');

    await expect(
      convertToNativeNext({ analysis, sourceRoot: 'relative-source', outputRoot }),
    ).rejects.toThrow('absolute');
    await expect(
      convertToNativeNext({ analysis, sourceRoot: fixtureRoot, outputRoot: 'relative-output' }),
    ).rejects.toThrow('absolute');
    await expect(
      convertToNativeNext({ analysis, sourceRoot: fixtureRoot, outputRoot: fixtureRoot }),
    ).rejects.toThrow('distinct');
    await expect(
      convertToNativeNext({ analysis, sourceRoot: fixtureRoot, outputRoot: nestedOutput }),
    ).rejects.toThrow('nested');

    await writeFile(join(outputRoot, 'sentinel'), 'do not overwrite');
    await expect(
      convertToNativeNext({ analysis, sourceRoot: fixtureRoot, outputRoot }),
    ).rejects.toThrow('empty');
    expect(await readFile(join(outputRoot, 'sentinel'), 'utf8')).toBe('do not overwrite');

    const inadmissible = {
      ...analysis,
      admissible: false,
      blockers: [{ code: 'worker_runtime' as const, path: 'worker/index.ts' }],
    };
    await expect(
      convertToNativeNext({
        analysis: inadmissible,
        sourceRoot: fixtureRoot,
        outputRoot: await emptyOutputRoot(),
      }),
    ).rejects.toThrow('admissible');
  });

  it('treats the analysis as an exact authorization snapshot and fails closed on drift', async () => {
    const sourceRoot = await fixtureCopy();
    const analysis = await analyze(sourceRoot);

    const missingAuthorization = {
      ...analysis,
      files: analysis.files.filter(({ path }) => path !== 'app/page.tsx'),
    };
    await expect(
      convertToNativeNext({
        analysis: missingAuthorization,
        sourceRoot,
        outputRoot: await emptyOutputRoot(),
      }),
    ).rejects.toThrow('authorization');

    await writeFile(join(sourceRoot, 'app/page.tsx'), 'unexpected source mutation');
    await expect(
      convertToNativeNext({ analysis, sourceRoot, outputRoot: await emptyOutputRoot() }),
    ).rejects.toThrow('digest');

    const additionalSource = await fixtureCopy();
    const additionalAnalysis = await analyze(additionalSource);
    await writeFile(join(additionalSource, 'app/unreviewed.tsx'), 'unreviewed source');
    await expect(
      convertToNativeNext({
        analysis: additionalAnalysis,
        sourceRoot: additionalSource,
        outputRoot: await emptyOutputRoot(),
      }),
    ).rejects.toThrow('authorization');
  });

  it('rejects unsafe analysis paths and symlinks without reading Task 1 exclusions', async () => {
    const sourceRoot = await fixtureCopy();
    const analysis = await analyze(sourceRoot);
    const unsafeAnalysis = {
      ...analysis,
      files: [
        ...analysis.files,
        { path: '../output-traversal', bytes: 0, digest: sha256(new Uint8Array()) },
      ],
    };
    await expect(
      convertToNativeNext({
        analysis: unsafeAnalysis,
        sourceRoot,
        outputRoot: await emptyOutputRoot(),
      }),
    ).rejects.toThrow('unsafe');

    await symlink(join(sourceRoot, 'app/page.tsx'), join(sourceRoot, 'linked-page.tsx'));
    await expect(
      convertToNativeNext({ analysis, sourceRoot, outputRoot: await emptyOutputRoot() }),
    ).rejects.toThrow('symlink');

    const excludedSource = await fixtureCopy();
    const excludedAnalysis = await analyze(excludedSource);
    await mkdir(join(excludedSource, 'node_modules/private-package'), { recursive: true });
    await writeFile(join(excludedSource, 'node_modules/private-package/secret.txt'), 'not read');
    const { candidate } = await convertFixture({
      sourceRoot: excludedSource,
      analysis: excludedAnalysis,
    });
    expect(candidate.outputPaths.some((path) => path.startsWith('node_modules/'))).toBe(false);
  });

  it('rewrites an npm v3 lock offline, prunes orphans, and preserves retained resolutions', async () => {
    const sourceLock = JSON.parse(
      await readFile(join(fixtureRoot, 'package-lock.json'), 'utf8'),
    ) as {
      packages: Record<string, Record<string, unknown>>;
    };
    const { candidate, outputRoot } = await convertFixture();
    const outputLockBytes = await readFile(join(outputRoot, 'package-lock.json'));
    const outputLock = JSON.parse(outputLockBytes.toString()) as {
      lockfileVersion: number;
      packages: Record<string, Record<string, unknown>>;
    };

    expect(outputLock.lockfileVersion).toBe(3);
    expect(outputLock.packages['']).toMatchObject(packageSections(candidate.packageJson));
    expect(outputLockBytes.at(-1)).toBe(10);
    for (const [path, entry] of Object.entries(outputLock.packages)) {
      if (path === '') continue;
      expect([
        '@cloudflare/vite-plugin',
        '@vitejs/plugin-react',
        'vinext',
        'vite',
        'vite-plugin-inspect',
        'wrangler',
      ]).not.toContain(lockPackageName(path));
      expect(entry.version).toBe(sourceLock.packages[path]?.version);
      expect(entry.resolved).toBe(sourceLock.packages[path]?.resolved);
      expect(entry.integrity).toBe(sourceLock.packages[path]?.integrity);
      expect(entry.integrity).toMatch(/^sha512-/u);
      expect(entry.resolved).toMatch(/^https:\/\/registry\.npmjs\.org\//u);
    }
    expect(Object.keys(outputLock.packages).length).toBeLessThan(
      Object.keys(sourceLock.packages).length,
    );
  });

  it.each([
    ['absent', async (root: string) => rm(join(root, 'package-lock.json'))],
    [
      'unsupported',
      async (root: string) => {
        const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8')) as {
          lockfileVersion: number;
        };
        lock.lockfileVersion = 2;
        await writeJson(join(root, 'package-lock.json'), lock);
      },
    ],
    [
      'malformed',
      async (root: string) => writeFile(join(root, 'package-lock.json'), '{ malformed'),
    ],
    [
      'non-public',
      async (root: string) => {
        const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8')) as {
          packages: Record<string, Record<string, unknown>>;
        };
        if (lock.packages['node_modules/next']) {
          lock.packages['node_modules/next'].resolved = 'https://packages.example.invalid/next.tgz';
        }
        await writeJson(join(root, 'package-lock.json'), lock);
      },
    ],
    [
      'missing-integrity',
      async (root: string) => {
        const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8')) as {
          packages: Record<string, Record<string, unknown>>;
        };
        if (lock.packages['node_modules/next']) delete lock.packages['node_modules/next'].integrity;
        await writeJson(join(root, 'package-lock.json'), lock);
      },
    ],
  ])('rejects %s lockfiles rather than fabricating reproducibility data', async (_kind, mutate) => {
    const sourceRoot = await fixtureCopy();
    await mutate(sourceRoot);
    const analysis = await analyze(sourceRoot);

    await expect(
      convertToNativeNext({ analysis, sourceRoot, outputRoot: await emptyOutputRoot() }),
    ).rejects.toThrow(/lock|integrity|registry/iu);
  });

  it('produces byte-identical output and receipts for equivalent analysis enumerations', async () => {
    const analysis = await analyze();
    const first = await convertFixture({ analysis });
    const second = await convertFixture({
      analysis: { ...analysis, files: [...analysis.files].reverse() },
    });

    expect(second.candidate).toEqual(first.candidate);
    for (const path of first.candidate.outputPaths) {
      expect(await readFile(join(second.outputRoot, path))).toEqual(
        await readFile(join(first.outputRoot, path)),
      );
    }
  });

  it.runIf(process.env.VEROW_RUN_TRUSTED_FIXTURE_BUILD === '1')(
    'installs the trusted converted fixture without lifecycle scripts and completes next build',
    async () => {
      const { outputRoot } = await convertFixture();
      await execFile('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], {
        cwd: outputRoot,
        maxBuffer: 10 * 1024 * 1024,
      });
      const { stdout, stderr } = await execFile(
        'npm',
        ['run', 'build', '--ignore-scripts'],
        {
          cwd: outputRoot,
          maxBuffer: 10 * 1024 * 1024,
        },
      );
      expect(`${stdout}\n${stderr}`).toContain('Compiled successfully');
    },
    180_000,
  );
});
