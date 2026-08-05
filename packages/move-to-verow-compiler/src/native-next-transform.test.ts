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
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';

import {
  analyzeSitesSource,
  type SitesSourceAnalysis,
  type WorkspaceReader,
} from './admission.js';
import { classifySitesHostingShim } from './hosting-shims.js';
import { compareCodePointStrings } from './inventory.js';
import { convertToNativeNext, writeOutputFiles } from './native-next-transform.js';

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

async function mutateJsonFile(
  path: string,
  mutate: (value: Record<string, unknown>) => void,
): Promise<void> {
  const value = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>;
  mutate(value);
  await writeJson(path, value);
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
    expect(candidate.outputPaths).not.toContain('worker/index.ts');
    expect(candidate.outputPaths).not.toContain('build/sites-vite-plugin.ts');
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

  it.each([
    ['Vinext', 'sh -c "vinext build"'],
    ['Vite', 'sh -c "vite build"'],
    ['Wrangler', "bash -lc 'wrangler deploy'"],
    ['OpenNext Cloudflare binary', 'opennextjs-cloudflare build'],
    ['next-on-pages binary', 'next-on-pages'],
    ['quoted OpenNext .bin path', 'sh -c "./node_modules/.bin/opennextjs-cloudflare build"'],
    ['quoted next-on-pages .bin path', 'sh -c "./node_modules/.bin/next-on-pages"'],
    ['Cloudflare Vinext package', 'sh -c "npm exec @cloudflare/vinext"'],
    ['Cloudflare Vite plugin package', 'sh -c "npm exec @cloudflare/vite-plugin"'],
    ['Cloudflare Worker types package', 'sh -c "npm exec @cloudflare/workers-types"'],
    ['OpenNext Cloudflare package', 'sh -c "npm exec @opennextjs/cloudflare"'],
    ['next-on-pages package', 'sh -c "npm exec @cloudflare/next-on-pages"'],
    ['Vite plugin package', 'sh -c "npm exec @vitejs/plugin-react"'],
    ['Vite tsconfig paths package', 'sh -c "npm exec vite-tsconfig-paths"'],
  ])('removes a script with a quoted or real %s invocation', async (_kind, command) => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package.json'), (packageJson) => {
      const scripts = packageJson.scripts as Record<string, string>;
      scripts['quoted-tool'] = command;
    });
    const analysis = await analyze(sourceRoot);
    const { candidate } = await convertFixture({ sourceRoot, analysis });

    expect((candidate.packageJson.scripts as Record<string, string>)['quoted-tool']).toBeUndefined();
    expect((candidate.packageJson.scripts as Record<string, string>).lint).toBe('eslint .');
  });

  it.each([
    ['npx unscoped range', 'npx vite@7.3.1 build'],
    ['quoted npx scoped tag', 'sh -c "npx @opennextjs/cloudflare@latest build"'],
    ['npm exec unscoped tag', 'npm exec vite@latest -- build'],
    ['npm exec scoped range', 'npm exec -- @cloudflare/next-on-pages@1.13.16'],
    ['pnpm dlx unscoped range', 'pnpm dlx vinext@0.0.11 build'],
    ['pnpm dlx scoped tag', 'pnpm dlx @opennextjs/cloudflare@latest build'],
    ['pnpm exec unscoped range', 'pnpm exec wrangler@4.61.1 deploy'],
    ['pnpm exec scoped range', 'pnpm exec @cloudflare/next-on-pages@1.13.16'],
    ['yarn dlx unscoped range', 'yarn dlx vite@7.3.1 build'],
    ['yarn dlx scoped tag', 'yarn dlx @cloudflare/vite-plugin@latest'],
    ['bunx unscoped range', 'bunx vite-tsconfig-paths@5.1.4'],
    ['bunx scoped tag', 'bunx @opennextjs/cloudflare@latest build'],
    ['quoted Vite plugin tag', 'sh -c "npx @vitejs/plugin-react@latest"'],
  ])('removes a hosting script selected through %s', async (_kind, command) => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package.json'), (packageJson) => {
      const scripts = packageJson.scripts as Record<string, string>;
      scripts['versioned-tool'] = command;
      scripts['safe-versioned-tool'] = 'npx eslint@9.0.0 .';
    });
    const analysis = await analyze(sourceRoot);
    const { candidate } = await convertFixture({ sourceRoot, analysis });
    const scripts = candidate.packageJson.scripts as Record<string, string>;

    expect(scripts['versioned-tool']).toBeUndefined();
    expect(scripts['safe-versioned-tool']).toBe('npx eslint@9.0.0 .');
  });

  it('removes script chains that terminate in a version-qualified hosting selector', async () => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package.json'), (packageJson) => {
      const scripts = packageJson.scripts as Record<string, string>;
      scripts['versioned-tool'] = 'sh -c "npx vite@7.3.1 build"';
      scripts['versioned-chain'] = 'pnpm run versioned-tool';
      scripts['versioned-chain-outer'] = 'bun run versioned-chain';
    });
    const analysis = await analyze(sourceRoot);
    const { candidate } = await convertFixture({ sourceRoot, analysis });
    const scripts = candidate.packageJson.scripts as Record<string, string>;

    expect(scripts['versioned-tool']).toBeUndefined();
    expect(scripts['versioned-chain']).toBeUndefined();
    expect(scripts['versioned-chain-outer']).toBeUndefined();
    expect(scripts.lint).toBe('eslint .');
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
        expect.objectContaining({ path: 'build/sites-vite-plugin.ts', action: 'removed' }),
        expect.objectContaining({ path: 'vite.config.ts', action: 'removed' }),
        expect.objectContaining({ path: 'worker/index.ts', action: 'removed' }),
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

  it('compares canonical roots before accepting a symlink-ancestor output path', async () => {
    const sourceRoot = await fixtureCopy();
    const physicalOutput = join(sourceRoot, 'compiler-output');
    await mkdir(physicalOutput);
    const sourceAlias = join(dirname(sourceRoot), 'source-alias');
    await symlink(sourceRoot, sourceAlias, 'dir');
    const analysis = await analyze(sourceRoot);

    await expect(
      convertToNativeNext({
        analysis,
        sourceRoot,
        outputRoot: join(sourceAlias, 'compiler-output'),
      }),
    ).rejects.toThrow(/canonical|nested|distinct/iu);
    expect(await readdir(physicalOutput)).toEqual([]);
  });

  it('refuses an output parent replaced by a symlink instead of writing through it', async () => {
    const outputRoot = await emptyOutputRoot();
    const escapeRoot = await mkdtemp(join(tmpdir(), 'verow-native-escape-'));
    temporaryRoots.add(escapeRoot);
    await symlink(escapeRoot, join(outputRoot, 'public'), 'dir');

    await expect(
      writeOutputFiles(
        outputRoot,
        new Map([['public/fixture-mark.svg', new TextEncoder().encode('blocked')]]),
      ),
    ).rejects.toThrow(/output|symlink|canonical/iu);
    await expect(lstat(join(escapeRoot, 'fixture-mark.svg'))).rejects.toThrow();
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
    ['wrong direct version', 'node_modules/next', '0.0.1'],
    ['wrong transitive prerelease', 'node_modules/styled-jsx', '5.1.6-beta.1'],
  ])('rejects a %s that does not satisfy its frozen declaring range', async (_kind, path, version) => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      if (packages[path]) packages[path].version = version;
    });
    const analysis = await analyze(sourceRoot);

    await expect(
      convertToNativeNext({ analysis, sourceRoot, outputRoot: await emptyOutputRoot() }),
    ).rejects.toThrow(/satisf|version|range/iu);
  });

  it('rejects a missing required peer but permits only explicitly optional absent peers', async () => {
    const requiredRoot = await fixtureCopy();
    await mutateJsonFile(join(requiredRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      const next = packages['node_modules/next'];
      if (next) {
        next.peerDependencies = {
          ...(next.peerDependencies as Record<string, string>),
          'missing-required-peer': '^1.0.0',
        };
      }
    });
    const requiredAnalysis = await analyze(requiredRoot);
    await expect(
      convertToNativeNext({
        analysis: requiredAnalysis,
        sourceRoot: requiredRoot,
        outputRoot: await emptyOutputRoot(),
      }),
    ).rejects.toThrow(/required peer/iu);

    const optionalRoot = await fixtureCopy();
    await mutateJsonFile(join(optionalRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      const next = packages['node_modules/next'];
      if (next) {
        next.peerDependencies = {
          ...(next.peerDependencies as Record<string, string>),
          'missing-optional-peer': '^1.0.0',
        };
        next.peerDependenciesMeta = {
          ...(next.peerDependenciesMeta as Record<string, unknown>),
          'missing-optional-peer': { optional: true },
        };
      }
    });
    const optionalAnalysis = await analyze(optionalRoot);
    await expect(
      convertToNativeNext({
        analysis: optionalAnalysis,
        sourceRoot: optionalRoot,
        outputRoot: await emptyOutputRoot(),
      }),
    ).resolves.toBeDefined();
  });

  it('removes a direct npm alias whose target is a hosting tool', async () => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package.json'), (packageJson) => {
      const dependencies = packageJson.dependencies as Record<string, string>;
      dependencies['hidden-vite'] = 'npm:vite@7.3.1';
    });
    await mutateJsonFile(join(sourceRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      const root = packages[''];
      const dependencies = root?.dependencies as Record<string, string>;
      dependencies['hidden-vite'] = 'npm:vite@7.3.1';
      packages['node_modules/hidden-vite'] = {
        ...packages['node_modules/vite'],
        name: 'vite',
      };
    });
    const analysis = await analyze(sourceRoot);
    const { candidate } = await convertFixture({ sourceRoot, analysis });

    expect(
      (candidate.packageJson.dependencies as Record<string, string>)['hidden-vite'],
    ).toBeUndefined();
  });

  it.each([
    ['alias specifier', 'npm:vite@7.3.1'],
    ['registry identity', '7.3.1'],
  ])('rejects a transitive hosting tool hidden by %s', async (_kind, specifier) => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      const next = packages['node_modules/next'];
      if (next) {
        next.dependencies = {
          ...(next.dependencies as Record<string, string>),
          'hidden-hosting-tool': specifier,
        };
      }
      packages['node_modules/hidden-hosting-tool'] = {
        ...packages['node_modules/vite'],
        name: 'vite',
      };
    });
    const analysis = await analyze(sourceRoot);

    await expect(
      convertToNativeNext({ analysis, sourceRoot, outputRoot: await emptyOutputRoot() }),
    ).rejects.toThrow(/hosting|vite|removed/iu);
  });

  it('derives package identity from the registry URL instead of a spoofable lock name', async () => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      const next = packages['node_modules/next'];
      const vite = packages['node_modules/vite'];
      if (next && vite) {
        next.name = 'safe-package';
        next.resolved = vite.resolved;
      }
    });
    const analysis = await analyze(sourceRoot);

    await expect(
      convertToNativeNext({ analysis, sourceRoot, outputRoot: await emptyOutputRoot() }),
    ).rejects.toThrow(/hosting|identity|registry|vite|name/iu);
  });

  it.each([
    ['latest', 'next', 'latest'],
    ['named tag', 'react', 'next-1'],
  ])('accepts a frozen direct dependency selected by %s', async (_kind, name, tag) => {
    const sourceRoot = await fixtureCopy();
    for (const file of ['package.json', 'package-lock.json']) {
      await mutateJsonFile(join(sourceRoot, file), (value) => {
        const dependencies = (file === 'package.json'
          ? value.dependencies
          : (value.packages as Record<string, Record<string, unknown>>)['']?.dependencies) as Record<
          string,
          string
        >;
        dependencies[name] = tag;
      });
    }
    const analysis = await analyze(sourceRoot);
    const { candidate } = await convertFixture({ sourceRoot, analysis });

    expect((candidate.packageJson.dependencies as Record<string, string>)[name]).toBe(tag);
  });

  it('accepts a frozen npm alias selected by a named dist-tag when all identities agree', async () => {
    const sourceRoot = await fixtureCopy();
    const specifier = 'npm:react@next-1';
    await mutateJsonFile(join(sourceRoot, 'package.json'), (packageJson) => {
      const dependencies = packageJson.dependencies as Record<string, string>;
      dependencies['react-alias'] = specifier;
    });
    await mutateJsonFile(join(sourceRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      const dependencies = packages['']?.dependencies as Record<string, string>;
      dependencies['react-alias'] = specifier;
      packages['node_modules/react-alias'] = {
        ...packages['node_modules/react'],
        name: 'react',
      };
    });
    const analysis = await analyze(sourceRoot);
    const { candidate } = await convertFixture({ sourceRoot, analysis });

    expect(
      (candidate.packageJson.dependencies as Record<string, string>)['react-alias'],
    ).toBe(specifier);
    expect(candidate.outputPaths).toContain('package-lock.json');
  });

  it('requires a concrete semantic version for a frozen dist-tag entry', async () => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package.json'), (packageJson) => {
      const dependencies = packageJson.dependencies as Record<string, string>;
      dependencies.next = 'latest';
    });
    await mutateJsonFile(join(sourceRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      const dependencies = packages['']?.dependencies as Record<string, string>;
      dependencies.next = 'latest';
      if (packages['node_modules/next']) packages['node_modules/next'].version = 'not-a-version';
    });
    const analysis = await analyze(sourceRoot);

    await expect(
      convertToNativeNext({ analysis, sourceRoot, outputRoot: await emptyOutputRoot() }),
    ).rejects.toThrow(/concrete|semantic|version/iu);
  });

  it.each([
    ['empty selector', ''],
    ['space-containing tag', 'not a tag'],
    ['path-like tag', 'tag/name'],
    ['encoded tag', 'tag%2fname'],
    ['malformed alias tag', 'npm:react@tag+name'],
  ])('rejects a malformed frozen registry selector: %s', async (_kind, specifier) => {
    const sourceRoot = await fixtureCopy();
    await mutateJsonFile(join(sourceRoot, 'package-lock.json'), (lock) => {
      const packages = lock.packages as Record<string, Record<string, unknown>>;
      const next = packages['node_modules/next'];
      if (next) {
        next.dependencies = {
          ...(next.dependencies as Record<string, string>),
          react: specifier,
        };
      }
    });
    const analysis = await analyze(sourceRoot);

    await expect(
      convertToNativeNext({ analysis, sourceRoot, outputRoot: await emptyOutputRoot() }),
    ).rejects.toThrow(/specifier|selector|satisf|version|range/iu);
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

  it('admits only the exact known Sites hosting shims and blocks semantic mutations', async () => {
    expect((await analyze()).admissible).toBe(true);
    for (const path of ['worker/index.ts', 'build/sites-vite-plugin.ts']) {
      const source = await readFile(join(fixtureRoot, path));
      expect(classifySitesHostingShim(path, source)).toBe('known_shim');
      expect(
        classifySitesHostingShim(
          path,
          new TextEncoder().encode(`// equivalent trivia\n${new TextDecoder().decode(source).replaceAll('"', "'")}`),
        ),
      ).toBe('known_shim');
    }
    const mutations: readonly [string, string, (source: string) => string][] = [
      ['custom route', 'worker/index.ts', (source) => `${source}\nexport const route = '/custom';\n`],
      [
        'global network call',
        'worker/index.ts',
        (source) => `${source}\nvoid fetch('https://example.invalid');\n`,
      ],
      [
        'non-Vinext import',
        'worker/index.ts',
        (source) => `import 'customer-worker';\n${source}`,
      ],
      ['arbitrary side effect', 'worker/index.ts', (source) => `${source}\nconsole.log('side effect');\n`],
      [
        'unsupported binding',
        'worker/index.ts',
        (source) => `${source}\nexport const queueBinding = 'MY_QUEUE';\n`,
      ],
      [
        'changed packaging behavior',
        'build/sites-vite-plugin.ts',
        (source) => source.replace('"hosting.json"', '".env"'),
      ],
      [
        'changed image fetch behavior',
        'worker/index.ts',
        (source) => source.replace('fetchAsset', 'fetchImage'),
      ],
      [
        'changed image response behavior',
        'worker/index.ts',
        (source) => source.replace('result.response()', 'result'),
      ],
      [
        'removed resolved root behavior',
        'build/sites-vite-plugin.ts',
        (source) => source.replace('root = config.root;', ''),
      ],
    ];

    for (const [, path, mutate] of mutations) {
      const sourceRoot = await fixtureCopy();
      const absolutePath = join(sourceRoot, path);
      await writeFile(absolutePath, mutate(await readFile(absolutePath, 'utf8')));
      const result = await analyze(sourceRoot);
      expect(result.blockers).toContainEqual({ code: 'worker_runtime', path });
    }

    const alternateRoot = await fixtureCopy();
    await writeFile(join(alternateRoot, 'worker/alternate.ts'), 'export default {};\n');
    expect((await analyze(alternateRoot)).blockers).toContainEqual({
      code: 'worker_runtime',
      path: 'worker/alternate.ts',
    });
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
