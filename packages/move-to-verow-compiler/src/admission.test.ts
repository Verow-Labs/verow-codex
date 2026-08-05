import { readdir, readFile, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { analyzeSitesSource, type WorkspaceReader } from './admission.js';

const fixtureRoot = resolve(import.meta.dirname, '..', 'fixtures');

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

async function analyzeFixture(name: string) {
  return analyzeSitesSource({
    root: resolve(fixtureRoot, name),
    reader: nodeReader,
  });
}

async function blockerCodes(name: string) {
  return (await analyzeFixture(name)).blockers.map(({ code }) => code);
}

describe('Codex Sites admission', () => {
  it('accepts Sites hosting files but rejects Worker bindings and auth', async () => {
    expect((await analyzeFixture('sites-minimal')).admissible).toBe(true);
    expect(await blockerCodes('sites-worker-binding')).toEqual(['d1_binding', 'worker_runtime']);
  });

  it.each(['private-registry', 'git-dependency', 'url-tarball', 'local-link'])(
    'rejects unsupported dependency source %s',
    async (fixture) => {
      expect(await blockerCodes(`sites-unsupported-dependencies/${fixture}`)).toContain(
        'unsupported_dependency_source',
      );
    },
  );

  it('never reads secret files or follows unsafe filesystem entries', async () => {
    const reads: string[] = [];
    const root = '/synthetic/site';
    const reader: WorkspaceReader = {
      async realpath(path) {
        return path;
      },
      async readDirectory(path) {
        if (path === root) {
          return [
            { name: '.dev.vars', kind: 'file' },
            { name: '.dev.vars.preview', kind: 'file' },
            { name: '.env', kind: 'file' },
            { name: '.openai', kind: 'directory' },
            { name: 'app', kind: 'directory' },
            { name: 'escape', kind: 'symlink' },
            { name: 'package.json', kind: 'file' },
          ];
        }
        if (path === `${root}/.openai`) {
          return [{ name: 'hosting.json', kind: 'file' }];
        }
        if (path === `${root}/app`) {
          return [{ name: 'page.tsx', kind: 'file' }];
        }
        return [];
      },
      async readFile(path) {
        reads.push(path);
        if (path.endsWith('hosting.json')) return Buffer.from('{"d1":null,"r2":null}');
        if (path.endsWith('package.json')) return Buffer.from('{"dependencies":{}}');
        if (path.endsWith('page.tsx'))
          return Buffer.from('export default function Page() { return <main>Safe</main>; }');
        throw new Error(`forbidden read: ${path}`);
      },
    };

    const result = await analyzeSitesSource({ root, reader });

    expect(result.blockers).toEqual(
      expect.arrayContaining([
        { code: 'secret_file', path: '.dev.vars' },
        { code: 'secret_file', path: '.dev.vars.preview' },
        { code: 'secret_file', path: '.env' },
        { code: 'unsafe_path', path: 'escape' },
      ]),
    );
    expect(reads).not.toContain(`${root}/.dev.vars`);
    expect(reads).not.toContain(`${root}/.dev.vars.preview`);
    expect(reads).not.toContain(`${root}/.env`);
    expect(reads).not.toContain(`${root}/escape`);
  });

  it.each([
    ['SSH Git', 'git@github.com:org/repository.git'],
    ['scp Git', 'developer@example.invalid:org/repository.git'],
    ['Git hosting shorthand', 'github:org/repository'],
    ['GitHub shorthand', 'org/repository'],
    ['URL tarball', 'https://example.invalid/repository.tgz'],
    ['Git URL', 'git+ssh://git@example.invalid/repository.git'],
    ['relative local path', '../repository'],
    ['absolute local tarball', '/tmp/repository.tgz'],
    ['bare local tarball', 'repository.tgz'],
    ['file protocol', 'file:../repository'],
    ['workspace protocol', 'workspace:*'],
    ['link protocol', 'link:../repository'],
    ['protocol variant', 'ftp://example.invalid/repository.tgz'],
  ])('rejects %s dependency sources in nested package manifests', async (_label, source) => {
    const root = '/synthetic/site';
    const files = new Map([
      [`${root}/.openai/hosting.json`, '{"d1":null,"r2":null}'],
      [`${root}/app/page.tsx`, 'export default function Page() { return <main>Safe</main>; }'],
      [`${root}/package.json`, '{"dependencies":{"react":"19.2.0"}}'],
      [
        `${root}/packages/nested/package.json`,
        JSON.stringify({ dependencies: { dependency: source } }),
      ],
    ]);
    const reader = readerForFiles(files);

    const result = await analyzeSitesSource({ root, reader });

    expect(result.blockers).toContainEqual({
      code: 'unsupported_dependency_source',
      path: 'packages/nested/package.json',
    });
  });

  it('accepts public-registry semver, tag, and alias dependency forms', async () => {
    const root = '/synthetic/site';
    const files = new Map([
      [`${root}/.openai/hosting.json`, '{"d1":null,"r2":null}'],
      [`${root}/app/page.tsx`, 'export default function Page() { return <main>Safe</main>; }'],
      [
        `${root}/package.json`,
        JSON.stringify({
          dependencies: {
            exact: '1.2.3',
            range: '^1.2.3',
            tilde: '~1.2.3',
            comparator: '>=1 <2',
            wildcard: '*',
            tag: 'latest',
            'hyphenated-tag': 'next-1',
            alias: 'npm:public-package@^1.2.3',
            'scoped-alias': 'npm:@public-scope/package@latest',
          },
        }),
      ],
    ]);

    const result = await analyzeSitesSource({
      root,
      reader: readerForFiles(files),
    });

    expect(result.blockers.map(({ code }) => code)).not.toContain('unsupported_dependency_source');
  });

  it('rejects a non-absolute workspace root before asking the reader for data', async () => {
    let touched = false;
    const reader: WorkspaceReader = {
      async realpath(path) {
        touched = true;
        return path;
      },
      async readDirectory() {
        touched = true;
        return [];
      },
      async readFile() {
        touched = true;
        return new Uint8Array();
      },
    };

    await expect(analyzeSitesSource({ root: 'relative/site', reader })).rejects.toThrow('absolute');
    expect(touched).toBe(false);
  });
});

function readerForFiles(files: ReadonlyMap<string, string>): WorkspaceReader {
  return {
    async realpath(path) {
      return path;
    },
    async readDirectory(directory) {
      const entries = new Map<string, 'file' | 'directory'>();
      for (const path of files.keys()) {
        if (!path.startsWith(`${directory}/`)) continue;
        const remainder = path.slice(directory.length + 1);
        const [name, ...rest] = remainder.split('/');
        if (name) entries.set(name, rest.length === 0 ? 'file' : 'directory');
      }
      return [...entries].map(([name, kind]) => ({ name, kind }));
    },
    async readFile(path) {
      const value = files.get(path);
      if (value === undefined) throw new Error(`unexpected read: ${path}`);
      return Buffer.from(value);
    },
  };
}
