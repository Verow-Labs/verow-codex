import { readdir, readFile, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  analyzeSitesSource,
  type WorkspaceReader,
} from './admission.js';

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
  return analyzeSitesSource({ root: resolve(fixtureRoot, name), reader: nodeReader });
}

async function blockerCodes(name: string) {
  return (await analyzeFixture(name)).blockers.map(({ code }) => code);
}

describe('Codex Sites admission', () => {
  it('accepts Sites hosting files but rejects Worker bindings and auth', async () => {
    expect((await analyzeFixture('sites-minimal')).admissible).toBe(true);
    expect(await blockerCodes('sites-worker-binding')).toEqual([
      'd1_binding',
      'worker_runtime',
    ]);
  });

  it.each(['private-registry', 'git-dependency', 'url-tarball', 'local-link'])(
    'rejects unsupported dependency source %s',
    async (fixture) => {
      expect(
        await blockerCodes(`sites-unsupported-dependencies/${fixture}`),
      ).toContain('unsupported_dependency_source');
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
        if (path.endsWith('page.tsx')) return Buffer.from('export default function Page() { return <main>Safe</main>; }');
        throw new Error(`forbidden read: ${path}`);
      },
    };

    const result = await analyzeSitesSource({ root, reader });

    expect(result.blockers).toEqual(
      expect.arrayContaining([
        { code: 'secret_file', path: '.env' },
        { code: 'unsafe_path', path: 'escape' },
      ]),
    );
    expect(reads).not.toContain(`${root}/.env`);
    expect(reads).not.toContain(`${root}/escape`);
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

    await expect(analyzeSitesSource({ root: 'relative/site', reader })).rejects.toThrow(
      'absolute',
    );
    expect(touched).toBe(false);
  });
});
