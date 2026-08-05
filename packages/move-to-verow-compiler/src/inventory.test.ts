import { readdir, readFile, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { analyzeSitesSource, type WorkspaceReader } from './admission.js';

const root = resolve(import.meta.dirname, '..', 'fixtures', 'sites-minimal');

const reader: WorkspaceReader = {
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

describe('source inventory', () => {
  it('inventories hidden and alternate human-facing values', async () => {
    const result = await analyzeSitesSource({ root, reader });

    expect(result.contentCandidates.map((item) => item.sourceKind)).toEqual(
      expect.arrayContaining(['jsx', 'json', 'css_content', 'aria']),
    );
    expect(result.routes).toEqual(['/', '/about']);
  });

  it('produces stable sorted file and source digests', async () => {
    const first = await analyzeSitesSource({ root, reader });
    const reverseReader: WorkspaceReader = {
      ...reader,
      async readDirectory(path) {
        return [...(await reader.readDirectory(path))].reverse();
      },
    };
    const second = await analyzeSitesSource({ root, reader: reverseReader });

    expect(first.sourceDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(second.sourceDigest).toBe(first.sourceDigest);
    expect(first.files.map(({ path }) => path)).toEqual(
      [...first.files.map(({ path }) => path)].sort(),
    );
    expect(first.files.every(({ digest }) => /^sha256:[0-9a-f]{64}$/u.test(digest))).toBe(
      true,
    );
  });
});
