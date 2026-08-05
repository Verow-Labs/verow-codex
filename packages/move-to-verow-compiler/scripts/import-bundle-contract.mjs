import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const generatedFiles = [
  'migration-bundle.schema.json',
  'migration-bundle.schema.sha256',
  'canonical-digest-vectors.json',
];

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function git(sourceRoot, args) {
  return (await exec('git', ['-C', sourceRoot, ...args], { encoding: 'utf8' })).stdout.trim();
}

export async function importBundleContract({ sourceRoot, destinationRoot }) {
  if (!isAbsolute(sourceRoot)) throw new TypeError('contract source worktree must be absolute');
  if (!isAbsolute(destinationRoot)) throw new TypeError('contract destination must be absolute');
  const source = await realpath(sourceRoot);
  const topLevel = await git(source, ['rev-parse', '--show-toplevel']);
  if (await realpath(topLevel) !== source) {
    throw new Error('contract source must be the worktree root');
  }
  const sourceCommit = await git(source, ['rev-parse', 'HEAD']);
  if (!/^[0-9a-f]{40}$/u.test(sourceCommit)) throw new Error('contract source HEAD is invalid');
  const status = await git(source, ['status', '--porcelain=v1', '--untracked-files=all']);
  if (status !== '') throw new Error('contract source worktree must be clean');

  const generatedRoot = join(
    source,
    'packages',
    'move-to-verow-contracts',
    'generated',
  );
  const contents = new Map();
  for (const file of generatedFiles) contents.set(file, await readFile(join(generatedRoot, file)));
  const schemaBytes = contents.get('migration-bundle.schema.json');
  const declaredSchemaDigest = contents
    .get('migration-bundle.schema.sha256')
    .toString('utf8')
    .trim();
  const schemaDigest = sha256(schemaBytes);
  if (declaredSchemaDigest !== schemaDigest) {
    throw new Error('generated schema digest does not match schema bytes');
  }
  JSON.parse(contents.get('migration-bundle.schema.json').toString('utf8'));
  JSON.parse(contents.get('canonical-digest-vectors.json').toString('utf8'));

  const provenance = {
    sourceCommit,
    sha256: schemaDigest,
    canonicalVectorsSha256: sha256(contents.get('canonical-digest-vectors.json')),
    files: Object.fromEntries(
      generatedFiles.map((file) => [file, sha256(contents.get(file))]),
    ),
  };
  await mkdir(destinationRoot, { recursive: true });
  for (const file of generatedFiles) await writeFile(join(destinationRoot, file), contents.get(file));
  await writeFile(join(destinationRoot, 'provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
  return provenance;
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  if (process.argv.length !== 3) {
    throw new Error('usage: node import-bundle-contract.mjs <absolute-verow-webapp-worktree>');
  }
  const destinationRoot = fileURLToPath(new URL('../contracts/', import.meta.url));
  await importBundleContract({ sourceRoot: process.argv[2], destinationRoot });
}
