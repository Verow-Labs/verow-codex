import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';

import { importBundleContract } from './import-bundle-contract.mjs';

const exec = promisify(execFile);
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

async function syntheticSource() {
  const root = await mkdtemp(join(tmpdir(), 'verow-contract-source-'));
  const generated = join(root, 'packages', 'move-to-verow-contracts', 'generated');
  await mkdir(generated, { recursive: true });
  const schema = Buffer.from('{"type":"object"}\n');
  const digest = createHash('sha256').update(schema).digest('hex');
  await writeFile(join(generated, 'migration-bundle.schema.json'), schema);
  await writeFile(join(generated, 'migration-bundle.schema.sha256'), `sha256:${digest}\n`);
  await writeFile(join(generated, 'canonical-digest-vectors.json'), '[]\n');
  await writeFile(join(generated, 'must-not-copy.txt'), 'forbidden');
  await exec('git', ['init', '--quiet'], { cwd: root });
  await exec('git', ['config', 'user.email', 'test@example.invalid'], {
    cwd: root,
  });
  await exec('git', ['config', 'user.name', 'Contract Test'], { cwd: root });
  await exec('git', ['add', '.'], { cwd: root });
  await exec('git', ['commit', '--quiet', '-m', 'fixture'], { cwd: root });
  return { root, generated };
}

test('imports only exact generated contract artifacts and records clean HEAD', async () => {
  const source = await syntheticSource();
  const destination = await mkdtemp(join(tmpdir(), 'verow-contract-destination-'));
  const expectedCommit = (
    await exec('git', ['rev-parse', 'HEAD'], { cwd: source.root })
  ).stdout.trim();

  const provenance = await importBundleContract({
    sourceRoot: source.root,
    destinationRoot: destination,
  });

  assert.equal(provenance.sourceCommit, expectedCommit);
  assert.match(provenance.sha256, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual((await readdir(destination)).sort(), [
    'canonical-digest-vectors.json',
    'migration-bundle.schema.json',
    'migration-bundle.schema.sha256',
    'provenance.json',
  ]);
});

test('rejects a dirty or relative source worktree', async () => {
  const source = await syntheticSource();
  const destination = await mkdtemp(join(tmpdir(), 'verow-contract-destination-'));

  await assert.rejects(
    importBundleContract({
      sourceRoot: 'relative/source',
      destinationRoot: destination,
    }),
    /absolute/u,
  );
  await writeFile(join(source.generated, 'migration-bundle.schema.json'), '{"dirty":true}\n');
  await assert.rejects(
    importBundleContract({
      sourceRoot: source.root,
      destinationRoot: destination,
    }),
    /clean/u,
  );
  await assert.rejects(readFile(join(destination, 'migration-bundle.schema.json')));
});

test('freezes an exact registry and integrity runtime closure for publication', async () => {
  const packageJson = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
  const shrinkwrap = JSON.parse(await readFile(join(packageRoot, 'npm-shrinkwrap.json'), 'utf8'));

  assert.equal(shrinkwrap.lockfileVersion, 3);
  assert.equal(shrinkwrap.name, packageJson.name);
  assert.equal(shrinkwrap.version, packageJson.version);
  assert.equal(shrinkwrap.packages[''].name, packageJson.name);
  assert.equal(shrinkwrap.packages[''].version, packageJson.version);
  assert.deepEqual(shrinkwrap.packages[''].dependencies, packageJson.dependencies);
  for (const [name, version] of Object.entries(packageJson.dependencies)) {
    assert.match(version, /^\d+\.\d+\.\d+$/u, `${name} must use an exact version`);
  }
  const reachable = reachableRuntimePackages(shrinkwrap.packages);
  assert.deepEqual(
    [...reachable].sort(),
    Object.keys(shrinkwrap.packages).sort(),
    'shrinkwrap must contain exactly the reachable runtime closure',
  );
  for (const path of reachable) {
    if (path === '') continue;
    const entry = shrinkwrap.packages[path];
    assert.match(
      entry.resolved,
      /^https:\/\/registry\.npmjs\.org\//u,
      `${path} must resolve from the public npm registry`,
    );
    assert.match(entry.integrity, /^sha512-/u, `${path} must pin integrity`);
  }
});

test('includes npm-shrinkwrap.json in the actual package contents', async () => {
  const { stdout } = await exec('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: packageRoot,
    maxBuffer: 10 * 1024 * 1024,
  });
  const [packed] = JSON.parse(stdout);

  assert.ok(
    packed.files.some(({ path }) => path === 'npm-shrinkwrap.json'),
    'packed package must include npm-shrinkwrap.json',
  );
});

function reachableRuntimePackages(packages) {
  const reachable = new Set();
  const pending = [''];
  while (pending.length > 0) {
    const path = pending.pop();
    if (path === undefined || reachable.has(path)) continue;
    const entry = packages[path];
    assert.ok(entry, `missing shrinkwrap entry ${path || '<root>'}`);
    reachable.add(path);
    for (const [name] of Object.entries({
      ...entry.dependencies,
      ...entry.optionalDependencies,
    })) {
      const resolved = resolveLockedDependency(packages, path, name);
      assert.ok(resolved, `${path || '<root>'} dependency ${name} must be frozen`);
      pending.push(resolved);
    }
    for (const name of Object.keys(entry.peerDependencies ?? {})) {
      const resolved = resolveLockedDependency(packages, path, name);
      if (resolved) pending.push(resolved);
    }
  }
  return reachable;
}

function resolveLockedDependency(packages, parentPath, name) {
  let base = parentPath;
  while (true) {
    const candidate = base ? `${base}/node_modules/${name}` : `node_modules/${name}`;
    if (packages[candidate]) return candidate;
    if (!base) return null;
    const nestedMarker = base.lastIndexOf('/node_modules/');
    base = nestedMarker === -1 ? '' : base.slice(0, nestedMarker);
  }
}
