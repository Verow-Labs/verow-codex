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

test('rejects a lock entry version that does not satisfy its declaring specifier', async () => {
  const shrinkwrap = JSON.parse(await readFile(join(packageRoot, 'npm-shrinkwrap.json'), 'utf8'));
  shrinkwrap.packages['node_modules/ajv'].version = '0.0.1';

  assert.throws(
    () => reachableRuntimePackages(shrinkwrap.packages),
    /ajv.*0\.0\.1.*8\.20\.0/u,
  );
});

test('rejects an unresolved required peer while allowing optional peers to be absent', async () => {
  const shrinkwrap = JSON.parse(await readFile(join(packageRoot, 'npm-shrinkwrap.json'), 'utf8'));
  delete shrinkwrap.packages['node_modules/playwright-core'];

  assert.throws(
    () => reachableRuntimePackages(shrinkwrap.packages),
    /@axe-core\/playwright.*playwright-core.*required peer/u,
  );

  shrinkwrap.packages['node_modules/@axe-core/playwright'].peerDependenciesMeta = {
    'playwright-core': { optional: true },
  };
  assert.doesNotThrow(() => reachableRuntimePackages(shrinkwrap.packages));
});

test('rejects a reachable prerelease that only satisfies ordinary b4a ranges numerically', async () => {
  const shrinkwrap = JSON.parse(await readFile(join(packageRoot, 'npm-shrinkwrap.json'), 'utf8'));
  shrinkwrap.packages['node_modules/b4a'].version = '1.9.0-beta';

  assert.throws(
    () => reachableRuntimePackages(shrinkwrap.packages),
    /b4a.*1\.9\.0-beta.*\^1\.(?:8\.1|6\.4)/u,
  );
});

test('accepts prereleases when the active comparator set names the same release tuple', () => {
  for (const [version, specifier] of [
    ['1.9.0-beta.2', '^1.9.0-beta.1'],
    ['1.9.0', '^1.9.0-beta.1'],
    ['1.9.0-beta.2', '~1.9.0-beta.1'],
    ['1.9.0-beta.2', '>=1.9.0-beta.1'],
    ['1.9.0-beta.2', '1.9.0-beta.2'],
    ['2.0.0-beta.2', '^1.0.0 || >=2.0.0-beta.1'],
  ]) {
    assert.equal(satisfiesSpecifier(version, specifier), true, `${version} must satisfy ${specifier}`);
  }
});

test('excludes prereleases from comparator sets without the same prerelease tuple', () => {
  for (const [version, specifier] of [
    ['1.9.0-beta', '^1.8.1'],
    ['1.8.2-beta', '~1.8.1'],
    ['1.9.0-beta', '>=1.8.1'],
    ['1.9.0-beta', '*'],
    ['1.10.0-beta', '^1.9.0-beta.1'],
    ['1.9.0-beta', '^1.8.1 || >=1.8.0'],
  ]) {
    assert.equal(
      satisfiesSpecifier(version, specifier),
      false,
      `${version} must not satisfy ${specifier}`,
    );
  }
});

function reachableRuntimePackages(packages) {
  const reachable = new Set();
  const pending = [''];
  while (pending.length > 0) {
    const path = pending.pop();
    if (path === undefined || reachable.has(path)) continue;
    const entry = packages[path];
    assert.ok(entry, `missing shrinkwrap entry ${path || '<root>'}`);
    assert.ok(
      parseConcreteVersion(entry.version),
      `${path || '<root>'} must have a concrete semantic version`,
    );
    reachable.add(path);
    for (const [name, specifier] of Object.entries({
      ...entry.dependencies,
      ...entry.optionalDependencies,
    })) {
      const resolved = resolveLockedDependency(packages, path, name);
      assert.ok(resolved, `${path || '<root>'} dependency ${name} must be frozen`);
      assertLockedVersion(packages[resolved], specifier, resolved);
      pending.push(resolved);
    }
    for (const [name, specifier] of Object.entries(entry.peerDependencies ?? {})) {
      const resolved = resolveLockedDependency(packages, path, name);
      const optional = entry.peerDependenciesMeta?.[name]?.optional === true;
      if (!resolved) {
        assert.ok(optional, `${path || '<root>'} ${name} required peer must be frozen`);
        continue;
      }
      assertLockedVersion(packages[resolved], specifier, resolved);
      pending.push(resolved);
    }
  }
  return reachable;
}

function assertLockedVersion(entry, specifier, path) {
  assert.ok(entry, `missing shrinkwrap entry ${path}`);
  assert.ok(
    satisfiesSpecifier(entry.version, specifier),
    `${path} ${entry.version} does not satisfy ${specifier}`,
  );
}

function satisfiesSpecifier(version, specifier) {
  const concrete = parseConcreteVersion(version);
  if (!concrete || typeof specifier !== 'string') return false;
  const alternatives = specifier.split('||').map((value) => value.trim());
  return alternatives.some((range) => {
    if (!comparatorSetAllowsPrerelease(concrete, range)) return false;
    if (range === '*') return true;
    if (range.startsWith('^')) return satisfiesCaret(concrete, range.slice(1));
    if (range.startsWith('~')) return satisfiesTilde(concrete, range.slice(1));
    if (range.startsWith('>=')) {
      const minimum = parseConcreteVersion(range.slice(2).trim());
      return minimum !== null && compareVersions(concrete, minimum) >= 0;
    }
    const exact = parseConcreteVersion(range);
    return exact !== null && compareVersions(concrete, exact) === 0;
  });
}

function comparatorSetAllowsPrerelease(version, range) {
  if (version.prerelease.length === 0) return true;
  const comparatorText = range.startsWith('^') || range.startsWith('~')
    ? range.slice(1)
    : range.startsWith('>=')
      ? range.slice(2).trim()
      : range;
  const comparator = parseConcreteVersion(comparatorText);
  return (
    comparator !== null &&
    comparator.prerelease.length > 0 &&
    comparator.major === version.major &&
    comparator.minor === version.minor &&
    comparator.patch === version.patch
  );
}

function satisfiesCaret(version, minimumText) {
  const minimum = parseConcreteVersion(minimumText);
  if (!minimum || compareVersions(version, minimum) < 0) return false;
  const maximum =
    minimum.major > 0
      ? { major: minimum.major + 1, minor: 0, patch: 0, prerelease: [] }
      : minimum.minor > 0
        ? { major: 0, minor: minimum.minor + 1, patch: 0, prerelease: [] }
        : { major: 0, minor: 0, patch: minimum.patch + 1, prerelease: [] };
  return compareVersions(version, maximum) < 0;
}

function satisfiesTilde(version, minimumText) {
  const minimum = parseConcreteVersion(minimumText);
  if (!minimum || compareVersions(version, minimum) < 0) return false;
  const maximum = {
    major: minimum.major,
    minor: minimum.minor + 1,
    patch: 0,
    prerelease: [],
  };
  return compareVersions(version, maximum) < 0;
}

function parseConcreteVersion(value) {
  if (typeof value !== 'string') return null;
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/u.exec(
    value,
  );
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4]?.split('.') ?? [],
  };
}

function compareVersions(left, right) {
  for (const key of ['major', 'minor', 'patch']) {
    if (left[key] !== right[key]) return left[key] - right[key];
  }
  if (left.prerelease.length === 0 || right.prerelease.length === 0) {
    return right.prerelease.length - left.prerelease.length;
  }
  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = left.prerelease[index];
    const rightPart = right.prerelease[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumber = /^\d+$/u.test(leftPart) ? Number(leftPart) : null;
    const rightNumber = /^\d+$/u.test(rightPart) ? Number(rightPart) : null;
    if (leftNumber !== null && rightNumber !== null) return leftNumber - rightNumber;
    if (leftNumber !== null) return -1;
    if (rightNumber !== null) return 1;
    return leftPart < rightPart ? -1 : 1;
  }
  return 0;
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
