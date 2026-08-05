import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('publishes one correctly governed verow plugin', async () => {
  const marketplace = JSON.parse(await readFile('.agents/plugins/marketplace.json'));
  assert.equal(marketplace.name, 'verow');
  assert.equal(marketplace.plugins.length, 1);
  assert.deepEqual(marketplace.plugins[0], {
    name: 'verow',
    source: { source: 'local', path: './plugins/verow' },
    policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' },
    category: 'Coding',
  });
});

test('pins reviewed compiler contract provenance without publishing compiler artifacts', async () => {
  const releaseLock = JSON.parse(await readFile('plugins/verow/release-lock.json'));
  const provenance = JSON.parse(
    await readFile('packages/move-to-verow-compiler/contracts/provenance.json'),
  );

  assert.deepEqual(
    {
      sourceCommit: provenance.sourceCommit,
      sha256: provenance.sha256,
      canonicalVectorsSha256: provenance.canonicalVectorsSha256,
    },
    {
      sourceCommit: '6f3061cf61b90acf3447a57c84792c3a8bfcb96f',
      sha256: 'sha256:35801419921e72879bbf298b45bfacea56daca1b3f890b69188616fe85728735',
      canonicalVectorsSha256:
        'sha256:fc37985b961bb76a557539dcd0ab3b40b457c9747f878dcd69fe296cdd1cbf1d',
    },
  );

  assert.deepEqual(releaseLock.contracts, {
    bundleVersion: 'move-to-verow.bundle.v1',
    manifestVersion: 'move-to-verow.manifest.v1',
    payloadIndexVersion: 'move-to-verow.payload-index.v1',
    bundleSchemaDigest: provenance.sha256,
    canonicalVectorsDigest: provenance.canonicalVectorsSha256,
    webappCommit: provenance.sourceCommit,
  });
  assert.equal(releaseLock.git.compilerSourceCommit, null);
  assert.deepEqual(releaseLock.packages['@verow/move-to-verow-compiler'], {
    version: '1.0.0',
    integrity: null,
    executableDigest: null,
    runtimeClosureDigest: null,
    browserRevision: null,
  });
});
