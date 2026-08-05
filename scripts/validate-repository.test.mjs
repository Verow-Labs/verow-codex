import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('publishes one correctly governed verow plugin', async () => {
  const marketplace = JSON.parse(await readFile('.agents/plugins/marketplace.json'));
  assert.equal(marketplace.name, 'verow');
  assert.deepEqual(marketplace.plugins[0], {
    name: 'verow',
    source: { source: 'local', path: './plugins/verow' },
    policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' },
    category: 'Coding',
  });
});
