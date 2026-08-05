import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import {
  bundleContractProvenance,
  canonicalDigest,
  canonicalDigestVectors,
  validateBundleDescriptor,
  validatePayloadIndex,
} from './bundle-contract.js';

const bundleSchemaBytes = readFileSync(
  new URL('../contracts/migration-bundle.schema.json', import.meta.url),
);

const validDescriptor = {
  version: 'move-to-verow.bundle.v1',
  migrationId: 'migration_01',
  websiteId: 'website_01',
  sourceDigest: `sha256:${'1'.repeat(64)}`,
  artifactDigest: `sha256:${'2'.repeat(64)}`,
  archiveFormat: 'tar_gzip_v1',
  sourceKind: 'codex_sites_local',
  framework: 'nextjs_app_router',
  fileCount: 2,
  totalBytes: 42,
  capabilityClaims: ['static_content'],
  privateManifestDigest: `sha256:${'3'.repeat(64)}`,
  evidenceDigest: `sha256:${'4'.repeat(64)}`,
};

const validPayloadIndex = {
  version: 'move-to-verow.payload-index.v1',
  entries: [
    { path: 'app/page.tsx', bytes: 20, digest: `sha256:${'5'.repeat(64)}` },
    { path: 'public/logo.svg', bytes: 22, digest: `sha256:${'6'.repeat(64)}` },
  ],
};

describe('reviewed webapp bundle contract', () => {
  it('uses the exact reviewed webapp bundle schema', () => {
    const digest = `sha256:${createHash('sha256').update(bundleSchemaBytes).digest('hex')}`;

    expect(digest).toBe(bundleContractProvenance.sha256);
    expect(bundleContractProvenance.sourceCommit).toMatch(/^[0-9a-f]{40}$/u);
    expect(validateBundleDescriptor(validDescriptor).valid).toBe(true);
    expect(
      validateBundleDescriptor({ ...validDescriptor, artifactDigest: 'sha256:bad' }).valid,
    ).toBe(false);
    expect(validatePayloadIndex(validPayloadIndex).valid).toBe(true);
    expect(
      validatePayloadIndex({
        ...validPayloadIndex,
        entries: [...validPayloadIndex.entries].reverse(),
      }).valid,
    ).toBe(false);
    for (const vector of canonicalDigestVectors) {
      expect(canonicalDigest(vector.value)).toBe(vector.digest);
    }
  });
});
