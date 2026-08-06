import { createHash } from 'node:crypto';
import { brotliCompressSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { inventoryMigrationAssets, type AssetInput } from './asset-inventory.js';

const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL7qQAAAABJRU5ErkJggg==', 'base64');
const png2x2 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAAEUlEQVR4nGP4z8DwH4QZYAwAR8oH+WdZbrcAAAAASUVORK5CYII=', 'base64');
const animatedGif = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAAKAAAALAAAAAABAAEAAAICRAEAIfkEAAoAAAAsAAAAAAEAAQAAAgJEAQA7', 'base64');
const sha256 = (bytes: Uint8Array): `sha256:${string}` => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const captureReceipt = (overrides: Record<string, unknown> = {}) => ({
  policyVersion: 'move-to-verow.capture-receipt.v1',
  originalUrl: 'https://assets.example.test/hero.png',
  finalUrl: 'https://assets.example.test/hero.png',
  redirects: [],
  resolvedAddresses: [{ host: 'assets.example.test', address: '8.8.8.8', public: true }],
  cookiesStripped: true,
  authorizationStripped: true,
  byteLimit: 1_000,
  byteCount: png.byteLength,
  sniffedMime: 'image/png',
  digest: sha256(png),
  ...overrides,
});

function local(overrides: Partial<Extract<AssetInput, { authority: 'source_local' }>> = {}): AssetInput {
  return {
    authority: 'source_local',
    classification: 'editorial_cms',
    reference: { id: 'hero-image', sourcePath: 'public/hero.png', target: { key: 'page.home.hero.image', locale: 'en', variant: null } },
    bytes: png,
    digest: sha256(png),
    ...overrides,
  } as AssetInput;
}

describe('migration asset inventory', () => {
  it('deduplicates identical editorial PNG bytes while retaining sorted references and inspected oriented metadata', async () => {
    const result = await inventoryMigrationAssets({
      assets: [
        local(),
        local({ reference: { id: 'shared-image', sourcePath: 'content/hero.png', target: { key: 'page.about.hero.image', locale: 'en', variant: null } } }),
      ],
    });

    expect(result).toMatchObject({ status: 'ready', blockers: [] });
    expect(result.bundled).toHaveLength(1);
    expect(result.bundled[0]).toMatchObject({
      digest: sha256(png), bytes: png.byteLength, mime: 'image/png', encodedWidth: 1, encodedHeight: 1,
      renderedWidth: 1, renderedHeight: 1, pageCount: 1, animated: false,
    });
    expect(result.bundled[0]?.references.map(({ sourcePath }) => sourcePath)).toEqual(['content/hero.png', 'public/hero.png']);
  });

  it('keeps structural assets out of upload blobs and blocks conflicting authority for identical bytes', async () => {
    const structural = local({
      classification: 'structural_git',
      reference: { id: 'control-icon', sourcePath: 'public/control.png' },
    });
    const separated = await inventoryMigrationAssets({ assets: [local(), structural] });
    expect(separated).toMatchObject({ status: 'ready' });
    expect(separated.bundled[0]?.references).toHaveLength(1);
    expect(separated.structural[0]?.references).toHaveLength(1);

    const conflict = await inventoryMigrationAssets({ assets: [
      local(),
      { ...structural, reference: local().reference } as AssetInput,
    ] });
    expect(conflict).toMatchObject({ status: 'needs_attention' });
    expect(conflict.blockers.map(({ code }) => code)).toContain('asset_authority_conflict');
  });

  it('requires a linked public HTTPS capture receipt and keeps declared external assets byte-free', async () => {
    const captured = local({ authority: 'hosted_source_capture' } as never);
    const missing = await inventoryMigrationAssets({ assets: [captured] });
    expect(missing.blockers.map(({ code }) => code)).toContain('capture_receipt_invalid');

    const ready = await inventoryMigrationAssets({ assets: [{ ...captured, captureReceipt: captureReceipt() } as AssetInput] });
    expect(ready.status).toBe('ready');

    const external: AssetInput = {
      authority: 'declared_external', classification: 'declared_external',
      reference: { id: 'vendor-map', sourcePath: 'remote/vendor-map', target: { key: 'page.home.map.image', locale: 'en', variant: null } },
      externalUrl: 'https://cdn.example.test/map.png', privateBoundary: 'widget.vendor-map',
    };
    const declared = await inventoryMigrationAssets({ assets: [external] });
    expect(declared).toMatchObject({ status: 'ready', bundled: [], external: [{ url: 'https://cdn.example.test/map.png', privateBoundary: 'widget.vendor-map' }] });
  });

  it('rejects reserved capture addresses and every strict receipt tamper without network resolution', async () => {
    const captured = local({ authority: 'hosted_source_capture' } as never);
    for (const captureReceiptValue of [
      captureReceipt({ resolvedAddresses: [{ host: 'assets.example.test', address: '10.0.0.1', public: true }] }),
      captureReceipt({ resolvedAddresses: [{ host: 'assets.example.test', address: '203.0.113.10', public: true }] }),
      captureReceipt({ resolvedAddresses: [{ host: 'assets.example.test', address: '::1', public: true }] }),
      captureReceipt({ resolvedAddresses: [{ host: 'assets.example.test', address: '2001:db8::1', public: true }] }),
      captureReceipt({ digest: 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' }),
      captureReceipt({ byteCount: png.byteLength + 1 }),
      captureReceipt({ byteLimit: png.byteLength - 1 }),
      captureReceipt({ sniffedMime: 'image/jpeg' }),
      captureReceipt({ cookiesStripped: false }),
      captureReceipt({ authorizationStripped: false }),
      captureReceipt({ redirects: ['https://other.example.test/hero.png'] }),
      { ...captureReceipt(), verified: true },
    ]) {
      const result = await inventoryMigrationAssets({ assets: [{ ...captured, captureReceipt: captureReceiptValue } as AssetInput] });
      expect(result.blockers.map(({ code }) => code)).toContain('capture_receipt_invalid');
    }
  });

  it('rejects IANA special-use IPv6 evidence while accepting clearly global unicast addresses', async () => {
    const captured = local({ authority: 'hosted_source_capture' } as never);
    const specialUse = [
      '::', '::1', '::ffff:10.0.0.1', '64:ff9b::808:808', '64:ff9b:1::1', '100::1', '100:0:0:1::1',
      '2001::1', '2001:1::1', '2001:2::1', '2001:3::1', '2001:4:112::1', '2001:10::1', '2001:20::1',
      '2001:30::1', '2001:db8::1', '2002::1', '2620:4f:8000::1', '3fff::1', '5f00::1', 'fc00::1', 'fe80::1', 'ff02::1',
    ];
    for (const address of specialUse) {
      const result = await inventoryMigrationAssets({ assets: [{ ...captured, captureReceipt: captureReceipt({ resolvedAddresses: [{ host: 'assets.example.test', address, public: true }] }) } as AssetInput] });
      expect(result.blockers, address).toContainEqual({ code: 'capture_receipt_invalid' });
    }
    for (const address of ['2001:4860:4860::8888', '2606:4700:4700::1111']) {
      const result = await inventoryMigrationAssets({ assets: [{ ...captured, captureReceipt: captureReceipt({ resolvedAddresses: [{ host: 'assets.example.test', address, public: true }] }) } as AssetInput] });
      expect(result.status, address).toBe('ready');
    }
  });

  it('blocks unsafe URLs, digest drift, malformed image data, and non-tightening limits with content-free blockers', async () => {
    const badUrls = ['http://example.test/a.png', 'https://user:pass@example.test/a.png', 'https://localhost/a.png', 'https://127.0.0.1/a.png', 'https://10.0.0.1/a.png', 'https://203.0.113.10/a.png', 'https://[::1]/a.png', 'https://[2001:db8::1]/a.png'];
    for (const externalUrl of badUrls) {
      const result = await inventoryMigrationAssets({ assets: [{ authority: 'declared_external', classification: 'declared_external', reference: { id: 'unsafe', sourcePath: 'remote/unsafe' }, externalUrl, privateBoundary: 'boundary' } as AssetInput] });
      expect(result.blockers.map(({ code }) => code)).toContain('external_url_invalid');
    }
    const drift = await inventoryMigrationAssets({ assets: [local({ digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' })] });
    expect(drift.blockers.map(({ code }) => code)).toContain('asset_digest_mismatch');
    const invalid = await inventoryMigrationAssets({ assets: [local({ bytes: Buffer.from('synthetic secret bytes'), digest: sha256(Buffer.from('synthetic secret bytes')) })] });
    expect(invalid.blockers).toEqual(expect.arrayContaining([expect.objectContaining({ code: 'asset_policy_blocked' })]));
    for (const maxSingleBytes of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 9_999_999_999]) {
      const result = await inventoryMigrationAssets({ assets: [local()], limits: { maxSingleBytes } });
      expect(result.blockers.map(({ code }) => code)).toContain('asset_limit_invalid');
    }
    expect(JSON.stringify(invalid.blockers)).not.toContain('synthetic secret bytes');
  });

  it('sniffs MIME independently of the extension and enforces count, aggregate, pixel, dimension and frame bounds', async () => {
    const extensionMismatch = await inventoryMigrationAssets({ assets: [local({ reference: { id: 'png-named-jpeg', sourcePath: 'public/hero.jpg', target: { key: 'page.home.hero.image', locale: 'en', variant: null } } })] });
    expect(extensionMismatch.bundled[0]?.mime).toBe('image/png');

    const aggregate = await inventoryMigrationAssets({ assets: [local(), local({ reference: { id: 'copy', sourcePath: 'public/copy.png', target: { key: 'page.copy.image', locale: 'en', variant: null } } })], limits: { maxTotalBytes: png.byteLength } });
    expect(aggregate.blockers.map(({ code }) => code)).toContain('asset_policy_blocked');
    const count = await inventoryMigrationAssets({ assets: [local(), local({ reference: { id: 'copy', sourcePath: 'public/copy.png', target: { key: 'page.copy.image', locale: 'en', variant: null } } })], limits: { maxAssets: 1 } });
    expect(count.blockers.map(({ code }) => code)).toContain('asset_policy_blocked');
    const pixels = await inventoryMigrationAssets({ assets: [local({ bytes: png2x2, digest: sha256(png2x2) })], limits: { maxPixels: 3 } });
    expect(pixels.blockers.map(({ code }) => code)).toContain('asset_policy_blocked');
    const dimensions = await inventoryMigrationAssets({ assets: [local({ bytes: png2x2, digest: sha256(png2x2) })], limits: { maxDimension: 1 } });
    expect(dimensions.blockers.map(({ code }) => code)).toContain('asset_policy_blocked');
    const frames = await inventoryMigrationAssets({ assets: [local({ bytes: animatedGif, digest: sha256(animatedGif), reference: { id: 'animation', sourcePath: 'public/animation.gif', target: { key: 'page.animation.image', locale: 'en', variant: null } } })], limits: { maxFrames: 1 } });
    expect(frames.blockers.map(({ code }) => code)).toContain('asset_policy_blocked');
  });

  it('short-circuits cardinality and byte preflight limits before hashing or decoder work', async () => {
    class ObservedBytes extends Uint8Array {
      reads = 0;
      override get byteLength(): number { this.reads += 1; return super.byteLength; }
    }
    const observed = (source: Uint8Array): { bytes: ObservedBytes; digest: `sha256:${string}` } => {
      const bytes = new ObservedBytes(source);
      const digest = sha256(bytes);
      bytes.reads = 0;
      return { bytes, digest };
    };
    const first = observed(png);
    const second = observed(png2x2);
    const assets = [
      local({ bytes: first.bytes, digest: first.digest }),
      local({ bytes: second.bytes, digest: second.digest, reference: { id: 'second', sourcePath: 'public/second.png', target: { key: 'page.second.image', locale: 'en', variant: null } } }),
    ];

    const cardinality = await inventoryMigrationAssets({ assets, limits: { maxAssets: 1 } });
    expect(cardinality.blockers).toEqual([{ code: 'asset_policy_blocked' }]);
    expect([first.bytes.reads, second.bytes.reads]).toEqual([0, 0]);

    first.bytes.reads = 0;
    second.bytes.reads = 0;
    const references = await inventoryMigrationAssets({ assets, limits: { maxAssets: 2, maxReferences: 1 } });
    expect(references.blockers).toEqual([{ code: 'asset_policy_blocked' }]);
    expect([first.bytes.reads, second.bytes.reads]).toEqual([0, 0]);

    first.bytes.reads = 0;
    second.bytes.reads = 0;
    const aggregate = await inventoryMigrationAssets({ assets, limits: { maxTotalBytes: png.byteLength + 1 } });
    expect(aggregate.blockers).toEqual([{ code: 'asset_policy_blocked' }]);
    expect(second.bytes.reads).toBe(1);

    second.bytes.reads = 0;
    const single = await inventoryMigrationAssets({ assets: [assets[1] as AssetInput], limits: { maxSingleBytes: png.byteLength } });
    expect(single.blockers).toEqual([{ code: 'asset_policy_blocked' }]);
    expect(second.bytes.reads).toBe(1);
  });

  it('accepts licensed structural WOFF evidence but blocks arbitrary structural binary and missing font licensing', async () => {
    const woff = Buffer.alloc(68);
    woff.write('wOFF', 0, 'ascii');
    woff.writeUInt32BE(0x0001_0000, 4);
    woff.writeUInt32BE(woff.byteLength, 8);
    woff.writeUInt16BE(1, 12);
    woff.writeUInt32BE(32, 16);
    woff.write('name', 44, 'ascii');
    woff.writeUInt32BE(64, 48);
    woff.writeUInt32BE(4, 52);
    woff.writeUInt32BE(4, 56);
    const font = local({
      classification: 'structural_git', bytes: woff, digest: sha256(woff),
      reference: { id: 'brand-font', sourcePath: 'fonts/brand.woff' },
      structuralKind: 'font', fontLicense: { spdxId: 'OFL-1.1', notice: 'Synthetic fixture font' },
    } as never);
    const ready = await inventoryMigrationAssets({ assets: [font] });
    expect(ready).toMatchObject({ status: 'ready', bundled: [], structural: [{ mime: 'font/woff' }] });

    const woff2Body = brotliCompressSync(Buffer.alloc(4));
    const woff2 = Buffer.alloc(50 + woff2Body.byteLength);
    woff2.write('wOF2', 0, 'ascii');
    woff2.writeUInt32BE(0x0001_0000, 4);
    woff2.writeUInt32BE(woff2.byteLength, 8);
    woff2.writeUInt16BE(1, 12);
    woff2.writeUInt32BE(32, 16);
    woff2.writeUInt32BE(woff2Body.byteLength, 20);
    woff2[48] = 5;
    woff2[49] = 4;
    woff2Body.copy(woff2, 50);
    const woff2Font = local({
      classification: 'structural_git', bytes: woff2, digest: sha256(woff2), reference: { id: 'brand-font-2', sourcePath: 'fonts/brand.woff2' },
      structuralKind: 'font', fontLicense: { spdxId: 'OFL-1.1', notice: 'Synthetic fixture font' },
    } as never);
    const woff2Ready = await inventoryMigrationAssets({ assets: [woff2Font] });
    expect(woff2Ready).toMatchObject({ status: 'ready', bundled: [], structural: [{ mime: 'font/woff2' }] });

    for (const candidate of [
      { ...font, fontLicense: undefined },
      local({ classification: 'structural_git', bytes: Buffer.from('arbitrary binary'), digest: sha256(Buffer.from('arbitrary binary')), reference: { id: 'binary', sourcePath: 'public/data.bin' } }),
    ]) {
      const result = await inventoryMigrationAssets({ assets: [candidate as AssetInput] });
      expect(result.blockers.map(({ code }) => code)).toContain('asset_policy_blocked');
    }
  });

  it('rejects header-only WOFF2 and malformed WOFF container directories with content-free blockers', async () => {
    const asFont = (bytes: Uint8Array, id: string): AssetInput => local({
      classification: 'structural_git', bytes, digest: sha256(bytes),
      reference: { id, sourcePath: `fonts/${id}` }, structuralKind: 'font',
      fontLicense: { spdxId: 'OFL-1.1', notice: 'Synthetic fixture font' },
    } as never);
    const fakeWoff2 = Buffer.alloc(48);
    fakeWoff2.write('wOF2', 0, 'ascii');
    fakeWoff2.writeUInt32BE(fakeWoff2.byteLength, 8);
    fakeWoff2.writeUInt16BE(1, 12);

    const validWoff = Buffer.alloc(68);
    validWoff.write('wOFF', 0, 'ascii');
    validWoff.writeUInt32BE(0x0001_0000, 4);
    validWoff.writeUInt32BE(validWoff.byteLength, 8);
    validWoff.writeUInt16BE(1, 12);
    validWoff.writeUInt32BE(32, 16);
    validWoff.write('name', 44, 'ascii');
    validWoff.writeUInt32BE(64, 48);
    validWoff.writeUInt32BE(4, 52);
    validWoff.writeUInt32BE(4, 56);
    const malformed = [
      fakeWoff2,
      (() => { const bytes = Buffer.from(validWoff); bytes.writeUInt32BE(0, 16); return bytes; })(),
      (() => { const bytes = Buffer.from(validWoff); bytes.writeUInt32BE(60, 48); return bytes; })(),
      (() => { const bytes = Buffer.concat([validWoff, Buffer.alloc(4)]); bytes.writeUInt32BE(bytes.byteLength, 8); return bytes; })(),
      (() => { const bytes = Buffer.from(validWoff); bytes.writeUInt32BE(64, 24); return bytes; })(),
      (() => { const bytes = Buffer.from(validWoff); bytes.writeUInt32BE(64, 36); bytes.writeUInt32BE(8, 40); return bytes; })(),
    ];

    for (const [index, bytes] of malformed.entries()) {
      const result = await inventoryMigrationAssets({ assets: [asFont(bytes, `malformed-${index}.woff`)] });
      expect(result.blockers).toEqual([{ code: 'asset_policy_blocked' }]);
      expect(JSON.stringify(result)).not.toContain('Synthetic fixture font');
    }
  });

  it('allows tightening-only positive safe integer limit overrides', async () => {
    const tightening = await inventoryMigrationAssets({ assets: [local()], limits: { maxAssets: 1, maxSingleBytes: png.byteLength, maxTotalBytes: png.byteLength, maxPixels: 1, maxDimension: 1, maxFrames: 1, maxReferences: 1, maxBlockers: 1 } });
    expect(tightening.status).toBe('ready');
    for (const limits of [
      { maxAssets: 501 }, { maxTotalBytes: 100_000_001 }, { maxPixels: 40_000_001 }, { maxDimension: 16_385 },
      { maxFrames: 257 }, { maxReferences: 2_001 }, { maxBlockers: 101 },
    ]) {
      const result = await inventoryMigrationAssets({ assets: [local()], limits });
      expect(result.blockers.map(({ code }) => code)).toContain('asset_limit_invalid');
    }
  });

  it('uses composite target identity deterministically and blocks one target with conflicting ownership', async () => {
    const fr = local({ reference: { id: 'fr', sourcePath: 'public/fr.png', target: { key: 'page.home.hero.image', locale: 'fr', variant: null } } });
    const dark = local({ reference: { id: 'dark', sourcePath: 'public/dark.png', target: { key: 'page.home.hero.image', locale: 'en', variant: 'dark' } } });
    const ordered = await inventoryMigrationAssets({ assets: [fr, local(), dark] });
    const reordered = await inventoryMigrationAssets({ assets: [dark, local(), fr] });
    expect(reordered).toEqual(ordered);
    expect(ordered.status).toBe('ready');

    const external: AssetInput = { authority: 'declared_external', classification: 'declared_external', reference: { id: 'external', sourcePath: 'remote/external', target: { key: 'page.home.hero.image', locale: 'en', variant: null } }, externalUrl: 'https://cdn.example.test/image.png', privateBoundary: 'widget.external' };
    const conflict = await inventoryMigrationAssets({ assets: [local(), external] });
    expect(conflict.blockers.map(({ code }) => code)).toContain('asset_target_conflict');
  });

  it('preserves a safe SVG byte-for-byte and rejects entity, case, external/data and cyclic-reference evasions', async () => {
    const safeBytes = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>');
    const safe = await inventoryMigrationAssets({ assets: [local({ bytes: safeBytes, digest: sha256(safeBytes), reference: { id: 'safe-svg', sourcePath: 'public/safe.svg', target: { key: 'page.home.safe.image', locale: 'en', variant: null } } })] });
    expect(safe).toMatchObject({ status: 'ready', blockers: [] });
    expect(safe.bundled[0]?.bytesValue).toEqual(safeBytes);
    for (const svg of [
      '<!DOCTYPE svg [<!ENTITY x "x">]><svg>&x;</svg>',
      '<svg><SCRIPT>alert(1)</SCRIPT></svg>',
      '<svg><foreignObject><html>unsafe</html></foreignObject></svg>',
      '<svg><rect onload="alert(1)"/></svg>',
      '<svg><style>@import url(https://example.test/x.css)</style></svg>',
      '<svg><rect style="fill:url(data:image/png;base64,AA==)"/></svg>',
      '<svg><image href="data:image/png;base64,AA=="/></svg>',
      '<svg><use href="https://example.test/x.svg#x"/></svg>',
      '<svg><animate attributeName="x" values="0;1"/></svg>',
      '<svg><filter id="f"><feImage href="#x"/></filter></svg>',
      '<svg><use href="#b"/><g id="b"><use href="#b"/></g></svg>',
    ]) {
      const bytes = Buffer.from(svg);
      const result = await inventoryMigrationAssets({ assets: [local({ bytes, digest: sha256(bytes), reference: { id: 'unsafe-svg', sourcePath: 'public/unsafe.svg', target: { key: 'page.home.unsafe.image', locale: 'en', variant: null } } })] });
      expect(result.blockers.map(({ code }) => code)).toContain('asset_policy_blocked');
    }

    const localFragmentBytes = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><defs><rect id="pixel" width="1" height="1"/></defs><use href="#pixel"/></svg>');
    const localFragment = await inventoryMigrationAssets({ assets: [local({ bytes: localFragmentBytes, digest: sha256(localFragmentBytes), reference: { id: 'local-reference', sourcePath: 'public/local-reference.svg', target: { key: 'page.home.local-reference.image', locale: 'en', variant: null } } })] });
    expect(localFragment.status).toBe('ready');
  });

  it('sorts references by unsigned UTF-8 bytes instead of the ambient locale', async () => {
    const result = await inventoryMigrationAssets({
      assets: [
        local({ reference: { id: 'accented', sourcePath: 'public/é.png', target: { key: 'page.accented.image', locale: 'en', variant: null } } }),
        local({ reference: { id: 'ascii', sourcePath: 'public/z.png', target: { key: 'page.ascii.image', locale: 'en', variant: null } } }),
      ],
    });

    expect(result.bundled[0]?.references.map(({ sourcePath }) => sourcePath)).toEqual(['public/z.png', 'public/é.png']);
  });

  it('rejects proxy, accessor, extra-field, and same-path conflicting inputs without evaluating customer code', async () => {
    const secret = 'sk_synthetic_asset_secret';
    const throwingProxy = new Proxy({ assets: [] }, {
      get() { throw new Error(secret); },
    });
    await expect(inventoryMigrationAssets(throwingProxy as never)).resolves.toMatchObject({
      status: 'needs_attention', blockers: [{ code: 'asset_input_invalid' }],
    });

    let reads = 0;
    const accessor = Object.defineProperty({}, 'assets', { enumerable: true, get() { reads += 1; return []; } });
    await expect(inventoryMigrationAssets(accessor as never)).resolves.toMatchObject({
      status: 'needs_attention', blockers: [{ code: 'asset_input_invalid' }],
    });
    expect(reads).toBe(0);

    const extra = await inventoryMigrationAssets({ assets: [{ ...local(), customerValue: secret } as unknown as AssetInput] });
    expect(extra.blockers).toContainEqual({ code: 'asset_input_invalid' });
    expect(JSON.stringify(extra)).not.toContain(secret);

    const conflictingPath = await inventoryMigrationAssets({
      assets: [
        local(),
        local({
          bytes: png2x2,
          digest: sha256(png2x2),
          reference: { id: 'different-id', sourcePath: 'public/hero.png', target: { key: 'page.other.image', locale: 'en', variant: null } },
        }),
      ],
    });
    expect(conflictingPath.blockers).toContainEqual({ code: 'asset_authority_conflict' });
  });

  it('requires bounded capture evidence to use exact canonical URLs', async () => {
    const captured = local({ authority: 'hosted_source_capture' } as never);
    const nonCanonical = captureReceipt({
      originalUrl: 'https://ASSETS.example.test/hero.png',
      finalUrl: 'https://ASSETS.example.test/hero.png',
    });
    const tooManyRedirects = captureReceipt({ redirects: Array.from({ length: 33 }, () => 'https://assets.example.test/hero.png') });

    for (const receipt of [nonCanonical, tooManyRedirects]) {
      const result = await inventoryMigrationAssets({ assets: [{ ...captured, captureReceipt: receipt } as AssetInput] });
      expect(result.blockers).toContainEqual({ code: 'capture_receipt_invalid' });
    }
  });

  it('applies the reference and tightened byte bounds inside SVG and capture evidence', async () => {
    const svgBytes = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><defs><rect id="a" width="1" height="1"/><rect id="b" width="1" height="1"/></defs><use href="#a"/><use href="#b"/></svg>');
    const svg = await inventoryMigrationAssets({
      assets: [local({ bytes: svgBytes, digest: sha256(svgBytes), reference: { id: 'bounded-svg', sourcePath: 'public/bounded.svg', target: { key: 'page.home.bounded.image', locale: 'en', variant: null } } })],
      limits: { maxReferences: 1 },
    });
    expect(svg.blockers).toContainEqual({ code: 'asset_policy_blocked' });

    const captured = local({ authority: 'hosted_source_capture' } as never);
    const capture = await inventoryMigrationAssets({
      assets: [{ ...captured, captureReceipt: captureReceipt() } as AssetInput],
      limits: { maxSingleBytes: png.byteLength },
    });
    expect(capture.blockers).toContainEqual({ code: 'capture_receipt_invalid' });
  });
});
