import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { compileMigrationArtifacts, type CompileMigrationArtifactsInput } from './manifest.js';

const sha256 = (value: string | Uint8Array): `sha256:${string}` => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const identity = { key: 'page.home.hero.heading', locale: 'en', variant: null } as const;

const imageBytes = new Uint8Array([1]);
const imageDigest = sha256(imageBytes);

function target(key: string, valueType: 'string' | 'rich_text' | 'url' | 'email' | 'telephone' | 'image' | 'collection' = 'string') {
  return {
    ...identity, key, label: `Private ${key}`, sourceKind: 'jsx' as const, valueType, routeId: 'home',
    sourcePath: 'app/page.tsx', sourceAnchor: `ast:${key}`, thirdPartyBoundary: null,
    owner: 'site_region' as const, structuredFamily: null,
  };
}

function value(key: string, content: string, locale = 'en', variant: string | null = null) {
  return { key, locale, variant, value: content };
}

function policyTarget(key: string) {
  return {
    key, locale: 'en', variant: null, required: true, cardinality: 'one' as const,
    actions: ['edit' as const], liveVerification: 'route' as const, imagePair: null, collection: null,
  };
}

function input(overrides: Partial<CompileMigrationArtifactsInput> = {}): CompileMigrationArtifactsInput {
  const target = {
    ...identity, label: 'Synthetic Hero Heading', sourceKind: 'jsx', valueType: 'string', routeId: 'home',
    sourcePath: 'app/page.tsx', sourceAnchor: 'ast:1', thirdPartyBoundary: null, owner: 'site_region', structuredFamily: null,
  } as const;
  return {
    websiteId: '11111111-1111-4111-8111-111111111111', migrationId: '22222222-2222-4222-8222-222222222222',
    sourceDigest: sha256('source'), candidateDigest: sha256('candidate'), cmsNativeProtocol: { package: '@verow/cms-native', version: '1.0.0', contractDigest: sha256('contract') },
    extraction: { status: 'ready', targets: [target], values: { 'page.home.hero.heading\u0000en\u0000': { ...identity, value: 'Synthetic customer heading' } }, structuredFamilies: [], thirdPartyBoundaries: [], derived: [], structural: [], needsAttention: [] },
    assets: { status: 'ready', bundled: [], structural: [], external: [], blockers: [] },
    routes: [{ routeId: 'home', path: '/', renderedSource: 'page.home' }],
    policy: { targets: [{ ...identity, required: true, cardinality: 'one', actions: ['edit'], liveVerification: 'route', imagePair: null, collection: null }], collectionPolicy: [] },
    ...overrides,
  } as CompileMigrationArtifactsInput;
}

describe('migration artifact compiler', () => {
  it('compiles deterministic four logical artifacts with a composite key-locale-variant identity bijection', () => {
    const result = compileMigrationArtifacts(input());
    expect(result.privateManifest.format).toBe('move-to-verow.manifest.v1');
    expect(result.runtimeExpectation.format).toBe('move-to-verow.runtime-expectation.v1');
    expect(result.contentFixture.values).toEqual([{ ...identity, value: 'Synthetic customer heading' }]);
    expect(result.repositoryBinding.bindings).toEqual([{ ...identity, key: 'page.home.hero.heading' }]);
    expect(result.digests.privateManifest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(JSON.stringify(result.repositoryBinding)).not.toContain('Synthetic customer heading');
    expect(JSON.stringify(result.runtimeExpectation)).not.toContain('Synthetic customer heading');
  });

  it('preserves owner/type/locale/variant/route/policy privately without leaking values, labels, paths, URLs, providers, or schema selectors to safe artifacts', () => {
    const result = compileMigrationArtifacts(input({
      extraction: { ...input().extraction, targets: [{ ...input().extraction.targets[0]!, locale: 'fr', variant: 'mobile', label: 'Synthetic Private Label', sourcePath: 'private/customer/path.tsx', sourceAnchor: 'anchor:secret' }], values: { 'page.home.hero.heading\u0000fr\u0000mobile': { key: identity.key, locale: 'fr', variant: 'mobile', value: 'Synthetic customer value' } } },
      policy: { ...input().policy, targets: [{ key: identity.key, locale: 'fr', variant: 'mobile', required: true, cardinality: 'one', actions: ['edit'], liveVerification: 'route', imagePair: null, collection: null }] },
    }));
    const privateTarget = result.privateManifest.targets[0];
    expect(privateTarget).toMatchObject({ owner: 'site_region', valueType: 'string', locale: 'fr', variant: 'mobile', routeId: 'home', label: 'Synthetic Private Label' });
    const safe = JSON.stringify([result.repositoryBinding, result.runtimeExpectation]);
    for (const forbidden of ['Synthetic customer value', 'Synthetic Private Label', 'private/customer/path.tsx', 'anchor:secret', 'http', 'provider', 'sanity', 'groq', 'token']) expect(safe.toLowerCase()).not.toContain(forbidden.toLowerCase());
  });

  it('blocks missing, duplicate or orphan composite identities rather than accepting equal-cardinality sets', () => {
    const missing = input({ extraction: { ...input().extraction, values: {} } });
    expect(() => compileMigrationArtifacts(missing)).toThrow('manifest_identity_bijection');
    const orphan = input({ extraction: { ...input().extraction, values: { ...input().extraction.values, 'page.home.other\u0000en\u0000': { key: 'page.home.other', locale: 'en', variant: null, value: 'Synthetic orphan' } } } });
    expect(() => compileMigrationArtifacts(orphan)).toThrow('manifest_identity_bijection');
    const duplicate = input({ extraction: { ...input().extraction, targets: [...input().extraction.targets, input().extraction.targets[0]!] } });
    expect(() => compileMigrationArtifacts(duplicate)).toThrow('manifest_identity_bijection');
  });

  it('fails closed above 500 editable identities and rejects assets or extraction blockers', () => {
    const targets = Array.from({ length: 501 }, (_, index) => ({ ...input().extraction.targets[0]!, key: `page.home.item${index}` }));
    const values = Object.fromEntries(targets.map((target) => [`${target.key}\u0000en\u0000`, { key: target.key, locale: 'en', variant: null, value: 'Synthetic value' }]));
    const policyTargets = targets.map((target) => ({ ...input().policy.targets[0]!, key: target.key }));
    expect(() => compileMigrationArtifacts(input({ extraction: { ...input().extraction, targets, values }, policy: { ...input().policy, targets: policyTargets } }))).toThrow('manifest_target_limit_exceeded');
    expect(() => compileMigrationArtifacts(input({ assets: { status: 'needs_attention', bundled: [], structural: [], external: [], blockers: [{ code: 'asset_policy_blocked' }] } }))).toThrow('manifest_assets_blocked');
  });

  it('sorts re-ordered inputs and changes the correct digest when an identity, value, route or policy changes', () => {
    const first = compileMigrationArtifacts(input());
    const reordered = compileMigrationArtifacts(input({ routes: [{ routeId: 'home', path: '/', renderedSource: 'page.home' }], extraction: { ...input().extraction, targets: [...input().extraction.targets].reverse() } }));
    expect(reordered).toEqual(first);
    const altered = compileMigrationArtifacts(input({ routes: [{ routeId: 'home', path: '/welcome', renderedSource: 'page.home' }] }));
    expect(altered.digests.privateManifest).not.toBe(first.digests.privateManifest);
    expect(JSON.stringify(first.privateManifest)).not.toContain(first.digests.privateManifest);
  });

  it('keeps editorial image pairs and collection stable ids disjoint from structural and runtime attestation claims', () => {
    const imageTarget = { ...input().extraction.targets[0]!, key: 'page.home.hero.image', valueType: 'image' as const };
    const result = compileMigrationArtifacts(input({
      extraction: { ...input().extraction, targets: [imageTarget], values: { 'page.home.hero.image\u0000en\u0000': { key: imageTarget.key, locale: 'en', variant: null, value: imageDigest } } },
      assets: { status: 'ready', bundled: [{ digest: imageDigest, bytes: 1, bytesValue: imageBytes, mime: 'image/png', encodedWidth: 1, encodedHeight: 1, renderedWidth: 1, renderedHeight: 1, pageCount: 1, animated: false, references: [{ id: 'hero', sourcePath: 'public/hero.png', target: { key: imageTarget.key, locale: 'en', variant: null }, classification: 'editorial_cms', provenance: { authority: 'source_local', sourcePath: 'public/hero.png' } }] }], structural: [], external: [], blockers: [] },
      policy: { ...input().policy, targets: [{ key: imageTarget.key, locale: 'en', variant: null, required: true, cardinality: 'one', actions: ['edit'], liveVerification: 'route', imagePair: null, collection: null }] },
    }));
    expect(result.contentFixture.editorialAssets).toEqual([{ digest: imageDigest, target: { key: imageTarget.key, locale: 'en', variant: null } }]);
    expect(result.runtimeExpectation).not.toHaveProperty('buildId');
    expect(JSON.stringify(result.runtimeExpectation).toLowerCase()).not.toContain('attestation');
  });

  it('requires strict lower-case UUIDs, digests, protocol identity, routes and finite policy values', () => {
    for (const malformed of [
      input({ websiteId: '11111111-1111-4111-8111-11111111111A' }),
      input({ migrationId: 'not-a-uuid' }),
      input({ sourceDigest: 'sha256:ABC' as `sha256:${string}` }),
      input({ cmsNativeProtocol: { package: '@verow/cms-native', version: '', contractDigest: sha256('contract') } }),
    ]) expect(() => compileMigrationArtifacts(malformed)).toThrow('manifest_input_invalid');
    expect(() => compileMigrationArtifacts(input({ routes: [] }))).toThrow('manifest_route_invalid');
    expect(() => compileMigrationArtifacts(input({ routes: [{ routeId: 'home', path: '/home?secret=value', renderedSource: 'page.home' }] }))).toThrow('manifest_route_invalid');
    expect(() => compileMigrationArtifacts(input({ policy: { ...input().policy, targets: [{ ...input().policy.targets[0]!, actions: [] }] } }))).toThrow('manifest_policy_invalid');
  });

  it('supports the same key across locale and variant dimensions and requires an exact policy bijection', () => {
    const baseTarget = input().extraction.targets[0]!;
    const frTarget = { ...baseTarget, locale: 'fr', variant: 'mobile' };
    const multi = input({
      extraction: {
        ...input().extraction,
        targets: [baseTarget, frTarget],
        values: {
          ...input().extraction.values,
          'page.home.hero.heading\u0000fr\u0000mobile': value(identity.key, 'Valeur synthétique', 'fr', 'mobile'),
        },
      },
      policy: {
        ...input().policy,
        targets: [input().policy.targets[0]!, { ...input().policy.targets[0]!, locale: 'fr', variant: 'mobile' }],
      },
    });
    expect(compileMigrationArtifacts(multi).privateManifest.targets.map(({ locale, variant }) => [locale, variant])).toEqual([
      ['en', null], ['fr', 'mobile'],
    ]);
    expect(() => compileMigrationArtifacts({ ...multi, policy: { ...multi.policy, targets: [multi.policy.targets[0]!] } })).toThrow('manifest_policy_bijection');
  });

  it('requires every image to have exactly one editorial digest or external boundary and reciprocal alt pairing', () => {
    const image = target('page.home.hero.image', 'image');
    const alt = target('page.home.hero.alt');
    const imageIdentity = { key: image.key, locale: 'en', variant: null } as const;
    const altIdentity = { key: alt.key, locale: 'en', variant: null } as const;
    const paired = input({
      extraction: {
        ...input().extraction,
        targets: [image, alt],
        values: {
          [`${image.key}\u0000en\u0000`]: value(image.key, imageDigest),
          [`${alt.key}\u0000en\u0000`]: value(alt.key, 'Synthetic alt'),
        },
      },
      assets: {
        status: 'ready',
        bundled: [{ digest: imageDigest, bytes: 1, bytesValue: imageBytes, mime: 'image/png', encodedWidth: 1, encodedHeight: 1, renderedWidth: 1, renderedHeight: 1, pageCount: 1, animated: false, references: [{ id: 'hero', sourcePath: 'public/hero.png', target: imageIdentity, classification: 'editorial_cms', provenance: { authority: 'source_local', sourcePath: 'public/hero.png' } }] }],
        structural: [], external: [], blockers: [],
      },
      policy: {
        targets: [
          { ...policyTarget(image.key), imagePair: { role: 'image' as const, target: altIdentity } },
          { ...policyTarget(alt.key), imagePair: { role: 'alt' as const, target: imageIdentity } },
        ], collectionPolicy: [],
      },
    });
    expect(compileMigrationArtifacts(paired).contentFixture.editorialAssets).toEqual([{ digest: imageDigest, target: imageIdentity }]);
    expect(() => compileMigrationArtifacts({ ...paired, policy: { ...paired.policy, targets: [{ ...paired.policy.targets[0]!, imagePair: null }, paired.policy.targets[1]!] } })).toThrow('manifest_image_pair_invalid');
    expect(() => compileMigrationArtifacts({ ...paired, assets: { ...paired.assets, bundled: [] } })).toThrow('manifest_image_binding_invalid');
  });

  it('preserves declared-external boundaries privately while excluding URLs from safe artifacts', () => {
    const image = target('page.home.hero.image', 'image');
    const imageIdentity = { key: image.key, locale: 'en', variant: null } as const;
    const externalUrl = 'https://assets.example.test/synthetic.png';
    const result = compileMigrationArtifacts(input({
      extraction: { ...input().extraction, targets: [image], values: { [`${image.key}\u0000en\u0000`]: value(image.key, externalUrl) } },
      assets: { status: 'ready', bundled: [], structural: [], external: [{ url: externalUrl, privateBoundary: 'third-party-runtime', reference: { id: 'hero', sourcePath: 'public/hero.url', target: imageIdentity }, provenance: { authority: 'declared_external', url: externalUrl, privateBoundary: 'third-party-runtime' } }], blockers: [] },
      policy: { targets: [policyTarget(image.key)], collectionPolicy: [] },
    }));
    expect(result.contentFixture.externalAssets).toEqual([{ target: imageIdentity, url: externalUrl }]);
    expect(result.privateManifest.targets[0]).toMatchObject({ externalBoundary: 'third-party-runtime', externalUrl });
    expect(JSON.stringify([result.repositoryBinding, result.runtimeExpectation])).not.toContain(externalUrl);
  });

  it('validates collection roots against sorted raw stable ids and derived item-field membership', () => {
    const root = target('page.home.cards', 'collection');
    const alpha = target('page.home.cards.items.alphaCard.heading');
    const beta = target('page.home.cards.items.betaCard.heading');
    const extraction = {
      ...input().extraction,
      targets: [root, alpha, beta],
      values: {
        [`${root.key}\u0000en\u0000`]: value(root.key, '["alpha-card","beta-card"]'),
        [`${alpha.key}\u0000en\u0000`]: value(alpha.key, 'Alpha'),
        [`${beta.key}\u0000en\u0000`]: value(beta.key, 'Beta'),
      },
    };
    const collectionPolicy = [{ key: root.key, locale: 'en', variant: null, minimumItems: 1, maximumItems: 4, requiredItemIds: ['beta-card', 'alpha-card'] }];
    const valid = input({ extraction, policy: { targets: [policyTarget(root.key), policyTarget(alpha.key), policyTarget(beta.key)], collectionPolicy } });
    const result = compileMigrationArtifacts(valid);
    expect(result.privateManifest.targets.find(({ key }) => key === root.key)?.collection).toEqual({ minimumItems: 1, maximumItems: 4, requiredItemIds: ['alpha-card', 'beta-card'] });
    const valuesWithoutBeta = Object.fromEntries(Object.entries(extraction.values).filter(([key]) => key !== `${beta.key}\u0000en\u0000`));
    expect(() => compileMigrationArtifacts({ ...valid, extraction: { ...extraction, targets: [root, alpha], values: valuesWithoutBeta }, policy: { ...valid.policy, targets: [policyTarget(root.key), policyTarget(alpha.key)] } })).toThrow('manifest_collection_invalid');
    expect(() => compileMigrationArtifacts({ ...valid, extraction: { ...extraction, values: { ...extraction.values, [`${root.key}\u0000en\u0000`]: value(root.key, '["alpha-card","alpha-card"]') } } })).toThrow('manifest_collection_invalid');
  });

  it('keeps structured, boundary, derived and structural declarations disjoint and content-free where required', () => {
    const structured = { ...target('global.faq.answer', 'rich_text'), routeId: 'global', owner: 'structured_family' as const, structuredFamily: 'faq' as const };
    const result = compileMigrationArtifacts(input({
      extraction: {
        status: 'ready', targets: [structured], values: { [`${structured.key}\u0000en\u0000`]: value(structured.key, 'Synthetic answer') }, structuredFamilies: ['faq'],
        thirdPartyBoundaries: [{ key: 'page.home.map.widget', provider: 'synthetic-provider', integration: 'synthetic-integration', renderedAnchor: 'rendered:map', sourcePath: 'app/page.tsx', sourceAnchor: 'ast:map', locale: 'en', variant: null }],
        derived: [{ key: 'page.home.seo.title', routeId: 'home', locale: 'en', variant: null, sourcePath: 'app/page.tsx', sourceAnchor: 'ast:seo', derivedFrom: structured.key }],
        structural: [{ key: 'page.home.hero.mask', routeId: 'home', sourcePath: 'app/page.tsx', sourceAnchor: 'ast:mask', locale: 'en', variant: null, reason: 'aria_hidden_decorative_asset' }], needsAttention: [],
      },
      policy: { targets: [{ ...policyTarget(structured.key), liveVerification: 'global' }], collectionPolicy: [] },
    }));
    expect(result.privateManifest.structuredFamilies).toEqual(['faq']);
    expect(result.privateManifest.targets[0]).toMatchObject({ owner: 'structured_family', structuredFamily: 'faq', valueType: 'rich_text' });
    expect(result.contentFixture.values).toHaveLength(1);
    expect(result.privateManifest).toMatchObject({ thirdPartyBoundaries: expect.any(Array), derived: expect.any(Array), structural: expect.any(Array) });
    expect(JSON.stringify([result.repositoryBinding, result.runtimeExpectation])).not.toMatch(/synthetic-provider|synthetic-integration|app\/page\.tsx|ast:/u);
  });

  it('rejects forged deployed-attestation fields and never embeds any artifact self-digest', () => {
    const forged = input() as CompileMigrationArtifactsInput & { runtimeAttestation?: unknown };
    forged.runtimeAttestation = { buildId: 'forged', deployed: true };
    expect(() => compileMigrationArtifacts(forged)).toThrow('manifest_input_invalid');
    const result = compileMigrationArtifacts(input());
    for (const [name, digest] of Object.entries(result.digests)) {
      expect(JSON.stringify(result[name as keyof typeof result])).not.toContain(digest);
    }
  });

  it('emits only stable content-free errors for hostile secret-bearing inputs', () => {
    const secret = 'sk_synthetic_customer_secret';
    try {
      compileMigrationArtifacts(input({ websiteId: secret }));
      throw new Error('expected compiler to reject input');
    } catch (error) {
      expect(String(error)).toBe('Error: manifest_input_invalid');
      expect(String(error)).not.toContain(secret);
    }
  });

  it('rejects non-canonical cms-native identity and extra nested fields', () => {
    expect(() => compileMigrationArtifacts(input({
      cmsNativeProtocol: { ...input().cmsNativeProtocol, package: 'synthetic-provider' } as never,
    }))).toThrow('manifest_input_invalid');

    expect(() => compileMigrationArtifacts(input({
      extraction: { ...input().extraction, customerValue: 'Synthetic customer secret' } as never,
    }))).toThrow('manifest_input_invalid');

    expect(() => compileMigrationArtifacts(input({
      extraction: {
        ...input().extraction,
        targets: [{ ...input().extraction.targets[0]!, customerValue: 'Synthetic customer secret' } as never],
      },
    }))).toThrow('manifest_input_invalid');

    expect(() => compileMigrationArtifacts(input({
      extraction: {
        ...input().extraction,
        values: {
          'page.home.hero.heading\u0000en\u0000': { ...input().extraction.values['page.home.hero.heading\u0000en\u0000']!, extra: true } as never,
        },
      },
    }))).toThrow('manifest_input_invalid');
  });

  it('rejects nested proxies and accessors without evaluating customer code', () => {
    const secret = 'sk_synthetic_manifest_secret';
    const bundled = new Proxy([], { get() { throw new Error(secret); } });
    try {
      compileMigrationArtifacts(input({ assets: { ...input().assets, bundled } }));
      throw new Error('expected compiler to reject proxy');
    } catch (error) {
      expect(String(error)).toBe('Error: manifest_input_invalid');
      expect(String(error)).not.toContain(secret);
    }

    let reads = 0;
    const targetWithAccessor = Object.defineProperty({ ...input().extraction.targets[0] }, 'label', {
      enumerable: true, get() { reads += 1; return 'Synthetic label'; },
    });
    expect(() => compileMigrationArtifacts(input({
      extraction: { ...input().extraction, targets: [targetWithAccessor as never] },
    }))).toThrow('manifest_input_invalid');
    expect(reads).toBe(0);
  });

  it('requires image and alt pairs to be same-dimension image-to-string reciprocals', () => {
    const first = target('page.home.first.image', 'image');
    const second = target('page.home.second.image', 'image');
    const firstIdentity = { key: first.key, locale: 'en', variant: null } as const;
    const secondIdentity = { key: second.key, locale: 'en', variant: null } as const;
    const secondBytes = Buffer.from('second synthetic image bytes');
    const secondDigest = sha256(secondBytes);
    const twoImages = input({
      extraction: {
        ...input().extraction,
        targets: [first, second],
        values: {
          [`${first.key}\u0000en\u0000`]: value(first.key, imageDigest),
          [`${second.key}\u0000en\u0000`]: value(second.key, secondDigest),
        },
      },
      assets: {
        status: 'ready', blockers: [], external: [], structural: [],
        bundled: [
          { digest: imageDigest, bytes: imageBytes.byteLength, bytesValue: imageBytes, mime: 'image/png', encodedWidth: 1, encodedHeight: 1, renderedWidth: 1, renderedHeight: 1, pageCount: 1, animated: false, references: [{ id: 'first', sourcePath: 'public/first.png', target: firstIdentity, classification: 'editorial_cms', provenance: { authority: 'source_local', sourcePath: 'public/first.png' } }] },
          { digest: secondDigest, bytes: secondBytes.byteLength, bytesValue: secondBytes, mime: 'image/png', encodedWidth: 1, encodedHeight: 1, renderedWidth: 1, renderedHeight: 1, pageCount: 1, animated: false, references: [{ id: 'second', sourcePath: 'public/second.png', target: secondIdentity, classification: 'editorial_cms', provenance: { authority: 'source_local', sourcePath: 'public/second.png' } }] },
        ],
      },
      policy: {
        targets: [
          { ...policyTarget(first.key), imagePair: { role: 'image', target: secondIdentity } },
          { ...policyTarget(second.key), imagePair: { role: 'alt', target: firstIdentity } },
        ],
        collectionPolicy: [],
      },
    });
    expect(() => compileMigrationArtifacts(twoImages)).toThrow('manifest_image_pair_invalid');

    const image = target('page.home.hero.image', 'image');
    const alt = { ...target('page.home.hero.alt'), locale: 'fr' };
    const imageIdentity = { key: image.key, locale: 'en', variant: null } as const;
    const altIdentity = { key: alt.key, locale: 'fr', variant: null } as const;
    const crossLocale = input({
      extraction: {
        ...input().extraction,
        targets: [image, alt],
        values: {
          [`${image.key}\u0000en\u0000`]: value(image.key, imageDigest),
          [`${alt.key}\u0000fr\u0000`]: value(alt.key, 'Texte alternatif', 'fr'),
        },
      },
      assets: {
        status: 'ready', blockers: [], external: [], structural: [],
        bundled: [{ digest: imageDigest, bytes: imageBytes.byteLength, bytesValue: imageBytes, mime: 'image/png', encodedWidth: 1, encodedHeight: 1, renderedWidth: 1, renderedHeight: 1, pageCount: 1, animated: false, references: [{ id: 'hero', sourcePath: 'public/hero.png', target: imageIdentity, classification: 'editorial_cms', provenance: { authority: 'source_local', sourcePath: 'public/hero.png' } }] }],
      },
      policy: {
        targets: [
          { ...policyTarget(image.key), imagePair: { role: 'image', target: altIdentity } },
          { ...policyTarget(alt.key), locale: 'fr', imagePair: { role: 'alt', target: imageIdentity } },
        ],
        collectionPolicy: [],
      },
    });
    expect(() => compileMigrationArtifacts(crossLocale)).toThrow('manifest_image_pair_invalid');
  });

  it('rejects extra or malformed private declarations instead of copying unknown content', () => {
    const declaration = {
      key: 'page.home.seo.title', routeId: 'home', locale: 'en', variant: null,
      sourcePath: 'app/page.tsx', sourceAnchor: 'ast:seo', derivedFrom: identity.key,
      value: 'Synthetic customer secret',
    };
    expect(() => compileMigrationArtifacts(input({
      extraction: { ...input().extraction, derived: [declaration] },
    }))).toThrow('manifest_input_invalid');
  });

  it('revalidates strict ready-inventory shapes and external URL authority', () => {
    const image = target('page.home.hero.image', 'image');
    const imageIdentity = { key: image.key, locale: 'en', variant: null } as const;
    const imageInput = input({
      extraction: { ...input().extraction, targets: [image], values: { [`${image.key}\u0000en\u0000`]: value(image.key, imageDigest) } },
      assets: {
        status: 'ready', external: [], structural: [], blockers: [],
        bundled: [{ digest: imageDigest, bytes: imageBytes.byteLength, bytesValue: imageBytes, mime: 'image/png', encodedWidth: 1, encodedHeight: 1, renderedWidth: 1, renderedHeight: 1, pageCount: 1, animated: false, references: [{ id: 'hero', sourcePath: 'public/hero.png', target: imageIdentity, classification: 'editorial_cms', provenance: { authority: 'source_local', sourcePath: 'public/hero.png' } }], customerValue: 'Synthetic secret' } as never],
      },
      policy: { targets: [policyTarget(image.key)], collectionPolicy: [] },
    });
    expect(() => compileMigrationArtifacts(imageInput)).toThrow('manifest_input_invalid');

    const privateExternal = input({
      extraction: { ...imageInput.extraction, values: { [`${image.key}\u0000en\u0000`]: value(image.key, 'https://10.0.0.1/secret.png') } },
      assets: {
        status: 'ready', bundled: [], structural: [], blockers: [],
        external: [{ url: 'https://10.0.0.1/secret.png', privateBoundary: 'synthetic-boundary', reference: { id: 'external', sourcePath: 'remote/external', target: imageIdentity }, provenance: { authority: 'declared_external', url: 'https://10.0.0.1/secret.png', privateBoundary: 'synthetic-boundary' } }],
      },
      policy: imageInput.policy,
    });
    expect(() => compileMigrationArtifacts(privateExternal)).toThrow('manifest_input_invalid');
  });

  it('rejects unknown target enums and malformed declaration semantics', () => {
    expect(() => compileMigrationArtifacts(input({
      extraction: { ...input().extraction, targets: [{ ...input().extraction.targets[0]!, valueType: 'generic_url' as never }] },
    }))).toThrow('manifest_input_invalid');
    expect(() => compileMigrationArtifacts(input({
      extraction: {
        ...input().extraction,
        structural: [{ key: 'page.home.mask', routeId: 'home', locale: 'en', variant: null, sourcePath: 'app/page.tsx', sourceAnchor: 'ast:mask', reason: 'Synthetic customer secret' as never }],
      },
    }))).toThrow('manifest_input_invalid');
    expect(() => compileMigrationArtifacts(input({
      extraction: {
        ...input().extraction,
        derived: [{ key: 'page.home.derived', routeId: 'home', locale: 'en', variant: null, sourcePath: 'app/page.tsx', sourceAnchor: 'ast:derived', derivedFrom: 42 as never }],
      },
    }))).toThrow('manifest_input_invalid');
  });

  it('caps finite collection policy at the extraction protocol bound', () => {
    const root = target('page.home.emptyCards', 'collection');
    expect(() => compileMigrationArtifacts(input({
      extraction: { ...input().extraction, targets: [root], values: { [`${root.key}\u0000en\u0000`]: value(root.key, '[]') } },
      policy: {
        targets: [policyTarget(root.key)],
        collectionPolicy: [{ key: root.key, locale: 'en', variant: null, minimumItems: 0, maximumItems: 1_001, requiredItemIds: [] }],
      },
    }))).toThrow('manifest_collection_invalid');
  });
});
