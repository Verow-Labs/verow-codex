import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { describe, expect, expectTypeOf, it } from 'vitest';

import {
  extractManagedContent,
  type AuthorizedContentSource,
  type ContentCandidate,
  type ContentExtractionInput,
} from './content-extractor.js';

const fixtureRoot = resolve(import.meta.dirname, '..', 'fixtures', 'sites-content-surfaces');

function digest(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function fixtureFiles(directory = fixtureRoot): Promise<AuthorizedContentSource[]> {
  const files: AuthorizedContentSource[] = [];
  async function visit(path: string): Promise<void> {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const absolute = join(path, entry.name);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile()) {
        const bytes = await readFile(absolute);
        files.push({
          path: relative(directory, absolute).split('\\').join('/'),
          bytes,
          digest: digest(bytes),
        });
      }
    }
  }
  await visit(directory);
  return files;
}

function source(path: string, text: string): AuthorizedContentSource {
  const bytes = Buffer.from(text);
  return { path, bytes, digest: digest(bytes) };
}

function inputFor(
  sources: readonly AuthorizedContentSource[],
  overrides: Partial<ContentExtractionInput> = {},
): ContentExtractionInput {
  return {
    sources,
    routeIdentities: {
      'app/page.tsx': { scope: 'page', pageId: 'home' },
      'app/about/page.tsx': { scope: 'page', pageId: 'about' },
      'app/styles.css': { scope: 'page', pageId: 'home' },
      'components/site-shell.tsx': { scope: 'global' },
      'content/collections.ts': { scope: 'page', pageId: 'home' },
      'content/seo.json': { scope: 'page', pageId: 'home' },
      'content/structured.ts': { scope: 'global' },
    },
    defaultLocale: 'en',
    localeVariants: {
      'app/about/page.tsx': { locale: 'fr', variant: 'mobile' },
    },
    integrations: [{ id: 'synthetic-map', provider: 'maps.example' }],
    ...overrides,
  };
}

async function extractFixture(overrides: Partial<ContentExtractionInput> = {}) {
  return extractManagedContent(inputFor(await fixtureFiles(), overrides));
}

describe('managed content extraction', () => {
  it('encodes editable ownership as a discriminated union', () => {
    expectTypeOf<Extract<ContentCandidate, { owner: 'site_region' }>['structuredFamily']>().toEqualTypeOf<null>();
    expectTypeOf<Extract<ContentCandidate, { owner: 'structured_family' }>['structuredFamily']>().toEqualTypeOf<'blog' | 'event' | 'social' | 'menu' | 'faq'>();
  });
  it('owns every representative source surface exactly once', async () => {
    const result = await extractFixture();
    const targetByKey = new Map(result.targets.map((target) => [target.key, target]));

    expect(result.status).toBe('ready');
    expect(result.needsAttention).toEqual([]);
    expect(targetByKey.get('page.home.hero.heading')).toMatchObject({ owner: 'site_region', sourceKind: 'typescript' });
    expect(targetByKey.get('page.home.hero.richText')).toMatchObject({ valueType: 'rich_text' });
    expect(targetByKey.get('page.home.hero.primaryCta.href')).toMatchObject({ valueType: 'url' });
    expect(targetByKey.get('page.home.contact.emailHref')).toMatchObject({ valueType: 'email' });
    expect(targetByKey.get('page.home.contact.telephoneHref')).toMatchObject({ valueType: 'telephone' });
    expect(targetByKey.get('page.home.editorialImage.src')).toMatchObject({ valueType: 'image' });
    expect(targetByKey.get('page.home.editorialImage.alt')).toBeDefined();
    expect(targetByKey.get('page.home.inquiryForm.namePlaceholder')).toBeDefined();
    expect(targetByKey.get('page.home.inquiryForm.nameHelp')).toBeDefined();
    expect(targetByKey.get('page.home.inquiryForm.successMessage')).toBeDefined();
    expect(targetByKey.get('page.home.inquiryForm.validationMessage')).toBeDefined();
    expect(targetByKey.get('page.home.main.ariaLabel')).toMatchObject({ sourceKind: 'aria' });
    expect(targetByKey.get('global.header.primaryNavigation.items.about.label')).toBeDefined();
    expect(targetByKey.get('global.footer.contact.email')).toBeDefined();
    expect(targetByKey.get('global.footer.legal.privacyLabel')).toBeDefined();
    expect(targetByKey.get('page.home.metadata.openGraph.title')).toMatchObject({ sourceKind: 'metadata' });
    expect(targetByKey.get('page.home.organization.description')).toMatchObject({ sourceKind: 'json' });
    expect(targetByKey.get('page.home.testimonial.generatedContent')).toMatchObject({ sourceKind: 'css_content' });
    expect(targetByKey.get('page.home.intro.richText')).toMatchObject({ sourceKind: 'jsx', valueType: 'rich_text' });
    expect(result.values['page.home.intro.richText\u0000en\u0000']?.value).toBe('Synthetic JSX <strong>rich text</strong>.');
    expect(targetByKey.get('page.home.ordinary.heading')).toMatchObject({ sourceKind: 'jsx' });
    expect(targetByKey.get('page.home.ordinary.body')).toMatchObject({ sourceKind: 'jsx', valueType: 'rich_text' });
    expect(result.values['page.home.ordinary.body\u0000en\u0000']?.value).toBe('Synthetic ordinary <em>rich text</em>.');
    expect(targetByKey.get('page.home.featureImage.src')).toMatchObject({ sourceKind: 'jsx', valueType: 'image' });
    expect(targetByKey.get('page.home.featureImage.alt')).toBeDefined();
    expect(targetByKey.get('page.home.secondaryCta.href')).toMatchObject({ valueType: 'url' });
    expect(targetByKey.get('page.home.secondaryCta.title')).toBeDefined();
    expect(targetByKey.get('page.home.search.placeholder')).toBeDefined();
    expect(targetByKey.get('page.home.statistics.items.uptime.value')).toBeDefined();
    expect(result.values['page.home.statistics.items.uptime.value\u0000en\u0000']?.value).toBe('99');
    expect(targetByKey.get('global.header.primaryNavigation')).toMatchObject({ valueType: 'collection' });
    expect(targetByKey.get('page.home.featureCards')).toMatchObject({ valueType: 'collection' });
    expect(targetByKey.get('page.home.testimonials')).toMatchObject({ valueType: 'collection' });
    expect(new Set(result.targets.map(({ valueType }) => valueType))).toEqual(new Set(['string', 'rich_text', 'url', 'email', 'telephone', 'image', 'collection']));
    expect(new Set(result.targets.map((target) => `${target.key}\u0000${target.locale}\u0000${target.variant ?? ''}`)).size).toBe(result.targets.length);
    expect(Object.keys(result.values)).toHaveLength(result.targets.length);
  });

  it('records a content-free ownership certification snapshot with no numeric key segments', async () => {
    const result = await extractFixture();
    const evidence = {
      status: result.status,
      targets: result.targets.map(({ key, owner, structuredFamily, sourceKind, valueType, locale, variant }) => ({
        key,
        owner,
        structuredFamily,
        sourceKind,
        valueType,
        locale,
        variant,
      })),
      thirdPartyBoundaries: result.thirdPartyBoundaries.map(({ key, provider, integration, renderedAnchor }) => ({ key, provider, integration, renderedAnchor })),
      derived: result.derived.map(({ key, derivedFrom }) => ({ key, derivedFrom })),
      structural: result.structural.map(({ key, reason }) => ({ key, reason })),
      blockers: result.needsAttention,
    };

    expect(result.targets.some(({ key }) => key.split('.').some((segment) => /^\d+$/u.test(segment)))).toBe(false);
    expect(evidence).toMatchSnapshot();
  });

  it('separates exact structured families without duplicate site-region authority', async () => {
    const result = await extractFixture();
    expect(result.structuredFamilies).toEqual(['faq', 'menu']);
    expect(result.targets).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: 'global.faq.items.syntheticQuestion.question', owner: 'structured_family', structuredFamily: 'faq' }),
      expect.objectContaining({ key: 'global.menu.items.syntheticItem.name', owner: 'structured_family', structuredFamily: 'menu' }),
    ]));
    expect(result.targets.filter(({ key }) => key.startsWith('global.faq.')).every(({ owner, structuredFamily }) => owner === 'structured_family' && structuredFamily === 'faq')).toBe(true);
  });

  it('declares widget internals but keeps its wrapper copy site-owned', async () => {
    const result = await extractFixture();
    expect(result.targets).toContainEqual(expect.objectContaining({ key: 'page.home.map.heading', owner: 'site_region' }));
    expect(result.thirdPartyBoundaries).toEqual([
      expect.objectContaining({ key: 'page.home.map.widget', provider: 'maps.example', integration: 'synthetic-map' }),
    ]);
    expect(JSON.stringify(result.thirdPartyBoundaries)).not.toContain('Synthetic map wrapper heading');
  });

  it('never traverses or owns third-party boundary attributes, text, or descendants', () => {
    const sources = [source('app/page.tsx', `export default () => <section id="map">
      <h2>Site-owned wrapper</h2>
      <MapWidget data-verow-boundary="map.widget" data-verow-provider="maps.example" data-verow-integration="synthetic-map" title="Vendor title" aria-label="Vendor label">
        <span>Vendor internal copy</span>
      </MapWidget>
    </section>;`)];
    const result = extractManagedContent(inputFor(sources));
    expect(result.status).toBe('ready');
    expect(result.targets).toContainEqual(expect.objectContaining({ key: 'page.home.map.heading' }));
    expect(result.thirdPartyBoundaries).toHaveLength(1);
    expect(result.targets.some(({ key }) => key.includes('mapWidget') || key.endsWith('.title') || key.endsWith('.ariaLabel'))).toBe(false);
    expect(JSON.stringify(result.values)).not.toContain('Vendor');
  });

  it('evaluates supported human attributes and blocks calls or JSX spreads', () => {
    const resolved = extractManagedContent(inputFor([
      source('app/page.tsx', `const placeholder = 'Synthetic resolved placeholder';
        export default () => <FormField data-verow-role="inquiry" placeholder={placeholder} label="Synthetic label" helpText="Synthetic help" successMessage="Synthetic success" validationMessage="Synthetic validation" />;`),
    ]));
    expect(resolved.status).toBe('ready');
    expect(resolved.targets.map(({ key }) => key)).toEqual(expect.arrayContaining([
      'page.home.inquiry.placeholder',
      'page.home.inquiry.label',
      'page.home.inquiry.helpText',
      'page.home.inquiry.successMessage',
      'page.home.inquiry.validationMessage',
    ]));

    for (const text of [
      'export default () => <input placeholder={getCopy()} />;',
      'const props = {}; export default () => <input {...props} />;',
    ]) {
      const blocked = extractManagedContent(inputFor([source('app/page.tsx', text)]));
      expect(blocked.status).toBe('needs_attention');
      expect(blocked.needsAttention.map(({ code }) => code)).toEqual(expect.arrayContaining(['dynamic_human_value']));
    }
  });

  it('recognizes property-access JSX values already owned by a supported static object and blocks unowned ones', () => {
    const owned = extractManagedContent(inputFor([source('app/page.tsx', `const fieldCopy = { placeholder: 'Synthetic property placeholder' } as const;
      export default () => <input data-verow-role="inquiry" placeholder={fieldCopy.placeholder} />;`)]));
    expect(owned.status).toBe('ready');
    expect(owned.targets).toContainEqual(expect.objectContaining({ key: 'page.home.fieldCopy.placeholder' }));

    const unowned = extractManagedContent(inputFor([source('app/page.tsx', `const fieldConfig = { placeholder: 'Synthetic property placeholder' } as const;
      export default () => <input data-verow-role="inquiry" placeholder={fieldConfig.placeholder} />;`)]));
    expect(unowned.status).toBe('needs_attention');
    expect(unowned.needsAttention.map(({ code }) => code)).toContain('ambiguous_owner');
  });

  it('blocks repeated unannotated JSX fields instead of inventing positional keys', () => {
    const sources = [source('app/page.tsx', 'export default () => <section id="details"><p>First synthetic paragraph.</p><p>Second synthetic paragraph.</p></section>;')];
    const result = extractManagedContent(inputFor(sources));
    expect(result.status).toBe('needs_attention');
    expect(result.needsAttention.map(({ code }) => code)).toContain('competing_sources');
    expect(result.targets.some(({ key }) => key === 'page.home.details.body')).toBe(false);
    expect(JSON.stringify(result.needsAttention)).not.toContain('synthetic paragraph');
  });

  it('owns local and relative static scalar references at their rendered semantic surface', () => {
    const localSources = [source('app/page.tsx', "const heading = 'Synthetic local heading'; export default () => <section id=\"hero\"><h1>{heading}</h1></section>;")];
    const local = extractManagedContent(inputFor(localSources));
    expect(local.status).toBe('ready');
    expect(local.targets).toContainEqual(expect.objectContaining({ key: 'page.home.hero.heading', sourceKind: 'jsx' }));

    const importedSources = [
      source('app/page.tsx', "import { heading } from '../content/copy'; export default () => <section id=\"hero\"><h1>{heading}</h1></section>;"),
      source('content/copy.ts', "export const heading = 'Synthetic imported heading';"),
    ];
    const imported = extractManagedContent(inputFor(importedSources, {
      routeIdentities: {
        'app/page.tsx': { scope: 'page', pageId: 'home' },
        'content/copy.ts': { scope: 'page', pageId: 'home' },
      },
    }));
    expect(imported.status).toBe('ready');
    expect(imported.targets).toContainEqual(expect.objectContaining({ key: 'page.home.hero.heading', sourceKind: 'jsx' }));
  });

  it('owns ordinary visible text on common semantic tags and custom components', () => {
    const sources = [source('app/page.tsx', `export default () => <main>
      <li data-verow-role="featureItem">Synthetic item</li>
      <span data-verow-role="badge">Synthetic badge</span>
      <table><tbody><tr><th data-verow-role="column">Synthetic column</th><td data-verow-role="cell">Synthetic cell</td></tr></tbody></table>
      <dl><dt data-verow-role="term">Synthetic term</dt><dd data-verow-role="definition">Synthetic definition</dd></dl>
      <details><summary data-verow-role="details">Synthetic summary</summary></details>
      <PromoCard data-verow-role="promotion">Synthetic promotion</PromoCard>
    </main>;`)];
    const result = extractManagedContent(inputFor(sources));
    expect(result.status).toBe('ready');
    expect(result.targets.map(({ key }) => key)).toEqual(expect.arrayContaining([
      'page.home.featureItem.itemLabel',
      'page.home.badge.text',
      'page.home.column.heading',
      'page.home.cell.text',
      'page.home.term.term',
      'page.home.definition.description',
      'page.home.details.summary',
      'page.home.promotion.text',
    ]));
  });

  it('traverses static objects with non-content boolean and null literals without coercing them', () => {
    const sources = [source('app/page.tsx', "const hero = { enabled: true, optionalNote: null, heading: 'Synthetic heading' } as const; const statistics = [{ id: 'change', value: -5 }];")];
    const result = extractManagedContent(inputFor(sources));
    expect(result.status).toBe('ready');
    expect(result.targets).toContainEqual(expect.objectContaining({ key: 'page.home.hero.heading' }));
    expect(result.targets.some(({ key }) => key.endsWith('.enabled') || key.endsWith('.optionalNote'))).toBe(false);
    expect(result.values['page.home.statistics.items.change.value\u0000en\u0000']?.value).toBe('-5');
  });

  it('rejects duplicate source paths independent of input order', () => {
    const first = source('app/page.tsx', "const hero = { heading: 'First synthetic value' };");
    const second = source('app/page.tsx', "const hero = { heading: 'Second synthetic value' };");
    for (const sources of [[first, second], [second, first]]) {
      const result = extractManagedContent(inputFor(sources));
      expect(result.status).toBe('needs_attention');
      expect(result.targets).toEqual([]);
      expect(result.needsAttention.map(({ code }) => code)).toContain('duplicate_source_path');
      expect(JSON.stringify(result.needsAttention)).not.toContain('synthetic value');
    }
  });

  it('rejects duplicate static TypeScript and JSON object keys', () => {
    const typescript = extractManagedContent(inputFor([source('app/page.tsx', "const hero = { heading: 'First', heading: 'Second' };")]));
    expect(typescript.status).toBe('needs_attention');
    expect(typescript.targets).toEqual([]);
    expect(typescript.needsAttention.map(({ code }) => code)).toContain('competing_sources');

    const json = extractManagedContent(inputFor([source('content/seo.json', '{"hero":{"heading":"First","heading":"Second"}}')], {
      routeIdentities: { 'content/seo.json': { scope: 'page', pageId: 'home' } },
    }));
    expect(json.status).toBe('needs_attention');
    expect(json.targets).toEqual([]);
    expect(json.needsAttention.map(({ code }) => code)).toContain('competing_sources');
  });

  it('validates limits and caps candidate attempts independently from collisions', () => {
    for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY, -1, 0]) {
      const result = extractManagedContent(inputFor([source('app/page.tsx', "const hero = { heading: 'Synthetic heading' };")], { limits: { maxFiles: invalid } }));
      expect(result.status).toBe('needs_attention');
      expect(result.targets).toEqual([]);
      expect(result.needsAttention.map(({ code }) => code)).toContain('source_limit_exceeded');
    }
    const limited = extractManagedContent(inputFor([source('app/page.tsx', `export default () => <section id="hero"><h1>One</h1><h1>Two</h1><h1>Three</h1></section>;`)], {
      limits: { maxCandidates: 1 },
    }));
    expect(limited.status).toBe('needs_attention');
    expect(limited.needsAttention.map(({ code }) => code)).toContain('candidate_limit_exceeded');
  });

  it('blocks cross-category authority collisions and ignores structural script/link attributes', () => {
    const collision = extractManagedContent(inputFor([source('app/page.tsx', `const decoration = { src: '/editorial.svg' };
      export default () => <img data-verow-role="decoration" src="/decorative.svg" aria-hidden="true" />;`)]));
    expect(collision.status).toBe('needs_attention');
    expect(collision.needsAttention.map(({ code }) => code)).toContain('competing_sources');
    expect(collision.targets.some(({ key }) => key === 'page.home.decoration.src')).toBe(false);
    expect(collision.structural.some(({ key }) => key === 'page.home.decoration.src')).toBe(false);

    const confusable = extractManagedContent(inputFor([source('app/page.tsx', `const team = { widget: 'Synthetic site value' };
      export default () => <MapWidget data-verow-boundary="tearn.widget" data-verow-provider="maps.example" data-verow-integration="synthetic-map" />;`)]));
    expect(confusable.status).toBe('needs_attention');
    expect(confusable.needsAttention.map(({ code }) => code)).toContain('confusable_collision');
    expect(confusable.targets).toEqual([]);
    expect(confusable.thirdPartyBoundaries).toEqual([]);

    const structuralOnly = extractManagedContent(inputFor([source('app/page.tsx', `export default () => <><script src="/analytics.js" /><link href="/styles.css" rel="stylesheet" /></>;`)]));
    expect(structuralOnly.status).toBe('ready');
    expect(structuralOnly.targets).toEqual([]);
  });

  it('separates objective structural and explicitly identified derived candidates', async () => {
    const result = await extractFixture();
    expect(result.structural).toContainEqual(expect.objectContaining({ key: 'page.home.decoration.src', reason: 'aria_hidden_decorative_asset' }));
    expect(result.derived).toContainEqual(expect.objectContaining({ key: 'page.home.copyright.year', derivedFrom: 'system.currentYear' }));
    expect(result.targets.some(({ key }) => key === 'page.home.decoration.src' || key === 'page.home.copyright.year')).toBe(false);
  });

  it('uses explicit page, global, locale, and variant identities independently from route paths', async () => {
    const result = await extractFixture();
    expect(result.targets).toContainEqual(expect.objectContaining({ key: 'page.about.overview.heading', routeId: 'about', locale: 'fr', variant: 'mobile' }));
    expect(result.targets).toContainEqual(expect.objectContaining({ key: 'global.footer.contact.email', routeId: 'global', locale: 'en', variant: null }));

    const renamed = (await fixtureFiles()).map((file) => file.path === 'app/about/page.tsx' ? { ...file, path: 'app/company/page.tsx' } : file);
    const routeIdentities = { ...inputFor(renamed).routeIdentities };
    delete routeIdentities['app/about/page.tsx'];
    routeIdentities['app/company/page.tsx'] = { scope: 'page', pageId: 'about' };
    const localeVariants = { 'app/company/page.tsx': { locale: 'fr', variant: 'mobile' } };
    const moved = extractManagedContent(inputFor(renamed, { routeIdentities, localeVariants }));
    expect(moved.targets).toContainEqual(expect.objectContaining({ key: 'page.about.overview.heading' }));
  });

  it('keeps keys invariant when wording, collection order, object order, formatting, and source enumeration change', async () => {
    const files = await fixtureFiles();
    const first = extractManagedContent(inputFor(files));
    const mutated = files.toReversed().map((file) => {
      let text = Buffer.from(file.bytes).toString('utf8');
      if (file.path === 'content/collections.ts') {
        text = `export const featureCards = [
  { body: 'Changed clear body', heading: 'Changed clear heading', id: 'clear' },
  { body: 'Changed fast body', heading: 'Changed fast heading', id: 'fast' },
] as const;

export const testimonials = [
  { attribution: 'Changed Person B', quote: 'Changed testimonial B', slug: 'sample-b' },
  { attribution: 'Changed Person A', quote: 'Changed testimonial A', slug: 'sample-a' },
] as const;

export const statistics = [
  { suffix: '%', value: 101, label: 'Changed uptime', id: 'uptime' },
] as const;
`;
      }
      return source(file.path, text);
    });
    const second = extractManagedContent(inputFor(mutated));
    expect(second.targets.map(({ key, locale, variant, owner }) => ({ key, locale, variant, owner }))).toEqual(first.targets.map(({ key, locale, variant, owner }) => ({ key, locale, variant, owner })));
  });

  it.each([
    ['duplicate key', [source('app/page.tsx', "const hero = { heading: 'One' }; const hero2 = { heading: 'Two' }; export default () => <h1 data-verow-role=\"hero\" data-verow-field=\"heading\">Three</h1>;")], 'competing_sources'],
    ['normalization collision', [source('app/page.tsx', "const hero = { 'Primary CTA': 'One', primaryCta: 'Two' };")], 'normalization_collision'],
    ['confusable collision', [source('app/page.tsx', "const team = { heading: 'One' }; const tearn = { heading: 'Two' };")], 'confusable_collision'],
    ['missing collection id', [source('app/page.tsx', "const cards = [{ heading: 'One' }];")], 'missing_collection_id'],
    ['duplicate collection id', [source('app/page.tsx', "const cards = [{ id: 'same', heading: 'One' }, { id: 'same', heading: 'Two' }];")], 'duplicate_collection_id'],
    ['dynamic expression', [source('app/page.tsx', 'export default () => <h1>{getHeading()}</h1>;')], 'dynamic_human_value'],
    ['computed key', [source('app/page.tsx', "const hero = { ['head' + 'ing']: 'One' };")], 'computed_human_key'],
    ['spread', [source('app/page.tsx', "const base = { heading: 'One' }; const hero = { ...base };")], 'unresolved_spread'],
    ['unresolved import', [source('app/page.tsx', "import { heading } from './missing'; export default () => <h1>{heading}</h1>;")], 'unresolved_static_reference'],
    ['ambiguous owner', [source('app/page.tsx', "const content = { heading: 'One' };")], 'ambiguous_owner'],
    ['unknown widget provider', [source('app/page.tsx', 'export default () => <MysteryWidget data-verow-boundary="map.widget" />;')], 'unknown_widget_provider'],
  ])('fails closed for %s with content-free deterministic evidence', (_name, sources, expectedCode) => {
    const result = extractManagedContent(inputFor(sources));
    expect(result.status).toBe('needs_attention');
    expect(result.needsAttention.map(({ code }) => code)).toContain(expectedCode);
    const evidence = JSON.stringify(result.needsAttention);
    for (const text of ['One', 'Two', 'Three', 'heading', 'getHeading', 'MysteryWidget']) expect(evidence).not.toContain(text);
  });

  it.each([
    ['missing route identity', { routeIdentities: {} }, 'missing_route_identity'],
    ['missing locale', { defaultLocale: '' }, 'missing_locale_identity'],
  ])('blocks %s safely', async (_name, overrides, expectedCode) => {
    const result = await extractFixture(overrides as Partial<ContentExtractionInput>);
    expect(result.status).toBe('needs_attention');
    expect(result.needsAttention.map(({ code }) => code)).toContain(expectedCode);
  });

  it('rejects digest drift and bounded-limit overflow without exposing values', () => {
    const file = source('app/page.tsx', "const hero = { heading: 'Sensitive synthetic value' };");
    const drifted = { ...file, digest: `sha256:${'0'.repeat(64)}` as const };
    const drift = extractManagedContent(inputFor([drifted]));
    expect(drift.needsAttention.map(({ code }) => code)).toContain('source_digest_mismatch');
    expect(JSON.stringify(drift.needsAttention)).not.toContain('Sensitive synthetic value');

    const limited = extractManagedContent(inputFor([file], { limits: { maxFiles: 0 } }));
    expect(limited.needsAttention.map(({ code }) => code)).toContain('source_limit_exceeded');
  });
});
