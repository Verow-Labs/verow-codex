import { describe, expect, it } from 'vitest';

import {
  compileCollectionContentKey,
  compileContentKey,
  contentKeyConfusablesProvenance,
  contentValueIdentity,
  normalizeSemanticSegment,
  semanticConfusableSkeleton,
} from './content-key.js';

describe('semantic content keys', () => {
  it('compiles page and global keys from immutable semantic roles', () => {
    expect(
      compileContentKey({
        scope: 'page',
        pageId: 'home',
        componentRole: ['hero', 'primaryCta'],
        fieldRole: 'href',
      }),
    ).toBe('page.home.hero.primaryCta.href');
    expect(
      compileContentKey({
        scope: 'global',
        componentRole: ['header'],
        fieldRole: 'primaryNavigation',
      }),
    ).toBe('global.header.primaryNavigation');
    expect(
      compileContentKey({
        scope: 'global',
        componentRole: ['footer', 'contact'],
        fieldRole: 'email',
      }),
    ).toBe('global.footer.contact.email');
  });

  it('uses an explicit stable collection identity and never a numeric index', () => {
    expect(
      compileCollectionContentKey({
        scope: 'global',
        componentRole: ['header', 'primaryNavigation'],
      }),
    ).toBe('global.header.primaryNavigation');
    expect(
      compileContentKey({
        scope: 'page',
        pageId: 'home',
        componentRole: ['featureCards'],
        itemId: 'fast-card',
        fieldRole: 'heading',
      }),
    ).toBe('page.home.featureCards.items.fastCard.heading');
    expect(() =>
      compileContentKey({
        scope: 'page',
        pageId: 'home',
        componentRole: ['featureCards'],
        itemId: '0',
        fieldRole: 'heading',
      }),
    ).toThrow('unsafe_semantic_segment');
  });

  it('normalizes the safe ASCII profile deterministically and rejects Unicode confusables', () => {
    expect(normalizeSemanticSegment('Primary CTA')).toBe('primaryCta');
    expect(normalizeSemanticSegment('CTA')).toBe('cta');
    expect(normalizeSemanticSegment('feature2')).toBe('feature2');
    expect(normalizeSemanticSegment(normalizeSemanticSegment('Primary CTA'))).toBe('primaryCta');
    expect(() => normalizeSemanticSegment('Cafe\u0301')).toThrow('unsafe_semantic_segment');
    expect(() => normalizeSemanticSegment('Ρrofile')).toThrow('unsafe_semantic_segment');
    expect(() => normalizeSemanticSegment('κey')).toThrow('unsafe_semantic_segment');
  });

  it.each(['', 'items', 'page', 'global', '__proto__', 'two..parts', '9', 'a/b', 'line:12'])(
    'rejects the empty, reserved, numeric, or unsafe segment %j',
    (segment) => {
      expect(() => normalizeSemanticSegment(segment)).toThrow('unsafe_semantic_segment');
    },
  );

  it.each(['ITEMS', 'Page', '__PROTO__'])(
    'rejects reserved segments case-insensitively: %s',
    (segment) => {
      expect(() => normalizeSemanticSegment(segment)).toThrow('unsafe_semantic_segment');
    },
  );

  it('includes key, locale, and variant in collision identity', () => {
    expect(contentValueIdentity('page.home.hero.heading', 'en', null)).toBe(
      'page.home.hero.heading\u0000en\u0000',
    );
    expect(contentValueIdentity('page.home.hero.heading', 'en', 'mobile')).not.toBe(
      contentValueIdentity('page.home.hero.heading', 'en', null),
    );
  });

  it('pins the complete Unicode 17 UTS 39 skeleton subset for the admitted ASCII domain', () => {
    expect(contentKeyConfusablesProvenance).toMatchObject({
      unicodeVersion: '17.0.0',
      sha256: '091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a',
    });
    expect(semanticConfusableSkeleton('team')).toBe(semanticConfusableSkeleton('tearn'));
    expect(semanticConfusableSkeleton('hero0')).toBe(semanticConfusableSkeleton('heroO'));
    expect(semanticConfusableSkeleton('card1')).toBe(semanticConfusableSkeleton('cardl'));
  });
});
