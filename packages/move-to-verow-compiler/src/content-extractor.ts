import { createHash } from 'node:crypto';
import { extname, posix } from 'node:path';

import postcss from 'postcss';
import ts from 'typescript';

import {
  compileCollectionContentKey,
  compileContentKey,
  contentValueIdentity,
  normalizeSemanticSegment,
  semanticConfusableSkeleton,
  type ContentKeyScope,
} from './content-key.js';
import { compareCodePointStrings } from './inventory.js';

type Sha256Digest = `sha256:${string}`;

export type StructuredFamily = 'blog' | 'event' | 'social' | 'menu' | 'faq';
export type ContentOwner =
  | 'site_region'
  | 'structured_family'
  | 'derived'
  | 'structural_code';
export type ManagedContentSourceKind =
  | 'jsx'
  | 'json'
  | 'typescript'
  | 'css_content'
  | 'aria'
  | 'metadata';
export type ManagedContentValueType =
  | 'string'
  | 'rich_text'
  | 'url'
  | 'email'
  | 'telephone'
  | 'image'
  | 'collection';

interface ContentCandidateBase {
  key: string;
  label: string;
  sourceKind: ManagedContentSourceKind;
  valueType: ManagedContentValueType;
  routeId: string;
  locale: string;
  variant: string | null;
  sourcePath: string;
  sourceAnchor: string;
  thirdPartyBoundary: string | null;
}

export type ContentCandidate = ContentCandidateBase & (
  | { owner: 'site_region'; structuredFamily: null }
  | { owner: 'structured_family'; structuredFamily: StructuredFamily }
  | { owner: 'derived'; structuredFamily: null }
  | { owner: 'structural_code'; structuredFamily: null }
);

export interface AuthorizedContentSource {
  path: string;
  bytes: Uint8Array;
  digest: Sha256Digest;
}

export interface ContentRouteIdentity {
  scope: ContentKeyScope;
  pageId?: string;
}

export interface ContentLocaleVariant {
  locale: string;
  variant: string | null;
}

export interface DetectedContentIntegration {
  id: string;
  provider: string;
}

export interface ContentExtractionLimits {
  maxFiles: number;
  maxSourceBytes: number;
  maxCandidates: number;
  maxCollectionItems: number;
  maxStringBytes: number;
  maxNesting: number;
  maxThirdPartyBoundaries: number;
  maxAstNodes: number;
  maxBlockers: number;
}

export interface ContentExtractionInput {
  sources: readonly AuthorizedContentSource[];
  routeIdentities: Readonly<Record<string, ContentRouteIdentity>>;
  defaultLocale: string;
  localeVariants?: Readonly<Record<string, ContentLocaleVariant>>;
  integrations: readonly DetectedContentIntegration[];
  limits?: Partial<ContentExtractionLimits>;
}

export type ContentExtractionBlockerCode =
  | 'ambiguous_owner'
  | 'candidate_limit_exceeded'
  | 'competing_sources'
  | 'computed_human_key'
  | 'confusable_collision'
  | 'duplicate_collection_id'
  | 'duplicate_source_path'
  | 'dynamic_human_value'
  | 'invalid_source_path'
  | 'malformed_source'
  | 'missing_collection_id'
  | 'missing_locale_identity'
  | 'missing_route_identity'
  | 'normalization_collision'
  | 'source_digest_mismatch'
  | 'source_limit_exceeded'
  | 'string_limit_exceeded'
  | 'unknown_widget_provider'
  | 'unresolved_spread'
  | 'unresolved_static_reference'
  | 'unsafe_semantic_key';

export interface ContentExtractionBlocker {
  code: ContentExtractionBlockerCode;
  path: string | null;
  anchor: string | null;
}

export interface ManagedContentValue {
  key: string;
  locale: string;
  variant: string | null;
  value: string;
}

export interface ThirdPartyBoundary {
  key: string;
  provider: string;
  integration: string;
  renderedAnchor: string;
  sourcePath: string;
  sourceAnchor: string;
  locale: string;
  variant: string | null;
}

export interface DerivedContentCandidate {
  key: string;
  routeId: string;
  locale: string;
  variant: string | null;
  sourcePath: string;
  sourceAnchor: string;
  derivedFrom: string;
}

export interface StructuralContentCandidate {
  key: string;
  routeId: string;
  sourcePath: string;
  sourceAnchor: string;
  locale: string;
  variant: string | null;
  reason: 'aria_hidden_decorative_asset' | 'explicit_structural_annotation';
}

export interface ContentExtractionResult {
  status: 'ready' | 'needs_attention';
  targets: readonly ContentCandidate[];
  values: Readonly<Record<string, ManagedContentValue>>;
  structuredFamilies: readonly StructuredFamily[];
  thirdPartyBoundaries: readonly ThirdPartyBoundary[];
  derived: readonly DerivedContentCandidate[];
  structural: readonly StructuralContentCandidate[];
  needsAttention: readonly ContentExtractionBlocker[];
}

const defaultLimits: ContentExtractionLimits = {
  maxFiles: 5_000,
  maxSourceBytes: 5 * 1024 * 1024,
  maxCandidates: 10_000,
  maxCollectionItems: 1_000,
  maxStringBytes: 64 * 1024,
  maxNesting: 32,
  maxThirdPartyBoundaries: 100,
  maxAstNodes: 100_000,
  maxBlockers: 1_000,
};

const structuredFamilyOrder: readonly StructuredFamily[] = [
  'blog',
  'event',
  'faq',
  'menu',
  'social',
];

const skippedObjectFields = new Set([
  '@context',
  '@type',
  'action',
  'analyticsId',
  'endpoint',
  'formAction',
  'id',
  'slug',
]);

type StaticValue = string | number | boolean | null | readonly StaticValue[] | { readonly [key: string]: StaticValue };

interface SourceContext {
  source: AuthorizedContentSource;
  text: string;
  sourceFile: ts.SourceFile;
  declarations: Map<string, ts.Expression>;
  imports: Map<string, { imported: string; path: string }>;
  route: ContentRouteIdentity;
  locale: string;
  variant: string | null;
}

interface Evaluated {
  value?: StaticValue;
  failure?: ContentExtractionBlockerCode;
}

interface TargetDraft {
  target: ContentCandidate;
  value: string;
  rawIdentity: string;
}

function sha256(bytes: Uint8Array): Sha256Digest {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function anchor(node: ts.Node): string {
  return `ast:${node.kind}:${node.pos}-${node.end}`;
}

function cssAnchor(index: number): string {
  return `css:declaration:${index}`;
}

function scriptKind(path: string): ts.ScriptKind {
  switch (extname(path).toLowerCase()) {
    case '.js': return ts.ScriptKind.JS;
    case '.jsx': return ts.ScriptKind.JSX;
    case '.tsx': return ts.ScriptKind.TSX;
    default: return ts.ScriptKind.TS;
  }
}

function isSafeSourcePath(path: string): boolean {
  return (
    path !== '' &&
    !path.startsWith('/') &&
    !path.includes('\\') &&
    !path.includes('\0') &&
    path.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..')
  );
}

function isPlainStaticObject(value: StaticValue): value is { readonly [key: string]: StaticValue } {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isNonNullExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function propertyName(node: ts.PropertyName): string | null {
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node)) {
    return node.text;
  }
  return null;
}

function familyForRoot(root: string): StructuredFamily | null {
  const normalized = root.toLowerCase();
  if (normalized === 'blog' || normalized === 'blogs' || normalized === 'posts') return 'blog';
  if (normalized === 'event' || normalized === 'events') return 'event';
  if (normalized === 'social' || normalized === 'socials' || normalized === 'socialposts') return 'social';
  if (normalized === 'menu' || normalized === 'menus' || normalized === 'menuitems') return 'menu';
  if (normalized === 'faq' || normalized === 'faqs') return 'faq';
  return null;
}

function rootRole(root: string, family: StructuredFamily | null): string {
  return family ?? root;
}

function valueType(field: string, value: string): ManagedContentValueType {
  const normalized = field.toLowerCase();
  if (value.startsWith('mailto:') || normalized === 'email' || normalized === 'emailhref') return 'email';
  if (value.startsWith('tel:') || normalized.includes('telephone') || normalized === 'phone') return 'telephone';
  if (normalized === 'src' || normalized.endsWith('image') || normalized.endsWith('imagehref')) return 'image';
  if (normalized.endsWith('href') || normalized === 'url' || normalized.endsWith('url')) return 'url';
  if (/richtext|html|body|description|answer/u.test(normalized)) return 'rich_text';
  return 'string';
}

function resolveRelativeImport(fromPath: string, specifier: string, paths: ReadonlySet<string>): string | null {
  if (!specifier.startsWith('.')) return null;
  const base = posix.normalize(posix.join(posix.dirname(fromPath), specifier));
  const candidates = [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.jsx`, `${base}.json`, posix.join(base, 'index.ts'), posix.join(base, 'index.tsx')];
  return candidates.find((candidate) => paths.has(candidate)) ?? null;
}

function extractAttributeLiteral(
  attributes: ts.JsxAttributes,
  name: string,
): string | null {
  for (const attribute of attributes.properties) {
    if (
      !ts.isJsxAttribute(attribute) ||
      !ts.isIdentifier(attribute.name) ||
      attribute.name.text !== name ||
      !attribute.initializer
    ) continue;
    if (ts.isStringLiteral(attribute.initializer)) return attribute.initializer.text;
    if (
      ts.isJsxExpression(attribute.initializer) &&
      attribute.initializer.expression &&
      ts.isStringLiteralLike(unwrapExpression(attribute.initializer.expression))
    ) {
      return (unwrapExpression(attribute.initializer.expression) as ts.StringLiteralLike).text;
    }
  }
  return null;
}

function jsxTagName(tagName: ts.JsxTagNameExpression): string {
  return tagName.getText();
}

function jsxElementAttributes(node: ts.JsxElement | ts.JsxSelfClosingElement): ts.JsxAttributes {
  return ts.isJsxElement(node) ? node.openingElement.attributes : node.attributes;
}

function jsxElementTagName(node: ts.JsxElement | ts.JsxSelfClosingElement): ts.JsxTagNameExpression {
  return ts.isJsxElement(node) ? node.openingElement.tagName : node.tagName;
}

function jsxRole(node: ts.JsxElement | ts.JsxSelfClosingElement): string {
  const attributes = jsxElementAttributes(node);
  const explicit = extractAttributeLiteral(attributes, 'data-verow-role') ?? extractAttributeLiteral(attributes, 'id');
  if (!explicit) {
    let parent: ts.Node | undefined = node.parent;
    while (parent) {
      if (ts.isJsxElement(parent)) {
        const parentAttributes = parent.openingElement.attributes;
        const parentRole = extractAttributeLiteral(parentAttributes, 'data-verow-role') ?? extractAttributeLiteral(parentAttributes, 'id');
        if (parentRole) return parentRole;
      }
      parent = parent.parent;
    }
  }
  const raw = explicit ?? jsxTagName(jsxElementTagName(node)).split('.').at(-1) ?? 'region';
  return raw.replace(/(?:Widget|Component)$/u, '') || 'region';
}

function renderedStaticText(node: ts.JsxElement): string {
  const pieces: string[] = [];
  function visit(child: ts.JsxChild): void {
    if (ts.isJsxText(child)) {
      const text = child.text.replace(/\s+/gu, ' ').trim();
      if (text !== '') pieces.push(text);
      return;
    }
    if (ts.isJsxElement(child)) child.children.forEach(visit);
    if (ts.isJsxExpression(child) && child.expression && ts.isStringLiteralLike(child.expression)) {
      pieces.push(child.expression.text);
    }
  }
  node.children.forEach(visit);
  return pieces.join(' ').trim();
}

const supportedInlineRichTextTags = new Set([
  'b',
  'br',
  'code',
  'em',
  'i',
  'span',
  'strong',
  'sub',
  'sup',
  'u',
]);

function renderedStaticRichText(node: ts.JsxElement): string | null {
  function render(child: ts.JsxChild): string | null {
    if (ts.isJsxText(child)) return child.text.replace(/\s+/gu, ' ');
    if (ts.isJsxExpression(child)) {
      return child.expression && ts.isStringLiteralLike(child.expression)
        ? child.expression.text
        : null;
    }
    if (ts.isJsxSelfClosingElement(child)) {
      const tag = child.tagName.getText().toLowerCase();
      if (tag !== 'br' || child.attributes.properties.length !== 0) return null;
      return '<br>';
    }
    if (ts.isJsxElement(child)) {
      const tag = child.openingElement.tagName.getText().toLowerCase();
      if (!supportedInlineRichTextTags.has(tag) || child.openingElement.attributes.properties.length !== 0) return null;
      const renderedChildren: string[] = [];
      for (const nested of child.children) {
        const value = render(nested);
        if (value === null) return null;
        renderedChildren.push(value);
      }
      return `<${tag}>${renderedChildren.join('')}</${tag}>`;
    }
    return null;
  }

  const rendered: string[] = [];
  for (const child of node.children) {
    const value = render(child);
    if (value === null) return null;
    rendered.push(value);
  }
  return rendered.join('').replace(/\s+/gu, ' ').trim();
}

function ordinaryJsxField(tagName: string): string {
  const lower = tagName.toLowerCase();
  if (/^h[1-6]$/u.test(lower) || lower === 'th') return 'heading';
  if (lower === 'p') return 'body';
  if (lower === 'a' || lower === 'button' || lower === 'label') return 'label';
  if (lower === 'figcaption') return 'caption';
  if (lower === 'li') return 'itemLabel';
  if (lower === 'dt') return 'term';
  if (lower === 'dd') return 'description';
  if (lower === 'summary') return 'summary';
  return 'text';
}

function isNestedInOwnedTextSurface(node: ts.JsxElement): boolean {
  let parent: ts.Node | undefined = node.parent;
  while (parent) {
    if (ts.isJsxElement(parent)) {
      const attributes = parent.openingElement.attributes;
      if (extractAttributeLiteral(attributes, 'data-verow-field')) return true;
      const tag = parent.openingElement.tagName.getText().toLowerCase();
      if (/^(?:a|button|dd|dt|figcaption|h[1-6]|label|li|p|summary|td|th)$/u.test(tag)) return true;
    }
    parent = parent.parent;
  }
  return false;
}

function hasDirectStaticJsxText(node: ts.JsxElement): boolean {
  return node.children.some((child) => {
    if (ts.isJsxText(child)) return child.text.trim() !== '';
    return ts.isJsxExpression(child) && !!child.expression && ts.isStringLiteralLike(child.expression);
  });
}

function humanAttributeField(tagName: string, attributeName: string): string | null {
  const tag = tagName.toLowerCase();
  if (['script', 'style', 'link', 'meta'].includes(tag)) return null;
  const custom = /^\p{Lu}/u.test(tagName);
  const names: Readonly<Record<string, string>> = {
    'aria-description': 'ariaDescription',
    'aria-label': 'ariaLabel',
    alt: 'alt',
    caption: 'caption',
    errorMessage: 'errorMessage',
    helpText: 'helpText',
    href: 'href',
    label: 'label',
    placeholder: 'placeholder',
    src: 'src',
    successMessage: 'successMessage',
    title: 'title',
    validationMessage: 'validationMessage',
  };
  const field = names[attributeName];
  if (!field) return null;
  if (attributeName === 'src' && !custom && !['audio', 'img', 'source', 'video'].includes(tag)) return null;
  if (attributeName === 'href' && !custom && !['a', 'area'].includes(tag)) return null;
  if (attributeName === 'alt' && !custom && tag !== 'img') return null;
  if (attributeName === 'placeholder' && !custom && !['input', 'textarea'].includes(tag)) return null;
  if (/^(?:errorMessage|helpText|label|successMessage|validationMessage)$/u.test(attributeName) && !custom) return null;
  return field;
}

function jsonHasDuplicateObjectKeys(text: string): boolean {
  const sourceFile = ts.parseJsonText('content.json', text);
  let duplicate = false;
  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) {
      const names = new Set<string>();
      for (const property of node.properties) {
        if (!ts.isPropertyAssignment(property)) continue;
        const name = propertyName(property.name);
        if (name !== null && names.has(name)) duplicate = true;
        if (name !== null) names.add(name);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return duplicate;
}

function rawSegmentsIdentity(segments: readonly string[]): string {
  return segments.map((segment) => segment.normalize('NFC')).join('\0');
}

function rawSegmentsNormalizationIdentity(segments: readonly string[]): string {
  return segments.join('\0');
}

function safeLabel(roles: readonly string[], field: string): string {
  return [...roles, field].join('.');
}

function blockedResult(code: ContentExtractionBlockerCode): ContentExtractionResult {
  return {
    status: 'needs_attention',
    targets: [],
    values: {},
    structuredFamilies: [],
    thirdPartyBoundaries: [],
    derived: [],
    structural: [],
    needsAttention: [{ code, path: null, anchor: null }],
  };
}

export function extractManagedContent(input: ContentExtractionInput): ContentExtractionResult {
  const limits: ContentExtractionLimits = { ...defaultLimits, ...input.limits };
  if (Object.values(limits).some((value) => !Number.isSafeInteger(value) || value <= 0)) {
    return blockedResult('source_limit_exceeded');
  }
  if (input.sources.length > limits.maxFiles) return blockedResult('source_limit_exceeded');
  const blockers: ContentExtractionBlocker[] = [];
  const blockerIdentities = new Set<string>();
  const targetDrafts = new Map<string, TargetDraft>();
  const removedIdentities = new Set<string>();
  const thirdPartyBoundaries: ThirdPartyBoundary[] = [];
  const derived: DerivedContentCandidate[] = [];
  const structural: StructuralContentCandidate[] = [];
  const authorityByIdentity = new Map<string, string>();
  const authorityBySkeleton = new Map<string, string>();
  const authorityRawByIdentity = new Map<string, string>();
  const blockedAuthorities = new Set<string>();
  let attemptedCandidates = 0;
  let visitedAstNodes = 0;

  function addBlocker(code: ContentExtractionBlockerCode, path: string | null, sourceAnchor: string | null): void {
    const identity = `${code}\0${path ?? ''}\0${sourceAnchor ?? ''}`;
    if (blockerIdentities.has(identity) || blockers.length >= limits.maxBlockers) return;
    blockerIdentities.add(identity);
    blockers.push({ code, path, anchor: sourceAnchor });
  }

  if (input.defaultLocale.trim() === '') {
    addBlocker('missing_locale_identity', null, null);
  }

  const acceptedSources: AuthorizedContentSource[] = [];
  const pathCounts = new Map<string, number>();
  for (const source of input.sources) pathCounts.set(source.path, (pathCounts.get(source.path) ?? 0) + 1);
  for (const source of [...input.sources].sort((left, right) => compareCodePointStrings(left.path, right.path))) {
    if ((pathCounts.get(source.path) ?? 0) > 1) {
      addBlocker('duplicate_source_path', source.path || null, null);
      continue;
    }
    if (!isSafeSourcePath(source.path)) {
      addBlocker('invalid_source_path', source.path || null, null);
      continue;
    }
    if (source.bytes.byteLength > limits.maxSourceBytes) {
      addBlocker('source_limit_exceeded', source.path, null);
      continue;
    }
    if (sha256(source.bytes) !== source.digest) {
      addBlocker('source_digest_mismatch', source.path, null);
      continue;
    }
    if (!input.routeIdentities[source.path]) {
      addBlocker('missing_route_identity', source.path, null);
      continue;
    }
    acceptedSources.push(source);
  }

  const sourcePaths = new Set(acceptedSources.map(({ path }) => path));
  const contexts = new Map<string, SourceContext>();
  for (const source of acceptedSources) {
    const extension = extname(source.path).toLowerCase();
    if (!['.js', '.jsx', '.ts', '.tsx'].includes(extension)) continue;
    const text = new TextDecoder('utf-8', { fatal: false }).decode(source.bytes);
    const sourceFile = ts.createSourceFile(source.path, text, ts.ScriptTarget.Latest, true, scriptKind(source.path));
    const parseDiagnostics = (sourceFile as unknown as { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    if (parseDiagnostics.length > 0) {
      addBlocker('malformed_source', source.path, null);
      continue;
    }
    const declarations = new Map<string, ts.Expression>();
    const unresolvedImports: { local: string; imported: string; specifier: string }[] = [];
    for (const statement of sourceFile.statements) {
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (ts.isIdentifier(declaration.name) && declaration.initializer) declarations.set(declaration.name.text, declaration.initializer);
        }
      }
      if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && statement.importClause) {
        const specifier = statement.moduleSpecifier.text;
        if (statement.importClause.name) unresolvedImports.push({ local: statement.importClause.name.text, imported: 'default', specifier });
        const bindings = statement.importClause.namedBindings;
        if (bindings && ts.isNamedImports(bindings)) {
          for (const element of bindings.elements) unresolvedImports.push({ local: element.name.text, imported: element.propertyName?.text ?? element.name.text, specifier });
        }
      }
    }
    const imports = new Map<string, { imported: string; path: string }>();
    for (const imported of unresolvedImports) {
      const path = resolveRelativeImport(source.path, imported.specifier, sourcePaths);
      if (path) imports.set(imported.local, { imported: imported.imported, path });
    }
    const route = input.routeIdentities[source.path] as ContentRouteIdentity;
    const dimensions = input.localeVariants?.[source.path];
    contexts.set(source.path, {
      source,
      text,
      sourceFile,
      declarations,
      imports,
      route,
      locale: dimensions?.locale ?? input.defaultLocale,
      variant: dimensions?.variant ?? null,
    });
  }

  function evaluate(
    expression: ts.Expression,
    context: SourceContext,
    visiting: ReadonlySet<string> = new Set(),
    depth = 0,
  ): Evaluated {
    visitedAstNodes += 1;
    if (visitedAstNodes > limits.maxAstNodes) return { failure: 'source_limit_exceeded' };
    if (depth > limits.maxNesting) return { failure: 'source_limit_exceeded' };
    const node = unwrapExpression(expression);
    if (ts.isStringLiteralLike(node)) return { value: node.text };
    if (ts.isNumericLiteral(node)) {
      const value = Number(node.text);
      return Number.isFinite(value) ? { value } : { failure: 'dynamic_human_value' };
    }
    if (
      ts.isPrefixUnaryExpression(node) &&
      (node.operator === ts.SyntaxKind.PlusToken || node.operator === ts.SyntaxKind.MinusToken) &&
      ts.isNumericLiteral(node.operand)
    ) {
      const unsigned = Number(node.operand.text);
      const value = node.operator === ts.SyntaxKind.MinusToken ? -unsigned : unsigned;
      return Number.isFinite(value) ? { value } : { failure: 'dynamic_human_value' };
    }
    if (node.kind === ts.SyntaxKind.TrueKeyword) return { value: true };
    if (node.kind === ts.SyntaxKind.FalseKeyword) return { value: false };
    if (node.kind === ts.SyntaxKind.NullKeyword) return { value: null };
    if (ts.isNoSubstitutionTemplateLiteral(node)) return { value: node.text };
    if (ts.isTemplateExpression(node)) return { failure: 'dynamic_human_value' };
    if (ts.isArrayLiteralExpression(node)) {
      const values: StaticValue[] = [];
      for (const element of node.elements) {
        if (ts.isSpreadElement(element)) return { failure: 'unresolved_spread' };
        const result = evaluate(element, context, visiting, depth + 1);
        if (result.failure || result.value === undefined) return result;
        values.push(result.value);
      }
      return { value: values };
    }
    if (ts.isObjectLiteralExpression(node)) {
      const object: Record<string, StaticValue> = {};
      const propertyNames = new Set<string>();
      for (const property of node.properties) {
        if (ts.isSpreadAssignment(property)) return { failure: 'unresolved_spread' };
        if (ts.isGetAccessorDeclaration(property) || ts.isSetAccessorDeclaration(property) || ts.isMethodDeclaration(property)) return { failure: 'dynamic_human_value' };
        if (ts.isShorthandPropertyAssignment(property)) {
          if (propertyNames.has(property.name.text)) return { failure: 'competing_sources' };
          propertyNames.add(property.name.text);
          const result = evaluate(property.name, context, visiting, depth + 1);
          if (result.failure || result.value === undefined) return result;
          object[property.name.text] = result.value;
          continue;
        }
        if (!ts.isPropertyAssignment(property)) continue;
        const name = propertyName(property.name);
        if (name === null) return { failure: 'computed_human_key' };
        if (propertyNames.has(name)) return { failure: 'competing_sources' };
        propertyNames.add(name);
        const result = evaluate(property.initializer, context, visiting, depth + 1);
        if (result.failure || result.value === undefined) return result;
        object[name] = result.value;
      }
      return { value: object };
    }
    if (ts.isIdentifier(node)) {
      const localIdentity = `${context.source.path}\0${node.text}`;
      if (visiting.has(localIdentity)) return { failure: 'unresolved_static_reference' };
      const local = context.declarations.get(node.text);
      if (local) return evaluate(local, context, new Set([...visiting, localIdentity]), depth + 1);
      const imported = context.imports.get(node.text);
      if (imported) {
        const importedContext = contexts.get(imported.path);
        const importedExpression = importedContext?.declarations.get(imported.imported);
        if (importedContext && importedExpression) return evaluate(importedExpression, importedContext, new Set([...visiting, localIdentity]), depth + 1);
      }
      return { failure: 'unresolved_static_reference' };
    }
    if (ts.isPropertyAccessExpression(node)) {
      const parent = evaluate(node.expression, context, visiting, depth + 1);
      if (parent.failure || parent.value === undefined) return parent;
      if (!isPlainStaticObject(parent.value)) return { failure: 'unresolved_static_reference' };
      const value = parent.value[node.name.text];
      return value === undefined ? { failure: 'unresolved_static_reference' } : { value };
    }
    if (ts.isElementAccessExpression(node)) return { failure: 'computed_human_key' };
    return { failure: 'dynamic_human_value' };
  }

  function dimensions(context: SourceContext): { routeId: string; locale: string; variant: string | null } {
    return {
      routeId: context.route.scope === 'global' ? 'global' : (context.route.pageId ?? ''),
      locale: context.locale,
      variant: context.variant,
    };
  }

  function compileKey(
    context: SourceContext,
    roles: readonly string[],
    field: string,
    itemId?: string,
  ): string | null {
    try {
      return compileContentKey({
        scope: context.route.scope,
        ...(context.route.pageId === undefined ? {} : { pageId: context.route.pageId }),
        componentRole: roles,
        fieldRole: field,
        ...(itemId === undefined ? {} : { itemId }),
      });
    } catch {
      addBlocker('unsafe_semantic_key', context.source.path, null);
      return null;
    }
  }

  function claimAuthority(
    identity: string,
    category: string,
    path: string,
    sourceAnchor: string,
    rawIdentity = identity,
  ): boolean {
    if (blockedAuthorities.has(identity)) {
      addBlocker('competing_sources', path, sourceAnchor);
      return false;
    }
    const priorRawIdentity = authorityRawByIdentity.get(identity);
    if (priorRawIdentity !== undefined && priorRawIdentity !== rawIdentity) {
      addBlocker('normalization_collision', path, sourceAnchor);
      authorityByIdentity.delete(identity);
      authorityRawByIdentity.delete(identity);
      blockedAuthorities.add(identity);
      removedIdentities.add(identity);
      targetDrafts.delete(identity);
      return false;
    }
    if (authorityByIdentity.has(identity)) {
      addBlocker('competing_sources', path, sourceAnchor);
      authorityByIdentity.delete(identity);
      blockedAuthorities.add(identity);
      removedIdentities.add(identity);
      targetDrafts.delete(identity);
      return false;
    }
    const skeleton = semanticConfusableSkeleton(identity);
    const skeletonPrior = authorityBySkeleton.get(skeleton);
    if (skeletonPrior !== undefined && skeletonPrior !== identity) {
      addBlocker('confusable_collision', path, sourceAnchor);
      authorityByIdentity.delete(skeletonPrior);
      authorityBySkeleton.delete(skeleton);
      blockedAuthorities.add(skeletonPrior);
      blockedAuthorities.add(identity);
      removedIdentities.add(skeletonPrior);
      removedIdentities.add(identity);
      targetDrafts.delete(skeletonPrior);
      return false;
    }
    authorityByIdentity.set(identity, category);
    authorityBySkeleton.set(skeleton, identity);
    authorityRawByIdentity.set(identity, rawIdentity);
    return true;
  }

  function addTarget(
    context: SourceContext,
    roles: readonly string[],
    field: string,
    value: string,
    sourceKind: ManagedContentSourceKind,
    sourceAnchor: string,
    structuredFamily: StructuredFamily | null,
    itemId?: string,
    rawIdentitySegments: readonly string[] = [...roles, ...(itemId ? [itemId] : []), field],
    valueTypeOverride?: ManagedContentValueType,
  ): void {
    attemptedCandidates += 1;
    if (attemptedCandidates > limits.maxCandidates) {
      addBlocker('candidate_limit_exceeded', context.source.path, sourceAnchor);
      return;
    }
    if (Buffer.byteLength(value, 'utf8') > limits.maxStringBytes) {
      addBlocker('string_limit_exceeded', context.source.path, sourceAnchor);
      return;
    }
    const key = compileKey(context, roles, field, itemId);
    if (!key) return;
    const { routeId, locale, variant } = dimensions(context);
    if (routeId === '') {
      addBlocker('missing_route_identity', context.source.path, sourceAnchor);
      return;
    }
    if (locale.trim() === '') {
      addBlocker('missing_locale_identity', context.source.path, sourceAnchor);
      return;
    }
    const identity = contentValueIdentity(key, locale, variant);
    const rawIdentity = rawSegmentsIdentity(rawIdentitySegments);
    const exactRawIdentity = rawSegmentsNormalizationIdentity(rawIdentitySegments);
    if (!claimAuthority(identity, 'target', context.source.path, sourceAnchor, exactRawIdentity)) return;
    targetDrafts.set(identity, {
      value,
      rawIdentity,
      target: {
        key,
        label: safeLabel(roles, field),
        ...(structuredFamily
          ? { owner: 'structured_family' as const, structuredFamily }
          : { owner: 'site_region' as const, structuredFamily: null }),
        sourceKind,
        valueType: valueTypeOverride ?? valueType(field, value),
        routeId,
        locale,
        variant,
        sourcePath: context.source.path,
        sourceAnchor,
        thirdPartyBoundary: null,
      },
    });
  }

  function addCollectionTarget(
    context: SourceContext,
    roles: readonly string[],
    stableIds: readonly string[],
    sourceAnchor: string,
    structuredFamily: StructuredFamily | null,
  ): void {
    attemptedCandidates += 1;
    if (attemptedCandidates > limits.maxCandidates) {
      addBlocker('candidate_limit_exceeded', context.source.path, sourceAnchor);
      return;
    }
    let key: string;
    try {
      key = compileCollectionContentKey({
        scope: context.route.scope,
        ...(context.route.pageId === undefined ? {} : { pageId: context.route.pageId }),
        componentRole: roles,
      });
    } catch {
      addBlocker('unsafe_semantic_key', context.source.path, sourceAnchor);
      return;
    }
    const { routeId, locale, variant } = dimensions(context);
    if (routeId === '') {
      addBlocker('missing_route_identity', context.source.path, sourceAnchor);
      return;
    }
    if (locale.trim() === '') {
      addBlocker('missing_locale_identity', context.source.path, sourceAnchor);
      return;
    }
    const identity = contentValueIdentity(key, locale, variant);
    const exactRawIdentity = rawSegmentsNormalizationIdentity(roles);
    if (!claimAuthority(identity, 'collection', context.source.path, sourceAnchor, exactRawIdentity)) return;
    const kind: ManagedContentSourceKind = extname(context.source.path).toLowerCase() === '.json'
      ? 'json'
      : 'typescript';
    targetDrafts.set(identity, {
      rawIdentity: rawSegmentsIdentity(roles),
      value: JSON.stringify([...stableIds].sort(compareCodePointStrings)),
      target: {
        key,
        label: roles.join('.'),
        ...(structuredFamily
          ? { owner: 'structured_family' as const, structuredFamily }
          : { owner: 'site_region' as const, structuredFamily: null }),
        sourceKind: kind,
        valueType: 'collection',
        routeId,
        locale,
        variant,
        sourcePath: context.source.path,
        sourceAnchor,
        thirdPartyBoundary: null,
      },
    });
  }

  function staticPropertyAccessIsOwned(expression: ts.PropertyAccessExpression, context: SourceContext): boolean {
    const fields: string[] = [];
    let current: ts.Expression = expression;
    while (ts.isPropertyAccessExpression(current)) {
      fields.unshift(current.name.text);
      current = unwrapExpression(current.expression);
    }
    if (!ts.isIdentifier(current) || fields.length === 0) return false;
    let ownerContext = context;
    let root = current.text;
    if (!context.declarations.has(root)) {
      const imported = context.imports.get(root);
      const importedContext = imported ? contexts.get(imported.path) : undefined;
      if (!imported || !importedContext?.declarations.has(imported.imported)) return false;
      ownerContext = importedContext;
      root = imported.imported;
    }
    const field = fields.at(-1);
    if (!field) return false;
    const family = familyForRoot(root);
    const roles = [rootRole(root, family), ...fields.slice(0, -1)];
    const key = compileKey(ownerContext, roles, field);
    if (!key) return false;
    const ownerDimensions = dimensions(ownerContext);
    return targetDrafts.has(contentValueIdentity(key, ownerDimensions.locale, ownerDimensions.variant));
  }

  function walkStaticValue(
    value: StaticValue,
    context: SourceContext,
    roles: readonly string[],
    node: ts.Node | null,
    family: StructuredFamily | null,
    depth = 0,
    itemId?: string,
  ): void {
    visitedAstNodes += 1;
    if (visitedAstNodes > limits.maxAstNodes) {
      addBlocker('source_limit_exceeded', context.source.path, node ? anchor(node) : null);
      return;
    }
    if (depth > limits.maxNesting) {
      addBlocker('source_limit_exceeded', context.source.path, node ? anchor(node) : null);
      return;
    }
    if (value === null || typeof value === 'boolean') return;
    if (typeof value === 'string' || typeof value === 'number') {
      const field = roles.at(-1);
      const componentRoles = roles.slice(0, -1);
      if (field && componentRoles.length > 0 && !skippedObjectFields.has(field)) {
        if (
          typeof value === 'number' &&
          !Number.isFinite(value)
        ) {
          addBlocker('dynamic_human_value', context.source.path, node ? anchor(node) : null);
          return;
        }
        if (
          typeof value === 'number' &&
          !/^(?:statistics?|stats)$/iu.test(roles[0] ?? '') &&
          !/^(?:amount|count|number|percentage|rating|statistic|value|year)$/iu.test(field)
        ) return;
        const serialized = typeof value === 'number' ? JSON.stringify(value) : value;
        const kind: ManagedContentSourceKind = extname(context.source.path).toLowerCase() === '.json'
          ? 'json'
          : roles[0] === 'metadata'
            ? 'metadata'
            : 'typescript';
        addTarget(context, componentRoles, field, serialized, kind, node ? anchor(node) : 'ast:static', family, itemId);
      }
      return;
    }
    if (Array.isArray(value)) {
      if (value.length > limits.maxCollectionItems) {
        addBlocker('source_limit_exceeded', context.source.path, node ? anchor(node) : null);
        return;
      }
      const ids = new Set<string>();
      const idSkeletons = new Set<string>();
      const records: { item: { readonly [key: string]: StaticValue }; stableId: string }[] = [];
      let invalid = false;
      for (const item of value) {
        if (!isPlainStaticObject(item)) {
          addBlocker('missing_collection_id', context.source.path, node ? anchor(node) : null);
          invalid = true;
          continue;
        }
        const stableId = typeof item.id === 'string' ? item.id : typeof item.slug === 'string' ? item.slug : null;
        if (!stableId) {
          addBlocker('missing_collection_id', context.source.path, node ? anchor(node) : null);
          invalid = true;
          continue;
        }
        let normalizedId: string;
        try {
          normalizedId = normalizeSemanticSegment(stableId);
        } catch {
          addBlocker('unsafe_semantic_key', context.source.path, node ? anchor(node) : null);
          invalid = true;
          continue;
        }
        if (ids.has(normalizedId)) {
          addBlocker('duplicate_collection_id', context.source.path, node ? anchor(node) : null);
          invalid = true;
          continue;
        }
        const idSkeleton = semanticConfusableSkeleton(normalizedId);
        if (idSkeletons.has(idSkeleton)) {
          addBlocker('confusable_collision', context.source.path, node ? anchor(node) : null);
          invalid = true;
          continue;
        }
        ids.add(normalizedId);
        idSkeletons.add(idSkeleton);
        records.push({ item, stableId });
      }
      if (invalid) return;
      addCollectionTarget(context, roles, records.map(({ stableId }) => stableId), node ? anchor(node) : 'ast:static', family);
      for (const { item, stableId } of records) {
        for (const [field, child] of Object.entries(item).sort(([left], [right]) => compareCodePointStrings(left, right))) {
          if (field === 'id' || field === 'slug') continue;
          walkStaticValue(child, context, [...roles, field], node, family, depth + 1, stableId);
        }
      }
      return;
    }
    for (const [field, child] of Object.entries(value).sort(([left], [right]) => compareCodePointStrings(left, right))) {
      if (skippedObjectFields.has(field)) continue;
      walkStaticValue(child, context, [...roles, field], node, family, depth + 1, itemId);
    }
  }

  function addEvaluationFailure(context: SourceContext, node: ts.Node, failure: ContentExtractionBlockerCode): void {
    addBlocker(failure, context.source.path, anchor(node));
  }

  for (const context of contexts.values()) {
    for (const statement of context.sourceFile.statements) {
      if (!ts.isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
        const name = declaration.name.text;
        if (/^(?:content|copy|data)$/iu.test(name)) {
          addBlocker('ambiguous_owner', context.source.path, anchor(declaration));
          continue;
        }
        if (/(?:config|options|styles|tokens|analytics|endpoint)$/iu.test(name)) continue;
        const result = evaluate(declaration.initializer, context);
        if (result.failure) {
          addEvaluationFailure(context, declaration.initializer, result.failure);
          continue;
        }
        if (result.value === undefined || typeof result.value === 'string') continue;
        const family = familyForRoot(name);
        walkStaticValue(result.value, context, [rootRole(name, family)], declaration.initializer, family);
      }
    }

    const visitJsx = (node: ts.Node): void => {
      visitedAstNodes += 1;
      if (visitedAstNodes > limits.maxAstNodes) {
        addBlocker('source_limit_exceeded', context.source.path, anchor(node));
        return;
      }
      if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
        const attributes = jsxElementAttributes(node);
        const role = jsxRole(node);
        const tag = jsxTagName(jsxElementTagName(node));
        const renderedAnchor = extractAttributeLiteral(attributes, 'data-verow-boundary');
        if (renderedAnchor !== null || /Widget$/u.test(tag)) {
          const provider = extractAttributeLiteral(attributes, 'data-verow-provider');
          const integration = extractAttributeLiteral(attributes, 'data-verow-integration');
          const matchedIntegration = provider && integration
            ? input.integrations.find((item) => item.id === integration && item.provider === provider)
            : undefined;
          if (!renderedAnchor || !provider || !integration || !matchedIntegration) {
            addBlocker('unknown_widget_provider', context.source.path, anchor(node));
          } else if (thirdPartyBoundaries.length >= limits.maxThirdPartyBoundaries) {
            addBlocker('source_limit_exceeded', context.source.path, anchor(node));
          } else {
            const boundaryParts = renderedAnchor.split('.');
            const field = boundaryParts.pop();
            const key = field ? compileKey(context, boundaryParts, field) : null;
            const { locale, variant } = dimensions(context);
            const identity = key ? contentValueIdentity(key, locale, variant) : null;
            attemptedCandidates += 1;
            if (attemptedCandidates > limits.maxCandidates) {
              addBlocker('candidate_limit_exceeded', context.source.path, anchor(node));
            } else if (key && identity && claimAuthority(identity, 'boundary', context.source.path, anchor(node), renderedAnchor)) {
              thirdPartyBoundaries.push({ key, provider, integration, renderedAnchor, sourcePath: context.source.path, sourceAnchor: anchor(node), locale, variant });
            }
          }
          return;
        }

        const ariaHidden = extractAttributeLiteral(attributes, 'aria-hidden');
        const src = extractAttributeLiteral(attributes, 'src');
        if (src !== null && ariaHidden === 'true') {
          const key = compileKey(context, [role], 'src');
          const { routeId, locale, variant } = dimensions(context);
          const identity = key ? contentValueIdentity(key, locale, variant) : null;
          attemptedCandidates += 1;
          if (attemptedCandidates > limits.maxCandidates) {
            addBlocker('candidate_limit_exceeded', context.source.path, anchor(node));
          } else if (key && identity && claimAuthority(identity, 'structural', context.source.path, anchor(node), `${role}\0src`)) {
            structural.push({ key, routeId, locale, variant, sourcePath: context.source.path, sourceAnchor: anchor(node), reason: 'aria_hidden_decorative_asset' });
          }
        }

        for (const attribute of attributes.properties) {
          if (ts.isJsxSpreadAttribute(attribute)) {
            addBlocker('dynamic_human_value', context.source.path, anchor(attribute));
            continue;
          }
          if (!ts.isJsxAttribute(attribute) || !ts.isIdentifier(attribute.name)) continue;
          const field = humanAttributeField(tag, attribute.name.text);
          if (!field || !attribute.initializer) continue;
          if (field === 'src' && ariaHidden === 'true') continue;
          const sourceKind: ManagedContentSourceKind = field.startsWith('aria') ? 'aria' : 'jsx';
          if (ts.isStringLiteral(attribute.initializer)) {
            addTarget(context, [role], field, attribute.initializer.text, sourceKind, anchor(attribute), null);
            continue;
          }
          if (ts.isJsxExpression(attribute.initializer) && attribute.initializer.expression) {
            const expression = unwrapExpression(attribute.initializer.expression);
            const result = evaluate(expression, context);
            if (result.failure) {
              addEvaluationFailure(context, expression, result.failure);
            } else if (
              (typeof result.value === 'string' || typeof result.value === 'number') &&
              (ts.isIdentifier(expression) || ts.isStringLiteralLike(expression) || ts.isNumericLiteral(expression))
            ) {
              addTarget(context, [role], field, typeof result.value === 'number' ? JSON.stringify(result.value) : result.value, sourceKind, anchor(attribute), null);
            } else if (
              (typeof result.value === 'string' || typeof result.value === 'number') &&
              ts.isPropertyAccessExpression(expression) &&
              !staticPropertyAccessIsOwned(expression, context)
            ) {
              addBlocker('ambiguous_owner', context.source.path, anchor(attribute));
            }
          }
        }

        const explicitField = extractAttributeLiteral(attributes, 'data-verow-field');
        if (explicitField && ts.isJsxElement(node)) {
          const hasNestedMarkup = node.children.some((child) => ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child));
          const text = hasNestedMarkup ? renderedStaticRichText(node) : renderedStaticText(node);
          if (text === null) {
            addBlocker('dynamic_human_value', context.source.path, anchor(node));
          } else if (text !== '') {
            addTarget(context, [role], explicitField, text, 'jsx', anchor(node), null);
          }
        }

        if (!explicitField && ts.isJsxElement(node) && !isNestedInOwnedTextSurface(node)) {
          const tagName = node.openingElement.tagName.getText();
          const knownTextTag = /^(?:a|button|dd|dt|figcaption|h[1-6]|label|li|p|span|summary|td|th)$/iu.test(tagName);
          const customComponent = /^\p{Lu}/u.test(tagName);
          if (knownTextTag || customComponent || hasDirectStaticJsxText(node)) {
            const ordinaryField = ordinaryJsxField(tagName);
            const hasNestedMarkup = node.children.some((child) => ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child));
            const text = hasNestedMarkup ? renderedStaticRichText(node) : renderedStaticText(node);
            if (text === null) {
              if (renderedStaticText(node) !== '') addBlocker('dynamic_human_value', context.source.path, anchor(node));
            } else if (text !== '') {
              addTarget(
                context,
                [role],
                ordinaryField,
                text,
                'jsx',
                anchor(node),
                null,
                undefined,
                [role, ordinaryField],
                hasNestedMarkup || ordinaryField === 'body' ? 'rich_text' : undefined,
              );
            }
          }
        }

        const derivedFrom = extractAttributeLiteral(attributes, 'data-verow-derived-from');
        if (derivedFrom && ts.isJsxElement(node)) {
          for (const child of node.children) {
            if (!ts.isJsxExpression(child) || !child.expression) continue;
            const expressionText = child.expression.getText().replace(/\s+/gu, '');
            if (derivedFrom === 'system.currentYear' && expressionText === 'newDate().getFullYear()') {
              const field = explicitField ?? 'value';
              const key = compileKey(context, [role], field);
              const resultDimensions = dimensions(context);
              const identity = key ? contentValueIdentity(key, resultDimensions.locale, resultDimensions.variant) : null;
              attemptedCandidates += 1;
              if (attemptedCandidates > limits.maxCandidates) {
                addBlocker('candidate_limit_exceeded', context.source.path, anchor(child));
              } else if (key && identity && claimAuthority(identity, 'derived', context.source.path, anchor(child), `${role}\0${field}`)) {
                derived.push({ key, ...resultDimensions, sourcePath: context.source.path, sourceAnchor: anchor(child), derivedFrom });
              }
            } else {
              addBlocker('dynamic_human_value', context.source.path, anchor(child));
            }
          }
        }
      }

      if (ts.isJsxExpression(node) && node.expression) {
        const parentElement = ts.isJsxElement(node.parent) ? node.parent : null;
        const parentAttributes = parentElement?.openingElement.attributes;
        const isDerived = parentAttributes && extractAttributeLiteral(parentAttributes, 'data-verow-derived-from');
        if (!isDerived) {
          const result = evaluate(node.expression, context);
          if (result.failure) addEvaluationFailure(context, node.expression, result.failure);
          else if (
            (typeof result.value === 'string' || typeof result.value === 'number') &&
            parentElement &&
            (ts.isStringLiteralLike(unwrapExpression(node.expression)) || ts.isIdentifier(unwrapExpression(node.expression)))
          ) {
            const role = jsxRole(parentElement);
            const field = extractAttributeLiteral(parentElement.openingElement.attributes, 'data-verow-field') ?? ordinaryJsxField(parentElement.openingElement.tagName.getText());
            addTarget(context, [role], field, typeof result.value === 'number' ? JSON.stringify(result.value) : result.value, 'jsx', anchor(node), null);
          } else if (
            (typeof result.value === 'string' || typeof result.value === 'number') &&
            ts.isPropertyAccessExpression(unwrapExpression(node.expression)) &&
            !staticPropertyAccessIsOwned(unwrapExpression(node.expression) as ts.PropertyAccessExpression, context)
          ) {
            addBlocker('ambiguous_owner', context.source.path, anchor(node));
          }
        }
      }
      ts.forEachChild(node, visitJsx);
    };
    visitJsx(context.sourceFile);
  }

  for (const source of acceptedSources) {
    const context = contexts.get(source.path);
    const extension = extname(source.path).toLowerCase();
    const route = input.routeIdentities[source.path];
    if (!route) continue;
    const localeDimensions = input.localeVariants?.[source.path];
    const genericContext: SourceContext = context ?? {
      source,
      text: new TextDecoder().decode(source.bytes),
      sourceFile: ts.createSourceFile(source.path, '', ts.ScriptTarget.Latest),
      declarations: new Map(),
      imports: new Map(),
      route,
      locale: localeDimensions?.locale ?? input.defaultLocale,
      variant: localeDimensions?.variant ?? null,
    };

    if (extension === '.json') {
      if (jsonHasDuplicateObjectKeys(genericContext.text)) {
        addBlocker('competing_sources', source.path, 'json:object');
        continue;
      }
      try {
        const parsed: unknown = JSON.parse(genericContext.text);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError('root');
        for (const [root, value] of Object.entries(parsed).sort(([left], [right]) => compareCodePointStrings(left, right))) {
          if (skippedObjectFields.has(root)) continue;
          if (typeof value === 'string') addTarget(genericContext, ['document'], root, value, 'json', 'json:pointer', null);
          else walkStaticValue(value as StaticValue, genericContext, [root], null, familyForRoot(root));
        }
      } catch {
        addBlocker('malformed_source', source.path, null);
      }
    }

    if (extension === '.css') {
      try {
        const root = postcss.parse(genericContext.text, { from: undefined });
        let declarationIndex = 0;
        root.walkDecls('content', (declaration) => {
          const match = /^(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)')$/u.exec(declaration.value.trim());
          if (!match) {
            addBlocker('dynamic_human_value', source.path, cssAnchor(declarationIndex));
            declarationIndex += 1;
            return;
          }
          const selector = declaration.parent?.type === 'rule' ? declaration.parent.selector : '';
          const selectorMatch = /\.([\p{L}_][\p{L}\p{N}_-]*)/u.exec(selector);
          if (!selectorMatch?.[1]) {
            addBlocker('ambiguous_owner', source.path, cssAnchor(declarationIndex));
            declarationIndex += 1;
            return;
          }
          addTarget(genericContext, [selectorMatch[1]], 'generatedContent', match[1] ?? match[2] ?? '', 'css_content', cssAnchor(declarationIndex), null);
          declarationIndex += 1;
        });
      } catch {
        addBlocker('malformed_source', source.path, null);
      }
    }
  }

  const uniqueBlockers = new Map<string, ContentExtractionBlocker>();
  for (const blocker of blockers) {
    const identity = `${blocker.code}\0${blocker.path ?? ''}\0${blocker.anchor ?? ''}`;
    uniqueBlockers.set(identity, blocker);
  }
  const needsAttention = [...uniqueBlockers.values()].sort((left, right) =>
    compareCodePointStrings(`${left.code}\0${left.path ?? ''}\0${left.anchor ?? ''}`, `${right.code}\0${right.path ?? ''}\0${right.anchor ?? ''}`),
  );
  const drafts = [...targetDrafts.values()].sort((left, right) =>
    compareCodePointStrings(contentValueIdentity(left.target.key, left.target.locale, left.target.variant), contentValueIdentity(right.target.key, right.target.locale, right.target.variant)),
  );
  const values = Object.fromEntries(drafts.map(({ target, value }) => {
    const identity = contentValueIdentity(target.key, target.locale, target.variant);
    return [identity, { key: target.key, locale: target.locale, variant: target.variant, value } satisfies ManagedContentValue];
  }));
  const targets = drafts.map(({ target }) => target);
  const structuredFamilies = structuredFamilyOrder.filter((family) => targets.some((target) => target.structuredFamily === family));

  const validBoundaries = thirdPartyBoundaries.filter((item) =>
    !blockedAuthorities.has(contentValueIdentity(item.key, item.locale, item.variant)),
  );
  const validDerived = derived.filter((item) =>
    !blockedAuthorities.has(contentValueIdentity(item.key, item.locale, item.variant)),
  );
  const validStructural = structural.filter((item) =>
    !blockedAuthorities.has(contentValueIdentity(item.key, item.locale, item.variant)),
  );
  validBoundaries.sort((left, right) => compareCodePointStrings(left.key, right.key));
  validDerived.sort((left, right) => compareCodePointStrings(left.key, right.key));
  validStructural.sort((left, right) => compareCodePointStrings(left.key, right.key));

  return {
    status: needsAttention.length === 0 ? 'ready' : 'needs_attention',
    targets,
    values,
    structuredFamilies,
    thirdPartyBoundaries: validBoundaries,
    derived: validDerived,
    structural: validStructural,
    needsAttention,
  };
}
