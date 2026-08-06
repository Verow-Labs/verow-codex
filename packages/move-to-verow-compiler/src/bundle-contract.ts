import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { types as nodeUtilTypes } from 'node:util';

import { Ajv, type AnySchema, type ErrorObject } from 'ajv';

export interface BundleContractProvenance {
  sourceCommit: string;
  sha256: `sha256:${string}`;
  canonicalVectorsSha256: `sha256:${string}`;
  files: Readonly<Record<string, `sha256:${string}`>>;
}

export interface CanonicalDigestVector {
  id: string;
  value: unknown;
  digest: `sha256:${string}`;
}

export interface ContractValidationResult {
  valid: boolean;
  errors: readonly string[];
}

function sha256(bytes: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function readJson(path: URL): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

const schemaUrl = new URL('../contracts/migration-bundle.schema.json', import.meta.url);
const schemaDigestUrl = new URL('../contracts/migration-bundle.schema.sha256', import.meta.url);
const vectorsUrl = new URL('../contracts/canonical-digest-vectors.json', import.meta.url);
const provenanceUrl = new URL('../contracts/provenance.json', import.meta.url);
const schemaBytes = readFileSync(schemaUrl);
const schemaDigestBytes = readFileSync(schemaDigestUrl);
const vectorsBytes = readFileSync(vectorsUrl);

export const bundleContractProvenance = readJson(provenanceUrl) as BundleContractProvenance;
export const canonicalDigestVectors = readJson(vectorsUrl) as readonly CanonicalDigestVector[];

export function verifyBundleContractArtifacts(input: {
  schemaBytes: Uint8Array;
  schemaDigestBytes: Uint8Array;
  vectorsBytes: Uint8Array;
  provenance: BundleContractProvenance;
}): void {
  const actualSchemaDigest = sha256(input.schemaBytes);
  const declaredSchemaDigest = new TextDecoder().decode(input.schemaDigestBytes).trim();
  if (
    sha256(input.schemaDigestBytes) !== input.provenance.files['migration-bundle.schema.sha256']
  ) {
    throw new Error('vendored schema digest file provenance mismatch');
  }
  if (
    actualSchemaDigest !== declaredSchemaDigest ||
    actualSchemaDigest !== input.provenance.sha256 ||
    input.provenance.files['migration-bundle.schema.json'] !== actualSchemaDigest
  ) {
    throw new Error('vendored migration bundle schema provenance mismatch');
  }
  const actualVectorsDigest = sha256(input.vectorsBytes);
  if (
    actualVectorsDigest !== input.provenance.canonicalVectorsSha256 ||
    input.provenance.files['canonical-digest-vectors.json'] !== actualVectorsDigest ||
    !/^[0-9a-f]{40}$/u.test(input.provenance.sourceCommit)
  ) {
    throw new Error('vendored canonical digest vector provenance mismatch');
  }
}

verifyBundleContractArtifacts({
  schemaBytes,
  schemaDigestBytes,
  vectorsBytes,
  provenance: bundleContractProvenance,
});

const ajv = new Ajv({ allErrors: true, strict: true });
const validateDescriptor = ajv.compile(readJson(schemaUrl) as AnySchema);

function formatAjvErrors(errors: readonly ErrorObject[] | null | undefined): readonly string[] {
  return (errors ?? []).map(
    ({ instancePath, message }) => `${instancePath || '/'} ${message ?? 'is invalid'}`,
  );
}

export function validateBundleDescriptor(value: unknown): ContractValidationResult {
  const valid = validateDescriptor(value) === true;
  return {
    valid,
    errors: valid ? [] : formatAjvErrors(validateDescriptor.errors),
  };
}

function canonicalJson(value: unknown, ancestors: Set<object>): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw canonicalValueError();
    return JSON.stringify(value);
  }
  if (
    typeof value !== 'object' ||
    value === null ||
    nodeUtilTypes.isProxy(value) ||
    ancestors.has(value)
  ) {
    throw canonicalValueError();
  }
  ancestors.add(value);
  try {
    return Array.isArray(value)
      ? canonicalArray(value, ancestors)
      : canonicalObject(value, ancestors);
  } finally {
    ancestors.delete(value);
  }
}

function canonicalArray(value: unknown[], ancestors: Set<object>): string {
  if (Object.getPrototypeOf(value) !== Array.prototype) throw canonicalValueError();
  if (Object.getOwnPropertySymbols(value).length > 0) throw canonicalValueError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).filter((key) => key !== 'length');
  if (keys.length !== value.length) throw canonicalValueError();
  const values: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
      throw canonicalValueError();
    }
    values.push(canonicalJson(descriptor.value, ancestors));
  }
  return `[${values.join(',')}]`;
}

function canonicalObject(value: object, ancestors: Set<object>): string {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw canonicalValueError();
  if (Object.getOwnPropertySymbols(value).length > 0) throw canonicalValueError();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const properties = Object.keys(descriptors)
    .sort()
    .map((key) => {
      const descriptor = descriptors[key];
      if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
        throw canonicalValueError();
      }
      return `${JSON.stringify(key)}:${canonicalJson(descriptor.value, ancestors)}`;
    });
  return `{${properties.join(',')}}`;
}

function canonicalValueError(): Error {
  return new Error('Expected a logical canonical JSON value.');
}

export function canonicalDigest(value: unknown): `sha256:${string}` {
  return sha256(canonicalJson(value, new Set()));
}

export function canonicalJsonBytes(value: unknown): Uint8Array {
  return Buffer.from(canonicalJson(value, new Set()), 'utf8');
}

const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const payloadIndexKeys = ['entries', 'version'];
const payloadEntryKeys = ['bytes', 'digest', 'mode', 'path'];

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function safePayloadPath(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const path = value.normalize('NFC');
  if (path === '' || path.startsWith('/') || path.includes('\\') || /\p{Cc}/u.test(path)) {
    return null;
  }
  if (path.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    return null;
  }
  return path;
}

function compareCanonicalPaths(left: string, right: string): number {
  return Buffer.from(left.normalize('NFC'), 'utf8').compare(
    Buffer.from(right.normalize('NFC'), 'utf8'),
  );
}

export function validatePayloadIndex(value: unknown): ContractValidationResult {
  const errors: string[] = [];
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { valid: false, errors: ['/ must be an object'] };
  }
  const object = value as Record<string, unknown>;
  if (!hasExactKeys(object, payloadIndexKeys)) errors.push('/ must use strict payload-index keys');
  if (object.version !== 'move-to-verow.payload-index.v1') {
    errors.push('/version must equal move-to-verow.payload-index.v1');
  }
  if (!Array.isArray(object.entries)) {
    errors.push('/entries must be an array');
  } else {
    const paths: string[] = [];
    for (const [index, entry] of object.entries.entries()) {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        errors.push(`/entries/${index} must be an object`);
        continue;
      }
      const item = entry as Record<string, unknown>;
      if (!hasExactKeys(item, payloadEntryKeys)) {
        errors.push(`/entries/${index} must use strict payload-entry keys`);
      }
      const path = safePayloadPath(item.path);
      if (path === null) {
        errors.push(`/entries/${index}/path must be a safe relative path`);
      } else {
        paths.push(path);
        if (path === 'verow/payload-index.json') {
          errors.push(`/entries/${index}/path must not index the payload index itself`);
        }
      }
      if (!Number.isSafeInteger(item.bytes) || (item.bytes as number) < 0) {
        errors.push(`/entries/${index}/bytes must be a non-negative safe integer`);
      }
      if (typeof item.digest !== 'string' || !digestPattern.test(item.digest)) {
        errors.push(`/entries/${index}/digest must be a sha256 digest`);
      }
      if (
        !Number.isSafeInteger(item.mode) ||
        (item.mode as number) < 0 ||
        (item.mode as number) > 0o7777
      ) {
        errors.push(`/entries/${index}/mode must be an unsigned file mode`);
      }
    }
    if (new Set(paths).size !== paths.length) errors.push('/entries paths must be unique');
    for (let index = 1; index < paths.length; index += 1) {
      if (compareCanonicalPaths(paths[index - 1] ?? '', paths[index] ?? '') >= 0) {
        errors.push('/entries must use canonical UTF-8 byte ordering');
      }
    }
  }
  return { valid: errors.length === 0, errors };
}

for (const vector of canonicalDigestVectors) {
  if (canonicalDigest(vector.value) !== vector.digest) {
    throw new Error(`canonical digest vector failed: ${vector.id}`);
  }
}
