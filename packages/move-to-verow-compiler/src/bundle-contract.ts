import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

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
const vectorsBytes = readFileSync(vectorsUrl);

export const bundleContractProvenance = readJson(
  provenanceUrl,
) as BundleContractProvenance;
export const canonicalDigestVectors = readJson(vectorsUrl) as readonly CanonicalDigestVector[];

const actualSchemaDigest = sha256(schemaBytes);
const declaredSchemaDigest = readFileSync(schemaDigestUrl, 'utf8').trim();
if (
  actualSchemaDigest !== declaredSchemaDigest ||
  actualSchemaDigest !== bundleContractProvenance.sha256 ||
  bundleContractProvenance.files['migration-bundle.schema.json'] !== actualSchemaDigest
) {
  throw new Error('vendored migration bundle schema provenance mismatch');
}
if (
  sha256(vectorsBytes) !== bundleContractProvenance.canonicalVectorsSha256 ||
  bundleContractProvenance.files['canonical-digest-vectors.json'] !== sha256(vectorsBytes) ||
  !/^[0-9a-f]{40}$/u.test(bundleContractProvenance.sourceCommit)
) {
  throw new Error('vendored canonical digest vector provenance mismatch');
}

const ajv = new Ajv({ allErrors: true, strict: true });
const validateDescriptor = ajv.compile(readJson(schemaUrl) as AnySchema);

function formatAjvErrors(errors: readonly ErrorObject[] | null | undefined): readonly string[] {
  return (errors ?? []).map(
    ({ instancePath, message }) => `${instancePath || '/'} ${message ?? 'is invalid'}`,
  );
}

export function validateBundleDescriptor(value: unknown): ContractValidationResult {
  const valid = validateDescriptor(value) === true;
  return { valid, errors: valid ? [] : formatAjvErrors(validateDescriptor.errors) };
}

function canonicalJson(value: unknown, ancestors: Set<object>): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON numbers must be finite');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object') throw new TypeError('value is not canonical JSON');
  if (ancestors.has(value)) throw new TypeError('canonical JSON cannot contain cycles');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((item) => canonicalJson(item, ancestors)).join(',')}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('canonical JSON objects must be plain objects');
    }
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key], ancestors)}`)
      .join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalDigest(value: unknown): `sha256:${string}` {
  return sha256(canonicalJson(value, new Set()));
}

const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const safePayloadPathPattern = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\)[^\0]+$/u;

export function validatePayloadIndex(value: unknown): ContractValidationResult {
  const errors: string[] = [];
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { valid: false, errors: ['/ must be an object'] };
  }
  const object = value as Record<string, unknown>;
  if (object.version !== 'move-to-verow.payload-index.v1') {
    errors.push('/version must equal move-to-verow.payload-index.v1');
  }
  if (!Array.isArray(object.entries) || object.entries.length === 0) {
    errors.push('/entries must be a non-empty array');
  } else {
    const paths: string[] = [];
    for (const [index, entry] of object.entries.entries()) {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        errors.push(`/entries/${index} must be an object`);
        continue;
      }
      const item = entry as Record<string, unknown>;
      if (typeof item.path !== 'string' || !safePayloadPathPattern.test(item.path)) {
        errors.push(`/entries/${index}/path must be a safe relative path`);
      } else {
        paths.push(item.path);
        if (item.path === 'verow/payload-index.json') {
          errors.push(`/entries/${index}/path must not index the payload index itself`);
        }
      }
      if (!Number.isSafeInteger(item.bytes) || (item.bytes as number) < 0) {
        errors.push(`/entries/${index}/bytes must be a non-negative safe integer`);
      }
      const digest = item.digest ?? item.sha256;
      if (typeof digest !== 'string' || !digestPattern.test(digest)) {
        errors.push(`/entries/${index}/digest must be a sha256 digest`);
      }
    }
    const sorted = [...paths].sort();
    if (new Set(paths).size !== paths.length) errors.push('/entries paths must be unique');
    if (paths.some((path, index) => path !== sorted[index])) {
      errors.push('/entries must be sorted by path');
    }
  }
  return { valid: errors.length === 0, errors };
}

for (const vector of canonicalDigestVectors) {
  if (canonicalDigest(vector.value) !== vector.digest) {
    throw new Error(`canonical digest vector failed: ${vector.id}`);
  }
}
