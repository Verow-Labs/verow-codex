import ts from 'typescript';

export type SitesHostingShimClassification = 'known_shim' | 'unsafe_shim' | 'not_shim';

const knownShimSources: Readonly<Record<string, string>> = {
  'worker/index.ts': `import handler from 'vinext/server/app-router-entry';
import {
  DEFAULT_DEVICE_SIZES,
  DEFAULT_IMAGE_SIZES,
  handleImageOptimization,
} from 'vinext/server/image-optimization';

interface Env {
  ASSETS: { fetch(request: Request): Promise<Response> };
  IMAGES: {
    input(body: ReadableStream): {
      transform(transforms: unknown): { output(options: unknown): Promise<Response> };
    };
  };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);
    if (url.pathname === '/_vinext/image') {
      return handleImageOptimization(request, {
        deviceSizes: DEFAULT_DEVICE_SIZES,
        imageSizes: DEFAULT_IMAGE_SIZES,
        fetcher: env.ASSETS.fetch.bind(env.ASSETS),
        transformer: async (body, transforms, output) =>
          env.IMAGES.input(body).transform(transforms).output(output),
      });
    }
    return handler.fetch(request, env, ctx);
  },
};
`,
  'build/sites-vite-plugin.ts': `import { copyFile, mkdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

import type { Plugin } from 'vite';

const hostingSource = resolve('.openai/hosting.json');
const hostingDirectory = resolve('dist/.openai');
const hostingDestination = resolve(hostingDirectory, 'hosting.json');

export function sitesHostingMetadataPlugin(): Plugin {
  return {
    name: 'sites-hosting-metadata',
    async closeBundle() {
      await rm(hostingDirectory, { recursive: true, force: true });
      await mkdir(hostingDirectory, { recursive: true });
      await copyFile(hostingSource, hostingDestination);
    },
  };
}
`,
};

function tokenFingerprint(source: string): string {
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    true,
    ts.LanguageVariant.Standard,
    source,
  );
  const tokens: string[] = [];
  for (let token = scanner.scan(); token !== ts.SyntaxKind.EndOfFileToken; token = scanner.scan()) {
    tokens.push(`${token}:${scanner.getTokenText()}`);
  }
  return tokens.join('\0');
}

const knownShimFingerprints = new Map(
  Object.entries(knownShimSources).map(([path, source]) => [path, tokenFingerprint(source)]),
);

export function classifySitesHostingShim(
  path: string,
  content: Uint8Array,
): SitesHostingShimClassification {
  const expected = knownShimFingerprints.get(path);
  if (expected === undefined) return 'not_shim';
  const actual = tokenFingerprint(new TextDecoder('utf-8', { fatal: false }).decode(content));
  return actual === expected ? 'known_shim' : 'unsafe_shim';
}
