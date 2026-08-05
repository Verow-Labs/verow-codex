import ts from 'typescript';

export type SitesHostingShimClassification = 'known_shim' | 'unsafe_shim' | 'not_shim';

const knownShimSources: Readonly<Record<string, string>> = {
  'worker/index.ts': `import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface Env {
  ASSETS: {
    fetch(request: Request): Promise<Response>;
  };
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
    }

    return handler.fetch(request, env, ctx);
  },
};

export default worker;
`,
  'build/sites-vite-plugin.ts': `import { cp, mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import type { Plugin } from "vite";

export function sites(): Plugin {
  let root = process.cwd();

  return {
    name: "sites",
    apply: "build",
    configResolved(config) {
      root = config.root;
    },
    async closeBundle() {
      const outputDirectory = resolve(root, "dist", ".openai");
      const hostingConfig = resolve(root, ".openai", "hosting.json");

      await rm(outputDirectory, { recursive: true, force: true });
      await mkdir(outputDirectory, { recursive: true });
      await cp(hostingConfig, resolve(outputDirectory, "hosting.json"));
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
    const tokenText = token === ts.SyntaxKind.StringLiteral
      ? scanner.getTokenValue()
      : scanner.getTokenText();
    tokens.push(`${token}:${tokenText}`);
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
