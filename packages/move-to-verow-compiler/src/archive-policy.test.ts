import { describe, expect, it } from 'vitest';

import {
  ARCHIVE_LIMITS,
  assertArchiveEntries,
  type BundleEntryInput,
} from './index.js';

const bytes = new TextEncoder().encode('synthetic');
const entry = (path: string, overrides: Partial<BundleEntryInput> = {}): BundleEntryInput => ({
  path,
  bytes,
  executable: false,
  ...overrides,
});

describe('migration archive admission policy', () => {
  it('admits NFC UTF-8 source paths and an explicitly requested shebang script', () => {
    expect(() =>
      assertArchiveEntries([
        entry('app/café/page.tsx'),
        entry('scripts/build.mjs', {
          bytes: new TextEncoder().encode('#!/usr/bin/env node\n'),
          executable: true,
        }),
        entry('empty.txt', { bytes: new Uint8Array() }),
      ]),
    ).not.toThrow();
  });

  it.each([
    '',
    '/absolute',
    'C:/drive.txt',
    '//server/share',
    '../escape',
    'app/./page.tsx',
    'app//page.tsx',
    'app\\page.tsx',
    'app/pa\nge.tsx',
    'cafe\u0301.txt',
    'verow/payload-index.json',
    '.env',
    '.env.production',
    '.dev.vars.local',
    '.git/config',
    'node_modules/pkg/index.js',
    '.pnpm-store/v3/index',
    '.next/server/app.js',
    '.wrangler/state.json',
    '.vite/cache.json',
    'coverage/lcov.info',
    'dist/index.js',
    'build/output.js',
    '.history/page.tsx',
    '.bash_history',
    '.DS_Store',
    '.npmrc',
    '.pypirc',
    'keys/id_rsa',
    'keys/private.pem',
    'state/main.tfstate',
    '.move-to-verow/receipt.json',
    'fixture.zip',
    'bundle.tar.gz',
    'native/addon.node',
    'bin/program.exe',
    '.netrc',
    'config/secrets.json',
    'config/api-token.txt',
    'config/api-key.txt',
    'config/access_token.json',
    'config/client-secret.yaml',
    'config/credentials.json',
    'config/token.json',
    'config/service-account.json',
    'config/service_account_key.json',
    'config/service-account-credentials.json',
    '.git-credentials',
    '.ssh/id_rsa.pub',
    'keys/id_ecdsa',
    'keys/id_dsa',
    '.docker/config.json',
    'config/access_token',
    'config/private-key',
    'config/github-token',
    'config/stripe-secret',
    'config/aws_credentials',
    'config/google-service-account',
    '.kube/config',
    '.config/gh/hosts.yml',
    '.config/gcloud/credentials.db',
    '.azure/accessTokens.json',
    '.cargo/credentials.toml',
    'composer/auth.json',
    'config/credentials.toml',
    'config/token.yaml',
    'config/secret.env',
    'config/auth.json',
    'config/openai-api-key',
    'config/openaiApiKey.json',
    'config/sendgrid_api_key.txt',
    'config/aws-access-key-id',
    'config/awsAccessKeyId.json',
    'config/api-secret.json',
    'config/access-credential.json',
    'config/private-token.yaml',
    'config/client-key.json',
    'config/service-secret.env',
    'config/tokens.yaml',
    'config/auth-token.json',
    'config/auth-live-secret.yaml',
    'config/production-auth-key.toml',
    'config/auth-prod-credentials.json',
    'config/refresh-token.json',
    'config/refresh-live-secret.yaml',
    'config/prod-refresh-key.toml',
    'config/refresh-production-credentials.json',
    'config/github-production-token.json',
    'config/production-github-token.json',
    'config/stripe-live-secret.env',
    'config/openai-token-production.yaml',
    'config/supabase-token-prod.toml',
    'fixture.zst',
    'bundle.tar.zst',
    'bundle.tar.zstd',
    'fixture.lz4',
    'fixture.cab',
    'fixture.cpio',
    'fixture.pdf',
  ])('rejects forbidden candidate path %s with a content-free code', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it('does not confuse ordinary source names with credential material', () => {
    expect(() =>
      assertArchiveEntries([
        entry('config/design-token.json'),
        entry('config/token-bucket.json'),
        entry('config/secret-santa.json'),
        entry('styles/design-tokens.css'),
        entry('lib/tokenizer.ts'),
        entry('people/secretary.ts'),
        entry('styles/keyframes.css'),
        entry('lib/api-client.ts'),
        entry('lib/authentication.ts'),
        entry('lib/auth-provider.ts'),
        entry('config/auth-provider.json'),
        entry('config/authentication.json'),
        entry('config/refresh-rate.json'),
        entry('config/github-auth-provider.json'),
        entry('config/site.json'),
        entry('config/theme.yaml'),
        entry('config/design-tokens.json'),
        entry('docker/config.example.json'),
      ]),
    ).not.toThrow();
  });

  it('classifies Unicode compatibility credential names after normalization without changing paths', () => {
    for (const path of [
      'config/ａｐｉＫｅｙ.json',
      'config/ｃｌｉｅｎｔＳｅｃｒｅｔ.yaml',
      'config/ｓｅｒｖｉｃｅＡｃｃｏｕｎｔ.toml',
      'config/𝖆𝖕𝖎Key.json',
      'config/ApiKEY.json',
    ]) {
      expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
    }

    expect(() =>
      assertArchiveEntries([
        entry('config/ｄｅｓｉｇｎＴｏｋｅｎ.json'),
        entry('config/ｔｏｋｅｎＢｕｃｋｅｔ.json'),
      ]),
    ).not.toThrow();
  });

  it.each([
    'config/api-production-secret.json',
    'config/credentials-release-access.yaml',
    'config/client-live-key.yml',
    'config/private-production-token.toml',
    'config/service-beta-secrets.env',
    'config/sanity-release-token.ini',
    'config/token-production-npm.txt',
    'config/oauth-live-credential.db',
    'config/key-production-bearer',
    'config/session-beta-credentials.json',
    'config/token-production-authentication.yaml',
    'config/authorization-prod-secret.toml',
    'config/key.json',
    'config/key',
    'config/github／production／token.json',
    'config/production：openai：secret.yaml',
    'config/supabase·production·token.toml',
  ])('rejects semantic credential basename %s across qualifiers and Unicode separators', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/github-token-count.json',
    'config/auth-token-bucket.yaml',
    'config/refresh-production-token-count.toml',
    'config/openai-production-token-bucket.env',
    'config/stripe-secret-santa.ini',
    'config/github-production-secret-santa',
    'config/sanity-design-token.txt',
    'config/npm-design-tokens.db',
    'config/authentication-token-count.yml',
    'config/github-token.js',
    'config/oauth-secret.ts',
    'config/session-key.css',
  ])('admits complete benign credential-like unit %s without weakening extension policy', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'config/github-token-count-secret.json',
    'config/refresh-token-bucket-key.yaml',
    'config/openai-secret-santa-token.toml',
    'config/authentication-design-token-credentials.env',
    'config/secret-santa-production-npm-key.ini',
    'config/design-tokens-oauth-secret.txt',
    'config/sanity-token-count-bearer-secret',
  ])('rejects unconsumed credential token in combined benign and sensitive basename %s', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/keys',
    'config/keys.json',
    'config/api-keys.yaml',
    'config/client-keys.toml',
    'config/private-keys.ini',
    'config/access-keys.txt',
    'config/production-key',
    'config/live-secret',
    'config/staging-token',
    'config/prod-credentials',
    'config/key.local',
    'config/secret.production',
    'config/token.release',
    'config/design-token-secret',
    'config/token-bucket-key',
    'config/secret-santa-keys.custom',
  ])('rejects every residual sensitive token in non-source basename %s', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'src/auth-token.js',
    'src/auth-token.jsx',
    'src/auth-token.ts',
    'src/auth-token.tsx',
    'src/auth-token.cjs',
    'src/auth-token.mjs',
    'styles/design-token-secret.css',
    'styles/design-token-secret.scss',
    'styles/design-token-secret.sass',
    'styles/design-token-secret.less',
    'pages/client-secret.html',
    'docs/private-key.md',
    'docs/private-key.mdx',
  ])('admits credential-like source basename %s only for a reviewed source extension', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'config/design-token.release',
    'config/design-tokens.custom',
    'config/token-bucket.local',
    'config/token-count.production',
    'config/secret-santa.stage',
    'config/keyframes.local',
    'config/tokenizer.production',
    'config/secretary.release',
    'config/authentication.json',
  ])('admits non-source basename %s when no unconsumed sensitive token remains', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'config/credentials.json.ts',
    'config/private-key.yaml.js',
    'config/token.env.mjs',
    'config/secret.toml.tsx',
    'config/CLIENTSECRET.JSON.TS',
  ])('rejects credential data filename %s hidden behind a source suffix', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/credentials.json.test.ts',
    'config/private-key.pem.spec.ts',
    'config/secrets.env.generated.js',
    'config/access-token.yaml.client.mjs',
    'config/keys.toml.fixture.tsx',
    'config/auth-token.db.browser.jsx',
    'config/token.txt.module.css',
  ])('rejects risky suffix %s anywhere in the pre-source dotted chain', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'src/auth-token.js',
    'src/foo.test.ts',
    'src/component.stories.tsx',
    'src/schema.ts',
    'src/credential-form.test.ts',
  ])('preserves ordinary reviewed source filename %s without a risky inner suffix', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'config/client.secret',
    'config/api.token',
    'config/private.credentials',
    'config/access.tokens',
    'config/design-token.secret',
    'config/token-bucket.credentials',
    'config/secret-santa.keys',
  ])('classifies the complete non-source basename %s including its final segment', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/APIKEY.json',
    'config/APIKEYS.release',
    'config/CLIENTSECRET.yaml',
    'config/ACCESSTOKENS.production',
    'config/SERVICEACCOUNT.toml',
    'config/OAUTHSECRET-prod.conf',
    'config/NPMTOKEN.stage',
  ])('rejects exact uppercase credential compound %s without substring matching', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/SECRETKEY',
    'config/SECRETKEYS',
    'config/MASTERKEY',
    'config/ENCRYPTIONKEY',
    'config/SIGNINGKEY',
    'config/PASSWORD',
    'config/PASSWORDS',
    'config/PASSPHRASE',
    'config/PASSPHRASES',
    'config/MASTERPASSPHRASE',
    'config/DBPASSWORD',
    'config/DATABASEPASSWORD',
    'config/USERPASSWORD',
    'config/OPENAIAPIKEY',
    'config/AWSACCESSKEYID',
    'config/SERVICEACCOUNTKEY',
    'config/DESIGNTOKENSECRET',
  ])('rejects exact full-token credential segmentation for %s', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/SSHPRIVATEKEY',
    'config/KEYSTOREPASSWORD',
    'config/TRUSTSTOREPASSWORD',
    'config/SECRETKEYBASE',
    'config/GOOGLEAPPLICATIONCREDENTIALS',
    'config/CLIENTCERTIFICATEPASSWORD',
    'config/DATABASECONNECTIONPASSWORD',
    'config/PRODUCTIONAPIKEY',
    'config/APIKEYPRODUCTION',
    'config/LIVECLIENTSECRET',
    'config/STAGINGTOKEN',
    'config/STAGETOKEN',
    'config/DEVELOPMENTAPIKEY',
    'config/DEVCLIENTSECRET',
    'config/TESTCREDENTIALS',
    'config/TESTINGPASSWORD',
    'config/LOCALTOKEN',
    'config/RELEASEKEY',
    'config/PRODCREDENTIALS',
  ])('rejects reviewed credential/context compound %s in either order', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/TOKENCOUNTSECRET',
    'config/TOKENBUCKETKEY',
    'config/SECRETSANTAKEYS',
    'config/DESIGNTOKENCOUNTSECRET',
  ])('rejects residual sensitive word after a concatenated benign unit in %s', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/DESIGNTOKEN',
    'config/DESIGNTOKENS',
    'config/TOKENCOUNT',
    'config/TOKENBUCKET',
    'config/SECRETSANTA',
  ])('admits exact concatenated benign credential-like unit %s', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'config/PRODUCTAPIKEY',
    'config/LIVELYCLIENTSECRETARY',
    'config/STAGEDTOKENIZER',
    'config/DEVELOPERKEYNOTE',
    'config/LOCALITYPASSWORDLESS',
    'config/RELEASESKEYBOARD',
    'config/TESTAMENTKEYNOTE',
  ])('admits qualifier near-neighbor %s without substring classification', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    `config/${'AWS'.repeat(7)}KEY`,
    `config/${'AWS'.repeat(8)}KEY`,
    `config/${'AWS'.repeat(9)}KEY`,
  ])('fails closed for fully recognized credential compound at and beyond the word bound: %s', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'config/MONKEY.json',
    'config/KEYBOARD.yaml',
    'config/APIKEYBOARD.toml',
    'config/KEYNOTE',
    'config/PASSWORDLESS',
    'config/SECRETARYKEY',
    'config/MASTERKEYBOARD',
    'config/KEYSTONE',
  ])('admits uppercase near-neighbor %s that is not an exact credential compound', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'config/.npmrc.ts',
    'config/.pypirc.test.tsx',
    'config/.netrc.client.js',
    'config/.git-credentials.generated.mjs',
    'keys/id_rsa.spec.ts',
    'keys/id_ed25519.ts',
    'repo/.docker/config.json.test.ts',
    'repo/.kube/config.client.tsx',
    'repo/.config/gh/hosts.yml.generated.js',
    'config/.ＮＰＭＲＣ.ＴＳ',
    'repo/.ＤＯＣＫＥＲ/config.ＪＳＯＮ.fixture.ＴＳＸ',
  ])('rejects exact canonical credential path %s behind reviewed source suffixes', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'src/.npmrc-reader.ts',
    'src/id_rsa_parser.ts',
    'src/docker-config.ts',
    'src/kube-config.ts',
    'src/hosts-yml.ts',
  ])('admits legitimate source near-neighbor %s of an exact credential path', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'public/key.avif',
    'public/token.gif',
    'public/keys.jpg',
    'public/client-secret.jpeg',
    'public/key.png',
    'public/api-key.svg',
    'public/secret.webp',
    'public/token.woff',
    'public/private-key.woff2',
  ])('defers supported candidate asset filename %s to structural validation', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'public/key．png',
    'public/token.ＰＮＧ',
  ])('canonically defers compatibility asset suffix %s to structural validation', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).not.toThrow();
  });

  it.each([
    'public/logo.ico',
    'public/key.ico',
  ])('keeps unsupported ICO candidate %s blocked', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it.each([
    'public/logo.ＩＣＯ',
    'public/logo．ico',
    'fixtures/fixture.ＺＩＰ',
    'bin/program.ＥＸＥ',
    'fixtures/fixture．ＰＤＦ',
  ])('rejects canonical compatibility alias of denylisted suffix %s', (path) => {
    expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
  });

  it('rejects generated provider state roots but admits similarly named source paths', () => {
    for (const path of [
      '.netlify/state.json',
      'site/.firebase/hosting.c3l0ZQ.cache',
      'apps/web/.amplify/#current-cloud-backend/backend-config.json',
      'packages/site/.sst/stage.json',
    ]) {
      expect(() => assertArchiveEntries([entry(path)])).toThrow(/^bundle_entry_forbidden$/u);
    }

    expect(() =>
      assertArchiveEntries([
        entry('netlify/state.ts'),
        entry('firebase/hosting.ts'),
        entry('amplify/backend.ts'),
        entry('sst/stage.ts'),
        entry('.netlify-source/config.ts'),
      ]),
    ).not.toThrow();
  });

  it('rejects normalized, case-folded, long, deep and duplicate path collisions', () => {
    for (const entries of [
      [entry('App/Page.tsx'), entry('app/page.tsx')],
      [entry('straße.ts'), entry('strasse.ts')],
      [entry('same.ts'), entry('same.ts')],
      [entry(`${'a'.repeat(91)}.tsx`)],
      [entry(`d/${'a'.repeat(81)}`)],
      [entry(`${Array.from({ length: ARCHIVE_LIMITS.maxPathDepth + 1 }, () => 'a').join('/')}.tsx`)],
    ]) {
      expect(() => assertArchiveEntries(entries)).toThrow(/^bundle_entry_forbidden$/u);
    }
  });

  it('rejects hostile entry shapes without invoking accessors', () => {
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'path', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'secret';
      },
    });
    const symbolEntry = entry('app/page.tsx') as BundleEntryInput & { [key: symbol]: boolean };
    symbolEntry[Symbol('hidden')] = true;
    const sparse = Array(1) as BundleEntryInput[];

    for (const entries of [new Proxy([], {}), sparse, [accessor], [symbolEntry]]) {
      expect(() => assertArchiveEntries(entries as BundleEntryInput[])).toThrow(
        /^bundle_input_invalid$/u,
      );
    }
    expect(getterCalls).toBe(0);
  });

  it('rejects unsafe modes, views, executable data and binary magic', () => {
    const backing = new Uint8Array([1, 2]);
    const shared = new Uint8Array(new SharedArrayBuffer(1));
    for (const invalid of [
      entry('app/page.tsx', { executable: true }),
      entry('scripts/run.mjs', { executable: true, bytes: new TextEncoder().encode('no shebang') }),
      entry('asset.dat', { bytes: new Uint8Array([0x7f, 0x45, 0x4c, 0x46]) }),
      entry('app/page.tsx', { bytes: backing.subarray(1) }),
      entry('app/page.tsx', { bytes: Buffer.from('buffer') as Uint8Array }),
      entry('app/page.tsx', { bytes: shared }),
    ]) {
      expect(() => assertArchiveEntries([invalid])).toThrow(/^bundle_(?:entry_forbidden|input_invalid)$/u);
    }
  });

  it('rejects renamed archive signatures independently of their extension', () => {
    const tarBytes = new Uint8Array(262);
    tarBytes.set(new TextEncoder().encode('ustar'), 257);
    for (const [path, content] of [
      ['renamed-zip.txt', new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2])],
      ['renamed-gzip.txt', new Uint8Array([0x1f, 0x8b, 8, 0, 1, 2])],
      ['renamed-7z.txt', new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])],
      ['renamed-xz.txt', new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])],
      ['renamed-tar.txt', tarBytes],
      ['renamed-zstd.txt', new Uint8Array([0x28, 0xb5, 0x2f, 0xfd])],
      ['renamed-skippable-frame.txt', new Uint8Array([0x50, 0x2a, 0x4d, 0x18])],
      ['renamed-lz4.txt', new Uint8Array([0x04, 0x22, 0x4d, 0x18])],
      ['renamed-legacy-lz4.txt', new Uint8Array([0x02, 0x21, 0x4c, 0x18])],
      ['renamed-cab.txt', new TextEncoder().encode('MSCFsynthetic')],
      ['renamed-ar.txt', new TextEncoder().encode('!<arch>\nsynthetic')],
      ['renamed-thin-ar.txt', new TextEncoder().encode('!<thin>\nsynthetic')],
      ['renamed-cpio-newc.txt', new TextEncoder().encode('070701synthetic')],
      ['renamed-cpio-crc.txt', new TextEncoder().encode('070702synthetic')],
      ['renamed-cpio-old.txt', new TextEncoder().encode('070707synthetic')],
      ['renamed-pdf.txt', new TextEncoder().encode('%PDF-1.7 synthetic')],
    ] as const) {
      expect(() => assertArchiveEntries([entry(path, { bytes: content })])).toThrow(
        /^bundle_entry_forbidden$/u,
      );
    }
  });

  it('does not reject truncated or adjacent blocked-format signatures as magic', () => {
    for (const content of [
      new Uint8Array([0x28, 0xb5, 0x2f]),
      new Uint8Array([0x28, 0xb5, 0x2f, 0xfc]),
      new TextEncoder().encode('MSCE synthetic text'),
      new TextEncoder().encode('!<arch synthetic text'),
      new TextEncoder().encode('070700 synthetic text'),
      new TextEncoder().encode('%PDE-1.7 synthetic text'),
    ]) {
      expect(() => assertArchiveEntries([entry('format-neighbor.txt', { bytes: content })])).not.toThrow();
    }
  });

  it('rejects PDF magic after only a bounded BOM and ASCII-whitespace prefix', () => {
    for (const content of [
      new TextEncoder().encode('\n  %PDF-1.7 synthetic'),
      new Uint8Array([0xef, 0xbb, 0xbf, 0x09, 0x0d, 0x0a, 0x25, 0x50, 0x44, 0x46, 0x2d, 0x31]),
      new Uint8Array([0x0b, 0x25, 0x50, 0x44, 0x46, 0x2d, 0x31]),
    ]) {
      expect(() => assertArchiveEntries([entry('prefixed-document.txt', { bytes: content })])).toThrow(
        /^bundle_entry_forbidden$/u,
      );
    }
  });

  it('does not scan arbitrary source text for PDF-like substrings', () => {
    for (const content of [
      new TextEncoder().encode('%PDE-1.7 synthetic'),
      new TextEncoder().encode("export const signature = '%PDF-1.7';\n"),
      new TextEncoder().encode('not-a-document\n%PDF-1.7'),
    ]) {
      expect(() => assertArchiveEntries([entry('pdf-control.ts', { bytes: content })])).not.toThrow();
    }
  });

  it('applies entry and byte limits with safe arithmetic', () => {
    expect(() =>
      assertArchiveEntries([entry('a.ts'), entry('b.ts')], {
        ...ARCHIVE_LIMITS,
        maxCandidateEntries: 1,
      }),
    ).toThrow(/^bundle_limit_exceeded$/u);
    expect(() =>
      assertArchiveEntries([entry('a.ts')], {
        ...ARCHIVE_LIMITS,
        maxSingleBytes: 1,
      }),
    ).toThrow(/^bundle_limit_exceeded$/u);
    expect(() =>
      assertArchiveEntries([entry('a.ts')], {
        maxCandidateEntries: ARCHIVE_LIMITS.maxCandidateEntries + 1,
      }),
    ).toThrow(/^bundle_input_invalid$/u);
  });

  it('admits the exact frozen candidate-entry boundary', () => {
    const entries = Array.from({ length: ARCHIVE_LIMITS.maxCandidateEntries }, (_, index) =>
      entry(`f/${index.toString().padStart(3, '0')}.ts`, { bytes: new Uint8Array() }),
    );
    expect(() => assertArchiveEntries(entries)).not.toThrow();
  });

  it('rejects an over-limit array before enumerating descriptors or observed items', () => {
    const originalDescriptors = Object.getOwnPropertyDescriptors;
    let descriptorReads = 0;
    let itemTraps = 0;
    const observedItem = new Proxy(entry('private.ts'), {
      ownKeys() {
        itemTraps += 1;
        throw new Error('private item trap');
      },
    });
    const oversized = Array.from(
      { length: ARCHIVE_LIMITS.maxCandidateEntries + 1 },
      () => observedItem,
    );
    Object.getOwnPropertyDescriptors = ((value: object) => {
      if (value === oversized) descriptorReads += 1;
      return originalDescriptors(value);
    }) as typeof Object.getOwnPropertyDescriptors;
    try {
      expect(() => assertArchiveEntries(oversized)).toThrow(/^bundle_limit_exceeded$/u);
    } finally {
      Object.getOwnPropertyDescriptors = originalDescriptors;
    }
    expect(descriptorReads).toBe(0);
    expect(itemTraps).toBe(0);

    const sparse = Array(ARCHIVE_LIMITS.maxCandidateEntries + 1) as BundleEntryInput[];
    Object.defineProperty(sparse, 0, {
      enumerable: true,
      get() {
        throw new Error('private accessor');
      },
    });
    expect(() => assertArchiveEntries(sparse)).toThrow(/^bundle_limit_exceeded$/u);
  });
});
