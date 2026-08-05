import { copyFile, mkdir, rm } from 'node:fs/promises';
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
