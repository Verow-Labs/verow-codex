import { cloudflare } from '@cloudflare/vite-plugin';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

import { sitesHostingMetadataPlugin } from './build/sites-vite-plugin';

export default defineConfig({ plugins: [react(), cloudflare(), sitesHostingMetadataPlugin()] });
