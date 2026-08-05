import handler from 'vinext/server/app-router-entry';
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
