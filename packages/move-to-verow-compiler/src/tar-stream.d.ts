declare module 'tar-stream' {
  import type { Readable } from 'node:stream';

  export interface Headers {
    name: string;
    mode?: number;
    uid?: number;
    gid?: number;
    size?: number;
    mtime?: Date;
    type?: string;
    uname?: string;
    gname?: string;
  }

  export interface Pack extends Readable {
    entry(
      header: Headers,
      buffer: Uint8Array,
      callback: (error?: Error | null) => void,
    ): void;
    finalize(): void;
  }

  export interface Extract extends NodeJS.WritableStream {
    on(
      event: 'entry',
      listener: (
        header: Headers,
        stream: Readable,
        next: (error?: Error | null) => void,
      ) => void,
    ): this;
    once(event: 'finish', listener: () => void): this;
    once(event: 'error', listener: (error: Error) => void): this;
    end(chunk?: Uint8Array): this;
  }

  export function pack(): Pack;
  export function extract(): Extract;
}
