declare module 'semver' {
  interface SemverSatisfiesOptions {
    includePrerelease?: boolean;
    loose?: boolean;
  }

  export function satisfies(
    version: string,
    range: string,
    options?: SemverSatisfiesOptions,
  ): boolean;
}
