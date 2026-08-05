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

  export function validRange(
    range: string,
    options?: Pick<SemverSatisfiesOptions, 'loose'>,
  ): string | null;

  export function valid(
    version: string,
    options?: Pick<SemverSatisfiesOptions, 'loose'>,
  ): string | null;
}
