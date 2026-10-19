export function overload(
  value: string
): string;
export function overload(
  value: number
): number;
export function overload(
  value: string | number
): string | number {
  return value;
}

export function genericFn<T extends { map: (fn: (x: T) => T) => T }>(
  input: T
): T {
  return input;
}

export type NestedFn = (
  x: (y: string) => number
) => (z: boolean) => void;

export {
  overload as overloaded,
};

export class Box<T> {
  constructor(public value: T) {}
}

export interface Shape<T> {
  value: T;
}

export namespace Outer {
  export function inner(): void {}
}

export const multilineConst:
  (x: string) => number =
  (
    x: string
  ) => x.length;
