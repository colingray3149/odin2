// Local ambient declarations cover the extension's Node.js APIs without vendoring @types/node.

declare namespace NodeJS {
	interface ProcessEnv {
		[key: string]: string | undefined;
	}
}

interface Buffer extends Uint8Array {
	toString(encoding?: string): string;
	subarray(start?: number, end?: number): Buffer;
	indexOf(value: number): number;
	readUInt32BE(offset: number): number;
	writeUInt32BE(value: number, offset: number): number;
	write(text: string, offset: number, encoding?: string): number;
}

interface BufferConstructor {
	alloc(size: number): Buffer;
	concat(list: Buffer[]): Buffer;
	from(value: string, encoding?: string): Buffer;
	byteLength(value: string, encoding?: string): number;
}

// Resolve bun:test during strict typechecking without importing the runner's full declarations.
declare module "bun:test" {
	interface Matchers {
		toBe(expected: unknown): void;
		toEqual(expected: unknown): void;
		toMatchObject(expected: unknown): void;
		toBeNull(): void;
		toBeDefined(): void;
		toBeUndefined(): void;
		toContain(expected: unknown): void;
		toHaveLength(length: number): void;
		toBeGreaterThan(expected: number): void;
		toBeLessThan(expected: number): void;
		toBeLessThanOrEqual(expected: number): void;
		toMatch(expected: string | RegExp): void;
		toThrow(expected?: string | RegExp): void;
		resolves: PromiseMatchers;
		rejects: PromiseMatchers;
		not: Matchers;
	}
	interface PromiseMatchers {
		toBe(expected: unknown): Promise<void>;
		toEqual(expected: unknown): Promise<void>;
		toBeNull(): Promise<void>;
		toBeDefined(): Promise<void>;
		toBeUndefined(): Promise<void>;
		toContain(expected: unknown): Promise<void>;
		toThrow(expected?: string | RegExp): Promise<void>;
	}
	export function test(name: string, handler: () => void | Promise<void>, timeout?: number): void;
	export function expect(value: unknown): Matchers;
}

declare const console: {
	error(...args: unknown[]): void;
};

declare const Buffer: BufferConstructor;

interface Process {
	env: NodeJS.ProcessEnv;
	pid: number;
}

declare const process: Process;

declare module "node:crypto" {
	export function createHash(algorithm: string): {
		update(data: string | Buffer, encoding?: string): { digest(encoding?: string): string };
	};
	export function randomUUID(): string;
}
