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
	export function test(name: string, handler: () => void | Promise<void>): void;
	export function expect(value: unknown): Matchers;
}

declare const console: {
	error(...args: unknown[]): void;
};

declare const Buffer: BufferConstructor;

interface Timer {
	unref?(): Timer;
}

declare function setTimeout(handler: (...args: unknown[]) => void, timeout: number, ...args: unknown[]): Timer;
declare function clearTimeout(timer: Timer | null | undefined): void;

interface AbortSignal {
	readonly aborted: boolean;
}

interface URL {
	readonly username: string;
	readonly password: string;
	readonly port: string;
	readonly hostname: string;
}

interface URLConstructor {
	new (input: string): URL;
}

declare const URL: URLConstructor;

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

declare module "node:path" {
	export function join(...segments: string[]): string;
	export function resolve(...segments: string[]): string;
	export function dirname(value: string): string;
	export function isAbsolute(value: string): boolean;
	export const sep: string;
}

declare module "node:net" {
	export interface Socket {
		setNoDelay(enable?: boolean): void;
		write(data: Uint8Array): boolean;
		destroy(): void;
		on(event: string, listener: (...args: any[]) => void): void;
		once(event: string, listener: (...args: any[]) => void): void;
		off(event: string, listener: (...args: any[]) => void): void;
	}
	export function connect(options: { path: string }): Socket;
}

declare module "node:fs" {
	export const constants: {
		O_RDONLY: number;
		O_WRONLY: number;
		O_DIRECTORY: number;
		O_NOFOLLOW: number;
		O_CREAT: number;
		O_EXCL: number;
	};
	export function readFileSync(path: string, options: { encoding: string } | string): string;
	export function readFileSync(path: string): Buffer;
	export function readdirSync(path: string): string[];
}

declare module "node:fs/promises" {
	export interface StatsBase<N> {
		isDirectory(): boolean;
		isFile(): boolean;
		mode: N;
		dev: N;
		ino: N;
		size: number;
	}
	export type Stats = StatsBase<number>;
	export type BigintStats = StatsBase<bigint>;
	export interface FileHandle {
		readonly fd: number;
		stat(): Promise<Stats>;
		stat(options: { bigint: true }): Promise<BigintStats>;
		writeFile(data: Buffer | string): Promise<void>;
		sync(): Promise<void>;
		close(): Promise<void>;
	}
	export function open(path: string, flags: number | string, mode?: number): Promise<FileHandle>;
	export function lstat(path: string): Promise<Stats>;
	export function lstat(path: string, options: { bigint: true }): Promise<BigintStats>;
	export function mkdir(path: string, options?: { recursive?: boolean; mode?: number }): Promise<string | undefined>;
	export function chmod(path: string, mode: number): Promise<void>;
	export function mkdtemp(prefix: string): Promise<string>;
	export function rm(path: string, options?: { recursive?: boolean; force?: boolean }): Promise<void>;
	export function rename(from: string, to: string): Promise<void>;
	export function unlink(path: string): Promise<void>;
}

declare module "node:child_process" {
	export interface Pipe {
		write(data: string | Buffer): boolean;
		end(): void;
		on(event: string, listener: (...args: any[]) => void): void;
		off(event: string, listener: (...args: any[]) => void): void;
	}
	export interface ReadablePipe {
		on(event: string, listener: (chunk: Buffer) => void): void;
		off(event: string, listener: (chunk: Buffer) => void): void;
	}
	export interface ChildProcess {
		readonly pid: number | undefined;
		readonly stdin: Pipe | null;
		readonly stdout: ReadablePipe | null;
		readonly stderr: ReadablePipe | null;
		readonly exitCode: number | null;
		readonly signalCode: string | null;
		once(event: string, listener: (...args: any[]) => void): void;
		on(event: string, listener: (...args: any[]) => void): void;
		off(event: string, listener: (...args: any[]) => void): void;
		kill(signal?: string): boolean;
	}
	export interface SpawnOptions {
		env?: NodeJS.ProcessEnv;
		detached?: boolean;
		stdio?: ["pipe" | "ignore", "pipe" | "ignore", "pipe" | "ignore"];
	}
	export function spawn(command: string, args: readonly string[], options?: SpawnOptions): ChildProcess;
}
