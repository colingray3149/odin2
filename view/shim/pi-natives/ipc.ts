// Node `net` stand-in for `@oh-my-pi/pi-natives` IPC (`crates/pi-natives/src/ipc` at e996e1c).
// Unix domain sockets only: owner-only bind, stale-socket takeover, LF framing. Windows named
// pipes are not available from `node:net`, so that path reports ENOTSUP.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";

const DEFAULT_MAX_FRAME_BYTES = 64 * 1024 * 1024;
const DEFAULT_CONNECT_TIMEOUT_MS = 3000;
const HIGH_WATER_BYTES = 1024 * 1024;
const SUN_PATH_MAX = process.platform === "linux" || process.platform === "android" ? 108 : 104;

type Framing = "lines" | "raw";

function ipcError(code: string, message: string): Error & { code: string } {
	return Object.assign(new Error(`${code}: ${message}`), { code });
}

function typeError(code: string, message: string): TypeError & { code: string } {
	return Object.assign(new TypeError(message), { code });
}

function ioCode(error: NodeJS.ErrnoException): string {
	return error.code ?? "EIO";
}

function parseFraming(framing: string): Framing {
	if (framing === "lines" || framing === "raw") return framing;
	throw typeError("ERR_INVALID_ARG_VALUE", `framing must be "lines" or "raw", got ${JSON.stringify(framing)}`);
}

function hash16(bytes: Buffer): string {
	return createHash("sha256").update(bytes).digest("hex").slice(0, 16);
}

function sanitizeStem(name: string): string {
	return name.replace(/[^A-Za-z0-9._-]/g, "_");
}

function resolveDir(dir: string): string {
	const joined = path.isAbsolute(dir) ? dir : path.join(process.cwd(), dir);
	const parts = joined.split(/[/\\]/);
	const out: string[] = [];
	for (const part of parts) {
		if (part === "" || part === ".") continue;
		if (part === "..") out.pop();
		else out.push(part);
	}
	return process.platform === "win32" ? path.win32.resolve(dir) : `/${out.join("/")}`;
}

/**
 * Platform endpoint for `name` scoped to directory `dir`.
 *
 * Unix: `<dir>/<stem>.sock`; when that path does not fit `sun_path` (104 bytes
 * on macOS/BSD, 108 on Linux, including NUL), `/tmp/omp-<euid>/<hash16>.sock`.
 * Windows: `\\.\pipe\omp-<stem>-<hash16(lowercase(resolve(dir)))>`.
 * `stem` is `name` with every char outside `[A-Za-z0-9._-]` replaced by "_".
 * Pure and deterministic: every process computes the same endpoint.
 */
export function ipcEndpoint(dir: string, name: string): string {
	const resolved = resolveDir(dir);
	const stem = sanitizeStem(name);
	if (process.platform === "win32") {
		return `\\\\.\\pipe\\omp-${stem}-${hash16(Buffer.from(resolved.toLowerCase()))}`;
	}
	const direct = resolved.endsWith("/") ? `${resolved}${stem}.sock` : `${resolved}/${stem}.sock`;
	if (Buffer.byteLength(direct) < SUN_PATH_MAX) return direct;
	const key = Buffer.concat([Buffer.from(resolved), Buffer.from([0]), Buffer.from(name)]);
	return `/tmp/omp-${process.getuid?.() ?? 0}/${hash16(key)}.sock`;
}

/** Options for `IpcConnection.connect`. */
export interface IpcConnectOptions {
	/**
	 * `lines`: UTF-8 text frames delimited by LF; `raw`: byte chunks as
	 * received.
	 */
	framing: "lines" | "raw";
	/** Connect deadline. Default 3000 ms. Expiry rejects with code ETIMEDOUT. */
	timeoutMs?: number;
	/** Max bytes of one received line (lines framing). Default 64 MiB. */
	maxFrameBytes?: number;
}

/** Options for `IpcServer.listen`. */
export interface IpcListenOptions {
	/**
	 * `lines`: UTF-8 text frames delimited by LF; `raw`: byte chunks as
	 * received.
	 */
	framing: "lines" | "raw";
	/**
	 * Max bytes of one received line (lines framing). Default 64 MiB.
	 * Exceeding closes that connection with reason "EMSGSIZE: …".
	 */
	maxFrameBytes?: number;
}

interface Delivery {
	onLine?: (line: string) => void;
	onChunk?: (chunk: Uint8Array) => void;
	onClose: (reason: string | null) => void;
}

/** One accepted or dialed IPC connection. */
export class IpcConnection {
	#socket: net.Socket;
	#framing: Framing;
	#maxFrameBytes: number;
	#closed = false;
	#started = false;
	#ending = false;
	#closeReason: string | null = null;
	#pending: Buffer[] = [];
	#pendingBytes = 0;
	#line = Buffer.alloc(0);
	#delivery: Delivery | undefined;
	#drainWaiters: Array<() => void> = [];
	#flushQueued = false;

	constructor(socket: net.Socket, framing: Framing, maxFrameBytes: number) {
		this.#socket = socket;
		this.#framing = framing;
		this.#maxFrameBytes = maxFrameBytes;
		socket.on("data", chunk => this.#onData(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
		socket.on("end", () => this.#finish(null));
		socket.on("close", () => this.#finish(null));
		socket.on("error", error => this.#finish(`${ioCode(error)}: ${error.message}`));
		socket.on("drain", () => this.#noteDrain());
	}

	/** An accepted socket, not yet started. */
	static accepted(socket: net.Socket, framing: Framing, maxFrameBytes: number): IpcConnection {
		return new IpcConnection(socket, framing, maxFrameBytes);
	}

	/**
	 * Dial `endpoint`. Rejects with code ENOENT (no endpoint), ECONNREFUSED
	 * (stale socket / no listener), ETIMEDOUT, EACCES (peer owned by another
	 * user, or permission), or the OS errno name.
	 */
	static connect(endpoint: string, options: IpcConnectOptions): Promise<IpcConnection> {
		const framing = parseFraming(options.framing);
		const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
		const timeoutMs = options.timeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
		if (process.platform === "win32") {
			return Promise.reject(ipcError("ENOTSUP", "named-pipe IPC is not available in the view shim"));
		}
		const { promise, resolve, reject } = Promise.withResolvers<IpcConnection>();
		const socket = net.createConnection(endpoint);
		let settled = false;
		const fail = (error: Error): void => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			socket.destroy();
			reject(error);
		};
		const timer = setTimeout(() => {
			fail(ipcError("ETIMEDOUT", `connect ${endpoint} timed out after ${timeoutMs} ms`));
		}, timeoutMs);
		socket.once("connect", () => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			socket.setNoDelay(true);
			resolve(new IpcConnection(socket, framing, maxFrameBytes));
		});
		socket.once("error", error => {
			fail(ipcError(ioCode(error), `connect ${endpoint}: ${error.message}`));
		});
		return promise;
	}

	/**
	 * Begin delivery on a `lines` connection (throws `TypeError` on a `raw`
	 * one). Call `start`/`startRaw` exactly once. Frames received before
	 * start are buffered, never dropped. `onLine` gets each non-empty line
	 * (one trailing CR stripped, invalid UTF-8 replaced lossily). `onClose`
	 * fires exactly once, after the last frame — including after local
	 * `end()`/`destroy()`: `null` for an orderly close, otherwise
	 * `"<CODE>: <message>"`.
	 */
	start(onLine: (line: string) => void, onClose: (reason: string | null) => void): void {
		this.#begin("lines", { onLine, onClose });
	}

	/**
	 * Same as `start()` for a `raw` connection (throws `TypeError` on a
	 * `lines` one): `onChunk` gets each received chunk.
	 */
	startRaw(onChunk: (chunk: Uint8Array) => void, onClose: (reason: string | null) => void): void {
		this.#begin("raw", { onChunk, onClose });
	}

	/**
	 * Send one frame. lines: a string without LF (`TypeError` otherwise);
	 * LF is appended. raw: string (UTF-8) or `Uint8Array` written as-is.
	 * Frames sent during one JS task are written together when it ends (a
	 * microtask), in order; `end()` writes them first. Returns false once
	 * unwritten bytes exceed 1 MiB (await `drained()` before sending more).
	 * After close: returns false and drops the frame.
	 */
	send(frame: string | Uint8Array): boolean {
		if (this.#closed) return false;
		let bytes: Buffer;
		if (this.#framing === "lines") {
			if (typeof frame !== "string") {
				throw typeError("ERR_INVALID_ARG_TYPE", "lines connections send strings, not bytes");
			}
			if (frame.includes("\n")) {
				throw typeError("ERR_INVALID_ARG_VALUE", 'lines frame must not contain "\\n"');
			}
			bytes = Buffer.from(`${frame}\n`);
		} else {
			bytes = typeof frame === "string" ? Buffer.from(frame) : Buffer.from(frame);
		}
		this.#pending.push(bytes);
		this.#pendingBytes += bytes.length;
		if (!this.#flushQueued) {
			this.#flushQueued = true;
			queueMicrotask(() => this.#flush());
		}
		return this.#pendingBytes <= HIGH_WATER_BYTES;
	}

	/** Resolves when the write queue is empty, or the connection closed. */
	drained(): Promise<void> {
		if (this.#closed || (this.#pendingBytes === 0 && this.#socket.writableLength === 0)) return Promise.resolve();
		const { promise, resolve } = Promise.withResolvers<void>();
		this.#drainWaiters.push(resolve);
		return promise;
	}

	/**
	 * Graceful: write everything queued, then shut the write half (Unix) /
	 * close the pipe (Windows); onClose follows when the read side ends.
	 */
	end(): void {
		if (this.#closed || this.#ending) return;
		this.#ending = true;
		this.#flush();
		if (this.#pendingBytes === 0) this.#socket.end();
	}

	/**
	 * Immediate close; queued writes are dropped; onClose(null) follows.
	 * Idempotent.
	 */
	destroy(): void {
		if (this.#closed) return;
		this.#pending = [];
		this.#pendingBytes = 0;
		this.#socket.destroy();
		this.#finish(null);
	}

	/** Keep the event loop alive while delivering (default). */
	ref(): void {
		this.#socket.ref();
	}

	/** Let the event loop exit while this connection is open. */
	unref(): void {
		this.#socket.unref();
	}

	/** Whether the connection is closed (or `destroy()` was called). */
	get closed(): boolean {
		return this.#closed;
	}

	#begin(framing: Framing, delivery: Delivery): void {
		if (this.#framing !== framing) {
			const message =
				framing === "lines"
					? "start() requires a lines connection; use startRaw()"
					: "startRaw() requires a raw connection; use start()";
			throw typeError("ERR_INVALID_ARG_TYPE", message);
		}
		if (this.#started) throw ipcError("ERR_INVALID_STATE", "connection already started");
		this.#started = true;
		this.#delivery = delivery;
		const buffered = this.#pending;
		this.#pending = [];
		if (this.#framing === "raw") {
			for (const chunk of buffered) delivery.onChunk?.(chunk);
		} else if (buffered.length > 0) {
			this.#emitLines(Buffer.concat(buffered));
		}
		if (this.#closed) this.#deliverClose();
	}

	#onData(chunk: Buffer): void {
		if (this.#closed) return;
		if (!this.#started) {
			this.#pending.push(chunk);
			return;
		}
		if (this.#framing === "raw") {
			this.#delivery?.onChunk?.(chunk);
			return;
		}
		this.#emitLines(chunk);
	}

	#emitLines(chunk: Buffer): void {
		const data = this.#line.length === 0 ? chunk : Buffer.concat([this.#line, chunk]);
		let start = 0;
		for (let i = 0; i < data.length; i++) {
			if (data[i] !== 0x0a) continue;
			let end = i;
			if (end > start && data[end - 1] === 0x0d) end--;
			if (end - start > this.#maxFrameBytes) {
				this.#oversize();
				return;
			}
			if (end > start) this.#delivery?.onLine?.(data.toString("utf8", start, end));
			start = i + 1;
		}
		this.#line = Buffer.from(data.subarray(start));
		if (this.#line.length > this.#maxFrameBytes) this.#oversize();
	}

	#oversize(): void {
		this.#closeReason = `EMSGSIZE: line exceeds maxFrameBytes (${this.#maxFrameBytes} bytes)`;
		this.#socket.destroy();
		this.#finish(this.#closeReason);
	}

	#flush(): void {
		this.#flushQueued = false;
		if (this.#closed || this.#pendingBytes === 0) {
			if (this.#ending) this.#socket.end();
			this.#noteDrain();
			return;
		}
		const batch = Buffer.concat(this.#pending);
		this.#pending = [];
		this.#pendingBytes = 0;
		const queued = this.#socket.write(batch);
		if (this.#ending && queued) this.#socket.end();
		if (queued) this.#noteDrain();
	}

	#noteDrain(): void {
		if (!this.#closed && (this.#pendingBytes !== 0 || this.#socket.writableLength !== 0)) return;
		const waiters = this.#drainWaiters;
		this.#drainWaiters = [];
		for (const waiter of waiters) waiter();
	}

	#finish(reason: string | null): void {
		if (this.#closed) return;
		this.#closed = true;
		this.#closeReason = this.#closeReason ?? reason;
		this.#socket.removeAllListeners("data");
		if (this.#started) this.#deliverClose();
		this.#noteDrain();
	}

	#deliverClose(): void {
		const delivery = this.#delivery;
		this.#delivery = undefined;
		delivery?.onClose(this.#closeReason);
	}
}

/** Listening IPC endpoint. */
export class IpcServer {
	#endpoint: string;
	#server: net.Server;
	#boundDev = 0;
	#boundIno = 0;

	constructor(endpoint: string, server: net.Server, bound: { dev: number; ino: number }) {
		this.#endpoint = endpoint;
		this.#server = server;
		this.#boundDev = bound.dev;
		this.#boundIno = bound.ino;
	}

	/**
	 * Bind and listen.
	 *
	 * Unix: creates the parent dir (0700) if missing; under an exclusive flock
	 * on `<path>.bind.lock`, rejects EADDRINUSE when a live server answers,
	 * otherwise replaces the stale socket file; the socket is chmod 0600 before
	 * `listen()`. Windows: first pipe instance (exists → EADDRINUSE), remote
	 * clients rejected, DACL granting only the current user.
	 * `onConnection` receives each accepted, peer-verified connection (not yet
	 * started).
	 */
	static listen(
		endpoint: string,
		options: IpcListenOptions,
		onConnection: (connection: IpcConnection) => void,
	): Promise<IpcServer> {
		const framing = parseFraming(options.framing);
		const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
		if (process.platform === "win32") {
			return Promise.reject(ipcError("ENOTSUP", "named-pipe IPC is not available in the view shim"));
		}
		return bindUnix(endpoint, framing, maxFrameBytes, onConnection);
	}

	/** The endpoint this server listens on. */
	get endpoint(): string {
		return this.#endpoint;
	}

	/**
	 * Stop accepting. Unix: unlink the socket file if it is still the inode
	 * this server bound. Accepted connections are untouched. Idempotent.
	 */
	close(): Promise<void> {
		try {
			const meta = fs.lstatSync(this.#endpoint);
			if (meta.dev === this.#boundDev && meta.ino === this.#boundIno) fs.unlinkSync(this.#endpoint);
		} catch {
			// Already gone, or a successor replaced it.
		}
		const { promise, resolve } = Promise.withResolvers<void>();
		this.#server.close(() => resolve());
		return promise;
	}

	/** Keep the event loop alive while listening (default). */
	ref(): void {
		this.#server.ref();
	}

	/** Let the event loop exit while listening. */
	unref(): void {
		this.#server.unref();
	}
}

function bindUnix(
	endpoint: string,
	framing: Framing,
	maxFrameBytes: number,
	onConnection: (connection: IpcConnection) => void,
): Promise<IpcServer> {
	const parent = path.dirname(endpoint);
	try {
		fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
	} catch (error) {
		const errno = error as NodeJS.ErrnoException;
		return Promise.reject(ipcError(ioCode(errno), `create ${parent}: ${errno.message}`));
	}
	const lockPath = `${endpoint}.bind.lock`;
	fs.closeSync(fs.openSync(lockPath, "a", 0o600));
	return withBindLock(lockPath, async () => {
		await takeStale(endpoint);
		const { promise, resolve, reject } = Promise.withResolvers<IpcServer>();
		const server = net.createServer(socket => {
			socket.setNoDelay(true);
			onConnection(IpcConnection.accepted(socket, framing, maxFrameBytes));
		});
		server.once("error", error => reject(ipcError(ioCode(error), `bind ${endpoint}: ${error.message}`)));
		server.listen(endpoint, () => {
			try {
				fs.chmodSync(endpoint, 0o600);
			} catch {
				// A filesystem that ignores socket mode still accepted the bind.
			}
			const meta = fs.lstatSync(endpoint);
			resolve(new IpcServer(endpoint, server, { dev: meta.dev, ino: meta.ino }));

		});
		return promise;
	});
}

function withBindLock<T>(lockPath: string, body: () => Promise<T>): Promise<T> {
	const { promise, resolve, reject } = Promise.withResolvers<T>();
	const child = spawn("flock", ["-x", lockPath, "sleep", "infinity"], { stdio: "ignore" });
	let released = false;
	const release = (): void => {
		if (released) return;
		released = true;
		child.kill();
	};
	child.once("error", error => reject(ipcError("EIO", `lock bind sidecar: ${error.message}`)));
	child.once("spawn", () => {
		body().then(
			value => {
				release();
				resolve(value);
			},
			error => {
				release();
				reject(error instanceof Error ? error : ipcError("EIO", String(error)));
			},
		);
	});
	child.once("exit", (status, signal) => {
		if (!released) reject(ipcError("EIO", `lock bind sidecar exited (${status ?? signal})`));
	});
	return promise;
}

async function takeStale(endpoint: string): Promise<void> {
	let meta: fs.Stats;
	try {
		meta = fs.lstatSync(endpoint);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
		throw ipcError(ioCode(error as NodeJS.ErrnoException), `stat ${endpoint}`);
	}
	if (!meta.isSocket()) throw ipcError("EADDRINUSE", `${endpoint} exists and is not a socket`);
	const live = await probeLive(endpoint);
	if (live) throw ipcError("EADDRINUSE", `${endpoint} already has a live listener`);
	try {
		fs.unlinkSync(endpoint);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
			throw ipcError(ioCode(error as NodeJS.ErrnoException), `remove stale ${endpoint}`);
		}
	}
}

function probeLive(endpoint: string): Promise<boolean> {
	const { promise, resolve } = Promise.withResolvers<boolean>();
	const probe = net.createConnection(endpoint);
	probe.once("connect", () => {
		probe.destroy();
		resolve(true);
	});
	probe.once("error", error => {
		const code = ioCode(error);
		resolve(code !== "ECONNREFUSED" && code !== "ENOENT");
	});
	return promise;
}
