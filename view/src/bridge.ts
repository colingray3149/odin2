// Runs the data bridge (`odin view --bridge`, or a dev stand-in) as a child and speaks the JSON-lines contract with it.
// The bridge's stderr goes to a log file so it can never draw over the TUI; if the bridge dies, the log's last line
// says why and the bridge is started again.
import * as fs from "node:fs";
import * as path from "node:path";
import { getStateDir } from "@oh-my-pi/pi-utils/dirs";
import type { BridgeMessage, ViewCommand } from "./protocol";

const RESTART_MS = 3000;

export function bridgeLogPath(): string {
	return path.join(getStateDir(), "view-bridge.log");
}

/** The bridge argv from `ODIN_VIEW_BRIDGE` (a JSON array of strings). */
export function bridgeArgv(env: Record<string, string | undefined> = process.env): string[] {
	const raw = env.ODIN_VIEW_BRIDGE;
	if (!raw) throw new Error("ODIN_VIEW_BRIDGE is not set: start the view with `odin view`");
	let argv: unknown;
	try {
		argv = JSON.parse(raw);
	} catch {
		throw new Error(`ODIN_VIEW_BRIDGE is not JSON: ${raw}`);
	}
	if (!Array.isArray(argv) || argv.length === 0 || !argv.every(a => typeof a === "string")) {
		throw new Error(`ODIN_VIEW_BRIDGE must be a non-empty JSON array of strings: ${raw}`);
	}
	return argv;
}

/** The last non-empty line of the bridge log, for the status bar. */
function lastLogLine(file: string): string {
	try {
		const lines = fs.readFileSync(file, "utf8").trimEnd().split("\n");
		return lines.at(-1)?.trim() ?? "";
	} catch {
		return "";
	}
}

export class Bridge {
	#child: ReturnType<typeof Bun.spawn> | undefined;
	#stopped = false;
	#starts = 0;

	constructor(
		readonly argv: string[],
		readonly logFile: string,
		readonly onMessage: (message: BridgeMessage) => void,
		readonly onExit: (cause: string) => void,
		/** How long a dead bridge stays down before it is started again. */
		readonly restartMs = RESTART_MS,
	) {}

	start(): void {
		fs.mkdirSync(path.dirname(this.logFile), { recursive: true });
		// Truncate on the first start; keep earlier crashes in the log on restarts.
		const fd = fs.openSync(this.logFile, this.#starts++ === 0 ? "w" : "a");
		let child: ReturnType<typeof Bun.spawn>;
		try {
			child = Bun.spawn(this.argv, { stdin: "pipe", stdout: "pipe", stderr: fd });
		} catch (err) {
			fs.closeSync(fd);
			this.#died(`cannot start ${this.argv[0]}: ${err instanceof Error ? err.message : String(err)}`);
			return;
		}
		fs.closeSync(fd);
		this.#child = child;
		void this.#read(child.stdout as ReadableStream<Uint8Array>);
		void child.exited.then(code => {
			if (this.#child !== child) return;
			this.#child = undefined;
			const last = lastLogLine(this.logFile);
			this.#died(`bridge exited (${code})${last ? `: ${last}` : ""}`);
		});
	}

	send(command: ViewCommand): boolean {
		const stdin = this.#child?.stdin;
		if (!stdin || typeof stdin === "number") return false;
		try {
			stdin.write(`${JSON.stringify(command)}\n`);
			stdin.flush();
			return true;
		} catch {
			return false; // The bridge just died; its exit handler reports why.
		}
	}

	stop(): void {
		this.#stopped = true;
		const child = this.#child;
		this.#child = undefined;
		child?.kill();
	}

	#died(cause: string): void {
		if (this.#stopped) return;
		this.onExit(cause);
		setTimeout(() => {
			if (!this.#stopped) this.start();
		}, this.restartMs);
	}

	async #read(stream: ReadableStream<Uint8Array>): Promise<void> {
		const decoder = new TextDecoder();
		let buffer = "";
		for await (const chunk of stream) {
			buffer += decoder.decode(chunk, { stream: true });
			let newline = buffer.indexOf("\n");
			while (newline !== -1) {
				const line = buffer.slice(0, newline).trim();
				buffer = buffer.slice(newline + 1);
				newline = buffer.indexOf("\n");
				if (!line) continue;
				let message: BridgeMessage;
				try {
					message = JSON.parse(line);
				} catch {
					continue; // Not a contract line; the contract says to ignore what we do not understand.
				}
				if (!message || typeof message !== "object" || typeof message.t !== "string") continue;
				try {
					this.onMessage(message);
				} catch (err) {
					// One malformed message must not end the reading: the page would freeze with the child still running.
					fs.appendFileSync(this.logFile, `view: ${message.t} message failed: ${err instanceof Error ? err.message : String(err)}\n`);
				}
			}
		}
	}
}
