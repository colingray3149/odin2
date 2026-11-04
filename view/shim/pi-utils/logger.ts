// Stand-in for OMP's logger: warnings and errors go to ~/.local/state/odin/view.log, never to the screen.
import * as fs from "node:fs";
import * as path from "node:path";
import { getStateDir } from "./dirs";

function write(level: string, message: string, context?: Record<string, unknown>): void {
	try {
		const file = path.join(getStateDir(), "view.log");
		fs.mkdirSync(path.dirname(file), { recursive: true });
		const extra = context ? ` ${JSON.stringify(context, (_k, v) => (v instanceof Error ? v.message : v))}` : "";
		fs.appendFileSync(file, `${new Date().toISOString()} ${level} ${message}${extra}\n`);
	} catch {
		// Logging must never take the view down.
	}
}

export function debug(_message: string, _context?: Record<string, unknown>): void {}

export function warn(message: string, context?: Record<string, unknown>): void {
	write("warn", message, context);
}

export function error(message: string, context?: Record<string, unknown>): void {
	write("error", message, context);
}
