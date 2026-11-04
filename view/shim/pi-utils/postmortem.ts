// Stand-in for OMP's postmortem: run the TUI's terminal-restore callbacks once on exit or a fatal signal.
type Callback = () => void | Promise<void>;

const callbacks = new Map<string, Callback>();
let ran = false;

function runAll(): void {
	if (ran) return;
	ran = true;
	for (const cb of [...callbacks.values()].reverse()) {
		try {
			void cb();
		} catch {
			// Restore what we can; one failing callback must not block the others.
		}
	}
}

process.on("exit", runAll);
for (const signal of ["SIGTERM", "SIGHUP"] as const) {
	process.on(signal, () => {
		runAll();
		process.exit(128 + (signal === "SIGTERM" ? 15 : 1));
	});
}

export function register(id: string, callback: Callback): () => void {
	callbacks.set(id, callback);
	return () => callbacks.delete(id);
}

export async function quit(code = 0, _options: { drainStdout?: boolean } = {}): Promise<void> {
	runAll();
	process.exit(code);
}
