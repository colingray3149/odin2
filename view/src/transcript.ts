// Folds one session's live events into transcript blocks. Pure state; rendering lives in render.ts.
import type { EventBody, LiveEvent } from "./protocol";

export type Usage = Extract<EventBody, { kind: "usage" }>;

export type Block = (
	/** `text` is the owner's own words; `raw` the whole turn as the seat got it (ctrl+r). */
	| { kind: "user"; text: string; raw: string }
	| { kind: "assistant"; text: string; streaming: boolean }
	| { kind: "thinking"; text: string }
	| {
			kind: "tool";
			id: string;
			name: string;
			args: unknown;
			status: "pending" | "job" | "success" | "error";
			result: string;
			/** The call became a background job: its id, when it started, and how it ended and how long it ran. */
			job?: Job;
	  }
	| { kind: "usage"; usage: Usage }
	/** `raw`: the whole turn an Odin note stands for (a job report, a routine), shown with ctrl+r. */
	| { kind: "note"; text: string; error: boolean; raw?: string }
) & {
	/** Bumped on every change, so renderers can cache by (block, version). */
	version: number;
};

export interface Job {
	id: string;
	startedAt: number;
	ended?: { ok: boolean; ms: number };
}

type WithoutVersion<T> = T extends unknown ? Omit<T, "version"> : never;
type NewBlock = WithoutVersion<Block>;

export class Transcript {
	readonly blocks: Block[] = [];
	state = "";
	/** The latest usage report: model and context for the status bar. */
	usage: Usage | undefined;
	/** Summed over every usage report seen in this session. */
	readonly totals = { input: 0, output: 0 };
	/** Bumped on every change. */
	revision = 0;
	/** Tool calls that became background jobs, by job id. */
	readonly #jobs = new Map<string, Extract<Block, { kind: "tool" }>>();
	/** Hermes's quiet reply token, from the latest reply line that carried it. */
	#quiet = "";

	constructor(
		readonly seat: string,
		readonly session: string,
		/** The session Sinmara's conversation rolled over from: the bridge replays its tail first. */
		readonly previous?: string,
	) {}

	/** Events of the previous session add their blocks only: usage, totals and state are this session's. */
	apply(event: EventBody | LiveEvent): void {
		this.revision++;
		const carried = "session" in event && event.session === this.previous;
		switch (event.kind) {
			case "user": {
				// A job report is Odin's, not the owner's: it settles its jobs and reads as one line per job.
				const reports = event.jobs ?? [];
				for (const report of reports) {
					const tool = this.#jobs.get(report.job);
					if (tool?.job && !tool.job.ended) {
						// The report's own duration; without one, from detaching to the report.
						const ms = report.seconds != null ? report.seconds * 1000 : eventTime(event) - tool.job.startedAt;
						tool.job.ended = { ok: report.ok, ms };
						tool.status = report.ok ? "success" : "error";
						tool.version++;
					}
					this.#push({ kind: "note", text: report.line, error: !report.ok, raw: event.text });
				}
				if (reports.length === 0) {
					const turn = userTurn(event.text);
					if ("odin" in turn) this.#push({ kind: "note", text: turn.odin, error: false, raw: event.text });
					else this.#push({ kind: "user", text: turn.words, raw: event.text });
				}
				break;
			}
			case "delta": {
				if (event.quiet) this.#quiet = event.quiet;
				const last = this.blocks.at(-1);
				if (last?.kind === "assistant" && last.streaming) {
					last.text += event.text;
					last.version++;
				} else {
					this.#push({ kind: "assistant", text: event.text, streaming: true });
				}
				break;
			}
			case "assistant": {
				if (event.quiet) this.#quiet = event.quiet;
				// The final message replaces the streamed block it completes; a text-less message (tool calls only)
				// just closes it.
				const open = this.blocks.findLast(b => b.kind === "assistant" && b.streaming);
				if (open?.kind === "assistant") {
					if (event.text) open.text = event.text;
					open.streaming = false;
					open.version++;
				} else if (event.text) {
					this.#push({ kind: "assistant", text: event.text, streaming: false });
				}
				break;
			}
			case "thinking": {
				// A message's thinking arrives when the message ends, after its streamed text: show it above that text.
				const at = this.blocks.findLastIndex(b => b.kind === "assistant" && b.streaming);
				const block: Block = { kind: "thinking", text: event.text, version: 0 };
				if (at === -1) this.blocks.push(block);
				else this.blocks.splice(at, 0, block);
				break;
			}
			case "toolStart":
				this.#push({ kind: "tool", id: event.id, name: event.name, args: event.args, status: "pending", result: "" });
				break;
			case "toolEnd": {
				const tool = this.blocks.findLast(b => b.kind === "tool" && b.id === event.id);
				if (tool?.kind === "tool") {
					tool.status = event.isError ? "error" : event.job ? "job" : "success";
					tool.result = event.text;
					if (event.job) {
						tool.job = { id: event.job, startedAt: eventTime(event) };
						this.#jobs.set(event.job, tool);
					}
					tool.version++;
				} else {
					this.#push({
						kind: "tool",
						id: event.id,
						name: "tool",
						args: undefined,
						status: event.isError ? "error" : "success",
						result: event.text,
					});
				}
				break;
			}
			case "usage":
				if (carried) {
					this.#push({ kind: "usage", usage: event });
					break;
				}
				this.usage = event;
				this.totals.input += event.input + event.cacheRead + event.cacheWrite;
				this.totals.output += event.output;
				this.#push({ kind: "usage", usage: event });
				break;
			case "state":
				if (!carried) this.state = event.state;
				break;
			case "error":
				this.#push({ kind: "note", text: event.text, error: true });
				break;
			case "note":
				this.#push({ kind: "note", text: event.text, error: false });
				break;
		}
	}

	/** Background jobs still running, oldest first. */
	runningJobs(): Extract<Block, { kind: "tool" }>[] {
		return [...this.#jobs.values()].filter(tool => tool.job && !tool.job.ended);
	}

	/** Hermes's quiet reply token, once a reply line has carried it. */
	quiet(): string {
		return this.#quiet;
	}

	#push(block: NewBlock): void {
		this.blocks.push({ ...block, version: 0 } as Block);
	}
}

/** The turns Odin sends itself, worded by their producers (reminders.rs, job_report.rs, workload_monitor.rs): the one line each reads as. */
const ODIN_TURNS: [RegExp, (found: RegExpExecArray) => string][] = [
	[/^\[Routine (\S+) from the harness/, found => `Routine ${found[1]}`],
	[/^\[Scheduled harness wake\. At [^"]*"([^"]*)"/, found => `Scheduled wake: ${found[1]}`],
	[/^\[Harness event observed .*? min ago\): ([^\n]*)/, found => `Harness event: ${found[1]}`],
	// `[Job report from Odin — not a message from the owner: <detail>`, `[Odin monitoring — not a message from the owner] <detail>`.
	[/^\[([^\]\n]*?)(?:,| —) not a message from the owner(?::|\])\s*([^\n]*)/, found => (found[2] ? `${found[1]}: ${found[2]}` : found[1]!)],
];

/**
 * the owner's words in a user turn: what follows the context line Odin opens each of his turns with (`[the owner's local
 * time: …] [You are running on …]`, after any recalled memory), as `owner_words` in odin-ledger's trace.rs reads it.
 * A routine, a scheduled wake, an observed event, a monitoring turn or a rollover's continuity context is Odin's turn,
 * named in one line.
 */
function userTurn(text: string): { words: string } | { odin: string } {
	if (/(^|\n)\[ODIN ROLLOVER/.test(text)) return { odin: "Continuity context from the previous session" };
	const context = text.lastIndexOf("[You are running on ");
	const close = context === -1 ? -1 : text.indexOf("]", context);
	const words = (close === -1 ? text : text.slice(close + 1)).trim();
	for (const [pattern, note] of ODIN_TURNS) {
		const found = pattern.exec(words);
		if (found) return { odin: note(found) };
	}
	return { words };
}

/** When an event happened: its journal time, or now for one without. */
function eventTime(event: EventBody | LiveEvent): number {
	const at = "at" in event && event.at ? Date.parse(event.at) : Number.NaN;
	return Number.isNaN(at) ? Date.now() : at;
}
