/**
 * Odin conformance fixture — deterministic in-process provider extension.
 *
 * Loaded into the pinned OMP child (`omp --mode rpc --extension <this file>`)
 * by the conformance probe only. It registers the `odin-mock` provider backed
 * by the pinned in-process mock streaming provider (`createMockModel` /
 * `streamMock` from `@oh-my-pi/pi-ai/providers/mock`): no network, no
 * credentials, no Kimi (or any real vendor) dependency, and no ambient clock beyond scripted,
 * abort-honoring delays.
 *
 * Every model response is a pure function of the conversation the harness
 * drives, keyed on the last user message text. The directive vocabulary below
 * is the frozen contract the case modules program against
 * (`odin_omp::probe`). The router keys on the
 * user-authored prompt text: it peels the pinned harness wrappers (the date/cwd
 * reminder block prepended to the first user turn of every request, and the
 * steering interjection envelope wrapped around mid-turn steers), so every
 * frozen directive routes identically for string or text-block-array user
 * content; any other content shape is ignored and falls back to the ack.
 *
 * Directives (exact prefixes on the prompt text):
 * - `odin-mock:echo <text>`        — assistant text reply `<text>`.
 * - `odin-mock:delay <ms> <text>`  — scripted delay (capped at 120 s, honors
 *   the pinned abort signal), then reply `<text>`. Opens the mid-turn windows
 *   the steer/follow-up/abort/state cases need.
 * - `odin-mock:error <text>`       — terminal `stopReason: "error"` with the
 *   given `errorMessage`.
 * - `odin-mock:throw <text>`       — the stream itself fails with
 *   `Error(<text>)` (provider-failure path).
 * - `odin-mock:read [path]`        — `read` toolCall (default path: this
 *   fixture file), then the fixed tool continuation.
 * - `odin-mock:host-tool <laneId>` — `odin_lane_status` toolCall bound to the
 *   supplied deterministic probe lane, driving the bridge host-tool side
 *   channel.
 * - `odin-mock:edit <path>`        — read-anchored sequential `edit` toolCalls
 *   change the fixed original marker to an edited marker and then restore it.
 * - `odin-mock:subagent <task>`    — `task` toolCall spawning one subagent
 *   whose own turns are answered by the default handler.
 * - `odin-mock:big <bytes>`        — reply of exactly N bytes (capped at
 *   8 MiB) of the shared deterministic xorshift32 pattern (mirrored
 *   byte-exactly by the Rust verifier); large enough responses force the
 *   pinned v2 chunk train on later history reads.
 * - A last user message starting with `# Source:` is the pinned compaction
 *   protocol: the fixture answers with a `rewrite` toolCall and, after its
 *   tool result arrives, an `approve` toolCall.
 * - Any other turn ending in a tool result replies
 *   `mock-tool-done:<toolName>:<ok|error>`; anything else replies
 *   `mock-ack:<message-count>`.
 *
 * `selfCheck()` checks directive routing across supported user-content shapes
 * and the deterministic `big` pattern. Registration runs it once and reports
 * failures on stderr.
 *
 * The extension also registers the local-only `/odin-fixture <args>` slash
 * command, which emits one `notify` extension-UI frame and completes without
 * an agent turn (`prompt_result` with `agentInvoked: false`).
 */

import type { Api, Context } from "@oh-my-pi/pi-ai";
import {
	createMockModel,
	MOCK_API,
	type MockModel,
	type MockResponse,
	streamMock,
} from "@oh-my-pi/pi-ai/providers/mock";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { fileURLToPath } from "node:url";

/** Provider name the fixture registers; the only provider the probe selects. */
export const FIXTURE_PROVIDER = "odin-mock";
/** First registered model id; the default launch selects it. */
export const FIXTURE_MODEL_A = "mock-a";
/** Second registered model id; case 10 switches between the two. */
export const FIXTURE_MODEL_B = "mock-b";
export const FIXTURE_COMMAND = "odin-fixture";

const DIRECTIVE_PREFIX = "odin-mock:";
const MAX_DELAY_MS = 120_000;
/** Cap on the `big` directive so a large reply stays memory-bounded. */
const MAX_BIG_BYTES = 8 * 1024 * 1024;

/**
 * Shared deterministic pattern contract for `big` replies, mirrored
 * byte-exactly by the Rust verifier: xorshift32 seeded at 0x6d2b79f5, stepped
 * once per byte with `x ^= x << 13; x ^= x >>> 17; x ^= x << 5` (u32
 * wrapping — plain JS bitwise ops preserve the exact 32-bit pattern and
 * `>>> 0` reinterprets it before the modulo), emitting
 * `PATTERN_ALPHABET[x % 62]`. ASCII-only, so string length equals byte
 * length; prefix-stable, deterministic, and free of clock or randomness.
 */
const PATTERN_SEED = 0x6d2b79f5;
const PATTERN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/** Exact first 64 chars of the pattern stream, pinned against drift. */
const PATTERN_EXPECTED_64 = "JbQx4pMl6u5eeZbSQg12t6C1LLpRNLiuYtgRCJ0bFJ0zh2p2euzeq7MDOYbDi0NG";
/** Char count per bounded assembly chunk; the chunks are joined. */
const PATTERN_CHUNK_CHARS = 65536;
/** Exact `big` byte count of the pinned oversized-reply case. */
const PATTERN_CASE_BYTES = 1_310_720;
/** Periodic negative-control cycle length. */
const PATTERN_OLD_HEX_CYCLE = 16;
/** First line of the pinned compaction request prompt (compress/prompts/request.md). */
const COMPACTION_PREFIX = "# Source:";
/** Deterministic pause that exposes the automatic-compaction abort window. */
const COMPACTION_DELAY_MS = 10_000;
/** Reversible edit fixture markers, including their exact newline. */
const EDIT_ORIGINAL = "odin-fixture-original\n";
const EDIT_CHANGED = "odin-fixture-edited\n";
/**
 * Pinned harness wrappers that ride ahead of the user's prompt text in the
 * provider context. The date/cwd reminder block
 * (packages/coding-agent/src/prompts/system/date-cwd-reminder.md) is prepended
 * to the first user turn of every request for prompt-cache stability; the
 * steering interjection envelope
 * (packages/coding-agent/src/prompts/steering/user-interjection.md) wraps
 * every mid-turn user steer. Directive routing peels both so the frozen
 * vocabulary stays keyed on the user-authored prompt text regardless of the
 * path the harness delivered it on.
 */
const HARNESS_REMINDER_PREFIX =
	/^<system-reminder>\nToday: \d{4}-\d{2}-\d{2}; current working directory: '[^']*'\. Do not repeat this information in your reply\.\n<\/system-reminder>\n+/;
const HARNESS_INTERJECTION_PREFIX =
	/^<system-notice>\nUser interjection during work: priority; supersedes conflicting prior instructions\. Re-read; ensure current work reflects user intent\.\n<\/system-notice>\n+/;

const ZERO_COST = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };

/** Exact text of a user message: plain string content, or joined text blocks. */
function userText(message: { content: unknown }): string {
	if (typeof message.content === "string") return message.content;
	if (!Array.isArray(message.content)) return "";
	return message.content
		.filter(block => block && typeof block === "object" && (block as { type?: unknown }).type === "text")
		.map(block => String((block as { text?: unknown }).text ?? ""))
		.join("\n");
}

/**
 * The user-authored prompt text the router keys on: `userText` with the pinned
 * harness wrappers peeled, so a directive routes identically whether it
 * arrives as string content, a bare text block, the reminder-prepended first
 * turn, or a steering-wrapped interjection.
 */
function promptText(message: { content: unknown }): string {
	let text = userText(message);
	for (;;) {
		const next = text.replace(HARNESS_REMINDER_PREFIX, "").replace(HARNESS_INTERJECTION_PREFIX, "");
		if (next === text) return text;
		text = next;
	}
}

/** Last user text in the active turn history, or an empty string. */
function latestUserText(context: Context): string {
	for (let index = context.messages.length - 1; index >= 0; index -= 1) {
		const message = context.messages[index];
		if (message?.role === "user") return promptText(message);
	}
	return "";
}

/** Tool results after the latest user message; used only for reversible edits. */
function currentTurnToolResults(context: Context, toolName: string): number {
	let count = 0;
	for (let index = context.messages.length - 1; index >= 0; index -= 1) {
		const message = context.messages[index];
		if (!message || message.role === "user") break;
		if (message.role === "toolResult" && message.toolName === toolName) count += 1;
	}
	return count;
}

/** Deterministic byte-exact pattern: ASCII, so string length equals byte length. */
function patternBytes(length: number): string {
	let x = PATTERN_SEED;
	const chunks: string[] = [];
	for (let start = 0; start < length; start += PATTERN_CHUNK_CHARS) {
		const size = Math.min(PATTERN_CHUNK_CHARS, length - start);
		const chars = new Array<string>(size);
		for (let i = 0; i < size; i++) {
			x ^= x << 13;
			x ^= x >>> 17;
			x ^= x << 5;
			chars[i] = PATTERN_ALPHABET[(x >>> 0) % 62];
		}
		chunks.push(chars.join(""));
	}
	return chunks.join("");
}

/**
 * Faithful suffix-cycle probe: true when the trailing `cycle` chars repeat
 * forward through the whole string (`text[i] === text[(i + cycle) % n]`), as
 * any `cycle`-periodic fill of this length satisfies. Single linear pass over
 * char codes with constant extra memory — safe at the 8 MiB cap.
 */
function hasSuffixCycle(text: string, cycle: number): boolean {
	const n = text.length;
	if (cycle <= 0 || cycle >= n) return false;
	for (let i = 0; i < n; i++) {
		if (text.charCodeAt(i) !== text.charCodeAt((i + cycle) % n)) return false;
	}
	return true;
}


/** The pinned compaction protocol's first answer: submit a deterministic draft. */
function compactionRewrite(): MockResponse {
	return {
		delayMs: COMPACTION_DELAY_MS,
		content: [
			{
				type: "toolCall",
				name: "rewrite",
				arguments: {
					text: "mock-compaction: the conversation was compressed deterministically by the conformance fixture",
					losses: [],
				},
			},
		],
	};
}

/** The pinned compaction protocol's second answer: accept the draft. */
function compactionApprove(): MockResponse {
	return {
		content: [
			{
				type: "toolCall",
				name: "approve",
				arguments: { verdict: "mock-compaction: deterministic draft accepted by the conformance fixture" },
			},
		],
	};
}

/** Reads the current hashline anchor before either half of the reversible edit. */
function readForReversibleEdit(path: string): MockResponse {
	return {
		content: [{ type: "toolCall", name: "read", arguments: { path } }],
	};
}

/** One read-anchored half of the reversible edit directive. */
function reversibleEdit(path: string, restore: boolean, readResult: { content: unknown }): MockResponse {
	const text = userText(readResult);
	const header = text.split("\n").find(line => /^\[.+#[0-9a-f]{4}\]$/i.test(line));
	const oldText = restore ? EDIT_CHANGED : EDIT_ORIGINAL;
	const newText = restore ? EDIT_ORIGINAL : EDIT_CHANGED;
	if (!text.split("\n").includes(`1:${oldText.slice(0, -1)}`)) {
		const detail = `mock-edit-anchor:${restore ? "changed" : "original"} marker not observed`;
		return { content: [detail], stopReason: "error", errorMessage: detail };
	}
	return {
		content: [
			{
				type: "toolCall",
				name: "edit",
				arguments: {
					input: header ? `${header}\nPUT 1.=1:\n+${newText.slice(0, -1)}\n` : "",
					path,
					old_string: oldText,
					new_string: newText,
				},
			},
		],
	};
}

/**
 * The shared deterministic router. One instance per registered model; the
 * response is fully determined by `context`.
 */
function route(context: Context): MockResponse {
	const last = context.messages.at(-1);

	// Compaction round two: the draft's tool result just arrived.
	if (last?.role === "toolResult" && last.toolName === "rewrite") return compactionApprove();
	if (last?.role === "toolResult" && last.toolName === "read") {
		const directive = latestUserText(context);
		const path = directive.startsWith(`${DIRECTIVE_PREFIX}edit `)
			? directive.slice(`${DIRECTIVE_PREFIX}edit `.length)
			: "";
		const reads = currentTurnToolResults(context, "read");
		if (path && !last.isError && (reads === 1 || reads === 2)) {
			return reversibleEdit(path, reads === 2, last);
		}
	}
	if (last?.role === "toolResult" && last.toolName === "edit") {
		const directive = latestUserText(context);
		const path = directive.startsWith(`${DIRECTIVE_PREFIX}edit `)
			? directive.slice(`${DIRECTIVE_PREFIX}edit `.length)
			: "";
		if (path && !last.isError && currentTurnToolResults(context, "edit") === 1) {
			return readForReversibleEdit(path);
		}
		return { content: [`mock-tool-done:edit:${last.isError ? "error" : "ok"}`] };
	}
	// Any other tool result closes the loop deterministically.
	if (last?.role === "toolResult") {
		return { content: [`mock-tool-done:${last.toolName}:${last.isError ? "error" : "ok"}`] };
	}
	if (last?.role !== "user") return { content: [`mock-ack:${context.messages.length}`] };

	const text = promptText(last);
	if (text.startsWith(COMPACTION_PREFIX)) return compactionRewrite();
	if (!text.startsWith(DIRECTIVE_PREFIX)) return { content: [`mock-ack:${context.messages.length}`] };

	const rest = text.slice(DIRECTIVE_PREFIX.length);
	const space = rest.indexOf(" ");
	const head = space === -1 ? rest : rest.slice(0, space);
	const arg = space === -1 ? "" : rest.slice(space + 1);

	switch (head) {
		case "echo":
			return { content: [arg] };
		case "delay": {
			const [msToken, ...words] = arg.split(" ");
			const parsed = Number.parseInt(msToken ?? "", 10);
			const delayMs = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 0), MAX_DELAY_MS) : 0;
			return { delayMs, content: [words.join(" ")] };
		}
		case "error":
			return { content: [`mock-error:${arg}`], stopReason: "error", errorMessage: arg };
		case "throw":
			return { throw: new Error(arg || "mock-throw") };
		case "read":
			return {
				content: [
					{
						type: "toolCall",
						name: "read",
						arguments: { path: arg || fileURLToPath(import.meta.url) },
					},
				],
			};
		case "host-tool":
			return {
				content: [
					{
						type: "toolCall",
						name: "odin_lane_status",
						arguments: { laneId: arg || "lane-missing" },
					},
				],
			};
		case "edit":
			return readForReversibleEdit(arg);
		case "subagent":
			return {
				content: [
					{
						type: "toolCall",
						name: "task",
						arguments: { task: arg || "Reply with the fixed word done.", agent: "task" },
					},
				],
			};
		case "big": {
			const parsed = Number.parseInt(arg, 10);
			const length = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 0), MAX_BIG_BYTES) : 0;
			return { content: [patternBytes(length)] };
		}
		default:
			return { content: [`mock-unknown-directive:${head}`] };
	}
}

/** Synthetic first-turn reminder exactly as the pinned harness renders it. */
const SELF_CHECK_REMINDER =
	"<system-reminder>\nToday: 2026-09-01; current working directory: '/odin/self-check'. Do not repeat this information in your reply.\n</system-reminder>";
/** Synthetic steering envelope exactly as the pinned harness renders it. */
const SELF_CHECK_INTERJECTION =
	"<system-notice>\nUser interjection during work: priority; supersedes conflicting prior instructions. Re-read; ensure current work reflects user intent.\n</system-notice>";

/** One user turn carrying `content`, the only context shape the router reads. */
function userTurn(content: unknown): Context {
	return { messages: [{ role: "user", content, attribution: "user", timestamp: 0 }] } as unknown as Context;
}

/** First content block of a response when it is a toolCall-shaped object. */
function firstToolCall(response: MockResponse): { name?: unknown } | undefined {
	const first = (response.content as unknown[])[0];
	return first && typeof first === "object" ? (first as { name?: unknown }) : undefined;
}

/** The frozen directives the self-check must prove, with their routed markers. */
const SELF_CHECK_DIRECTIVES: Array<{ directive: string; verify: (response: MockResponse) => string | null }> = [
	{
		directive: `${DIRECTIVE_PREFIX}read /tmp/odin-fixture-self-check`,
		verify: response => (firstToolCall(response)?.name === "read" ? null : "expected a read toolCall"),
	},
	{
		directive: `${DIRECTIVE_PREFIX}delay 5 self-check`,
		verify: response =>
			response.delayMs === 5 && response.content[0] === "self-check"
				? null
				: "expected the scripted 5 ms delay and reply text",
	},
	{
		directive: `${DIRECTIVE_PREFIX}big 64`,
		verify: response =>
			response.content[0] === PATTERN_EXPECTED_64
				? null
				: "expected the pinned 64-char xorshift pattern reply",
	},
	{
		directive: `${DIRECTIVE_PREFIX}host-tool lane-self-check`,
		verify: response =>
			firstToolCall(response)?.name === "odin_lane_status" ? null : "expected an odin_lane_status toolCall",
	},
	{
		directive: `${DIRECTIVE_PREFIX}subagent self-check`,
		verify: response => (firstToolCall(response)?.name === "task" ? null : "expected a task toolCall"),
	},
	{
		directive: `${DIRECTIVE_PREFIX}edit /tmp/odin-fixture-self-check`,
		verify: response =>
			firstToolCall(response)?.name === "read" ? null : "expected the read-anchored read toolCall",
	},
];

/** User-content shapes the router must treat identically. */
const SELF_CHECK_SHAPES: Array<{ label: string; build: (directive: string) => Context }> = [
	{ label: "string", build: directive => userTurn(directive) },
	{ label: "text-block-array", build: directive => userTurn([{ type: "text", text: directive }]) },
	{
		label: "reminder-prepended",
		build: directive =>
			userTurn([{ type: "text", text: SELF_CHECK_REMINDER }, { type: "text", text: directive }]),
	},
	{
		label: "steering-envelope",
		build: directive => userTurn([{ type: "text", text: `${SELF_CHECK_INTERJECTION}\n${directive}` }]),
	},
];

/** Content shapes outside the two supported forms; the router must ignore them. */
const SELF_CHECK_IGNORED_SHAPES: Record<string, unknown> = {
	"non-array-object": { type: "text", text: `${DIRECTIVE_PREFIX}echo ignored` },
	"untyped-blocks": [{ type: "unknown" }],
};

/**
 * Checks routing parity across supported content shapes and deterministic
 * pattern output. Returns one line per failed expectation, or an empty array.
 */
export function selfCheck(): string[] {
	const failures: string[] = [];
	for (const { directive, verify } of SELF_CHECK_DIRECTIVES) {
		const routed = SELF_CHECK_SHAPES.map(shape => ({ label: shape.label, response: route(shape.build(directive)) }));
		for (const { label, response } of routed) {
			const problem = verify(response);
			if (problem) failures.push(`${label} ${directive}: ${problem}`);
		}
		const canonical = JSON.stringify(routed[0].response);
		for (const { label, response } of routed) {
			if (JSON.stringify(response) !== canonical) {
				failures.push(`${label} ${directive}: response diverges from the string-content form`);
			}
		}
	}
	for (const [label, content] of Object.entries(SELF_CHECK_IGNORED_SHAPES)) {
		const response = route(userTurn(content));
		if (response.content[0] !== "mock-ack:1") {
			failures.push(`${label}: expected the mock-ack fallback, got ${JSON.stringify(response.content[0])}`);
		}
	}
	const bigDirective = `${DIRECTIVE_PREFIX}big ${PATTERN_CASE_BYTES}`;
	const routedBig = route(userTurn(bigDirective)).content[0] as string;
	const routedBigAgain = route(userTurn(bigDirective)).content[0] as string;
	if (
		routedBig.length !== PATTERN_CASE_BYTES ||
		routedBig !== routedBigAgain ||
		routedBig !== patternBytes(PATTERN_CASE_BYTES)
	) {
		failures.push(`pattern: expected ${PATTERN_CASE_BYTES} deterministic xorshift32 bytes on every route`);
	}
	const head64 = patternBytes(64);
	const head4096 = patternBytes(4096);
	if (head64 !== PATTERN_EXPECTED_64 || !head4096.startsWith(head64) || routedBig.slice(0, head4096.length) !== head4096) {
		failures.push("pattern: expected the pinned 64-char head and stable prefixes");
	}
	const windowSize = 4096;
	const windowOffsets = [0, windowSize, 2 * windowSize, 65536, 262144, 1_048_576, PATTERN_CASE_BYTES - windowSize];
	const windows = windowOffsets.map(offset => routedBig.slice(offset, offset + windowSize));
	if (new Set(windows).size !== windows.length) {
		failures.push("pattern: expected distinct 4KiB windows across the stream");
	}
	if (hasSuffixCycle(routedBig, PATTERN_OLD_HEX_CYCLE)) {
		failures.push(`pattern: aperiodic stream must not cycle with the retired ${PATTERN_OLD_HEX_CYCLE}-char hex period`);
	}
	const retiredFill = "0123456789abcdef"
		.repeat(Math.ceil(PATTERN_CASE_BYTES / PATTERN_OLD_HEX_CYCLE))
		.slice(0, PATTERN_CASE_BYTES);
	if (!hasSuffixCycle(retiredFill, PATTERN_OLD_HEX_CYCLE)) {
		failures.push("pattern: retired periodic hex fill must trip the suffix-cycle checker");
	}
	return failures;
}

/**
 * Fixture entry point. Registers the mock provider with one `MockModel` per
 * model id (per-model call recording and attribution) and the local command.
 */
export default function mockProviderFixture(pi: ExtensionAPI): void {
	const failures = selfCheck();
	if (failures.length > 0) {
		console.error(`[odin-mock] fixture self-check failed:\n\t${failures.join("\n\t")}`);
	}
	const mockA = createMockModel({
		id: FIXTURE_MODEL_A,
		provider: FIXTURE_PROVIDER,
		baseUrl: "mock://odin-m3",
		handler: route,
	});
	const mockB = createMockModel({
		id: FIXTURE_MODEL_B,
		provider: FIXTURE_PROVIDER,
		baseUrl: "mock://odin-m3",
		handler: route,
	});
	const mocks = new Map<string, MockModel>([
		[mockA.id, mockA],
		[mockB.id, mockB],
	]);

	pi.registerProvider(FIXTURE_PROVIDER, {
		baseUrl: "mock://odin-m3",
		// Synthetic and local: makes model fallback eligibility deterministic
		// without consulting ambient auth storage or an environment variable.
		apiKey: "odin-mock-fixture-key",
		api: MOCK_API as unknown as Api,
		// The registry's own model object is not a MockModel; dispatch to the
		// per-id instance that carries the scripted router.
		streamSimple: (model, context, options) => streamMock(mocks.get(model.id) ?? mockA, context, options),
		models: [
			{
				id: FIXTURE_MODEL_A,
				name: "Odin Mock A",
				reasoning: false,
				input: ["text"],
				cost: ZERO_COST,
				contextWindow: 200_000,
				maxTokens: 32_768,
			},
			{
				id: FIXTURE_MODEL_B,
				name: "Odin Mock B",
				reasoning: false,
				input: ["text"],
				cost: ZERO_COST,
				contextWindow: 200_000,
				maxTokens: 32_768,
			},
		],
	});

	pi.registerCommand(FIXTURE_COMMAND, {
		description: "Odin conformance fixture: deterministic local-only command.",
		handler: async (args, ctx) => {
			ctx.ui.notify(`odin-fixture:${args}`, "info");
		},
	});
}
