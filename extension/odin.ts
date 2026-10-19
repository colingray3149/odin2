//! Trusted Odin extension entry for stock OMP.
//!
//! Host-issued capability listings restrict the active tools and every tool call.
//! Capsule eval/edit use `host_tool_call`; the sidecar stays private to odind.
//! Stop controls remain in Huginn and the CLI.
//! Reads admit declared URI schemes, HTTPS egress hosts, and staged input files only.

import { createHash, randomUUID } from "node:crypto";
import { countTokens, Encoding } from "@oh-my-pi/pi-natives";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

const ENTRY_PREFIX = "odin.extension";

/// The pinned harness tool that resolves internal URIs; the bridge serves
/// host-registered schemes through it.
const URI_READ_TOOL = "read";

/// The host-staged complete-request context budgets, one
/// `provider|model|window|reserve|tokenizer` lane per model the session may
/// run, `;`-joined: each lane's declared window, its compiler-resolved
/// effective output reserve, and the exact declared context tokenizer
/// identity. A request is guarded by the lane of the model serving it.
/// Mirrors `LaneContextBudgets` in crates/odin-omp/src/live/control.rs.
const CONTEXT_BUDGET_ENV = "ODIN_CONTEXT_BUDGET";

/// Tokenizer identities must match the brain's declared counters; unknown identities are refused.
const BYTE_TOKENIZER_ID = "odin.tokenizer.utf8-bytes.v1";
const QWEN3_TOKENIZER_ID = "odin.tokenizer.qwen3.v1";
// Native tokenizer families must match the harness's Model.tokenizer mapping.
const NATIVE_FAMILIES: Record<string, string> = {
	[QWEN3_TOKENIZER_ID]: "qwen3",
};

interface ContextBudget {
	provider: string;
	model: string;
	window: number;
	reserve: number;
	tokenizer: string;
}

// An absent budget disables the guard; one invalid lane rejects the entire declaration.
function parseContextBudgets(raw: string | undefined):
	| { budgets?: ContextBudget[]; error?: string }
	| undefined {
	if (raw === undefined) return undefined;
	const budgets: ContextBudget[] = [];
	for (const lane of raw.split(";")) {
		const parsed = parseContextBudget(lane);
		if (parsed.error !== undefined || parsed.budget === undefined) return { error: parsed.error };
		budgets.push(parsed.budget);
	}
	return { budgets };
}

function parseContextBudget(raw: string): { budget?: ContextBudget; error?: string } {
	const parts = raw.split("|");
	if (parts.length !== 5) {
		return { error: `expected 5 pipe-delimited fields, got ${parts.length}` };
	}
	const [provider, model, windowRaw, reserveRaw, tokenizer] = parts;
	const window = Number(windowRaw);
	const reserve = Number(reserveRaw);
	if (
		provider.length === 0 ||
		model.length === 0 ||
		!Number.isSafeInteger(window) ||
		!Number.isSafeInteger(reserve) ||
		window < 1 ||
		reserve < 0 ||
		reserve >= window
	) {
		return { error: `window/reserve are not a usable declared pair: ${JSON.stringify(raw)}` };
	}
	if (tokenizer !== BYTE_TOKENIZER_ID && !(tokenizer in NATIVE_FAMILIES)) {
		return { error: `declared tokenizer identity ${JSON.stringify(tokenizer)} has no implementation` };
	}
	return { budget: { provider, model, window, reserve, tokenizer } };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

// The harness injects `write` for transport; hide it from the model and refuse dispatch.
const TRANSPORT_INJECTED_TOOLS = new Set(["write"]);

/**
 * Match tool names at the top level or under `function`, depending on the provider.
 * Preserve unknown shapes and return the original payload when nothing is pruned.
 */
function pruneTransportInjectedTools(payload: Record<string, unknown>): Record<string, unknown> {
	const tools = payload.tools;
	if (!Array.isArray(tools)) return payload;
	const kept = tools.filter((tool) => {
		if (!isRecord(tool)) return true;
		const name = typeof tool.name === "string"
			? tool.name
			: isRecord(tool.function) && typeof tool.function.name === "string"
				? tool.function.name
				: undefined;
		return name === undefined || !TRANSPORT_INJECTED_TOOLS.has(name);
	});
	if (kept.length === tools.length) return payload;
	return { ...payload, tools: kept };
}

function asCount(value: unknown): number | undefined {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
		? value
		: undefined;
}

// Malformed output limits must be refused, not treated as missing and replaced by the reserve.
function outputBoundField(
	value: unknown,
	field: string,
): number | undefined | { error: string } {
	if (value === undefined) return undefined;
	const count = asCount(value);
	if (count !== undefined) return count;
	return {
		error: `${field} is present but not a non-negative integer (${value === null ? "null" : typeof value})`,
	};
}

// Retain the producer's field path so narrowing cannot introduce a second output limit.
type OutputBound = { tokens: number; field: string };

function requestedOutputTokens(
	api: string,
	payload: Record<string, unknown>,
): OutputBound | undefined | { error: string } {
	switch (api) {
		case "openai-completions":
		case "openrouter": {
			// Validate both fields before choosing one; an invalid alternate must not be ignored.
			const modern = outputBoundField(payload.max_completion_tokens, "max_completion_tokens");
			const legacy = outputBoundField(payload.max_tokens, "max_tokens");
			if (typeof modern === "object") return modern;
			if (typeof legacy === "object") return legacy;
			if (modern !== undefined) return { tokens: modern, field: "max_completion_tokens" };
			if (legacy !== undefined) return { tokens: legacy, field: "max_tokens" };
			return undefined;
		}
		case "openai-responses":
		case "azure-openai-responses":
		case "openai-codex-responses": {
			const bound = outputBoundField(payload.max_output_tokens, "max_output_tokens");
			if (typeof bound === "object") return bound;
			return bound === undefined ? undefined : { tokens: bound, field: "max_output_tokens" };
		}
		case "anthropic-messages": {
			const bound = outputBoundField(payload.max_tokens, "max_tokens");
			if (typeof bound === "object") return bound;
			return bound === undefined ? undefined : { tokens: bound, field: "max_tokens" };
		}
		case "google-generative-ai":
		case "google-vertex": {
			// Pinned google-shared.ts: onPayload receives the SDK params
			// and paramsToWireBody lifts ONLY params.config.maxOutputTokens
			// into the wire body's generationConfig — the cap lives on
			// `config`, never on a top-level generationConfig. A present
			// non-object config is an unknown shape, not an omission.
			if (payload.config !== undefined && !isRecord(payload.config)) {
				return { error: "request config is present but not an object" };
			}
			const config = isRecord(payload.config) ? payload.config : {};
			const bound = outputBoundField(config.maxOutputTokens, "config.maxOutputTokens");
			if (typeof bound === "object") return bound;
			return bound === undefined
				? undefined
				: { tokens: bound, field: "config.maxOutputTokens" };
		}
		case "google-gemini-cli": {
			// Pinned google-gemini-cli.ts: onPayload receives the whole
			// CloudCodeAssistRequest {project, model, request}; the cap
			// lives on request.generationConfig.maxOutputTokens.
			if (payload.request !== undefined && !isRecord(payload.request)) {
				return { error: "request envelope is present but not an object" };
			}
			const request = isRecord(payload.request) ? payload.request : {};
			if (request.generationConfig !== undefined && !isRecord(request.generationConfig)) {
				return { error: "request.generationConfig is present but not an object" };
			}
			const config = isRecord(request.generationConfig) ? request.generationConfig : {};
			const bound = outputBoundField(
				config.maxOutputTokens,
				"request.generationConfig.maxOutputTokens",
			);
			if (typeof bound === "object") return bound;
			return bound === undefined
				? undefined
				: { tokens: bound, field: "request.generationConfig.maxOutputTokens" };
		}
		default:
			return { error: `request model api ${api} has no known output bound field` };
	}
}

// These providers may omit the limit, so the guard inserts the declared reserve.
function outputBoundOmittable(api: string): boolean {
	switch (api) {
		case "openai-completions":
		case "openrouter":
		case "openai-responses":
		case "azure-openai-responses":
		case "openai-codex-responses":
		case "google-generative-ai":
		case "google-gemini-cli":
		case "google-vertex":
			return true;
		default:
			return false;
	}
}

// Copy only the output-limit path to preserve opaque SDK objects and the caller's payload.
function applyOutputCap(
	api: string,
	payload: Record<string, unknown>,
	cap: number,
	field?: string,
): Record<string, unknown> | { error: string } {
	const path = field ?? defaultCapField(api);
	if (path === undefined) {
		return { error: `api ${api} cannot carry a declared output cap` };
	}
	if (path === "max_completion_tokens" || path === "max_tokens" || path === "max_output_tokens") {
		return { ...payload, [path]: cap };
	}
	if (path === "config.maxOutputTokens") {
		// Pinned google-shared.ts: the wire lifts params.config into
		// the body's generationConfig, so the cap must land on
		// `config` itself, preserving every other config field.
		const config = isRecord(payload.config) ? payload.config : {};
		return { ...payload, config: { ...config, maxOutputTokens: cap } };
	}
	if (path === "request.generationConfig.maxOutputTokens") {
		// Pinned google-gemini-cli.ts: the wire body is
		// {project, model, request}; the cap lands on
		// request.generationConfig, preserving every other field.
		const request = isRecord(payload.request) ? payload.request : {};
		const config = isRecord(request.generationConfig) ? request.generationConfig : {};
		return {
			...payload,
			request: { ...request, generationConfig: { ...config, maxOutputTokens: cap } },
		};
	}
	return { error: `api ${api} cannot carry a declared output cap on ${path}` };
}

/// The canonical insert path when the provider omitted the bound entirely.
function defaultCapField(api: string): string | undefined {
	switch (api) {
		case "openai-completions":
		case "openrouter":
			return "max_completion_tokens";
		case "openai-responses":
		case "azure-openai-responses":
		case "openai-codex-responses":
			return "max_output_tokens";
		case "anthropic-messages":
			return "max_tokens";
		case "google-generative-ai":
		case "google-vertex":
			return "config.maxOutputTokens";
		case "google-gemini-cli":
			return "request.generationConfig.maxOutputTokens";
		default:
			return undefined;
	}
}

/**
 * Provider media content parts by their own part discriminator, per the
 * pinned wire types (openai-chat-wire.ts content parts,
 * openai-responses-wire.ts input items): inside a content position these
 * types ARE provider media — even a malformed part is refused, never
 * guessed at. Unknown part types are wire text, never media.
 */
const MEDIA_PART_TYPE: Record<string, true> = {
	file: true,
	image_url: true,
	input_audio: true,
	input_file: true,
	input_image: true,
};

/**
 * Anthropic content blocks the provider renders as media, by block type
 * alone (anthropic-wire.ts): source forms base64/url/file all decode to
 * an unbounded provider-side cost.
 */
const ANTHROPIC_MEDIA_BLOCK: Record<string, true> = {
	document: true,
	image: true,
};

function partIsMedia(part: unknown): boolean {
	return isRecord(part) && typeof part.type === "string" && MEDIA_PART_TYPE[part.type] === true;
}

/**
 * Google GenerateContent media parts are field-discriminated, not
 * type-discriminated: a record-valued inlineData/inline_data/fileData/
 * file_data ON A PART is the media payload. Only `parts` arrays of
 * Content records are entered — functionCall.args and
 * functionResponse.response are arbitrary model/tool JSON, model-facing
 * TEXT whatever keys they carry, and are never traversed.
 */
function googleContentHasMedia(scope: Record<string, unknown>): boolean {
	const partHasMediaField = (part: unknown): boolean =>
		isRecord(part) &&
		(isRecord(part.inlineData) ||
			isRecord(part.inline_data) ||
			isRecord(part.fileData) ||
			isRecord(part.file_data));
	const visitContent = (value: unknown): boolean => {
		if (Array.isArray(value)) return value.some(visitContent);
		return isRecord(value) && Array.isArray(value.parts) && value.parts.some(partHasMediaField);
	};
	return (
		visitContent(scope.contents) ||
		visitContent(scope.systemInstruction) ||
		visitContent(scope.system_instruction)
	);
}

/**
 * Walks ONLY the provider content structure of one payload — the
 * positions where a provider interprets request structure as media parts
 * — following the pinned request shapes edge by edge: chat message
 * content arrays, responses input items (message content, direct media
 * items, computer_call_output screenshots), anthropic type/content block
 * edges incl. tool_result nesting, google parts arrays. Arbitrary JSON
 * the provider renders as text — tool-call argument strings,
 * function_call_output strings, functionResponse.response and
 * functionCall.args objects, tool_use inputs, unknown part or block
 * types — is never traversed, so unknown user JSON in a tool result
 * counts as text and only actual provider media parts are media. Tool
 * JSON schemas and every non-content field are wire TEXT bounded by the
 * byte count. An api with no enumerated content position walks nothing
 * and fails closed at the output-bound step instead.
 */
function contentHasMedia(api: string, payload: Record<string, unknown>): boolean {
	switch (api) {
		case "openai-completions":
		case "openrouter": {
			const visitMessage = (value: unknown): boolean => {
				if (Array.isArray(value)) return value.some(visitMessage);
				// string content and tool_calls argument strings are text
				return isRecord(value) && Array.isArray(value.content) && value.content.some(partIsMedia);
			};
			return visitMessage(payload.messages);
		}
		case "openai-responses":
		case "azure-openai-responses":
		case "openai-codex-responses": {
			// codex websocket frames spread the responses body into
			// {type:"response.create", ...body}: `input` stays top-level.
			const visitItem = (value: unknown): boolean => {
				if (Array.isArray(value)) return value.some(visitItem);
				if (!isRecord(value)) return false; // plain string input is text
				if (partIsMedia(value)) return true; // direct media items
				if (Array.isArray(value.content)) return value.content.some(partIsMedia);
				// computer-use tool output renders image_url as media; a
				// function_call_output's string output is text
				return (
					value.type === "computer_call_output" &&
					isRecord(value.output) &&
					typeof value.output.image_url === "string"
				);
			};
			return visitItem(payload.input);
		}
		case "anthropic-messages": {
			const visitBlock = (value: unknown): boolean => {
				if (Array.isArray(value)) return value.some(visitBlock);
				if (!isRecord(value)) return false; // system string, tool_result content string
				if (typeof value.type === "string") {
					if (ANTHROPIC_MEDIA_BLOCK[value.type] === true) return true;
					// tool_result content nests text/image blocks; tool_use
					// input and server-tool results are arbitrary JSON text
					return value.type === "tool_result" && visitBlock(value.content);
				}
				// a message record: content is a string or a block array
				return visitBlock(value.content);
			};
			return visitBlock(payload.system) || visitBlock(payload.messages);
		}
		case "google-generative-ai":
		case "google-vertex":
			return googleContentHasMedia(payload);
		case "google-gemini-cli":
			// {project, model, request}: the GenerateContent request lives
			// under request; google Content rules apply inside it.
			return isRecord(payload.request) && googleContentHasMedia(payload.request);
		default:
			return false;
	}
}

/**
 * One declared request counter: the counting unit of the lane's staged
 * tokenizer identity. Byte lanes count the serialized request text as
 * exact UTF-8 bytes (the pinned house rule: one token per byte). Native
 * lanes count the same serialized text with the pinned
 * `@oh-my-pi/pi-natives` engine for the declared family — the same bundled
 * module the harness itself counts with (static import: the pinned omp
 * binary always carries pi-natives in-process, so the extension and the
 * harness share one exact engine). A native lane whose engine refuses the
 * text is refused, never approximated with bytes or any ratio.
 */
type RequestCounter = { kind: "bytes" } | { kind: "native"; family: string; encoding: Encoding };

function counterFor(budget: ContextBudget): RequestCounter | { error: string } {
	if (budget.tokenizer === BYTE_TOKENIZER_ID) return { kind: "bytes" };
	if (budget.tokenizer === QWEN3_TOKENIZER_ID) {
		return { kind: "native", family: "qwen3", encoding: Encoding.Qwen3 };
	}
	return { error: `declared tokenizer identity ${budget.tokenizer} has no implementation` };
}

/**
 * The complete-request count of one provider payload under one declared
 * counter — system, tools, history, current input, and in-turn results all
 * contribute — reported in BOTH units, always: the counter's own
 * `input_tokens` and the serialized text's exact `request_bytes`. The two
 * numbers are never conflated: byte lanes report equal values because the
 * declared identity says one token per byte; native lanes report the real
 * native count next to the real byte length.
 */
function countRequest(
	counter: RequestCounter,
	payload: unknown,
): { inputTokens: number; requestBytes: number } | { error: string } {
	if (!isRecord(payload)) {
		return { error: "provider request payload is not a JSON object" };
	}
	let serialized: string | undefined;
	try {
		serialized = JSON.stringify(payload);
	} catch {
		serialized = undefined;
	}
	if (typeof serialized !== "string") {
		return { error: "provider request payload is not JSON-serializable" };
	}
	const requestBytes = Buffer.byteLength(serialized, "utf8");
	if (counter.kind === "bytes") {
		return { inputTokens: requestBytes, requestBytes };
	}
	try {
		return { inputTokens: countTokens(serialized, counter.encoding), requestBytes };
	} catch (error) {
		return {
			error: `the pinned native tokenizer refused the request text: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
}

function parseListing(raw: string | undefined): Set<string> {
	return new Set(
		(raw ?? "")
			.split(",")
			.map((entry) => entry.trim())
			.filter((entry) => entry.length > 0),
	);
}

/// The host-staged index of a seat that declares `[tools] always`
/// (crates/odin-omp/src/live/runtime/tool_index.rs): the granted tools the
/// provider request lists from the first turn, and every granted tool with
/// its group and a one-sentence summary for `odin_kernel_search`.
const TOOL_INDEX_ENV = "ODIN_TOOL_INDEX";
const KERNEL_SEARCH_TOOL = "odin_kernel_search";
const KERNEL_SEARCH_RESULTS = 8;

export interface IndexedTool {
	name: string;
	group: string;
	summary: string;
}

export interface ToolIndex {
	always: string[];
	tools: IndexedTool[];
}

/**
 * Parses the staged index. Every name must be a granted tool: the search
 * never finds, and the listing never shows, anything outside the grant.
 */
export function parseToolIndex(raw: string | undefined, granted: Set<string>): ToolIndex | undefined {
	if (raw === undefined) return undefined;
	const fail = (detail: string): never => {
		throw new Error(`fail-closed: tool index ${detail}`);
	};
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return fail("is not JSON");
	}
	if (!isRecord(parsed) || !Array.isArray(parsed.always) || !Array.isArray(parsed.tools)) {
		return fail("is malformed");
	}
	const grantedName = (name: unknown): string =>
		typeof name === "string" && granted.has(name) ? name : fail(`names an ungranted tool ${JSON.stringify(name)}`);
	const tools = parsed.tools.map((entry): IndexedTool => {
		if (!isRecord(entry) || typeof entry.group !== "string" || typeof entry.summary !== "string") {
			return fail("entry is malformed");
		}
		return { name: grantedName(entry.name), group: entry.group, summary: entry.summary };
	});
	return { always: parsed.always.map(grantedName), tools };
}

function words(text: string): string[] {
	return text
		.toLowerCase()
		.split(/[^a-z0-9]+/)
		.filter((word) => word.length > 0);
}

/**
 * The indexed tools a query names, best first: a query word matching a
 * word of the tool's name counts most, then its group, then its summary
 * (a word of three or more letters also matches as a prefix).
 */
export function searchTools(index: ToolIndex, query: string): IndexedTool[] {
	const terms = words(query).filter((term) => term.length >= 2);
	const hit = (list: string[], term: string) =>
		list.some((word) => word === term || (term.length >= 3 && word.startsWith(term)));
	return index.tools
		.map((tool) => {
			const name = words(tool.name);
			const group = words(tool.group);
			const summary = words(tool.summary);
			let score = 0;
			for (const term of terms) {
				if (hit(name, term)) score += 3;
				else if (hit(group, term)) score += 2;
				else if (hit(summary, term)) score += 1;
			}
			return { tool, score };
		})
		.filter((entry) => entry.score > 0)
		.sort((a, b) => b.score - a.score || a.tool.name.localeCompare(b.tool.name))
		.slice(0, KERNEL_SEARCH_RESULTS)
		.map((entry) => entry.tool);
}

/**
 * The canonical identifier envelope the host's own URI parser enforces
 * (`ensure_canonical_id`: 1..=128 ASCII alphanumerics or `.`, `_`, `:`, `-`,
 * starting alphanumeric). A remainder outside it is never a canonical host
 * URI, so refusing it here cannot refuse a legitimate read.
 */
const CANONICAL_HOST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/**
 * The one canonical host URI a read call may target, or null. The extension
 * never parses, normalizes, or repairs a URI: it requires the call's exact one
 * argument to be a single `scheme://` target whose scheme the host declared
 * **verbatim** (scheme case is canonical and significant to the host parser,
 * so an upper- or mixed-case scheme is refused rather than forwarded) and
 * whose identifier stays inside the canonical envelope. Whitespace, local
 * paths, `file://`, web URLs, semicolons (the pinned harness splits routed
 * URLs into multi-target reads on `;`), commas, percent-encoding, path
 * separators, credentials, fragments, queries, traversal, control bytes, and
 * non-ASCII identifiers are all refused here, before the harness can route
 * the call anywhere or fall back to any local reader. Whatever survives is
 * forwarded verbatim and then parsed again by the host's strict URI grammar
 * under the session's bound scope.
 */
function hostUriTarget(input: unknown, schemes: Set<string>): string | null {
	if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
	const keys = Object.keys(input);
	if (keys.length !== 1 || keys[0] !== "path") return null;
	const raw = (input as Record<string, unknown>).path;
	if (typeof raw !== "string" || raw.length === 0) return null;
	const match = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/.exec(raw);
	if (!match || !schemes.has(match[1])) return null;
	const remainder = match[2];
	if (remainder.length > 0 && !CANONICAL_HOST_ID.test(remainder)) return null;
	return raw;
}

/**
 * The one staged launch-input file a workload pod's read call may target,
 * or null: EXACTLY one of the pod's declared input paths
 * (`ODIN_READ_PATHS`, staged only for workload sessions with launch
 * inputs; each a read-only file under the pod's staging mount), optionally
 * with the harness's `:raw` selector. Nothing else on the pod's filesystem.
 */
function readPathTarget(input: unknown, paths: Set<string>): string | null {
	if (paths.size === 0) return null;
	if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
	const keys = Object.keys(input);
	if (keys.length !== 1 || keys[0] !== "path") return null;
	const raw = (input as Record<string, unknown>).path;
	if (typeof raw !== "string") return null;
	const file = raw.endsWith(":raw") ? raw.slice(0, -":raw".length) : raw;
	return paths.has(file) ? raw : null;
}

// Strip persisted envelopes and retrieved memory so history does not duplicate retrieval.
const ENVELOPE_BEGIN = "<odin-turn v1>\n";
const ENVELOPE_END = "\n</odin-turn>\n";

function dropPersistedEnvelope(text: string): string | undefined {
	if (!text.startsWith(ENVELOPE_BEGIN)) return undefined;
	const rest = text.slice(ENVELOPE_BEGIN.length);
	const end = rest.indexOf(ENVELOPE_END);
	if (end < 0) return undefined;
	const body = rest.slice(end + ENVELOPE_END.length);
	let manifest: unknown;
	try {
		manifest = JSON.parse(rest.slice(0, end));
	} catch {
		return body;
	}
	if (!isRecord(manifest) || typeof manifest.header !== "string" || !Array.isArray(manifest.entries)) {
		return body;
	}
	const lines = [
		manifest.header,
		...manifest.entries.map((entry) => (isRecord(entry) && typeof entry.text === "string" ? entry.text : "")),
	];
	if (typeof manifest.note === "string") lines.push(manifest.note);
	const block = lines.join("\n");
	const at = body.indexOf(block);
	if (at < 0 || body.indexOf(block, at + 1) >= 0) return body;
	return `${body.slice(0, at).trimEnd()}\n\n${body.slice(at + block.length).trimStart()}`.trim();
}
const MODEL_REQUEST = `${ENTRY_PREFIX}.model_request`;
const MODEL_REQUEST_LINK = `${ENTRY_PREFIX}.model_request_link`;
const SYSTEM_KEYS = ["system", "systemInstruction", "instructions", "system_instruction"];
const TOOL_KEYS = ["tools", "toolConfig"];
const MESSAGE_KEYS = ["messages", "input", "contents"];

function sha256(value: unknown): string {
	return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function messageText(value: unknown): string {
	if (!isRecord(value)) return "";
	if (typeof value.content === "string") return value.content;
	if (typeof value.text === "string") return value.text;
	const parts = Array.isArray(value.content) ? value.content : value.parts;
	if (!Array.isArray(parts)) return "";
	return parts
		.map((part: unknown) => (isRecord(part) && typeof part.text === "string" ? part.text : ""))
		.join("");
}

function messageRole(value: unknown): "guidance" | "memory" | "history" {
	const text = messageText(value);
	if (text.includes("brain://") || text.includes("<odin-memory")) return "memory";
	if (text.includes(ENVELOPE_BEGIN) || (isRecord(value) && (value.role === "system" || value.role === "developer"))) {
		return "guidance";
	}
	return "history";
}

/**
 * The exact outgoing payload, split by JSON path. Repeated blocks are named
 * by digest; history that extends the previous call keeps only the suffix.
 */
function traceBlocks(
	payload: Record<string, unknown>,
	seen: Set<string>,
	previous: Map<string, { digest: string; items: unknown[] }>,
): {
	skeleton: Record<string, unknown>;
	blocks: Array<{ path: string; role: string; sha256: string; body?: unknown }>;
	seen: Set<string>;
	previous: Map<string, { digest: string; items: unknown[] }>;
} {
	const nextSeen = new Set(seen);
	const nextPrevious = new Map(previous);
	const skeleton: Record<string, unknown> = {};
	const blocks: Array<{ path: string; role: string; sha256: string; body?: unknown }> = [];
	const note = (path: string, role: string, body: unknown) => {
		const digest = sha256(body);
		const block: { path: string; role: string; sha256: string; body?: unknown } = { path, role, sha256: digest };
		if (!nextSeen.has(digest)) {
			nextSeen.add(digest);
			block.body = body;
		}
		blocks.push(block);
		return { blob: digest };
	};
	const walk = (scope: Record<string, unknown>, prefix: string, into: Record<string, unknown>) => {
		for (const [key, value] of Object.entries(scope)) {
			const path = prefix === "" ? `/${key}` : `${prefix}/${key}`;
			if (SYSTEM_KEYS.includes(key)) {
				into[key] = note(path, "system", value);
			} else if (TOOL_KEYS.includes(key)) {
				into[key] = note(path, "tools", value);
			} else if (MESSAGE_KEYS.includes(key) && Array.isArray(value)) {
				const guidance = value.filter((item) => messageRole(item) === "guidance");
				const memory = value.filter((item) => messageRole(item) === "memory");
				if (guidance.length > 0) note(`${path}/guidance`, "guidance", guidance);
				if (memory.length > 0) note(`${path}/memory`, "memory", memory);
				const prior = nextPrevious.get(path);
				const samePrefix =
					prior !== undefined &&
					value.length >= prior.items.length &&
					prior.items.every((item, index) => JSON.stringify(item) === JSON.stringify(value[index]));
				if (samePrefix && prior !== undefined && value.length === prior.items.length) {
					into[key] = { blob: prior.digest };
				} else if (samePrefix && prior !== undefined) {
					into[key] = note(`${path}/delta`, "history", {
						prefix: prior.digest,
						suffix: value.slice(prior.items.length),
					});
				} else {
					into[key] = note(path, "history", value);
				}
				const stored = into[key] as { blob: string };
				nextPrevious.set(path, { digest: stored.blob, items: value });
			} else if (isRecord(value) && prefix === "") {
				const nested: Record<string, unknown> = {};
				walk(value, path, nested);
				into[key] = nested;
			} else {
				into[key] = value;
			}
		}
	};
	walk(payload, "", skeleton);
	return { skeleton, blocks, seen: nextSeen, previous: nextPrevious };
}

export default function (pi: ExtensionAPI) {
	const capabilities = parseListing(process.env.ODIN_CAPABILITIES);

	const hostTools = process.env.ODIN_HOST_TOOLS;
	if (hostTools === undefined) {
		throw new Error("fail-closed: host-issued tool listing is missing");
	}
	const allowed = parseListing(hostTools);
	// The host declares the exact canonical URI schemes it registered with this
	// child; with a non-empty set the harness read tool has a host surface to
	// reach, so it is admitted — for those schemes only.
	const hostUriSchemes = parseListing(process.env.ODIN_HOST_URI_SCHEMES);
	// Only declared staging files are readable; other local paths remain inaccessible.
	const readPaths = new Set([...parseListing(process.env.ODIN_READ_PATHS)].filter((path) =>
		path.startsWith("/var/run/odin/staging/"),
	));
	const governed = new Set(allowed);
	if (hostUriSchemes.size > 0 || readPaths.size > 0) {
		governed.add(URI_READ_TOOL);
	}
	// A seat declaring an always set lists that set plus what
	// odin_kernel_search loads; every other seat lists its whole grant.
	const toolIndex = parseToolIndex(process.env[TOOL_INDEX_ENV], allowed);
	const listed =
		toolIndex === undefined
			? governed
			: new Set([
					...toolIndex.always,
					KERNEL_SEARCH_TOOL,
					...(governed.has(URI_READ_TOOL) ? [URI_READ_TOOL] : []),
				]);
	if (toolIndex !== undefined) {
		governed.add(KERNEL_SEARCH_TOOL);
		pi.registerTool({
			name: KERNEL_SEARCH_TOOL,
			label: "Find Odin tools",
			description:
				"Finds the Odin tools this session holds but does not list yet, by a few words naming the action, " +
				"and lists them and the rest of their group for the rest of this session.",
			parameters: pi.zod.object({
				query: pi.zod.string().min(1).max(200).describe('A few words naming the action, e.g. "drain a node"'),
			}),
			async execute(_toolCallId, params) {
				const found = searchTools(toolIndex, typeof params?.query === "string" ? params.query : "");
				const groups = new Set(found.map((tool) => tool.group));
				for (const tool of toolIndex.tools) {
					if (groups.has(tool.group)) listed.add(tool.name);
				}
				const available = new Set(pi.getAllTools().map((tool) => tool.name));
				await pi.setActiveTools([...listed].filter((name) => available.has(name)));
				const text =
					found.length === 0
						? "No tool this session holds matches that; try other words for the action."
						: found.map((tool) => `${tool.name} (${tool.group}): ${tool.summary}`).join("\n") +
							"\nThese tools and the rest of their groups are now listed for this session.";
				return { content: [{ type: "text", text }], details: { found: found.map((tool) => tool.name) } };
			},
		});
	}

	// The declared complete-request budget of the bound lane, when the seat
	// declares one. A malformed host staging is a fail-closed configuration
	// error: every armed request is refused honestly before the provider is
	// reached, never silently passed through unguarded.
	const contextBudgets = parseContextBudgets(process.env[CONTEXT_BUDGET_ENV]);

	/**
	 * The machine-readable contract of one context refusal, thrown after
	 * the abort so the pinned harness routes it to the child stdout wire as
	 * an `extension_error` frame (`{type:"extension_error", extensionPath,
	 * event:"before_provider_request", error}`). The host bridge consumes
	 * this marker — never ad-hoc string matching — to type the terminal.
	 */
	const REFUSAL_MARKER = "odin.context_refusal.v1";

	/**
	 * The honest refusal terminal of the complete-request guard. The abort
	 * executes in `finally`: a journaling failure is swallowed by the pinned
	 * harness, and only the abort — never a throw — reliably stops the
	 * dispatch. After the durable record and the abort, the marker error is
	 * thrown so the refusal ALSO rides the wire (works even when the
	 * journal is down). `ctx.abort` is always wired by the pinned harness;
	 * the required contract type forbids a silent no-op when armed.
	 */
	async function refuseContextRequest(
		ctx: { sessionManager: { getSessionId(): string }; abort: () => void },
		code: string,
		reason: string,
		details: Record<string, unknown>,
	): Promise<never> {
		try {
			await pi.appendEntry(`${ENTRY_PREFIX}.context_refusal`, {
				session_id: ctx.sessionManager.getSessionId(),
				code,
				reason,
				...details,
			});
		} catch (journalError) {
			// The journal is best-effort evidence; the wire marker thrown
			// below carries the refusal even when journaling is down.
			console.error(
				`odin: context refusal journal entry failed: ${journalError instanceof Error ? journalError.message : String(journalError)}`,
			);
		} finally {
			ctx.abort();
		}
		console.error(`odin: context request refused: ${reason}`);
		throw new Error(
			`${REFUSAL_MARKER}|${JSON.stringify({ code, reason, ...details })}`,
		);
	}

	pi.on("context", async (event) => {
		// Pinned harness contract (omp-contract.d.ts, "context"): the event
		// carries the full message list.
		let messages = (event as { messages: unknown[] }).messages;
		let copied = false;
		const replace = (index: number, next: Record<string, unknown>) => {
			if (!copied) {
				messages = [...messages];
				copied = true;
			}
			messages[index] = next;
		};
		for (let index = 0; index < messages.length; index++) {
			const message: unknown = messages[index];
			if (!isRecord(message) || message.role !== "user") continue;
			const content = message.content;
			if (typeof content === "string") {
				const dropped = dropPersistedEnvelope(content);
				if (dropped !== undefined) replace(index, { ...message, content: dropped });
			} else if (Array.isArray(content)) {
				let parts: unknown[] | undefined;
				content.forEach((part: unknown, partIndex: number) => {
					if (!isRecord(part) || part.type !== "text" || typeof part.text !== "string") return;
					const dropped = dropPersistedEnvelope(part.text);
					if (dropped === undefined) return;
					parts ??= [...content];
					parts[partIndex] = { ...part, text: dropped };
				});
				if (parts !== undefined) replace(index, { ...message, content: parts });
			}
		}
		return { messages };
	});

	pi.on("before_provider_request", async (event, ctx) => {
		if (contextBudgets === undefined) {
			if (isRecord(event.payload)) recordModelRequest(ctx, event.payload);
			return undefined;
		}
		if (contextBudgets.error !== undefined || contextBudgets.budgets === undefined) {
			return refuseContextRequest(ctx, "declaration_unusable", `context budget declaration is unusable: ${contextBudgets.error}`, {
				declaration: process.env[CONTEXT_BUDGET_ENV],
			});
		}
		// The budget of the model serving THIS request: a declared switch is
		// guarded by its own lane; an identity with no declared lane —
		// fallback, default, or undeclared switch — has no applicable
		// declaration and is refused below.
		const current = ctx.models?.current();
		const declared = contextBudgets.budgets.map((lane) => `${lane.provider}/${lane.model}`).join(", ");
		const budget = contextBudgets.budgets.find(
			(lane) => lane.provider === current?.provider && lane.model === current?.id,
		);
		if (current === undefined || budget === undefined) {
			return refuseContextRequest(
				ctx,
				"model_identity_mismatch",
				`context budgets are declared for ${declared} but the request model is ` +
					`${current?.provider ?? "unresolved"}/${current?.id ?? "unresolved"}`,
				{ declared },
			);
		}
		const counter = counterFor(budget);
		if ("error" in counter) {
			return refuseContextRequest(ctx, "declaration_unusable", `context budget declaration is unusable: ${counter.error}`, {
				declaration: process.env[CONTEXT_BUDGET_ENV],
			});
		}
		// A declared NATIVE identity additionally requires the resolved
		// model's catalog tokenizer family to match exactly: an unresolved or
		// foreign family means the lane's counting engine is not this
		// model's, and guessing a family or falling back to bytes is
		// forbidden.
		if (counter.kind === "native" && current.tokenizer !== counter.family) {
			return refuseContextRequest(
				ctx,
				"model_identity_mismatch",
				`context budget is declared for the ${counter.family} counting family but the ` +
					`resolved model carries tokenizer ${current.tokenizer ?? "unresolved"}`,
				{ declared: `${budget.provider}/${budget.model}` },
			);
		}
		if (typeof current.api !== "string") {
			return refuseContextRequest(ctx, "api_unresolved", "the request model api is unresolved; the output bound cannot be located", {});
		}
		if (!isRecord(event.payload)) {
			return refuseContextRequest(ctx, "payload_not_json", "provider request payload is not a JSON object", {});
		}
		// The provider request carries ONLY the governed tool surface:
		// transport-injected tools are pruned before anything is counted
		// or sent, so the model never sees — and never calls — host
		// transport machinery. Dispatch still refuses them if named.
		const payload = pruneTransportInjectedTools(event.payload);
		// Media is detected only by walking actual provider content
		// structure: tool JSON schemas and every non-content field are wire
		// TEXT bounded by the declared counter, so a schema that names or
		// exemplifies media cannot refuse a text-only request, while actual
		// media in content fails closed before any counting.
		if (contentHasMedia(current.api, payload)) {
			return refuseContextRequest(
				ctx,
				"media_uncountable",
				"provider request is uncountable: non-text media cannot be bounded by the declared text counting policy",
				{},
			);
		}
		// The provider must enforce the output reserve; accounting for it alone does not cap output.
		const requested = requestedOutputTokens(current.api, payload);
		if (requested !== undefined && "error" in requested) {
			return refuseContextRequest(ctx, "output_unboundable", `provider request output is unboundable: ${requested.error}`, {});
		}
		let outgoing: Record<string, unknown> | undefined = payload === event.payload ? undefined : payload;
		let outputCap: number;
		if (requested === undefined) {
			if (!outputBoundOmittable(current.api)) {
				return refuseContextRequest(ctx, "output_unboundable", `api ${current.api} request carries no output bound and cannot take a declared cap`, {});
			}
			outputCap = budget.reserve;
			const capped = applyOutputCap(current.api, payload, budget.reserve);
			if ("error" in capped) {
				// Unreachable behind the omittable gate: kept for the
				// defensive api default inside applyOutputCap.
				return refuseContextRequest(ctx, "output_uncappable", `declared output cap could not be applied: ${capped.error}`, {});
			} else {
				outgoing = capped;
			}
		} else if (requested.tokens > budget.reserve) {
			outputCap = budget.reserve;
			const capped = applyOutputCap(current.api, payload, budget.reserve, requested.field);
			if ("error" in capped) {
				return refuseContextRequest(ctx, "output_uncappable", `declared output cap could not be applied: ${capped.error}`, {});
			} else {
				outgoing = capped;
			}
		} else {
			// The request's own ask already fits the lane's reserve: it
			// stands as the output allowance, payload untouched.
			outputCap = requested.tokens;
		}
		const counted = countRequest(counter, outgoing ?? payload);
		if ("error" in counted) {
			return refuseContextRequest(ctx, "payload_uncountable", `provider request is uncountable: ${counted.error}`, {});
		}
		const required = counted.inputTokens + outputCap;
		if (required > budget.window) {
			// The strict host parser (bridge/contracts.rs) accepts numeric
			// fields only as JSON numbers — an absent optional bound is
			// OMITTED, never null. Both units are reported truthfully: the
			// declared counter's input tokens AND the serialized bytes.
			const details: Record<string, unknown> = {
				request_bytes: counted.requestBytes,
				input_tokens: counted.inputTokens,
				reserve: budget.reserve,
				window: budget.window,
				model: `${budget.provider}/${budget.model}`,
			};
			if (requested !== undefined) details.requested_output = requested.tokens;
			return refuseContextRequest(
				ctx,
				"window_exceeded",
				`request requires ${required} ${counter.kind === "bytes" ? "byte" : counter.family} tokens ` +
					`(${counted.inputTokens} input tokens over ${counted.requestBytes} serialized bytes + ` +
					`${outputCap} output allowance` +
					(requested === undefined
						? `: declared reserve ${budget.reserve} (inserted as the request's output cap)`
						: requested.tokens > budget.reserve
							? `: ${requested.tokens} requested, narrowed to the ${budget.reserve} effective reserve`
							: `: ${requested.tokens} requested`) +
					`), exceeding the declared window ${budget.window}`,
				details,
			);
		}
		recordModelRequest(ctx, outgoing ?? payload);
		return outgoing;
	});

	let seenBlocks = new Set<string>();
	let previousHistory = new Map<string, { digest: string; items: unknown[] }>();
	let openAttempt: { callId: string; payloadDigest: string } | null = null;
	let completedAttempt: { callId: string; payloadDigest: string; requestId: string | null } | null = null;

	function recordModelRequest(ctx: { sessionManager: { getSessionId(): string }; models?: { current(): { provider?: string; id?: string; api?: string } | undefined } }, outgoing: Record<string, unknown>) {
		openAttempt = null;
		completedAttempt = null;
		const current = ctx.models?.current();
		const traced = traceBlocks(outgoing, seenBlocks, previousHistory);
		const payloadDigest = sha256(outgoing);
		const callId = randomUUID();
		try {
			pi.appendEntry(MODEL_REQUEST, {
				v: 1,
				session_id: ctx.sessionManager.getSessionId(),
				call_id: callId,
				provider: current?.provider,
				model: current?.id,
				api: current?.api,
				payload_digest: payloadDigest,
				blocks: traced.blocks,
				skeleton: traced.skeleton,
			});
		} catch (error) {
			console.error(`odin: model request trace append failed: ${error instanceof Error ? error.message : String(error)}`);
			return;
		}
		seenBlocks = traced.seen;
		previousHistory = traced.previous;
		openAttempt = { callId, payloadDigest };
	}

	pi.on("after_provider_response", async (event, ctx) => {
		const requestId = typeof event.requestId === "string" && event.requestId.length > 0 ? event.requestId : null;
		const attempt = openAttempt;
		openAttempt = null;
		if (attempt === null) {
			try {
				pi.appendEntry(MODEL_REQUEST_LINK, {
					v: 1,
					session_id: ctx.sessionManager.getSessionId(),
					request_id: requestId,
					trace_error: "provider response arrived with no captured request",
				});
			} catch (error) {
				console.error(`odin: model request link append failed: ${error instanceof Error ? error.message : String(error)}`);
			}
			return;
		}
		completedAttempt = { callId: attempt.callId, payloadDigest: attempt.payloadDigest, requestId };
		const traceError = requestId === null ? "provider response has no requestId" : undefined;
		try {
			pi.appendEntry(MODEL_REQUEST_LINK, {
				v: 1,
				session_id: ctx.sessionManager.getSessionId(),
				call_id: attempt.callId,
				payload_digest: attempt.payloadDigest,
				request_id: requestId,
				trace_error: traceError,
			});
		} catch (error) {
			console.error(`odin: model request link append failed: ${error instanceof Error ? error.message : String(error)}`);
		}
	});

	pi.on("message_end", async (event, ctx) => {
		if (event.message.role !== "assistant") return;
		const responseId = typeof event.message.responseId === "string" && event.message.responseId.length > 0 ? event.message.responseId : null;
		const toolIds = Array.isArray(event.message.content)
			? event.message.content.flatMap((part) => isRecord(part) && part.type === "toolCall" && typeof part.id === "string" ? [part.id] : [])
			: [];
		const attempt = completedAttempt;
		completedAttempt = null;
		if (attempt === null) {
			try {
				pi.appendEntry(MODEL_REQUEST_LINK, {
					v: 1,
					session_id: ctx.sessionManager.getSessionId(),
					response_id: responseId,
					tool_call_ids: toolIds,
					trace_error: "assistant message has no linked provider request",
				});
			} catch (error) {
				console.error(`odin: model response link append failed: ${error instanceof Error ? error.message : String(error)}`);
			}
			return;
		}
		const traceError = [
			attempt.requestId === null ? "assistant message has no linked provider requestId" : undefined,
			responseId === null ? "assistant message has no responseId" : undefined,
		].filter((item) => item !== undefined).join("; ") || undefined;
		try {
			pi.appendEntry(MODEL_REQUEST_LINK, {
				v: 1,
				session_id: ctx.sessionManager.getSessionId(),
				call_id: attempt.callId,
				payload_digest: attempt.payloadDigest,
				request_id: attempt.requestId,
				response_id: responseId,
				tool_call_ids: toolIds,
				usage: event.message.usage,
				stop_reason: event.message.stopReason,
				trace_error: traceError,
			});
		} catch (error) {
			console.error(`odin: model response link append failed: ${error instanceof Error ? error.message : String(error)}`);
		}
	});

	async function lockToolSurface(sessionId: string, requireHostTools: boolean): Promise<void> {
		const available = new Set(pi.getAllTools().map((tool) => tool.name));
		const shellAdmitted = process.env.ODIN_SHELL === "1";
		const target = [...listed].filter((name) => available.has(name));
		if (shellAdmitted && available.has("bash") && !target.includes("bash")) {
			target.push("bash");
		}
		await pi.setActiveTools(target);
		const active = [...pi.getActiveTools()].sort();
		const transportInjected = active
			.filter((name) => !governed.has(name) && TRANSPORT_INJECTED_TOOLS.has(name))
			.sort();
		const extras = active.filter(
			(name) =>
				!governed.has(name) &&
				!TRANSPORT_INJECTED_TOOLS.has(name) &&
				!(shellAdmitted && name === "bash"),
		);
		const missing = requireHostTools ? [...listed].filter((name) => !active.includes(name)) : [];
		if (extras.length > 0 || missing.length > 0) {
			throw new Error(
				`fail-closed: governed tool surface mismatch; extras=${JSON.stringify(extras)} missing=${JSON.stringify(missing)}`,
			);
		}
		pi.appendEntry(`${ENTRY_PREFIX}.surface`, {
			session_id: sessionId,
			transport_injected_tools: transportInjected,
			active_tools: active,
			listed_of_granted: `${listed.size}/${governed.size}`,
			capabilities: [...capabilities].sort(),
			host_uri_schemes: [...hostUriSchemes].sort(),
		});
	}

	pi.on("session_start", async (_event, ctx) => {
		// Host tools arrive immediately afterward through set_host_tools; first
		// strip every ambient/native tool without requiring names not registered
		// yet.
		await lockToolSurface(ctx.sessionManager.getSessionId(), false);
		// Each staged five-field lane, journaled once in parsed form: the
		// runtime driver asserts authored == resolved == staged from these
		// entries and bounds every request's actual output cap by them.
		for (const budget of contextBudgets?.budgets ?? []) {
			pi.appendEntry(`${ENTRY_PREFIX}.context_budget`, {
				session_id: ctx.sessionManager.getSessionId(),
				...budget,
				counter:
					budget.tokenizer === BYTE_TOKENIZER_ID
						? "bytes"
						: (NATIVE_FAMILIES[budget.tokenizer] ?? "unknown"),
			});
		}
	});

	pi.on("before_agent_start", async (_event, ctx) => {
		// set_host_tools must finish before validating the active surface.
		await lockToolSurface(ctx.sessionManager.getSessionId(), true);
	});

	pi.on("tool_call", async (event) => {
		if (!governed.has(event.toolName)) {
			// A declared shell is confined by the process bubble's bash wrapper,
			// not by this gate. Without ODIN_SHELL the tool stays blocked.
			if (process.env.ODIN_SHELL === "1" && event.toolName === "bash") {
				// The tool runs in-process. Prefixing /bin/bash enters the wrapper,
				// which is the shell bubble. The process bubble's own /bin/sh stays
				// available for models.yml key lookup.
				const command = typeof event.input.command === "string" ? event.input.command : "";
				const quoted = `'${command.replace(/'/g, `'\\''`)}'`;
				return { input: { ...event.input, command: `/bin/bash -c ${quoted}` } };
			}
			// Explain that retrying cannot grant a missing capability.
			return {
				block: true,
				reason:
					`fact: "${event.toolName}" is not one of this session's governed tools — it is host transport machinery, ` +
					"not a capability offered to you, and calling it again cannot succeed. This is not a connection or " +
					"availability problem. Use only the governed tools of this session's tool surface; delegating work to " +
					"another seat goes through that seat's governed ask tool.",
			};
		}
		if (
			event.toolName === URI_READ_TOOL &&
			hostUriTarget(event.input, hostUriSchemes) === null &&
			readPathTarget(event.input, readPaths) === null
		) {
			// The native reader follows redirects unchecked; web_read re-checks every hop.
			const web = governed.has("web_read") ? " Read web pages with web_read." : "";
			const inputs =
				readPaths.size > 0
					? ` This pod's launch inputs can be read at exactly: ${[...readPaths].join(", ")}.`
					: "";
			return {
				block: true,
				reason:
					"fail-closed: only one canonical host URI of the schemes this session registered can be read; local paths, URLs, and multi-target reads are outside the governed Odin surface." +
					web +
					inputs,
			};
		}
		// Compute the digest before authorization; the kernel and effector still
		// verify the exact source/digest pair. No execution authority changes.
		if (event.toolName === "capsule_eval_run" && typeof event.input.source === "string") {
			return { input: { ...event.input, source_sha256: createHash("sha256").update(event.input.source, "utf8").digest("hex") } };
		}
	});
}
