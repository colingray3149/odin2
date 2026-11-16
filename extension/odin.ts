//! Trusted Odin extension entry for stock OMP.
//!
//! Host-issued capability listings restrict the active tools and every tool call.
//! Capsule eval/edit use `host_tool_call`; the sidecar stays private to odind.
//! Stop controls remain in Huginn and the CLI.
//! Reads admit declared URI schemes and staged input files only.

import { createHash, randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { countTokens, Encoding } from "@oh-my-pi/pi-natives";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

// odind sets ODIN_SHELL exactly when it binds the shell-bubble bash wrapper
// (process/sandbox.rs); only then may the bash tool run.
const shellAdmitted = (): boolean => process.env.ODIN_SHELL === "1";
// The prefix that sends a bash tool command into the shell bubble.
const SHELL_WRAPPER = "/bin/bash -c";
// A command that is exactly one wrapper around a single-quoted body.
const WRAPPED_COMMAND = new RegExp(`^${SHELL_WRAPPER.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")} '(?:[^']|'\\\\'')*'$`);
const ENTRY_PREFIX = "odin.extension";

/// The pinned harness tool that resolves internal URIs; the bridge serves
/// host-registered schemes through it.
const URI_READ_TOOL = "read";
/// Where a workload pod's launch inputs are staged (POD_STAGING_PREFIX in crates/odin-omp/src/live/runtime/assembly.rs).
const STAGING_MOUNT = "/var/run/odin/staging/";

/// The host-staged complete-request context budgets, one
/// `provider|model|window|reserve|tokenizer` lane per model the session may
/// run, `;`-joined: each lane's declared window, its compiler-resolved
/// effective output reserve, and the exact declared context tokenizer
/// identity. A request is guarded by the lane of the model serving it.
/// Mirrors `LaneContextBudgets` in crates/odin-omp/src/live/control.rs.
const CONTEXT_BUDGET_ENV = "ODIN_CONTEXT_BUDGET";

/**
 * One declared request counter: the counting unit of a lane's staged tokenizer
 * identity. Byte lanes count the serialized request text as exact UTF-8 bytes
 * (the pinned house rule: one token per byte). Native lanes count the same
 * serialized text with the pinned `@oh-my-pi/pi-natives` engine for the declared
 * family — the same bundled module the harness itself counts with (static
 * import: the pinned omp binary always carries pi-natives in-process, so the
 * extension and the harness share one exact engine). A native lane whose engine
 * refuses the text is refused, never approximated with bytes or any ratio.
 * Estimate lanes count bytes times a per-lane tokens-per-byte ratio (see
 * `ESTIMATE_TOKENS_PER_BYTE`), calibrated from provider usage.
 */
type RequestCounter =
	| { kind: "bytes" }
	| { kind: "estimate" }
	| { kind: "native"; family: string; encoding: Encoding };

/**
 * The estimate counter's tokens per byte until a response on its lane reports
 * usage (one token per four bytes, as the brain's `ESTIMATE_BYTES_PER_TOKEN`).
 * Each later response replaces its lane's ratio with the provider's own count.
 */
const ESTIMATE_TOKENS_PER_BYTE = 1 / 4;

/// Tokenizer identities must match the brain's declared counters; unknown identities are refused.
/// A native family must match the harness's Model.tokenizer mapping.
const COUNTERS = new Map<string, RequestCounter>([
	["odin.tokenizer.utf8-bytes.v1", { kind: "bytes" }],
	["odin.tokenizer.estimate.v1", { kind: "estimate" }],
	["odin.tokenizer.qwen3.v1", { kind: "native", family: "qwen3", encoding: Encoding.Qwen3 }],
]);

/// The unit a refusal names the counted tokens in.
function counterUnit(counter: RequestCounter): string {
	return counter.kind === "bytes" ? "byte" : counter.kind === "estimate" ? "estimated" : counter.family;
}

interface ContextBudget {
	provider: string;
	model: string;
	window: number;
	reserve: number;
	tokenizer: string;
	counter: RequestCounter;
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
	const counter = COUNTERS.get(tokenizer);
	if (counter === undefined) {
		return { error: `declared tokenizer identity ${JSON.stringify(tokenizer)} has no implementation` };
	}
	return { budget: { provider, model, window, reserve, tokenizer, counter } };
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
function pruneTransportInjectedTools(payload: Record<string, unknown>, readDescription?: string): Record<string, unknown> {
	const tools = payload.tools;
	if (!Array.isArray(tools)) return payload;
	let described = false;
	const listed = readDescription === undefined ? tools : tools.map((tool) => {
		// The harness's read text teaches coding-session paths; a seat reads what its own description says.
		if (!isRecord(tool)) return tool;
		if (tool.name === URI_READ_TOOL && typeof tool.description === "string") {
			described = true;
			return { ...tool, description: readDescription };
		}
		if (isRecord(tool.function) && tool.function.name === URI_READ_TOOL) {
			described = true;
			return { ...tool, function: { ...tool.function, description: readDescription } };
		}
		return tool;
	});
	const kept = listed.filter((tool) => {
		if (!isRecord(tool)) return true;
		const name = typeof tool.name === "string"
			? tool.name
			: isRecord(tool.function) && typeof tool.function.name === "string"
				? tool.function.name
				: undefined;
		return name === undefined || !TRANSPORT_INJECTED_TOOLS.has(name);
	});
	if (kept.length === tools.length && !described) return payload;
	return { ...payload, tools: kept };
}

/**
 * The real file a read targets inside one of the seat's own folders (`ODIN_READ_ROOTS`, the
 * bubble's seat mounts), or null. Symlinks are resolved first, so a link cannot lead out of a
 * folder; a line selector (`notes.md:40-80`) or query (`data.json?q=.x`) after the file is kept.
 */
export function readRootTarget(input: unknown, roots: string[]): string | null {
	if (roots.length === 0) return null;
	if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
	const raw = (input as Record<string, unknown>).path;
	if (typeof raw !== "string" || !raw.startsWith("/")) return null;
	let file = raw.replace(/\?.*$/, "");
	for (let strip = 0; strip < 3; strip++) {
		let real: string | null = null;
		try {
			real = realpathSync(file);
		} catch {
			real = null;
		}
		if (real !== null) {
			return roots.some((root) => real === root || real.startsWith(`${root}/`)) ? raw : null;
		}
		const selector = file.lastIndexOf(":");
		if (selector <= 0) return null;
		file = file.slice(0, selector);
	}
	return null;
}

function asCount(value: unknown): number | undefined {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
		? value
		: undefined;
}

// A response's provider input: fresh input plus cached reads and writes; absent without an input count.
function providerInputTokens(usage: unknown): number | undefined {
	if (!isRecord(usage)) return undefined;
	const input = asCount(usage.input);
	if (input === undefined) return undefined;
	return input + (asCount(usage.cacheRead) ?? 0) + (asCount(usage.cacheWrite) ?? 0);
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
 * What one image counts toward a lane window. Odin downscales every image
 * it sends to at most 1568 px, which providers bill at well under this.
 * Mirrors `IMAGE_TOKENS` in crates/odin-omp/src/live/control.rs.
 */
const IMAGE_TOKENS = 8192;

function isInlineImage(part: unknown): part is { image_url: { url: string } } {
	return (
		isRecord(part) &&
		part.type === "image_url" &&
		isRecord(part.image_url) &&
		typeof part.image_url.url === "string" &&
		part.image_url.url.startsWith("data:image/")
	);
}

/**
 * Chat-completions inline images (the `image_url` data URLs OMP sends for
 * image blocks) mapped through `replace`, and how many there were. Other
 * apis are returned unchanged with zero.
 */
function mapInlineImages(
	api: string,
	payload: Record<string, unknown>,
	replace: (part: { image_url: { url: string } }) => unknown[],
): { payload: Record<string, unknown>; images: number } {
	if ((api !== "openai-completions" && api !== "openrouter") || !Array.isArray(payload.messages)) {
		return { payload, images: 0 };
	}
	let images = 0;
	const messages = payload.messages.map((message: unknown) => {
		if (!isRecord(message) || !Array.isArray(message.content) || !message.content.some(isInlineImage)) return message;
		const content = message.content.flatMap((part: unknown) => {
			if (!isInlineImage(part)) return [part];
			images++;
			return replace(part);
		});
		return { ...message, content };
	});
	return images === 0 ? { payload, images } : { payload: { ...payload, messages }, images };
}

/** The request as counted text: inline images removed (each counts IMAGE_TOKENS). */
function withoutInlineImages(api: string, payload: Record<string, unknown>): { payload: Record<string, unknown>; images: number } {
	return mapInlineImages(api, payload, () => []);
}

/** The request as traced: each inline image named by its digest and size, not its bytes. */
function tracedImages(api: string | undefined, payload: Record<string, unknown>): Record<string, unknown> {
	return mapInlineImages(api ?? "", payload, (part) => [
		{ type: "image_url", image_url: { url: `sha256:${sha256(part.image_url.url)} (${part.image_url.url.length} bytes)` } },
	]).payload;
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
	tokensPerByte: number,
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
	if (counter.kind === "estimate") {
		return { inputTokens: Math.ceil(requestBytes * tokensPerByte), requestBytes };
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

// The harness's read selectors on a staged path: `:raw`, `:N`, `:N-M`, and
// `:raw:N-M` or `:N-M:raw` (N, M decimal line numbers). Nothing else.
const READ_SELECTOR = /:(?:raw|\d+|\d+-\d+|raw:\d+-\d+|\d+-\d+:raw)$/;

/**
 * The one staged launch-input file a workload pod's read call may target,
 * or null: EXACTLY one of the pod's declared input paths
 * (`ODIN_READ_PATHS`, staged only for workload sessions with launch
 * inputs; each a read-only file under the pod's staging mount), optionally
 * with one read selector so a long file can be paged. Nothing else on the
 * pod's filesystem.
 */
function readPathTarget(input: unknown, paths: Set<string>): string | null {
	if (paths.size === 0) return null;
	if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
	const keys = Object.keys(input);
	if (keys.length !== 1 || keys[0] !== "path") return null;
	const raw = (input as Record<string, unknown>).path;
	if (typeof raw !== "string") return null;
	const file = raw.replace(READ_SELECTOR, "");
	return paths.has(file) ? raw : null;
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
	// The system prompt carries core memory's brain:// links; it is guidance, not injected memory.
	if (isRecord(value) && (value.role === "system" || value.role === "developer")) return "guidance";
	// Memory is injected into the owner's turn; a link the assistant or a tool result quotes is history.
	if (isRecord(value) && value.role === "user" && messageText(value).includes("brain://")) return "memory";
	return "history";
}

/** One stored part of a request; `bytes` is its serialized size, which the host sums into the request's prefix. */
type TraceBlock = { path: string; role: string; sha256: string; bytes: number; body?: unknown };

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
	blocks: TraceBlock[];
	seen: Set<string>;
	previous: Map<string, { digest: string; items: unknown[] }>;
} {
	const nextSeen = new Set(seen);
	const nextPrevious = new Map(previous);
	const skeleton: Record<string, unknown> = {};
	const blocks: TraceBlock[] = [];
	const note = (path: string, role: string, body: unknown) => {
		const digest = sha256(body);
		const block: TraceBlock = { path, role, sha256: digest, bytes: Buffer.byteLength(JSON.stringify(body), "utf8") };
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
				const prior = nextPrevious.get(path);
				const samePrefix =
					prior !== undefined &&
					value.length >= prior.items.length &&
					prior.items.every((item, index) => JSON.stringify(item) === JSON.stringify(value[index]));
				// Memory counts in the request that injected it: only the messages added to the prior history.
				const added = samePrefix && prior !== undefined ? value.slice(prior.items.length) : value;
				const guidance = value.filter((item) => messageRole(item) === "guidance");
				const memory = added.filter((item) => messageRole(item) === "memory");
				if (guidance.length > 0) note(`${path}/guidance`, "guidance", guidance);
				if (memory.length > 0) note(`${path}/memory`, "memory", memory);
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
	const hostTools = process.env.ODIN_HOST_TOOLS;
	if (hostTools === undefined) {
		throw new Error("fail-closed: host-issued tool listing is missing");
	}
	const allowed = parseListing(hostTools);
	// The host declares the exact canonical URI schemes it registered with this
	// child; with a non-empty set the harness read tool has a host surface to
	// reach, so it is admitted — for those schemes only.
	const hostUriSchemes = parseListing(process.env.ODIN_HOST_URI_SCHEMES);
	// Only declared staging files are readable; other local paths remain inaccessible. A declared path outside the
	// staging mount is a launch error, not an input to drop: the model would meet a refusal with no cause.
	const readPaths = parseListing(process.env.ODIN_READ_PATHS);
	for (const path of readPaths) {
		if (!path.startsWith(STAGING_MOUNT)) throw new Error(`fail-closed: ODIN_READ_PATHS names ${path}, outside ${STAGING_MOUNT}`);
	}
	// The seat's own folders, resolved once: a root that does not resolve is not readable.
	const readRoots = (process.env.ODIN_READ_ROOTS ?? "")
		.split(":")
		.filter((root) => root.startsWith("/"))
		.flatMap((root) => {
			try {
				return [realpathSync(root)];
			} catch {
				return [];
			}
		});
	const governed = new Set(allowed);
	if (hostUriSchemes.size > 0 || readPaths.size > 0 || readRoots.length > 0) {
		governed.add(URI_READ_TOOL);
	}
	const webRead = governed.has("research") ? " Web pages: research {op: read}." : "";
	const readDescription =
		`Reads one Odin link (${[...hostUriSchemes].map((scheme) => `${scheme}://`).join(", ")})` +
		(readRoots.length > 0 ? ` or a file in your folders: ${readRoots.join(", ")}` : "") +
		(readPaths.size > 0 ? `, or a launch input: ${[...readPaths].join(", ")}` : "") +
		". Line ranges go in the path (notes.md:40-80, notes.md:-20 for the last 20); PDFs and documents come back as text." +
		webRead;
	const listed = governed;

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

	pi.on("context", async (event, ctx) => {
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
		// A model whose catalog entry lacks image input never sees the
		// pixels: each image becomes one line it can relay instead.
		const current = ctx.models?.current();
		if (current !== undefined && !(current.input ?? []).includes("image")) {
			const unseen = {
				type: "text",
				text:
					`[Odin: an image was here, but this model (${current.provider}/${current.id}) cannot see images; ` +
					"say so in one line instead of guessing what it shows]",
			};
			const isImage = (part: unknown) => isRecord(part) && part.type === "image";
			for (let index = 0; index < messages.length; index++) {
				const message: unknown = messages[index];
				if (!isRecord(message) || !Array.isArray(message.content) || !message.content.some(isImage)) continue;
				replace(index, { ...message, content: message.content.map((part: unknown) => (isImage(part) ? unseen : part)) });
			}
		}
		return { messages };
	});

	pi.on("before_provider_request", async (event, ctx) => {
		if (contextBudgets === undefined) {
			// No window to guard, but the model still sees only the governed tool surface.
			if (!isRecord(event.payload)) return undefined;
			const pruned = pruneTransportInjectedTools(event.payload, readDescription);
			await recordModelRequest(ctx, pruned);
			return pruned === event.payload ? undefined : pruned;
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
		const { counter } = budget;
		const laneKey = `${budget.provider}/${budget.model}`;
		const tokensPerByte = estimateRatios.get(laneKey) ?? ESTIMATE_TOKENS_PER_BYTE;
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
		const payload = pruneTransportInjectedTools(event.payload, readDescription);
		// Inline images (vision lanes) count a fixed IMAGE_TOKENS each on a
		// byte lane; a native text counter cannot bound them.
		const text = withoutInlineImages(current.api, payload);
		// Media is detected only by walking actual provider content
		// structure: tool JSON schemas and every non-content field are wire
		// TEXT bounded by the declared counter, so a schema that names or
		// exemplifies media cannot refuse a text-only request, while actual
		// media in content fails closed before any counting.
		if (contentHasMedia(current.api, text.payload) || (text.images > 0 && counter.kind === "native")) {
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
		const countedText = countRequest(counter, withoutInlineImages(current.api, outgoing ?? payload).payload, tokensPerByte);
		if ("error" in countedText) {
			return refuseContextRequest(ctx, "payload_uncountable", `provider request is uncountable: ${countedText.error}`, {});
		}
		const counted = { ...countedText, inputTokens: countedText.inputTokens + text.images * IMAGE_TOKENS };
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
			if (text.images > 0) details.images = text.images;
			return refuseContextRequest(
				ctx,
				"window_exceeded",
				`request requires ${required} ${counterUnit(counter)} tokens ` +
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
		if (counter.kind === "estimate") {
			pendingEstimate = { lane: laneKey, requestBytes: counted.requestBytes, tokensPerByte };
		}
		await recordModelRequest(ctx, outgoing ?? payload);
		return outgoing;
	});

	// Per lane: the tokens-per-byte the estimate counter uses, calibrated from the provider's usage.
	const estimateRatios = new Map<string, number>();
	// The estimate-lane request in flight, settled by its response's usage.
	let pendingEstimate: { lane: string; requestBytes: number; tokensPerByte: number } | undefined;
	let seenBlocks = new Set<string>();
	let previousHistory = new Map<string, { digest: string; items: unknown[] }>();
	let openAttempt: { callId: string; payloadDigest: string } | null = null;
	let completedAttempt: { callId: string; payloadDigest: string; requestId: string | null } | null = null;

	// The trace is evidence, not a gate: a write that fails, by throwing or rejecting, is named on stderr and the turn goes on.
	async function journal(entry: string, data: Record<string, unknown>): Promise<boolean> {
		try {
			await pi.appendEntry(entry, data);
			return true;
		} catch (error) {
			console.error(`odin: ${entry} append failed: ${error instanceof Error ? error.message : String(error)}`);
			return false;
		}
	}

	async function recordModelRequest(ctx: { sessionManager: { getSessionId(): string }; models?: { current(): { provider?: string; id?: string; api?: string } | undefined } }, outgoing: Record<string, unknown>) {
		openAttempt = null;
		completedAttempt = null;
		const current = ctx.models?.current();
		const traced = traceBlocks(tracedImages(current?.api, outgoing), seenBlocks, previousHistory);
		const payloadDigest = sha256(outgoing);
		const callId = randomUUID();
		const stored = await journal(MODEL_REQUEST, {
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
		if (!stored) return;
		seenBlocks = traced.seen;
		previousHistory = traced.previous;
		openAttempt = { callId, payloadDigest };
	}

	pi.on("after_provider_response", async (event, ctx) => {
		const requestId = typeof event.requestId === "string" && event.requestId.length > 0 ? event.requestId : null;
		const attempt = openAttempt;
		openAttempt = null;
		if (attempt === null) {
			await journal(MODEL_REQUEST_LINK, {
				v: 1,
				session_id: ctx.sessionManager.getSessionId(),
				request_id: requestId,
				trace_error: "provider response arrived with no captured request",
			});
			return;
		}
		completedAttempt = { callId: attempt.callId, payloadDigest: attempt.payloadDigest, requestId };
		const traceError = requestId === null ? "provider response has no requestId" : undefined;
		const header = (name: string) => {
			const value = event.headers?.[name];
			return typeof value === "string" && value.length > 0 ? value : undefined;
		};
		await journal(MODEL_REQUEST_LINK, {
			v: 1,
			session_id: ctx.sessionManager.getSessionId(),
			call_id: attempt.callId,
			payload_digest: attempt.payloadDigest,
			request_id: requestId,
			served_model: header("x-litellm-model-name"),
			model_group: header("x-litellm-model-group"),
			attempted_fallbacks: header("x-litellm-attempted-fallbacks"),
			gateway_call_id: header("x-litellm-call-id"),
			response_cost: header("x-litellm-response-cost"),
			trace_error: traceError,
		});
	});

	pi.on("message_end", async (event, ctx) => {
		if (event.message.role !== "assistant") return;
		const responseId = typeof event.message.responseId === "string" && event.message.responseId.length > 0 ? event.message.responseId : null;
		const toolIds = Array.isArray(event.message.content)
			? event.message.content.flatMap((part) => isRecord(part) && part.type === "toolCall" && typeof part.id === "string" ? [part.id] : [])
			: [];
		const attempt = completedAttempt;
		completedAttempt = null;
		// Calibrate the estimate lane from this response's provider usage: its input, cached reads and writes.
		const estimate = pendingEstimate;
		pendingEstimate = undefined;
		const observedInput = providerInputTokens(event.message.usage);
		if (estimate !== undefined && observedInput !== undefined && estimate.requestBytes > 0) {
			estimateRatios.set(estimate.lane, observedInput / estimate.requestBytes);
		}
		if (attempt === null) {
			await journal(MODEL_REQUEST_LINK, {
				v: 1,
				session_id: ctx.sessionManager.getSessionId(),
				response_id: responseId,
				tool_call_ids: toolIds,
				trace_error: "assistant message has no linked provider request",
			});
			return;
		}
		const traceError = [
			attempt.requestId === null ? "assistant message has no linked provider requestId" : undefined,
			responseId === null ? "assistant message has no responseId" : undefined,
		].filter((item) => item !== undefined).join("; ") || undefined;
		await journal(MODEL_REQUEST_LINK, {
			v: 1,
			session_id: ctx.sessionManager.getSessionId(),
			call_id: attempt.callId,
			payload_digest: attempt.payloadDigest,
			request_id: attempt.requestId,
			response_id: responseId,
			tool_call_ids: toolIds,
			usage: event.message.usage,
			stop_reason: event.message.stopReason,
			estimate:
				estimate === undefined
					? undefined
					: { lane: estimate.lane, request_bytes: estimate.requestBytes, tokens_per_byte: estimate.tokensPerByte, observed_input_tokens: observedInput },
			trace_error: traceError,
		});
	});

	async function lockToolSurface(sessionId: string, requireHostTools: boolean): Promise<void> {
		const available = new Set(pi.getAllTools().map((tool) => tool.name));
		const target = [...listed].filter((name) => available.has(name));
		if (shellAdmitted() && available.has("bash") && !target.includes("bash")) {
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
				!(shellAdmitted() && name === "bash"),
		);
		const missing = requireHostTools ? [...listed].filter((name) => !active.includes(name)) : [];
		if (extras.length > 0 || missing.length > 0) {
			throw new Error(
				`fail-closed: governed tool surface mismatch; extras=${JSON.stringify(extras)} missing=${JSON.stringify(missing)}`,
			);
		}
		await pi.appendEntry(`${ENTRY_PREFIX}.surface`, {
			session_id: sessionId,
			transport_injected_tools: transportInjected,
			active_tools: active,
			listed_of_granted: `${listed.size}/${governed.size}`,
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
		for (const { provider, model, window, reserve, tokenizer, counter } of contextBudgets?.budgets ?? []) {
			await pi.appendEntry(`${ENTRY_PREFIX}.context_budget`, {
				session_id: ctx.sessionManager.getSessionId(),
				provider,
				model,
				window,
				reserve,
				tokenizer,
				counter: counter.kind === "native" ? counter.family : counter.kind,
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
			if (shellAdmitted() && event.toolName === "bash") {
				// The tool runs in-process. Prefixing /bin/bash enters the wrapper,
				// which is the shell bubble. The process bubble's own /bin/sh stays
				// available for models.yml key lookup.
				const command = typeof event.input.command === "string" ? event.input.command : "";
				// OMP writes the revised input into the model's history, so the model
				// copies the wrapper. A command that is exactly one wrapper already
				// enters the shell bubble; wrapping it again nests quotes every turn.
				if (WRAPPED_COMMAND.test(command)) return undefined;
				const quoted = `'${command.replace(/'/g, `'\\''`)}'`;
				return { input: { ...event.input, command: `${SHELL_WRAPPER} ${quoted}` } };
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
			readPathTarget(event.input, readPaths) === null &&
			readRootTarget(event.input, readRoots) === null
		) {
			// The native reader follows redirects unchecked; web_read re-checks every hop.
			const web = governed.has("web_read")
				? " Read web pages with web_read."
				: governed.has("research")
					? " Read web pages with research {op: read, url}."
					: "";
			const folders =
				readRoots.length > 0 ? ` Files can be read inside your folders only: ${readRoots.join(", ")}.` : "";
			// An artifact reference reads through the files tool's artifact op, not the native reader.
			const artifacts = governed.has("files")
				? " Read an artifact reference (artifact://…) with the files tool's artifact op."
				: "";
			const inputs =
				readPaths.size > 0
					? ` This pod's launch inputs can be read at exactly: ${[...readPaths].join(", ")}.`
					: "";
			return {
				block: true,
				reason:
					"fail-closed: only one canonical host URI of the schemes this session registered can be read; local paths, URLs, and multi-target reads are outside the governed Odin surface." +
					folders +
					web +
					artifacts +
					inputs,
			};
		}
	});
}
