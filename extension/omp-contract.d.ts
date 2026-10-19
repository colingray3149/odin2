// Contract for the bundled OMP APIs used by this extension.
// tsconfig checks owned files against this surface without loading package
// implementation types. Runtime tests import the pinned packages.

/// The pinned native tokenizer module the trusted extension counts with.
/// Under the pinned harness, `@oh-my-pi/pi-natives` imports resolve onto
/// the bundled in-process module (legacy-pi-compat specifier routing), so
/// the extension and the harness share one exact counting engine.
declare module "@oh-my-pi/pi-natives" {
	export enum Encoding {
		O200kBase = "O200kBase",
		Cl100kBase = "Cl100kBase",
		ClaudeV3 = "ClaudeV3",
		ClaudeV47 = "ClaudeV47",
		ClaudeV5 = "ClaudeV5",
		ClaudeV5Sonnet = "ClaudeV5Sonnet",
		Qwen3 = "Qwen3",
		DeepSeekV3 = "DeepSeekV3",
		KimiK2 = "KimiK2",
		Glm5 = "Glm5",
	}
	export function countTokens(
		input: string | string[],
		encoding?: Encoding | undefined | null,
	): number;
}

declare module "@oh-my-pi/pi-coding-agent" {
	export interface ZodString {
		min(limit: number): ZodString;
		max(limit: number): ZodString;
		regex(pattern: RegExp, message?: string): ZodString;
		refine(check: (value: string) => boolean, params?: { message: string }): ZodString;
		nullable(): ZodNullable;
		describe(text: string): ZodString;
	}
	export interface ZodNumber {
		int(): ZodNumber;
		min(limit: number): ZodNumber;
		max(limit: number): ZodNumber;
	}
	export interface ZodNullable {
		describe(text: string): ZodNullable;
	}
	export interface ZodObject {
		describe(text: string): ZodObject;
	}
	export interface Zod {
		object(fields: Record<string, unknown>): ZodObject;
		string(): ZodString;
		number(): ZodNumber;
		enum(values: readonly string[]): unknown;
	}
	export interface ExtensionLogger {
		warn?(message: string): void;
	}
	/**
	 * Read-only model query of the pinned harness: `current()` is the model
	 * serving THIS request (not the primary session model), or undefined
	 * when no model is resolved.
	 */
	export interface ExtensionModelQuery {
		current():
			| { provider?: string; id?: string; api?: string; tokenizer?: string }
			| undefined;
	}
	export interface ExtensionContext {
		sessionManager: { getSessionId(): string };
		hasUI: boolean;
		ui: { notify(message: string, level: "info" | "error" | "warning"): void };
		abort(): void;
		models?: ExtensionModelQuery;
	}
	export interface ExtensionTool {
		name: string;
		label?: string;
		description?: string;
		approval?: "read" | "write" | "exec";
		parameters: unknown;
		execute(toolCallId: string, params: any, signal: AbortSignal | undefined, onUpdate: unknown, ctx: ExtensionContext): Promise<unknown>;
	}
	export interface ExtensionCommand {
		description?: string;
		handler(args: string, ctx: ExtensionContext): void | Promise<void>;
	}
	export interface ExtensionAPI {
		zod: Zod;
	on(
		event:
			| "session_start"
			| "session_shutdown",
		handler: (event: unknown, ctx: ExtensionContext) => void | Promise<void>,
	): void;
	/**
	 * Fires before the agent turn starts. When the host composed a staged
	 * dispatch root for the turn, it rides on `prompt`.
	 */
	on(
		event: "before_agent_start",
		handler: (
			event: { prompt?: unknown },
			ctx: ExtensionContext,
		) => void | Promise<void>,
	): void;
	/**
	 * Fires when the agent assembles the turn's context. Returning
	 * `{ messages }` REPLACES the message list; the input list and its
	 * records are never mutated by the harness.
	 */
	on(
		event: "context",
		handler: (
			event: { messages: unknown[] },
			ctx: ExtensionContext,
		) => { messages: unknown[] } | void | Promise<{ messages: unknown[] } | void>,
	): void;
		/**
		 * Fires after the provider builds a request and before it is sent.
		 * Returning a value REPLACES the request body; returning undefined
		 * keeps the original. A throw is logged as an extension error and
		 * swallowed — it never aborts the dispatch.
		 */
		on(
			event: "before_provider_request",
			handler: (
				event: { type: "before_provider_request"; payload: unknown },
				ctx: ExtensionContext,
			) => unknown | Promise<unknown>,
		): void;
		on(
			event: "after_provider_response",
			handler: (
				event: { type: "after_provider_response"; requestId?: string | null; status?: number },
				ctx: ExtensionContext,
			) => void | Promise<void>,
		): void;
		on(
			event: "message_end",
			handler: (
				event: { type: "message_end"; message: { role?: string; responseId?: string; content?: unknown; usage?: unknown; stopReason?: string } },
				ctx: ExtensionContext,
			) => void | Promise<void>,
		): void;
		on(
			event: "tool_call",
			handler: (
				event: { toolName: string; input: Record<string, unknown>; toolCallId: string },
				ctx: ExtensionContext,
			) =>
				| void
				| { block?: boolean; reason?: string; input?: Record<string, unknown> }
				| Promise<void | { block?: boolean; reason?: string; input?: Record<string, unknown> }>,
		): void;
		registerTool(tool: ExtensionTool): void;
		registerCommand(name: string, command: ExtensionCommand): void;
		appendEntry(customType: string, data?: unknown): unknown;
		getActiveTools(): string[];
		getAllTools(): Array<{ name: string }>;
		setActiveTools(toolNames: string[]): Promise<void>;
		logger: ExtensionLogger;
	}
}
