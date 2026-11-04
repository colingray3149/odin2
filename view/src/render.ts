// Renders transcript blocks the way OMP's chat does: user bubble, Markdown replies, dim italic thinking, one-line tool
// calls with folded results, and a dim per-turn usage row. Glyphs come from the theme's Nerd Font preset.
import { formatNumber } from "@oh-my-pi/pi-utils";
import { formatContextUsage, getContextUsageLevel, getContextUsageThemeColor } from "../omp/chrome/context-thresholds";
import { Markdown } from "../omp/components/markdown";
import type { SymbolKey } from "../omp/theme/symbols";
import { getMarkdownTheme, theme } from "../omp/theme/theme";
import { replaceTabs, truncateToWidth, visibleWidth, wrapTextWithAnsi } from "../omp/utils";
import { spoken } from "./protocol";
import type { Block, Job, Usage } from "./transcript";

const FOLD_LINES = 3;

const cache = new WeakMap<Block, { key: string; lines: readonly string[] }>();

/** Rows for one block at `width`; cached until the block, the width or the fold changes. */
export function renderBlock(block: Block, width: number, expanded: boolean, quiet = ""): readonly string[] {
	const key = `${block.version}:${width}:${expanded}:${quiet}`;
	const hit = cache.get(block);
	if (hit?.key === key) return hit.lines;
	const lines = draw(block, width, expanded, quiet);
	cache.set(block, { key, lines });
	return lines;
}

function draw(block: Block, width: number, expanded: boolean, quiet: string): readonly string[] {
	switch (block.kind) {
		case "user":
			return userBubble(expanded ? block.raw : block.text, width);
		case "assistant": {
			const text = spoken(block.text, quiet);
			return text ? new Markdown(text, 1, 0, getMarkdownTheme()).render(width) : [];
		}
		case "thinking": {
			const head = ` ${theme.fg("thinkingText", theme.symbol("icon.intelligence"))} ${theme.fg("muted", "Thinking")}`;
			const body = new Markdown(block.text, 1, 0, getMarkdownTheme(), {
				color: (text: string) => theme.fg("thinkingText", text),
				italic: true,
			}).render(width);
			return [head, ...fold(body, expanded, width)];
		}
		case "tool":
			return toolRows(block, width, expanded);
		case "usage":
			return [usageRow(block.usage, width)];
		case "note": {
			const glyph = block.error ? theme.fg("error", theme.status.error) : theme.fg("dim", theme.status.info);
			const text = theme.fg(block.error ? "error" : "dim", block.text);
			const rows = wrapTextWithAnsi(text, Math.max(10, width - 3)).map((line, i) => (i === 0 ? ` ${glyph} ` : "   ") + line);
			if (!block.raw || !expanded) return rows;
			const raw = replaceTabs(block.raw)
				.split("\n")
				.flatMap(line => wrapTextWithAnsi(theme.fg("dim", line), Math.max(10, width - 3)))
				.map(line => `   ${line}`);
			return [...rows, ...raw];
		}
	}
}

function userBubble(text: string, width: number): readonly string[] {
	return new Markdown(text, 1, 1, getMarkdownTheme(), {
		bgColor: (value: string) => theme.bg("userMessageBg", value),
	}).render(width);
}

/** A pending line sent from this terminal, before the conversation's session shows it. */
export function pendingBubble(text: string, width: number, to?: string): readonly string[] {
	return [...userBubble(text, width), ` ${theme.fg("dim", `${theme.status.pending} sending${to ? ` to ${to}` : ""}`)}`];
}

function fold(lines: readonly string[], expanded: boolean, width: number): readonly string[] {
	if (expanded || lines.length <= FOLD_LINES) return lines;
	const more = theme.fg("dim", `   … ${lines.length - FOLD_LINES} more lines (ctrl+r)`);
	return [...lines.slice(0, FOLD_LINES), truncateToWidth(more, width)];
}

// Tool glyph by capability family (`brain.search` → brain).
const TOOL_GLYPHS: Record<string, SymbolKey> = {
	brain: "tool.memory",
	memory: "tool.memory",
	web: "tool.webSearch",
	search: "tool.webSearch",
	shell: "tool.bash",
	bash: "tool.bash",
	exec: "tool.bash",
	process: "tool.bash",
	file: "tool.edit",
	files: "tool.edit",
	fs: "tool.edit",
	seat: "tool.task",
	task: "tool.task",
	browser: "tool.browser",
	kube: "tool.job",
	job: "tool.job",
	github: "tool.gh",
	gh: "tool.gh",
	hermes: "tool.irc",
	discord: "tool.irc",
	ask: "tool.ask",
	todo: "tool.todo",
	ssh: "tool.ssh",
};

function toolGlyph(name: string): string {
	const family = name.split(/[._:/]/)[0]!.toLowerCase();
	return theme.symbol(TOOL_GLYPHS[family] ?? "icon.extensionTool");
}

/** The argument worth showing: a common key's value, a lone primitive, or compact JSON. */
function compactArgs(args: unknown): string {
	if (args === undefined || args === null) return "";
	if (typeof args !== "object") return String(args);
	const record = args as Record<string, unknown>;
	for (const key of ["query", "command", "path", "url", "text", "message", "prompt", "id", "name"]) {
		const value = record[key];
		if (typeof value === "string" && value) return JSON.stringify(value);
	}
	const entries = Object.entries(record);
	if (entries.length === 1 && typeof entries[0]![1] !== "object") return String(entries[0]![1]);
	return entries.length === 0 ? "" : JSON.stringify(args);
}

/** OMP tool results arrive as `{"content":[{"type":"text","text":…}],"details":…}`; show the text inside. */
function toolText(result: string): string {
	if (!result.startsWith("{")) return result;
	try {
		const parsed = JSON.parse(result) as { content?: { text?: unknown }[] };
		if (!Array.isArray(parsed.content)) return result;
		return parsed.content.map(c => (typeof c.text === "string" ? c.text : "")).join("\n");
	} catch {
		return result;
	}
}

function toolRows(block: Extract<Block, { kind: "tool" }>, width: number, expanded: boolean): readonly string[] {
	const status =
		block.status === "pending" || block.status === "job"
			? theme.fg("accent", theme.status.pending)
			: block.status === "success"
				? theme.fg("success", theme.status.success)
				: theme.fg("error", theme.status.error);
	const title = `${theme.fg("accent", toolGlyph(block.name))} ${theme.fg("toolTitle", theme.bold(block.name))}`;
	const args = compactArgs(block.args).replace(/\s+/g, " ");
	const headRoom = width - 1 - visibleWidth(title) - 2 - 2;
	const head = ` ${title}${args && headRoom > 3 ? ` ${theme.fg("muted", truncateToWidth(args, headRoom))}` : ""} ${status}`;
	const rows = [truncateToWidth(head, width)];
	// A job's own result is the model's "continues in the background as job j6…" note; the job row says it.
	const result = block.job && !expanded ? "" : toolText(block.result).trim();
	if (block.job) {
		const tree = result ? theme.tree.branch : theme.tree.last;
		rows.push(truncateToWidth(` ${theme.fg("dim", tree)} ${jobLabel(block.job)}`, width));
	}
	if (!result) return rows;
	const lead = ` ${theme.fg("dim", theme.tree.last)} `;
	const body = replaceTabs(result)
		.split("\n")
		.flatMap(line => wrapTextWithAnsi(line, Math.max(10, width - visibleWidth(lead))))
		.map((line, i) => (i === 0 ? lead : " ".repeat(visibleWidth(lead))) + theme.fg(block.status === "error" ? "error" : "toolOutput", line));
	return [...rows, ...fold(body, expanded, width)];
}

/** `45s`, `3m`, `2h 05m`, `1d 03h`. One formatter for a span in seconds. */
export function formatDuration(seconds: number): string {
	const whole = Math.max(0, Math.round(seconds));
	if (whole < 60) return `${whole}s`;
	const minutes = Math.floor(whole / 60);
	if (minutes < 60) return `${minutes}m`;
	const hours = Math.floor(minutes / 60);
	const rest = minutes % 60;
	if (hours < 48) return rest === 0 ? `${hours}h` : `${hours}h ${String(rest).padStart(2, "0")}m`;
	const days = Math.floor(hours / 24);
	const dayHours = hours % 24;
	return dayHours === 0 ? `${days}d` : `${days}d ${String(dayHours).padStart(2, "0")}h`;
}

/** A job's state: running (its age is in the job row below the transcript), or how it ended and how long it ran. */
function jobLabel(job: Job): string {
	if (!job.ended) return theme.fg("accent", `job ${job.id} running in the background`);
	const took = formatDuration(job.ended.ms / 1000);
	return job.ended.ok
		? theme.fg("success", `job ${job.id} done after ${took}`)
		: theme.fg("error", `job ${job.id} failed after ${took}`);
}

/** One running job under the transcript, with its live age. */
export function runningJobRow(tool: Extract<Block, { kind: "tool" }>, width: number, now = Date.now()): string {
	const job = tool.job!;
	const args = compactArgs(tool.args).replace(/\s+/g, " ");
	const row = ` ${theme.fg("accent", theme.status.pending)} ${theme.fg("accent", `job ${job.id}`)} ${theme.fg("toolTitle", tool.name)}${args ? ` ${theme.fg("muted", args)}` : ""} ${theme.fg("dim", `· ${formatDuration((now - job.startedAt) / 1000)}`)}`;
	return truncateToWidth(row, width);
}

/** The glyph and colour for a seat or session state. Claude Code's mid-turn
 * states (`opening`, `prompting`, `stopping`) are turn-in-progress, not idle. */
export function stateStyle(state: string): { glyph: string; color: "accent" | "success" | "warning" | "error" | "muted" } {
	switch (state) {
		case "running":
		case "starting":
		case "aborting":
		case "opening":
		case "prompting":
		case "stopping":
		// A local Claude Code session working, or waiting on its background shell.
		case "busy":
		case "shell":
			return { glyph: theme.status.running, color: "accent" };
		case "idle":
		case "online":
		// A Claude Code tab open between Odin's prompts.
		case "open":
			return { glyph: theme.status.enabled, color: "success" };
		case "requiresAction":
		case "degraded":
			return { glyph: theme.status.warning, color: "warning" };
		case "failed":
		case "configurationError":
			return { glyph: theme.status.error, color: "error" };
		default:
			return { glyph: theme.status.disabled, color: "muted" };
	}
}

/** `ctx 12.3%/500K` coloured by OMP's thresholds; `N/?` when the window is unknown. */
export function contextLabel(usage: Usage | undefined): string {
	if (!usage) return "";
	const window = usage.contextWindow ?? 0;
	const percent = window > 0 ? (usage.contextTokens / window) * 100 : null;
	const label = formatContextUsage(percent, window, usage.contextTokens);
	const color = getContextUsageThemeColor(getContextUsageLevel(percent ?? 0, window));
	return theme.fg(color, `${theme.icon.context} ${label}`);
}

function usageRow(usage: Usage, width: number): string {
	const parts = [
		`${theme.icon.input} ${formatNumber(usage.input + usage.cacheWrite)}`,
		`${theme.icon.output} ${formatNumber(usage.output)}`,
	];
	if (usage.cacheRead > 0) parts.push(`${theme.icon.cache} ${formatNumber(usage.cacheRead)}`);
	const row = ` ${theme.fg("dim", parts.join("  "))}  ${contextLabel(usage)}`;
	return truncateToWidth(row, width);
}
