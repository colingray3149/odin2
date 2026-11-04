// What the pages lay out the same way: a padded row, aligned columns, the age of a timestamp and a pod's glyph.
import { theme } from "../omp/theme/theme";
import { padding, truncateToWidth, visibleWidth } from "../omp/utils";

/** One row's coloured pieces joined with spaces, truncated to the width. */
export function row(width: number, ...parts: (string | false | undefined)[]): string {
	return truncateToWidth(` ${parts.filter(Boolean).join(" ")}`, width);
}

/** Rows of cells with each column padded to its widest cell, so names, states and figures line up. */
export function table(width: number, lines: string[][]): string[] {
	const widths: number[] = [];
	for (const line of lines) line.forEach((cell, i) => (widths[i] = Math.max(widths[i] ?? 0, visibleWidth(cell))));
	return lines.map(line =>
		truncateToWidth(` ${line.map((cell, i) => (i === line.length - 1 ? cell : cell + padding(widths[i]! - visibleWidth(cell)))).join(" ")}`, width),
	);
}

/** `45s`, `12m`, `3h`, `4d` — the age of an RFC 3339 timestamp, or "" when unknown. */
export function ago(iso: string | null | undefined, now = Date.now()): string {
	if (!iso) return "";
	const at = Date.parse(iso);
	if (Number.isNaN(at)) return "";
	const seconds = Math.max(0, Math.floor((now - at) / 1000));
	if (seconds < 60) return `${seconds}s`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m`;
	const hours = Math.floor(minutes / 60);
	return hours < 48 ? `${hours}h` : `${Math.floor(hours / 24)}d`;
}

/** A pod's glyph and colour: live ones work, a success is done, a failure is an error. */
export function podStyle(state: string): { glyph: string; color: "accent" | "success" | "error" | "muted" } {
	switch (state) {
		case "pending":
		case "scheduling":
		case "running":
		case "terminating":
			return { glyph: theme.status.running, color: "accent" };
		case "succeeded":
			return { glyph: theme.status.success, color: "success" };
		case "failed":
			return { glyph: theme.status.error, color: "error" };
		default:
			return { glyph: theme.status.disabled, color: "muted" };
	}
}
