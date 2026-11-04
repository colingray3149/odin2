// The Capabilities tab: the authority's evaluated rows, one per capability grouped by toolset, then the services, each
// with its tone and label. A row that is not green shows its checks' details beneath it. Colours come from the Cyber
// Blossom theme, as on the board and overview.
import { theme } from "../omp/theme/theme";
import type { FeatureRow, FeaturesValue } from "./protocol";
import { ago, row } from "./layout";

const TONE: Record<FeatureRow["status"], { glyph: string; color: "success" | "error" | "muted" }> = {
	green: { glyph: "●", color: "success" },
	gray: { glyph: "○", color: "muted" },
	red: { glyph: "✕", color: "error" },
};

/** A commit's first seven characters, or "" when unknown. */
function short(sha: string | null | undefined): string {
	return sha ? sha.slice(0, 7) : "";
}

/** The evaluation's local clock time, `hh:mm`, or "" when unreadable. */
function clock(iso: string): string {
	const at = new Date(iso);
	if (Number.isNaN(at.getTime())) return "";
	return `${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;
}

/** `Capabilities · <n> of <m> tested · tested <sha> <age> · live r<rev> <sha> · evaluated <hh:mm>`. */
function header(value: FeaturesValue): string {
	const sep = theme.fg("dim", " · ");
	const parts = [theme.fg("accent", "Capabilities")];
	parts.push(theme.fg("dim", `${value.counts.tested} of ${value.counts.capabilities} tested`));
	const tested = value.tested;
	if (tested?.sha) {
		const inherited = tested.inherited ? " (inherited)" : "";
		parts.push(theme.fg("dim", `tested ${short(tested.sha)} ${ago(tested.at)}`.trimEnd() + inherited));
	} else {
		parts.push(theme.fg("dim", "not tested"));
	}
	const commit = short(value.live.commit);
	parts.push(theme.fg("dim", `live r${value.live.registryRevision}${commit ? ` ${commit}` : ""}`));
	const evaluated = clock(value.evaluatedAt);
	if (evaluated) parts.push(theme.fg("dim", `evaluated ${evaluated}`));
	return parts.join(sep);
}

/**
 * The tab's body: the header, then each area's rows, then a settled note or a refresh in progress. A note beside a value
 * keeps the value and says why it is old.
 */
export function featureRows(value: FeaturesValue | undefined, note: string | undefined, width: number, refreshing = false): string[] {
	const rows: string[] = [""];
	if (!value) {
		if (note) rows.push(row(width, theme.fg("error", `Capabilities unavailable: ${note} · F5 to retry`)));
		else rows.push(row(width, theme.fg("dim", refreshing ? "refreshing…" : "reading the capabilities…")));
		return rows;
	}
	rows.push(row(width, header(value)));
	if (note) rows.push(row(width, theme.fg("warning", `${theme.status.warning} ${note} · F5 to retry`)));
	if (refreshing) rows.push(row(width, theme.fg("dim", "refreshing…")));
	if (value.rows.length === 0) {
		rows.push(row(width, theme.fg("dim", "no capabilities declared")));
		return rows;
	}
	// Areas in the order the authority listed them.
	const areas = new Map<string, FeatureRow[]>();
	for (const item of value.rows) {
		areas.set(item.area, [...(areas.get(item.area) ?? []), item]);
	}
	for (const [area, items] of areas) {
		rows.push("", row(width, theme.fg("accent", area)));
		for (const item of items) {
			const tone = TONE[item.status];
			rows.push(row(width, `${theme.fg(tone.color, tone.glyph)} ${theme.bold(item.title)} ${theme.fg(tone.color, item.label)}`));
			if (item.status === "green") continue;
			for (const check of item.checks) {
				rows.push(row(width, `  ${theme.fg("dim", `${check.check}: ${check.detail}`)}`));
			}
		}
	}
	return rows;
}
