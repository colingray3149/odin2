// The Brain tab: the authority's copy of ~/knowledge/_system/status.json (written by kb-status), one row per part grouped
// by area, then the newest changes. Colours follow the Capabilities tab; paused and behind exist only here.
import { theme } from "../omp/theme/theme";
import type { KnowledgeValue } from "./protocol";
import { ago, row } from "./layout";

const TONE = {
	green: { glyph: "●", color: "success" },
	paused: { glyph: "◐", color: "muted" },
	behind: { glyph: "◔", color: "warning" },
	red: { glyph: "✕", color: "error" },
	grey: { glyph: "○", color: "muted" },
} as const;

/** The tab's body. `refreshing` is true between F5 and the authority's answer. */
export function brainRows(value: KnowledgeValue | undefined, width: number, refreshing = false): string[] {
	const rows: string[] = [""];
	if (!value) {
		rows.push(row(width, theme.fg("dim", refreshing ? "refreshing…" : "reading the brain…")));
		return rows;
	}
	const c = value.counts;
	const head = [theme.fg("accent", "Brain")];
	if (c) head.push(theme.fg("dim", `${c.parts} parts · ${c.green} green · ${c.paused} paused · ${c.behind} behind · ${c.red} red · ${c.grey} grey`));
	if (value.evaluated_at) head.push(theme.fg("dim", `evaluated ${ago(value.evaluated_at)} ago`));
	rows.push(row(width, head.join(theme.fg("dim", " · "))));
	if (value.error) rows.push(row(width, theme.fg("error", `${value.error}`)));
	if (refreshing) rows.push(row(width, theme.fg("dim", "refreshing…")));
	const areas = new Map<string, NonNullable<KnowledgeValue["parts"]>>();
	for (const part of value.parts ?? []) areas.set(part.area, [...(areas.get(part.area) ?? []), part]);
	for (const [area, parts] of areas) {
		rows.push("", row(width, theme.fg("accent", area)));
		for (const part of parts) {
			const tone = TONE[part.state];
			rows.push(row(width, `${theme.fg(tone.color, tone.glyph)} ${theme.bold(part.title)} ${theme.fg(part.state === "green" ? "dim" : tone.color, part.text)}`));
		}
	}
	rows.push("", row(width, theme.fg("accent", "Recent changes")));
	const recent = (value.recent ?? []).slice(0, 15);
	if (recent.length === 0) rows.push(row(width, theme.fg("dim", "none yet")));
	for (const change of recent) {
		rows.push(row(width, `${theme.fg("dim", (change.ts ?? "").slice(11, 16))} ${(change.actor ?? "?").padEnd(14)} ${change.op ?? ""} ${change.path ?? ""}`));
	}
	return rows;
}
