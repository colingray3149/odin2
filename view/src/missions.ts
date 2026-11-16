// The Missions tab: Odin's simulation board (every pod but research pods) from the authority's `Status/missions` object.
// One line per mission; the open one adds plots and its newest frame. PNG uses terminal graphics when available;
// SVG and unsupported formats are named in text rather than sent to a raster-only protocol.
import { Image } from "../omp/components/image";
import { theme } from "../omp/theme/theme";
import type { MissionRow, MissionsValue } from "./protocol";
import { ago, row } from "./layout";

const SPARKS = "▁▂▃▄▅▆▇█";

/** One series as a sparkline, scaled between its own lowest and highest point. */
function sparkline(values: readonly number[]): string {
	if (values.length === 0) return "";
	const low = Math.min(...values);
	const span = Math.max(...values) - low;
	return values.map(value => SPARKS[span > 0 ? Math.round(((value - low) / span) * (SPARKS.length - 1)) : 0]).join("");
}

function stageStyle(stage: string): { glyph: string; color: "accent" | "success" | "error" | "warning" | "muted" } {
	switch (stage) {
		case "running":
		case "preparing":
			return { glyph: theme.status.running, color: "accent" };
		case "succeeded":
			return { glyph: theme.status.success, color: "success" };
		case "failed":
		case "aborted":
			return { glyph: theme.status.error, color: "error" };
		case "paused":
			return { glyph: "◐", color: "warning" };
		default:
			return { glyph: "○", color: "muted" };
	}
}

function missionLine(mission: MissionRow, selected: boolean, width: number): string {
	const style = stageStyle(mission.stage);
	const parts = [
		selected ? theme.fg("accent", "›") : " ",
		theme.fg(style.color, style.glyph),
		theme.bold(mission.label),
		theme.fg(style.color, mission.stage),
		mission.node ? theme.fg("dim", mission.node) : undefined,
		mission.sampleAt ? theme.fg("dim", `sample ${ago(mission.sampleAt)} ago`) : theme.fg("dim", "no sample yet"),
		mission.checkpoints > 0 ? theme.fg("dim", `${mission.checkpoints} checkpoints`) : undefined,
		mission.openRenders > 0 ? theme.fg("warning", `${mission.openRenders} rendering`) : undefined,
		mission.frame ? theme.fg("dim", `frame #${mission.frame.seq}`) : undefined,
	];
	return row(width, ...parts);
}

export interface MissionFrame {
	run: string;
	artifact: string;
	mediaType?: string | null;
	data?: string;
	error?: string;
}

// SIXEL encoding completes asynchronously, so retain the component until a new frame arrives.
const frameImages = new WeakMap<MissionFrame, { height: number; image: Image }>();

/** The tab's body. `frame` is the newest frame the bridge sent for the open mission. */
export function missionRows(
	value: MissionsValue | undefined,
	selected: number,
	open: boolean,
	frame: MissionFrame | undefined,
	width: number,
	requestRender: () => void = () => {},
	viewportHeight = Infinity,
): string[] {
	const rows: string[] = [""];
	if (!value) return [...rows, row(width, theme.fg("dim", "reading the board…"))];
	const missions = value.rows;
	rows.push(row(width, theme.fg("accent", "Missions"), theme.fg("dim", `${missions.length} on the board · ↑↓ choose · enter opens · r render · p pause · u resume`)));
	if (missions.length === 0) return [...rows, row(width, theme.fg("dim", "no pod is running"))];
	missions.forEach((mission, i) => rows.push(missionLine(mission, i === selected, width)));
	const mission = missions[selected];
	if (!open || !mission) return rows;
	rows.push("", row(width, theme.fg("accent", mission.label), theme.fg("dim", mission.run)));
	if (mission.failure) rows.push(row(width, theme.fg("error", mission.failure)));
	for (const [key, values] of Object.entries(mission.series ?? {})) {
		const last = values.at(-1);
		rows.push(row(width, theme.fg("dim", key.padEnd(12)), theme.fg("accent", sparkline(values)), last === undefined ? "" : String(last)));
	}
	if (mission.lastSample) rows.push(row(width, theme.fg("dim", "last sample"), JSON.stringify(mission.lastSample)));
	if (!mission.frame) return [...rows, row(width, theme.fg("dim", "no frame yet"))];
	const label = `frame ${mission.frame.renderer} #${mission.frame.seq} · ${ago(mission.frame.at)} ago`;
	rows.push(row(width, theme.fg("dim", label)));
	if (!frame || frame.run !== mission.run || frame.artifact !== mission.frame.artifact) {
		return [...rows, row(width, theme.fg("dim", "fetching the frame…"))];
	}
	if (frame.error || !frame.data) return [...rows, row(width, theme.fg("error", `frame unreadable: ${frame.error ?? "empty"}`))];
	// Older bridges omitted mediaType; recognize PNG by its signature rather than assuming a format.
	const mediaType = frame.mediaType ?? (frame.data.startsWith("iVBORw0KGgo") ? "image/png" : undefined);
	// Terminal graphics protocols used by Image accept raster data, not SVG source.
	if (mediaType !== "image/png") {
		return [...rows, row(width, theme.fg("dim", `frame available as ${frame.mediaType ?? "unknown format"} (inline display unsupported)`))];
	}
	// Direct graphics are emitted on their last reserved row. Fit that row into
	// the initial page viewport rather than leaving an apparently blank image.
	const height = Math.max(1, Math.min(24, viewportHeight - rows.length));
	let cached = frameImages.get(frame);
	if (!cached || cached.height !== height) {
		const image = new Image(frame.data, mediaType, { fallbackColor: text => theme.fg("dim", text) }, {
			maxHeightCells: height,
			filename: label,
			imageKey: frame.artifact,
			requestRender,
		});
		cached = { height, image };
		frameImages.set(frame, cached);
	}
	return [...rows, ...cached.image.render(width)];
}
