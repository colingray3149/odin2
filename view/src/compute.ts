// The overview's compute section: one line per computer that has a view open, then its GPUs,
// loaded models and pods. Samples arrive from the collector; ages are computed here.
import { formatBytes } from "@oh-my-pi/pi-utils";
import { theme } from "../omp/theme/theme";
import { visibleWidth, wrapLiteralLine } from "../omp/utils";
import type { ComputeGpu, ComputeHost, ComputeModel, ComputePod, ComputeSample } from "./protocol";
import { ago, podStyle, row, table } from "./layout";
import { stateStyle } from "./render";

type Tone = "accent" | "success" | "warning" | "error" | "muted" | "dim";

/** Colour for a utilisation or temperature: quiet, working, warm, hot. */
function loadColor(percent: number): "success" | "accent" | "warning" | "error" {
	if (percent >= 90) return "error";
	if (percent >= 70) return "warning";
	if (percent >= 40) return "accent";
	return "success";
}

/** `12%`, coloured. A missing reading is "", never 0%. */
function percent(value: number | null): string {
	if (value == null || !Number.isFinite(value)) return "";
	const shown = Math.round(value);
	return theme.fg(loadColor(shown), `${shown}%`);
}

/** `12.0GB/32.0GB`, the used side coloured by how full it is. A missing reading is "". */
function bytesOf(used: number | null, total: number | null): string {
	if (used == null && total == null) return "";
	if (used == null) return theme.fg("dim", `—/${formatBytes(total!)}`);
	if (total == null || total <= 0) return formatBytes(used);
	return `${theme.fg(loadColor((used / total) * 100), formatBytes(used))}${theme.fg("dim", `/${formatBytes(total)}`)}`;
}

/** `46°`, coloured like a load. A missing reading is "". */
function temperature(celsius: number | null): string {
	if (celsius == null || !Number.isFinite(celsius)) return "";
	const shown = Math.round(celsius);
	return theme.fg(loadColor(shown), `${shown}°`);
}

/** A figure only when it was read: `cpu 12%`, never `cpu` with nothing after it. */
function figure(label: string, value: string): string {
	return value ? `${theme.fg("dim", label)} ${value}` : "";
}

/** A model row's glyph and colour from the state the collector derived: ready, loaded, or the unit's own. */
function modelStyle(state: string): { glyph: string; color: Tone } {
	switch (state) {
		case "loaded":
		case "ready":
			return { glyph: theme.status.enabled, color: "success" };
		case "activating":
		case "deactivating":
			return { glyph: theme.status.running, color: "accent" };
		case "active":
			return { glyph: theme.status.running, color: "warning" };
		case "inactive":
		case "absent":
			return { glyph: theme.status.disabled, color: "muted" };
		case "failed":
			return { glyph: theme.status.error, color: "error" };
		default:
			return stateStyle(state);
	}
}

/** Wide enough for the aligned columns; narrower terminals stack each figure. */
const WIDE = 72;

function computerLine(sample: ComputeSample, now: number): string[] {
	if (sample.error) {
		return [theme.fg("error", theme.status.error), theme.bold(sample.node), theme.fg("error", sample.error)];
	}
	const age = ago(sample.sampledAt, now);
	return [
		theme.fg("accent", theme.status.enabled),
		theme.bold(sample.node),
		figure("cpu", percent(sample.cpuPercent)),
		figure("ram", bytesOf(sample.memoryUsedBytes, sample.memoryTotalBytes)),
		figure("disk", bytesOf(sample.storageUsedBytes, sample.storageTotalBytes)),
		figure("temp", temperature(sample.temperatureCelsius)),
		age ? theme.fg("dim", age) : "",
	];
}

function gpuLine(gpu: ComputeGpu): string[] {
	const hot = gpu.temperatureCelsius != null && gpu.temperatureCelsius >= 90;
	return [
		theme.fg(hot ? "error" : "accent", theme.status.running),
		theme.fg("dim", gpu.name),
		figure("gpu", percent(gpu.utilizationPercent)),
		figure("vram", bytesOf(gpu.memoryUsedBytes, gpu.memoryTotalBytes)),
		figure("temp", temperature(gpu.temperatureCelsius)),
	];
}

function modelLine(model: ComputeModel): string[] {
	const { glyph, color } = modelStyle(model.state);
	const unit = model.unit && model.unit !== model.state ? theme.fg("dim", model.unit) : "";
	return [
		theme.fg(color, glyph),
		model.name,
		theme.fg("dim", model.runtime),
		unit,
		theme.fg(color === "muted" ? "dim" : color, model.state),
	];
}

function podLine(pod: ComputePod): string[] {
	const { glyph, color } = podStyle(pod.state);
	return [theme.fg(color, glyph), pod.name, theme.fg(color === "muted" ? "dim" : color, pod.state)];
}

/** Pack cells onto as many width-bounded lines as they need. A cell wider than the terminal wraps; nothing is discarded. */
export function wrapCells(width: number, cells: string[], indent = ""): string[] {
	const visible = cells.filter(Boolean);
	if (visible.length === 0) return [];
	const rows: string[] = [];
	let line: string[] = [];
	let used = visibleWidth(indent);
	const flush = () => {
		if (line.length === 0) return;
		rows.push(`${indent}${row(width - visibleWidth(indent), ...line)}`);
		line = [];
		used = visibleWidth(indent);
	};
	for (const cell of visible) {
		const cellWidth = visibleWidth(cell);
		const room = width - visibleWidth(indent);
		if (cellWidth > room) {
			flush();
			rows.push(...wrapLiteralLine(`${indent}${cell}`, width));
			continue;
		}
		const gap = line.length > 0 ? 1 : 0;
		if (used + gap + cellWidth > width && line.length > 0) flush();
		line.push(cell);
		used += gap + cellWidth;
	}
	flush();
	return rows.map(line => (visibleWidth(line) > width ? wrapLiteralLine(line, width) : [line])).flat();
}

/** A snapshot host becomes one row. A miss has no gauges, so a previous sample cannot linger. */
export function hostRow(host: ComputeHost): ComputeSample {
	if (host.sample && !host.error) return host.sample;
	return {
		node: host.node,
		sampledAt: "",
		cpuPercent: null,
		memoryUsedBytes: null,
		memoryTotalBytes: null,
		storageUsedBytes: null,
		storageTotalBytes: null,
		temperatureCelsius: null,
		gpus: [],
		models: [],
		modelsNote: null,
		pods: [],
		error: host.error ?? "unavailable",
	};
}

/**
 * The compute section of the overview: a Computers heading, then one block per sample.
 * An empty list is `none`. Narrow terminals wrap figures onto more lines; they are not clipped.
 */
export function computeRows(samples: readonly ComputeSample[], width: number, now = Date.now()): string[] {
	const rows: string[] = ["", ` ${theme.fg("accent", "Computers")}`];
	if (samples.length === 0) {
		rows.push(` ${theme.fg("dim", "none")}`);
		return rows;
	}
	const wide = width >= WIDE;
	const hosts = samples.map(sample => computerLine(sample, now));
	const aligned = wide ? table(width, hosts) : [];
	samples.forEach((sample, index) => {
		if (wide) {
			rows.push(aligned[index]!);
		} else if (sample.error) {
			rows.push(...wrapCells(width, hosts[index]!.filter(Boolean)));
		} else {
			const [glyph, name, cpu, ram, disk, host, age] = hosts[index]!;
			rows.push(...wrapCells(width, [glyph, name, age].filter(Boolean)));
			rows.push(...wrapCells(width, [cpu, ram, disk, host].filter(Boolean)));
		}
		if (sample.modelsNote) rows.push(...wrapCells(width, [theme.fg("warning", sample.modelsNote)], "  "));
		if (sample.podsNote) rows.push(...wrapCells(width, [theme.fg("warning", sample.podsNote)], "  "));
		const detail = [...sample.gpus.map(gpuLine), ...sample.models.map(modelLine), ...sample.pods.map(podLine)];
		if (detail.length === 0) return;
		if (wide) {
			rows.push(...table(width - 2, detail).map(line => `  ${line}`));
		} else {
			for (const cells of detail) rows.push(...wrapCells(width, cells, "  "));
		}
	});
	return rows.flatMap(line => (visibleWidth(line) > width ? wrapLiteralLine(line, width) : [line]));
}
