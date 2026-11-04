import { expect, test } from "bun:test";
import { initThemeSync, theme } from "../omp/theme/theme";
import { visibleWidth } from "../omp/utils";
import { computeRows } from "../src/compute";
import type { ComputeSample } from "../src/protocol";
import { plain } from "./support";

initThemeSync("nerd", false, "cyber-blossom", "cyber-blossom");

const GiB = 1024 ** 3;
const NOW = Date.parse("2026-10-27T12:00:00Z");

function sample(patch: Partial<ComputeSample> = {}): ComputeSample {
	return {
		node: "pc",
		sampledAt: "2026-10-27T11:59:48Z",
		cpuPercent: 12,
		memoryUsedBytes: 8 * GiB,
		memoryTotalBytes: 32 * GiB,
		storageUsedBytes: 400 * GiB,
		storageTotalBytes: 1000 * GiB,
		temperatureCelsius: 46,
		gpus: [],
		models: [],
		modelsNote: null,
		pods: [],
		...patch,
	};
}

test("a computer's figures line up, coloured by how hard it is working", () => {
	const rows = computeRows(
		[
			sample(),
			sample({
				node: "mini",
				cpuPercent: 91,
				memoryUsedBytes: 30 * GiB,
				temperatureCelsius: 82,
				sampledAt: "2026-10-27T11:57:00Z",
			}),
		],
		100,
		NOW,
	);
	const text = plain(rows);
	expect(text).toContain("Computers");
	const pc = text.split("\n").find(line => line.includes("pc") && line.includes("cpu"))!;
	const mini = text.split("\n").find(line => line.includes("mini") && line.includes("cpu"))!;
	expect(pc).toContain("cpu 12%");
	expect(pc).toContain("ram 8.0GB/32.0GB");
	expect(pc).toContain("disk 400.0GB/1000.0GB");
	expect(pc).toContain("temp 46°");
	expect(pc).toContain("12s");
	expect(mini).toContain("cpu 91%");
	expect(mini).toContain("3m");
	// Names, then each figure, share a column.
	expect(pc.indexOf("cpu")).toBe(mini.indexOf("cpu"));
	expect(pc.indexOf("ram")).toBe(mini.indexOf("ram"));
	expect(pc.indexOf("temp")).toBe(mini.indexOf("temp"));
	const hot = rows.find(line => line.includes("mini"))!;
	expect(hot).toContain(theme.fg("error", "91%"));
	expect(hot).toContain(theme.fg("warning", "82°"));
	expect(rows.find(line => line.includes("pc"))).toContain(theme.fg("success", "12%"));
});

test("a missing reading keeps its column and is never drawn as zero", () => {
	const rows = computeRows([
		sample({ node: "laptop", cpuPercent: null, memoryUsedBytes: null, memoryTotalBytes: null, temperatureCelsius: null }),
		sample({ storageUsedBytes: 2 * GiB, storageTotalBytes: null }),
	], 120, NOW);
	const text = plain(rows);
	const laptop = text.split("\n").find(row => row.includes("laptop"))!;
	const pc = text.split("\n").find(row => row.includes("pc") && row.includes("disk"))!;
	expect(laptop).not.toContain("cpu");
	expect(laptop).not.toContain("ram");
	expect(laptop).not.toContain("temp");
	expect(laptop).not.toContain("0%");
	expect(pc).toContain("disk 2.0GB");
	expect(pc).not.toContain("2.0GB/");
	expect(pc).not.toContain("0B");
	// The blank cells still hold the column, so the disks share a place.
	expect(laptop.indexOf("disk")).toBe(pc.indexOf("disk"));
});

test("gpus, loaded models and pods indent under their computer", () => {
	const rows = computeRows([sample({
		gpus: [{
			name: "RTX 3070",
			utilizationPercent: 73,
			memoryUsedBytes: 6 * GiB,
			memoryTotalBytes: 8 * GiB,
			temperatureCelsius: 67,
		}],
		models: [
			{ name: "wemm", runtime: "llama.cpp", state: "loaded" },
			{ name: "nemotron", runtime: "vllm", state: "running" },
		],
		pods: [
			{ name: "heat-sim", node: "pc", state: "running" },
			{ name: "floyds-times", node: "pc", state: "failed" },
		],
	})], 110, NOW);
	const text = plain(rows);
	const lines = text.split("\n");
	const host = lines.findIndex(line => line.includes("pc") && line.includes("cpu"));
	const gpu = lines.findIndex(line => line.includes("RTX 3070"));
	const model = lines.findIndex(line => line.includes("wemm"));
	const pod = lines.findIndex(line => line.includes("heat-sim"));
	expect(gpu).toBeGreaterThan(host);
	expect(model).toBeGreaterThan(gpu);
	expect(pod).toBeGreaterThan(model);
	expect(lines[gpu]!.indexOf("RTX")).toBeGreaterThan(lines[host]!.indexOf("pc"));
	expect(lines[gpu]).toContain("gpu 73%");
	expect(lines[gpu]).toContain("vram 6.0GB/8.0GB");
	expect(lines[gpu]).toContain("temp 67°");
	expect(lines[model]).toContain("llama.cpp");
	expect(lines[model]).toContain("loaded");
	expect(lines[model + 1]).toContain("vllm");
	expect(lines[model + 1]).toContain("running");
	expect(lines[model]!.indexOf("llama.cpp")).toBe(lines[model + 1]!.indexOf("vllm"));
	expect(lines[pod]).toContain("running");
	expect(lines[pod + 1]).toContain("failed");
	expect(rows.find(line => line.includes("73%"))).toContain(theme.fg("warning", "73%"));
	expect(rows.find(line => line.includes("failed"))).toContain(theme.fg("error", "failed"));
});

test("no computers is a dim none, and every line fits the width", () => {
	const empty = computeRows([], 40);
	expect(plain(empty)).toContain("none");
	expect(empty.join("")).toContain(theme.fg("dim", "none"));
	const narrow = computeRows([sample({
		gpus: [{ name: "RTX 3070", utilizationPercent: 3, memoryUsedBytes: GiB, memoryTotalBytes: 8 * GiB, temperatureCelsius: 40 }],
		models: [{ name: "kubert", runtime: "llama.cpp", state: "active", unit: "active", ready: false }],
		pods: [{ name: "heat-sim", node: "pc", state: "running" }],
	})], 45, NOW);
	for (const line of narrow) expect(visibleWidth(line)).toBeLessThanOrEqual(45);
	const text = plain(narrow);
	expect(text).toContain("cpu 12%");
	expect(text).toContain("ram 8.0GB/32.0GB");
	expect(text).toContain("disk 400.0GB/1000.0GB");
	expect(text).toContain("temp 46°");
	expect(text).toContain("vram 1.0GB/8.0GB");
	expect(text).toContain("RTX 3070");
	expect(text).toContain("kubert");
	expect(text).toContain("heat-sim");
	expect(text).toContain("active");
	// A phone-width terminal wraps the figures; the host name does not share a line with RAM.
	const host = text.split("\n").find(line => line.includes("pc") && !line.includes("heat-sim"))!;
	expect(host).not.toContain("ram");
});
