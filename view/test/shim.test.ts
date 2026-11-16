import { describe, expect, test } from "bun:test";
import { Ellipsis, encodeSixel, encodeSixelAsync, extractSegments, sliceWithWidth, truncateToWidth, wrapTextWithAnsi } from "../shim/pi-natives";
import { PNG } from "pngjs";
import { visibleWidth } from "../omp/utils";
import { ImageProtocol, TERMINAL } from "../omp/terminal-capabilities";
import { initThemeSync } from "../omp/theme/theme";
import { missionRows } from "../src/missions";

const RED = "\x1b[31m";
const RESET = "\x1b[0m";

describe("pi-natives shim text", () => {
	test("wrap carries colour across lines and keeps widths", () => {
		const lines = wrapTextWithAnsi(`${RED}alpha beta gamma delta${RESET}`, 11, 3);
		expect(lines).toEqual([`${RED}alpha beta`, `${RED}gamma delta${RESET}`]);
		for (const line of lines) expect(visibleWidth(line)).toBeLessThanOrEqual(11);
	});

	test("wrap breaks a long word and counts wide characters as two cells", () => {
		const lines = wrapTextWithAnsi("日本語のテキスト", 6, 3);
		expect(lines).toEqual(["日本語", "のテキ", "スト"]);
		expect(wrapTextWithAnsi("", 10, 3)).toEqual([""]);
	});

	test("truncate adds the ellipsis, resets colour, and pads", () => {
		expect(truncateToWidth("hello world", 8, Ellipsis.Unicode, false, 3)).toBe("hello w…");
		expect(truncateToWidth(`${RED}hello world`, 8, Ellipsis.Unicode, false, 3)).toBe(`${RED}hello w${RESET}…`);
		expect(truncateToWidth("日本語のテ", 6, Ellipsis.Unicode, false, 3)).toBe("日本…");
		expect(truncateToWidth("short", 8, Ellipsis.Unicode, true, 3)).toBe("short   ");
		expect(truncateToWidth("abcdef", 4, Ellipsis.Omit, false, 3)).toBe("abcd");
	});

	test("slice selects columns, keeps escapes, and honours strict wide edges", () => {
		expect(sliceWithWidth(`${RED}hello${RESET} world`, 0, 5, false, 3)).toEqual({ text: `${RED}hello${RESET}`, width: 5 });
		expect(sliceWithWidth("ab日本", 0, 3, true, 3)).toEqual({ text: "ab", width: 2 });
		expect(sliceWithWidth("ab日本", 2, 4, false, 3)).toEqual({ text: "日本", width: 4 });
	});

	test("segments around an overlay reopen the style for the after part", () => {
		const r = extractSegments(`${RED}0123456789`, 3, 6, 2, false, 3);
		expect(r).toEqual({ before: `${RED}012`, beforeWidth: 3, after: `${RED}67`, afterWidth: 2 });
	});
});

test("SIXEL encodes scaled PNG pixels and composites transparency", async () => {
	const png = new PNG({ width: 2, height: 1 });
	png.data.set([255, 0, 0, 255, 0, 0, 0, 0]);
	const input = PNG.sync.write(png);
	const sequence = encodeSixel(input, 2, 1, 0x0000ff);
	expect(sequence).toContain('\x1bPq"1;1;2;1');
	expect(sequence).toContain("#224;2;100;0;0");
	expect(sequence).toContain("#3;2;0;0;100");
	expect(sequence).toContain("#224@?");
	expect(sequence).toContain("#3?@");
	expect(sequence.endsWith("\x1b\\")).toBe(true);
	expect(await encodeSixelAsync(input, 2, 1, 0x0000ff)).toBe(sequence);
	expect(() => encodeSixel(input, 0, 1, 0)).toThrow();
});

test("a mission PNG reaches the SIXEL terminal after the image encode settles", async () => {
	initThemeSync("nerd", false, "cyber-blossom", "cyber-blossom");
	const previous = TERMINAL.imageProtocol;
	TERMINAL.imageProtocol = ImageProtocol.Sixel;
	try {
		const png = new PNG({ width: 1, height: 1 });
		png.data.set([255, 0, 0, 255]);
		const at = new Date().toISOString();
		const frame = { run: "run", artifact: "artifact:frame", mediaType: "image/png", data: PNG.sync.write(png).toString("base64") };
		const board = { rows: [{ run: "run", label: "test", stage: "running", node: "node", updatedAt: at, checkpoints: 0, renderers: [], openRenders: 0, frame: { artifact: frame.artifact, renderer: "field", seq: 1, at } }] };
		let repaints = 0;
		missionRows(board, 0, true, frame, 80, () => repaints++);
		await Promise.resolve();
		expect(repaints).toBe(1);
		expect(missionRows(board, 0, true, frame, 80).join("\n")).toContain("\x1bPq");
	} finally {
		TERMINAL.imageProtocol = previous;
	}
});
