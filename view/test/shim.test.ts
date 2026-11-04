import { describe, expect, test } from "bun:test";
import { Ellipsis, extractSegments, sliceWithWidth, truncateToWidth, wrapTextWithAnsi } from "../shim/pi-natives";
import { visibleWidth } from "../omp/utils";

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
