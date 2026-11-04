// Pure-JS stand-in for `@oh-my-pi/pi-natives`, covering only what the vendored TUI in ../omp imports.
// The text functions follow OMP 2a2c6dc `crates/pi-natives/src/text.rs` (ANSI-aware wrap, truncate, slice, and
// overlay segments; widths from `Bun.stringWidth` with the same options as omp/utils.ts `visibleWidth`). OSC 66
// text-sizing spans are treated as zero-width escapes; the view never emits them.
// Keys use OMP's pure-JS parser. Highlighting, sixel, fuzzy find and macOS appearance are inert.
import * as jsKeys from "../omp/key-parser";

export enum Ellipsis {
	Unicode = 0,
	Ascii = 1,
	Omit = 2,
}

export enum KeyEventType {
	Press = 1,
	Repeat = 2,
	Release = 3,
}

export interface SliceResult {
	text: string;
	width: number;
}

export interface ExtractSegmentsResult {
	before: string;
	beforeWidth: number;
	after: string;
	afterWidth: number;
}

// ---------------------------------------------------------------------------
// Widths
// ---------------------------------------------------------------------------

const STRING_WIDTH_OPTS = { countAnsiEscapeCodes: false, ambiguousIsNarrow: true } as const;
const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });

// 0 = platform default, 1 = narrow, 2 = wide, 3 = unicode (see omp/utils.ts).
let hangulOverride = 0;

export function setHangulCompatJamoWidthOverride(value: number): void {
	hangulOverride = value;
}

function hangulTarget(): number | null {
	if (hangulOverride === 1 || hangulOverride === 2) return hangulOverride;
	if (hangulOverride === 3) return null;
	return process.platform === "darwin" ? 1 : null;
}

function graphemeWidth(g: string, tabWidth: number): number {
	if (g === "\t") return tabWidth;
	let width = Bun.stringWidth(g, STRING_WIDTH_OPTS);
	const target = hangulTarget();
	if (target === null) return width;
	for (const ch of g) {
		const cp = ch.codePointAt(0)!;
		if (cp < 0x3131 || cp > 0x318e) continue;
		// Bun counts every Compatibility Jamo as 2; the filler U+3164 is 0 in Unicode and only ever narrowed.
		const unicodeWidth = cp === 0x3164 ? 0 : 2;
		const bunWidth = 2;
		if (unicodeWidth === 0) width -= bunWidth;
		else width += target - bunWidth;
	}
	return Math.max(0, width);
}

/** Each visible grapheme of `text` (no escapes inside) with its cell width. */
function* graphemes(text: string, tabWidth: number): Generator<[string, number]> {
	for (let i = 0; i < text.length; i++) {
		if (text.charCodeAt(i) > 0x7e || text.charCodeAt(i) < 0x20) {
			for (const { segment } of segmenter.segment(text.slice(i))) yield [segment, graphemeWidth(segment, tabWidth)];
			return;
		}
		yield [text[i]!, 1];
	}
}

// ---------------------------------------------------------------------------
// Escape sequences
// ---------------------------------------------------------------------------

const ESC = "\x1b";

/** Length of the escape sequence starting at `pos`, or 0 when there is none (or it is unterminated). */
function escLen(s: string, pos: number): number {
	if (s[pos] !== ESC || pos + 1 >= s.length) return 0;
	const next = s.charCodeAt(pos + 1);
	if (next === 0x5b) {
		// CSI: parameters up to a final byte 0x40..0x7e.
		for (let j = pos + 2; j < s.length; j++) {
			const c = s.charCodeAt(j);
			if (c >= 0x40 && c <= 0x7e) return j + 1 - pos;
		}
		return 0;
	}
	if (next === 0x5d || next === 0x50 || next === 0x58 || next === 0x5e || next === 0x5f) {
		// OSC, DCS, SOS, PM, APC: terminated by BEL or ST.
		for (let j = pos + 2; j < s.length; j++) {
			if (s[j] === "\x07") return j + 1 - pos;
			if (s[j] === ESC && s[j + 1] === "\\") return j + 2 - pos;
		}
		return 0;
	}
	if (next >= 0x20 && next <= 0x2f) {
		for (let j = pos + 2; j < s.length; j++) {
			const c = s.charCodeAt(j);
			if (c >= 0x30 && c <= 0x7e) return j + 1 - pos;
		}
		return 0;
	}
	if (next >= 0x40 && next <= 0x7e) return 2;
	return 0;
}

type Piece = { esc: string } | { text: string };

/** Split a line into escape sequences and runs of text. A stray ESC becomes a zero-width escape. */
function pieces(s: string): Piece[] {
	const out: Piece[] = [];
	let i = 0;
	while (i < s.length) {
		const esc = s.indexOf(ESC, i);
		if (esc === -1) {
			out.push({ text: s.slice(i) });
			break;
		}
		if (esc > i) out.push({ text: s.slice(i, esc) });
		const len = escLen(s, esc) || 1;
		out.push({ esc: s.slice(esc, esc + len) });
		i = esc + len;
	}
	return out;
}

function isSgr(seq: string): boolean {
	return seq.length >= 3 && seq[1] === "[" && seq.endsWith("m");
}

/** OSC 8 URI of a hyperlink sequence ("" closes), or undefined when `seq` is not OSC 8. */
function osc8Uri(seq: string): string | undefined {
	if (!seq.startsWith("\x1b]8;")) return undefined;
	const body = seq.slice(4, seq.endsWith("\x07") ? -1 : -2);
	const sep = body.indexOf(";");
	return sep === -1 ? undefined : body.slice(sep + 1);
}

const OSC8_CLOSE = "\x1b]8;;\x1b\\";

/** SGR attributes, colours and the open hyperlink, so styling can be closed and reopened across lines. */
class AnsiState {
	attrs = new Set<number>();
	fg = "";
	bg = "";
	hyperlink = "";

	apply(seq: string): void {
		if (isSgr(seq)) {
			this.#sgr(seq.slice(2, -1));
			return;
		}
		const uri = osc8Uri(seq);
		if (uri !== undefined) this.hyperlink = uri ? seq : "";
	}

	#sgr(params: string): void {
		if (params === "") {
			this.#reset();
			return;
		}
		const p = params.split(/[;:]/).map(x => Number.parseInt(x, 10) || 0);
		for (let i = 0; i < p.length; i++) {
			const code = p[i]!;
			if (code === 0) this.#reset();
			else if ((code >= 1 && code <= 5) || (code >= 7 && code <= 9)) this.attrs.add(code);
			else if (code === 21) this.attrs.delete(1);
			else if (code === 22) {
				this.attrs.delete(1);
				this.attrs.delete(2);
			} else if (code >= 23 && code <= 29) this.attrs.delete(code - 20);
			else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) this.fg = String(code);
			else if (code === 39) this.fg = "";
			else if ((code >= 40 && code <= 47) || (code >= 100 && code <= 107)) this.bg = String(code);
			else if (code === 49) this.bg = "";
			else if (code === 38 || code === 48) {
				const mode = p[i + 1];
				let color: string;
				if (mode === 5) {
					color = `${code};5;${p[i + 2] ?? 0}`;
					i += 2;
				} else if (mode === 2) {
					color = `${code};2;${p[i + 2] ?? 0};${p[i + 3] ?? 0};${p[i + 4] ?? 0}`;
					i += 4;
				} else {
					i += 1;
					continue;
				}
				if (code === 38) this.fg = color;
				else this.bg = color;
			}
		}
	}

	#reset(): void {
		this.attrs.clear();
		this.fg = "";
		this.bg = "";
	}

	/** Sequences that reopen the current style (and hyperlink) at the start of a line. */
	restore(): string {
		const codes = [...this.attrs].sort((a, b) => a - b).map(String);
		if (this.fg) codes.push(this.fg);
		if (this.bg) codes.push(this.bg);
		return (codes.length ? `\x1b[${codes.join(";")}m` : "") + this.hyperlink;
	}

	/** Closes underline, strikethrough and the hyperlink so they do not bleed into padding. */
	lineEndReset(): string {
		const off: string[] = [];
		if (this.attrs.has(4)) off.push("24");
		if (this.attrs.has(9)) off.push("29");
		return (off.length ? `\x1b[${off.join(";")}m` : "") + (this.hyperlink ? OSC8_CLOSE : "");
	}
}

function applyAll(s: string, state: AnsiState): void {
	for (const p of pieces(s)) if ("esc" in p) state.apply(p.esc);
}

function widthOf(s: string, tabWidth: number): number {
	let w = 0;
	for (const p of pieces(s)) if ("text" in p) for (const [, gw] of graphemes(p.text, tabWidth)) w += gw;
	return w;
}

// ---------------------------------------------------------------------------
// wrapTextWithAnsi
// ---------------------------------------------------------------------------

export function wrapTextWithAnsi(text: string, width: number, tabWidth: number): string[] {
	if (!text) return [""];
	const result: string[] = [];
	const state = new AnsiState();
	for (const line of text.split("\n")) {
		const prefix = result.length > 0 ? state.restore() : "";
		result.push(...wrapSingleLine(prefix + line, width, tabWidth));
		applyAll(line, state);
	}
	return result.length ? result : [""];
}

/** Words and space runs; an escape after visible text closes that token, one after a space opens the next. */
function tokens(line: string): string[] {
	const out: string[] = [];
	let current = "";
	let pending = "";
	let inSpace = false;
	for (const p of pieces(line)) {
		if ("esc" in p) {
			if (!current || inSpace) pending += p.esc;
			else current += p.esc;
			continue;
		}
		for (const ch of p.text) {
			const isSpace = ch === " ";
			if (isSpace !== inSpace && current) {
				out.push(current);
				current = "";
			}
			current += pending;
			pending = "";
			inSpace = isSpace;
			current += ch;
		}
	}
	current += pending;
	if (current) out.push(current);
	return out;
}

function isWhitespaceToken(token: string): boolean {
	for (const p of pieces(token)) if ("text" in p && /[^ ]/.test(p.text)) return false;
	return true;
}

function trimEndSpaces(s: string): string {
	return s.replace(/ +$/, "");
}

function breakLongWord(word: string, width: number, tabWidth: number, state: AnsiState): string[] {
	const lines: string[] = [];
	let line = state.restore();
	let lineWidth = 0;
	for (const p of pieces(word)) {
		if ("esc" in p) {
			line += p.esc;
			state.apply(p.esc);
			continue;
		}
		for (const [g, gw] of graphemes(p.text, tabWidth)) {
			if (lineWidth + gw > width) {
				lines.push(line + state.lineEndReset());
				line = state.restore();
				lineWidth = 0;
			}
			line += g;
			lineWidth += gw;
		}
	}
	if (line) lines.push(line);
	return lines;
}

function wrapSingleLine(line: string, width: number, tabWidth: number): string[] {
	if (!line) return [""];
	if (widthOf(line, tabWidth) <= width) {
		const state = new AnsiState();
		applyAll(line, state);
		return [line + (state.hyperlink ? OSC8_CLOSE : "")];
	}
	const wrapped: string[] = [];
	const state = new AnsiState();
	let current = "";
	let currentWidth = 0;
	for (const token of tokens(line)) {
		const tokenWidth = widthOf(token, tabWidth);
		const isSpace = isWhitespaceToken(token);
		if (tokenWidth > width && !isSpace) {
			if (current) {
				wrapped.push(current + state.lineEndReset());
				current = "";
				currentWidth = 0;
			}
			const broken = breakLongWord(token, width, tabWidth, state);
			const last = broken.pop();
			wrapped.push(...broken);
			if (last !== undefined) {
				current = last;
				currentWidth = widthOf(last, tabWidth);
			}
			continue;
		}
		if (currentWidth + tokenWidth > width && currentWidth > 0) {
			wrapped.push(trimEndSpaces(current) + state.lineEndReset());
			current = state.restore();
			if (isSpace) currentWidth = 0;
			else {
				current += token;
				currentWidth = tokenWidth;
			}
		} else {
			current += token;
			currentWidth += tokenWidth;
		}
		applyAll(token, state);
	}
	if (current) wrapped.push(current + (state.hyperlink ? OSC8_CLOSE : ""));
	return wrapped.length ? wrapped.map(trimEndSpaces) : [""];
}

// ---------------------------------------------------------------------------
// truncateToWidth
// ---------------------------------------------------------------------------

const ELLIPSES: Record<Ellipsis, [string, number]> = {
	[Ellipsis.Unicode]: ["…", 1],
	[Ellipsis.Ascii]: ["...", 3],
	[Ellipsis.Omit]: ["", 0],
};

export function truncateToWidth(
	text: string,
	maxWidth: number,
	ellipsisKind: Ellipsis | undefined | null,
	pad: boolean | undefined | null,
	tabWidth: number,
): string {
	const textWidth = widthOf(text, tabWidth);
	if (textWidth <= maxWidth) return pad && textWidth < maxWidth ? text + " ".repeat(maxWidth - textWidth) : text;

	const [ellipsis, ellipsisWidth] = ELLIPSES[ellipsisKind ?? Ellipsis.Unicode];
	const target = Math.max(0, maxWidth - ellipsisWidth);
	if (target === 0) {
		const cut = ellipsisWidth <= maxWidth ? ellipsis : ellipsis.slice(0, maxWidth);
		const w = Math.min(ellipsisWidth, maxWidth);
		return pad && w < maxWidth ? cut + " ".repeat(maxWidth - w) : cut;
	}

	let out = "";
	let w = 0;
	let sawSgr = false;
	outer: for (const p of pieces(text)) {
		if ("esc" in p) {
			out += p.esc;
			if (isSgr(p.esc)) sawSgr = true;
			continue;
		}
		for (const [g, gw] of graphemes(p.text, tabWidth)) {
			if (w + gw > target) break outer;
			out += g;
			w += gw;
		}
		if (w >= target) break;
	}
	if (sawSgr) out += "\x1b[0m";
	out += ellipsis;
	const outWidth = w + ellipsisWidth;
	return pad && outWidth < maxWidth ? out + " ".repeat(maxWidth - outWidth) : out;
}

// ---------------------------------------------------------------------------
// sliceWithWidth / extractSegments
// ---------------------------------------------------------------------------

export function sliceWithWidth(
	line: string,
	startCol: number,
	length: number,
	strict: boolean | undefined | null,
	tabWidth: number,
): SliceResult {
	const endCol = startCol + length;
	const all = pieces(line);
	let out = "";
	let outWidth = 0;
	let col = 0;
	let pending = "";
	let k = 0;
	for (; k < all.length && col < endCol; k++) {
		const p = all[k]!;
		if ("esc" in p) {
			if (col >= startCol) out += p.esc;
			else pending += p.esc;
			continue;
		}
		for (const [g, gw] of graphemes(p.text, tabWidth)) {
			if (col >= endCol) break;
			if (col >= startCol && (!strict || col + gw <= endCol)) {
				out += pending + g;
				pending = "";
				outWidth += gw;
			}
			col += gw;
		}
	}
	// Escapes (resets) that immediately follow the slice ride along.
	for (; k < all.length; k++) {
		const p = all[k]!;
		if (!("esc" in p)) break;
		out += p.esc;
	}
	return { text: out, width: outWidth };
}

export function extractSegments(
	line: string,
	beforeEnd: number,
	afterStart: number,
	afterLen: number,
	strictAfter: boolean,
	tabWidth: number,
): ExtractSegmentsResult {
	const afterEnd = afterStart + afterLen;
	const doneCol = afterLen === 0 ? beforeEnd : afterEnd;
	const state = new AnsiState();
	let before = "";
	let beforeWidth = 0;
	let after = "";
	let afterWidth = 0;
	let pendingBefore = "";
	let afterStarted = false;
	let col = 0;
	for (const p of pieces(line)) {
		if (col >= doneCol) break;
		if ("esc" in p) {
			if (isSgr(p.esc)) state.apply(p.esc);
			if (col < beforeEnd) pendingBefore += p.esc;
			else if (col >= afterStart && col < afterEnd && afterStarted) after += p.esc;
			continue;
		}
		for (const [g, gw] of graphemes(p.text, tabWidth)) {
			if (col >= doneCol) break;
			if (col < beforeEnd) {
				before += pendingBefore + g;
				pendingBefore = "";
				beforeWidth += gw;
			} else if (col >= afterStart && col < afterEnd && (!strictAfter || col + gw <= afterEnd)) {
				if (!afterStarted) {
					// Only SGR reaches `state` here: like the native engine, `after` reopens colours, not hyperlinks.
					after += state.restore();
					afterStarted = true;
				}
				after += g;
				afterWidth += gw;
			}
			col += gw;
		}
	}
	return { before, beforeWidth, after, afterWidth };
}

// ---------------------------------------------------------------------------
// Keys (OMP's pure-JS parser; the native API passes the Kitty state per call)
// ---------------------------------------------------------------------------

export function matchesKey(data: string, keyId: string, kittyProtocolActive: boolean): boolean {
	jsKeys.setKittyProtocolActive(kittyProtocolActive);
	return jsKeys.matchesKey(data, keyId as jsKeys.KeyId);
}

export function parseKey(data: string, kittyProtocolActive: boolean): string | null {
	jsKeys.setKittyProtocolActive(kittyProtocolActive);
	return jsKeys.parseKey(data) ?? null;
}

const EVENT_TYPES = { press: KeyEventType.Press, repeat: KeyEventType.Repeat, release: KeyEventType.Release };

export function parseKittySequence(data: string) {
	const r = jsKeys.parseKittySequence(data);
	if (!r) return null;
	return {
		codepoint: r.codepoint,
		shiftedKey: r.shiftedKey,
		baseLayoutKey: r.baseLayoutKey,
		modifier: r.modifier,
		eventType: EVENT_TYPES[r.eventType],
	};
}

// ---------------------------------------------------------------------------
// Inert: no native addon in the view
// ---------------------------------------------------------------------------

/** Absent on purpose: terminal.ts catches the throw and writes stdout directly. */
export class TtyWriter {
	constructor(_fd: number) {
		throw new Error("TtyWriter: the odin view has no native tty pump");
	}
}

export const HighlightStream = undefined;

export function highlightCode(code: string, _lang?: string, _colors?: unknown): string {
	return code;
}

export function supportsLanguage(_lang: string): boolean {
	return false;
}

export async function warmHighlighter(): Promise<void> {}

export function encodeSixel(
	_data: Uint8Array,
	_width: number,
	_height: number,
	_backgroundRgb: number,
): string {
	throw new Error("encodeSixel: the odin view does not render images");
}

/** Same contract as `encodeSixel`; the view has no native blocking pool, so this rejects immediately. */
export function encodeSixelAsync(
	_data: Uint8Array,
	_width: number,
	_height: number,
	_backgroundRgb: number,
): Promise<string> {
	return Promise.reject(new Error("encodeSixelAsync: the odin view does not render images"));
}

export function detectMacOSAppearance(): "dark" | "light" | null {
	return null;
}

export const MacAppearanceObserver = {
	start(_cb: (err: Error | null, appearance: string) => void): { stop(): void } {
		throw new Error("MacAppearanceObserver: not available in the odin view");
	},
};

export async function fuzzyFind(_profile: unknown): Promise<{ matches: { path: string; score: number }[] }> {
	return { matches: [] };
}

// ---------------------------------------------------------------------------
// IPC (crates/pi-natives/src/ipc at e996e1c), over Node net Unix sockets.
// ---------------------------------------------------------------------------

export {
	IpcConnection,
	type IpcConnectOptions,
	IpcServer,
	type IpcListenOptions,
	ipcEndpoint,
} from "./pi-natives/ipc.ts";
