"use strict";

// Sole JavaScript mechanism adapter for odin-browser.  Stdout is protocol-only:
// one bounded JSON object per line, no diagnostics and no page-supplied errors.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const VERSION = 1;
const READY = "odin-playwright-worker";
const HARD_MAX_LINE_BYTES = 256 * 1024 * 1024;
const PRELAUNCH_MAX_LINE_BYTES = 1024 * 1024;
const MAX_URL_BYTES = 4096;
const MAX_SELECTOR_BYTES = 1024;
const MAX_ACTION_TEXT_BYTES = 8192;
const MAX_KEY_BYTES = 64;
const MAX_FRAGMENT_BYTES = 4096;
const MAX_READ_BYTES = 1024 * 1024;
const MAX_LINKS = 512;
const MAX_TABLES = 16;
const MAX_TABLE_ROWS = 256;
const MAX_TABLE_COLUMNS = 32;
const MAX_AX_NODES = 1024;
const MAX_DOM_NODES = 2048;
const FRAME_INTERVAL_MS = 250;
const PROGRESS_INTERVAL_BYTES = 256 * 1024;
const MASK_SELECTOR = "input, textarea, select, [contenteditable]";
const SAFE_COMPONENT = /^[A-Za-z0-9_-]{1,64}$/;
const REQUEST_DIGEST = /^blake3:[0-9a-f]{64}$/;
const DOCUMENT_TOKEN = /^[0-9a-f]{64}$/;
const REQUEST_ID = /^[1-9][0-9]{0,19}$/;
const METHODS = new Set([
	"Launch",
	"ObservePage",
	"Read",
	"Preflight",
	"Dispatch",
	"ReleaseBinding",
	"StageDownload",
	"CancelDownload",
	"StopFrames",
	"CloseBrowser",
	"Shutdown",
]);

let maxLineBytes = PRELAUNCH_MAX_LINE_BYTES;
let context = null;
let page = null;
let browserClosed = false;
let launched = false;
let frameProducerRunning = false;
let frameCapture = null;
let frameTimer = null;
let lastFrameDigest = null;
let stdoutBlocked = false;
let shuttingDown = false;
let shutdownAcknowledged = false;
let downloadRoot = null;
let maxEncodedFrameBytes = 0;
let maxDecodedFrameBytes = 0;
let maxActiveDownloads = 0;
let maxDownloadFileBytes = 0;
let maxDownloadTotalBytes = 0;
let stagedDownloadBytes = 0;
let retainedBinding = null;
let mainDocumentGeneration = 0n;
const downloads = new Map();
const requests = new Map();
let serial = Promise.resolve();

process.stdout.on("drain", () => {
	stdoutBlocked = false;
});
process.stdout.on("error", () => {
	hardExit();
});
process.stdin.on("error", () => {
	hardExit();
});
process.on("uncaughtException", () => {
	hardExit();
});
process.on("unhandledRejection", () => {
	hardExit();
});

class WorkerFailure extends Error {
	constructor(code, uncertain = false, fatal = false) {
		super(code);
		this.code = code;
		this.uncertain = uncertain;
		this.fatal = fatal;
	}
}

function hardExit() {
	try {
		process.stdout.end();
	} finally {
		process.exitCode = 70;
		setImmediate(() => process.exit(70));
	}
}

function exactObject(value, required, optional = []) {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
	const keys = Object.keys(value);
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) && keys.every((key) => allowed.has(key));
}

function boundedString(value, max, nonempty = false) {
	return typeof value === "string" && (!nonempty || value.length > 0) && Buffer.byteLength(value, "utf8") <= max;
}

function positiveInteger(value, max = Number.MAX_SAFE_INTEGER) {
	return Number.isSafeInteger(value) && value > 0 && value <= max;
}

function nonnegativeInteger(value, max = Number.MAX_SAFE_INTEGER) {
	return Number.isSafeInteger(value) && value >= 0 && value <= max;
}

function safeAbsolute(value) {
	return boundedString(value, 16 * 1024, true) && path.isAbsolute(value) && value.indexOf("\0") === -1;
}

function clipUtf8(value, limit) {
	value = String(value ?? "");
	if (Buffer.byteLength(value, "utf8") <= limit) return value;
	let low = 0;
	let high = value.length;
	while (low < high) {
		const midpoint = Math.ceil((low + high) / 2);
		if (Buffer.byteLength(value.slice(0, midpoint), "utf8") <= limit) low = midpoint;
		else high = midpoint - 1;
	}
	return value.slice(0, low);
}

function sha256(value) {
	return crypto.createHash("sha256").update(value).digest("hex");
}

function sanitizeUrl(exact) {
	if (!boundedString(exact, MAX_URL_BYTES, true)) throw new WorkerFailure("operationFailed");
	let parsed;
	try {
		parsed = new URL(exact);
	} catch (_) {
		throw new WorkerFailure("operationFailed");
	}
	parsed.username = "";
	parsed.password = "";
	parsed.search = "";
	parsed.hash = "";
	return {
		displayUrl: parsed.href,
		origin: parsed.origin,
		urlToken: sha256(exact),
	};
}

function encode(message) {
	let encoded;
	try {
		encoded = JSON.stringify(message);
	} catch (_) {
		throw new WorkerFailure("internal", false, true);
	}
	const bytes = Buffer.byteLength(encoded, "utf8") + 1;
	if (bytes > maxLineBytes || bytes > HARD_MAX_LINE_BYTES) {
		throw new WorkerFailure("boundExceeded", false, true);
	}
	return encoded + "\n";
}

function emit(message, droppable = false) {
	if (droppable && stdoutBlocked) return false;
	let line;
	try {
		line = encode(message);
	} catch (_) {
		if (droppable) return false;
		hardExit();
		return false;
	}
	const accepted = process.stdout.write(line);
	if (!accepted) stdoutBlocked = true;
	return accepted;
}

function emitEvent(event, droppable = false) {
	return emit({ v: VERSION, event }, droppable);
}

function success(id, result) {
	emit({ v: VERSION, id, ok: true, result });
}

function failure(id, error) {
	const safe = error instanceof WorkerFailure ? error : new WorkerFailure("operationFailed");
	emit({
		v: VERSION,
		id,
		ok: false,
		error: { code: safe.code, uncertain: !!safe.uncertain, fatal: !!safe.fatal },
	});
}

function ack() {
	return { acknowledged: true };
}

async function documentToken() {
	ensurePage();
	// Playwright obtains the serialized document through its isolated browser
	// channel. Page code cannot replace hashing primitives or forge this token.
	return sha256(await page.content());
}

async function pageIdentity() {
	ensurePage();
	const exactUrl = page.url();
	const document = await page.content();
	return { ...sanitizeUrl(exactUrl), documentToken: sha256(document) };
}

function ensurePage() {
	if (!launched || browserClosed || !page || page.isClosed()) {
		throw new WorkerFailure("browserClosed", false, true);
	}
}

function markMutatorInvoked(record, fatalUncertainty = false) {
	record.mutatorInvoked = true;
	if (fatalUncertainty) record.fatalUncertainty = true;
}

function ensureNotCancelled(record, mutation = false) {
	const uncertain = mutation || record.mutatorInvoked;
	const fatal = uncertain && record.fatalUncertainty;
	if (record.cancelled) {
		throw new WorkerFailure(uncertain ? "outcomeUncertain" : "cancelledBeforeDispatch", uncertain, fatal);
	}
	if (Date.now() >= record.deadlineAt) {
		throw new WorkerFailure(uncertain ? "outcomeUncertain" : "deadlineExceeded", uncertain, fatal);
	}
}

function remainingTimeout(record) {
	return Math.max(1, record.deadlineAt - Date.now());
}

function parseRequest(envelope) {
	if (!exactObject(envelope, ["v", "id", "method", "deadlineMs", "params"])) return null;
	if (
		envelope.v !== VERSION ||
		typeof envelope.id !== "string" ||
		!REQUEST_ID.test(envelope.id) ||
		!METHODS.has(envelope.method) ||
		!positiveInteger(envelope.deadlineMs)
	)
		return null;
	return envelope;
}

function receiveEnvelope(envelope) {
	if (exactObject(envelope, ["v", "cancel"])) {
		if (envelope.v !== VERSION || typeof envelope.cancel !== "string" || !REQUEST_ID.test(envelope.cancel)) {
			hardExit();
			return;
		}
		const record = requests.get(envelope.cancel);
		if (record) record.cancelled = true;
		return;
	}

	const request = parseRequest(envelope);
	if (!request || requests.has(request.id) || shuttingDown) {
		if (request && REQUEST_ID.test(request.id)) failure(request.id, new WorkerFailure("invalidEnvelope", false, true));
		else hardExit();
		return;
	}
	const record = {
		id: request.id,
		method: request.method,
		params: request.params,
		deadlineAt: Date.now() + request.deadlineMs,
		cancelled: false,
		executing: false,
		mutatorInvoked: false,
		fatalUncertainty: false,
	};
	requests.set(record.id, record);
	serial = serial.then(
		() => executeRecord(record),
		() => executeRecord(record),
	);
}

async function executeRecord(record) {
	try {
		if (record.cancelled || Date.now() >= record.deadlineAt) {
			throw new WorkerFailure("cancelledBeforeDispatch");
		}
		record.executing = true;
		const result = await dispatchMethod(record);
		if (record.cancelled || Date.now() >= record.deadlineAt) {
			if (record.method === "Preflight" && retainedBinding && retainedBinding.bindingId === result.bindingId) {
				const binding = retainedBinding;
				retainedBinding = null;
				await disposeBinding(binding);
			}
			const mutation = record.method === "Dispatch" ? record.mutatorInvoked : WorkerMutates(record.method);
			throw new WorkerFailure(
				mutation ? "outcomeUncertain" : record.cancelled ? "cancelledBeforeDispatch" : "deadlineExceeded",
				mutation,
				mutation && record.fatalUncertainty,
			);
		}
		success(record.id, result);
		if (record.method === "Shutdown") shutdownAcknowledged = true;
	} catch (error) {
		failure(record.id, error);
	} finally {
		requests.delete(record.id);
	}
}

function WorkerMutates(method) {
	return (
		method === "Launch" ||
		method === "Dispatch" ||
		method === "StageDownload" ||
		method === "CancelDownload" ||
		method === "CloseBrowser" ||
		method === "Shutdown"
	);
}

async function dispatchMethod(record) {
	switch (record.method) {
		case "Launch":
			return launch(record);
		case "ObservePage":
			return observePage(record);
		case "Read":
			return readPage(record);
		case "Preflight":
			return preflight(record);
		case "Dispatch":
			return dispatchAction(record);
		case "ReleaseBinding":
			return releaseBinding(record);
		case "StageDownload":
			return stageDownload(record);
		case "CancelDownload":
			return cancelDownload(record);
		case "StopFrames":
			return stopFrames(record);
		case "CloseBrowser":
			return closeBrowser(record);
		case "Shutdown":
			return shutdown(record);
		default:
			throw new WorkerFailure("invalidMethod", false, true);
	}
}

function validateLaunchParams(params) {
	const fields = [
		"playwrightModuleRoot",
		"chromiumExecutable",
		"userDataDir",
		"downloadRoot",
		"chromiumArguments",
		"viewportWidth",
		"viewportHeight",
		"maxMessageBytes",
		"maxEncodedFrameBytes",
		"maxDecodedFrameBytes",
		"maxActiveDownloads",
		"maxDownloadFileBytes",
		"maxDownloadTotalBytes",
	];
	if (
		!exactObject(params, fields) ||
		!safeAbsolute(params.playwrightModuleRoot) ||
		!safeAbsolute(params.chromiumExecutable) ||
		!safeAbsolute(params.userDataDir) ||
		!safeAbsolute(params.downloadRoot) ||
		!Array.isArray(params.chromiumArguments) ||
		params.chromiumArguments.length > 256 ||
		!params.chromiumArguments.every((arg) => boundedString(arg, 16 * 1024)) ||
		!positiveInteger(params.viewportWidth, 8192) ||
		!positiveInteger(params.viewportHeight, 8192) ||
		!positiveInteger(params.maxMessageBytes, HARD_MAX_LINE_BYTES) ||
		!positiveInteger(params.maxEncodedFrameBytes, params.maxMessageBytes) ||
		!positiveInteger(params.maxDecodedFrameBytes, params.maxMessageBytes) ||
		!positiveInteger(params.maxActiveDownloads, 1024) ||
		!positiveInteger(params.maxDownloadFileBytes) ||
		!positiveInteger(params.maxDownloadTotalBytes) ||
		params.maxDownloadFileBytes > params.maxDownloadTotalBytes
	) {
		throw new WorkerFailure("invalidParams", false, true);
	}
}

async function launch(record) {
	if (launched || context) throw new WorkerFailure("protocolViolation", false, true);
	validateLaunchParams(record.params);
	ensureNotCancelled(record, false);
	const params = record.params;
	let playwright;
	try {
		// The configured absolute module is the only resolution path.  NODE_PATH,
		// cwd packages, and environment-selected browser downloads are ignored.
		playwright = require(params.playwrightModuleRoot);
	} catch (err) {
		console.error("PLAYWRIGHT REQUIRE ERROR:", err);
		throw new WorkerFailure("browserLaunchFailed", false, true);
	}
	if (!playwright || !playwright.chromium || typeof playwright.chromium.launchPersistentContext !== "function") {
		throw new WorkerFailure("browserLaunchFailed", false, true);
	}

	const forbidden = params.chromiumArguments.some(
		(argument) =>
			argument === "--headless" ||
			argument.startsWith("--headless=") ||
			argument === "--no-sandbox" ||
			argument.startsWith("--remote-debugging-") ||
			argument.startsWith("--user-data-dir"),
	);
	if (forbidden) throw new WorkerFailure("invalidParams", false, true);

	maxLineBytes = params.maxMessageBytes;
	maxEncodedFrameBytes = params.maxEncodedFrameBytes;
	maxDecodedFrameBytes = params.maxDecodedFrameBytes;
	maxActiveDownloads = params.maxActiveDownloads;
	maxDownloadFileBytes = params.maxDownloadFileBytes;
	maxDownloadTotalBytes = params.maxDownloadTotalBytes;
	try {
		downloadRoot = fs.realpathSync(params.downloadRoot);
		if (!fs.lstatSync(downloadRoot).isDirectory()) throw new Error("not-directory");
	} catch (err) {
		console.error("DOWNLOAD ROOT ERROR:", err);
		throw new WorkerFailure("browserLaunchFailed", false, true);
	}

	try {
		context = await playwright.chromium.launchPersistentContext(params.userDataDir, {
			executablePath: params.chromiumExecutable,
			headless: false,
			chromiumSandbox: true,
			acceptDownloads: true,
			viewport: { width: params.viewportWidth, height: params.viewportHeight },
			args: [
				"--no-first-run",
				"--disable-sync",
				"--disable-background-networking",
				"--disable-gpu",
				`--window-size=${params.viewportWidth},${params.viewportHeight}`,
				...params.chromiumArguments,
			],
			timeout: remainingTimeout(record),
		});
	} catch (err) {
		console.error("LAUNCH CONTEXT ERROR:", err);
		context = null;
		throw new WorkerFailure("browserLaunchFailed", false, true);
	}

	try {
		const initialPages = context.pages();
		page = initialPages.shift() || (await context.newPage());
		for (const extra of initialPages) await extra.close({ runBeforeUnload: false }).catch(() => {});
		if (page.url() !== "about:blank") await page.goto("about:blank", { waitUntil: "commit", timeout: remainingTimeout(record) });
		context.on("page", (candidate) => {
			if (candidate !== page) candidate.close({ runBeforeUnload: false }).catch(() => {});
		});
		page.on("popup", (candidate) => candidate.close({ runBeforeUnload: false }).catch(() => {}));
		page.on("download", retainDownload);
		page.on("framenavigated", (frame) => {
			if (frame !== page.mainFrame()) return;
			mainDocumentGeneration += 1n;
			emitEvent({ type: "Protocol", name: "page-changed", sessionScoped: true }, true);
		});
		browserClosed = false;
		launched = true;
		ensureNotCancelled(record, true);
	} catch (err) {
		console.error("PAGE INIT ERROR:", err);
		await context.close().catch(() => {});
		context = null;
		page = null;
		launched = false;
		throw new WorkerFailure("browserLaunchFailed", false, true);
	}

	try {
		frameProducerRunning = true;
		await captureFrame();
		scheduleFrame();
	} catch (err) {
		console.error("FRAME PRODUCER ERROR:", err);
		frameProducerRunning = false;
		await context.close().catch(() => {});
		context = null;
		page = null;
		launched = false;
		browserClosed = true;
		throw new WorkerFailure("frameProducerStartFailed", false, true);
	}
	return { browserLaunched: true, frameProducerStarted: true };
}

async function observePage(record) {
	if (!exactObject(record.params, [])) throw new WorkerFailure("invalidParams");
	ensureNotCancelled(record, false);
	const before = await pageIdentity();
	const pageTitle = await page.title();
	const after = await pageIdentity();
	ensureNotCancelled(record, false);
	return { before, after, pageTitle: clipUtf8(pageTitle, MAX_FRAGMENT_BYTES) };
}

function validateReadParams(params) {
	return (
		exactObject(params, ["kind", "maxBytes"]) &&
		["text", "links", "tables", "accessibility", "sanitizedDom"].includes(params.kind) &&
		positiveInteger(params.maxBytes, MAX_READ_BYTES)
	);
}

async function readPage(record) {
	if (!validateReadParams(record.params)) throw new WorkerFailure("invalidParams");
	ensureNotCancelled(record, false);
	const before = await pageIdentity();
	const data = await fixedRead(record.params.kind, record.params.maxBytes);
	const after = await pageIdentity();
	ensureNotCancelled(record, false);
	return { before, after, data };
}

async function fixedRead(kind, maxBytes) {
	switch (kind) {
		case "text":
			return { type: "text", text: await extractText(maxBytes) };
		case "links":
			return { type: "links", links: await extractLinks(maxBytes) };
		case "tables":
			return { type: "tables", tables: await extractTables(maxBytes) };
		case "accessibility":
			return { type: "accessibility", root: await extractAccessibility(maxBytes) };
		case "sanitizedDom":
			return { type: "sanitizedDom", root: await extractDom(maxBytes) };
		default:
			throw new WorkerFailure("invalidParams");
	}
}

async function extractText(maxBytes) {
	const text = await page.evaluate(
		({ maxBytes, fragmentBytes }) => {
			const encoder = new TextEncoder();
			const clip = (input, max) => {
				const value = String(input ?? "");
				if (encoder.encode(value).length <= max) return value;
				let low = 0;
				let high = value.length;
				while (low < high) {
					const middle = Math.ceil((low + high) / 2);
					if (encoder.encode(value.slice(0, middle)).length <= max) low = middle;
					else high = middle - 1;
				}
				return value.slice(0, low);
			};
			const root = document.body || document.documentElement;
			if (!root) return "";
			let remaining = maxBytes;
			const parts = [];
			const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
			for (let node = walker.nextNode(); node && remaining > 0; node = walker.nextNode()) {
				const parent = node.parentElement;
				if (!parent || parent.closest("input,textarea,select,option,[contenteditable],script,style,template,noscript")) continue;
				const part = clip(node.nodeValue, Math.min(fragmentBytes, remaining));
				const used = encoder.encode(part).length;
				if (used) {
					parts.push(part);
					remaining -= used;
				}
			}
			return clip(parts.join(" ").replace(/\s+/g, " ").trim(), maxBytes);
		},
		{ maxBytes, fragmentBytes: MAX_FRAGMENT_BYTES },
	);
	return clipUtf8(text, maxBytes);
}

async function extractLinks(maxBytes) {
	const entries = Math.max(1, Math.min(MAX_LINKS, Math.floor(maxBytes / MAX_FRAGMENT_BYTES) || 1));
	const raw = await page.evaluate(
		({ entries, maxBytes, fragmentBytes, urlBytes }) => {
			const encoder = new TextEncoder();
			const clip = (input, max) => {
				const value = String(input ?? "");
				if (encoder.encode(value).length <= max) return value;
				let low = 0;
				let high = value.length;
				while (low < high) {
					const middle = Math.ceil((low + high) / 2);
					if (encoder.encode(value.slice(0, middle)).length <= max) low = middle;
					else high = middle - 1;
				}
				return value.slice(0, low);
			};
			const safeText = (root, max) => {
				const parts = [];
				let remaining = max;
				const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
				for (let node = walker.nextNode(); node && remaining > 0; node = walker.nextNode()) {
					const parent = node.parentElement;
					if (!parent || parent.closest("input,textarea,select,option,[contenteditable],script,style,template,noscript")) continue;
					const part = clip(node.nodeValue, remaining);
					remaining -= encoder.encode(part).length;
					if (part) parts.push(part);
				}
				return clip(parts.join(" ").replace(/\s+/g, " ").trim(), max);
			};
			const root = document.body || document.documentElement;
			if (!root) return [];
			const output = [];
			let remaining = maxBytes;
			for (const link of root.querySelectorAll("a[href],area[href]")) {
				if (output.length >= entries || remaining === 0) break;
				const exactUrl = String(link.href || "");
				if (!exactUrl || encoder.encode(exactUrl).length > urlBytes) continue;
				const text = safeText(link, Math.min(fragmentBytes, remaining));
				remaining -= Math.min(remaining, encoder.encode(text).length);
				output.push({ exactUrl, text });
			}
			return output;
		},
		{ entries, maxBytes, fragmentBytes: MAX_FRAGMENT_BYTES, urlBytes: MAX_URL_BYTES },
	);
	if (!Array.isArray(raw)) throw new WorkerFailure("operationFailed");
	const links = [];
	for (const candidate of raw.slice(0, MAX_LINKS)) {
		if (!exactObject(candidate, ["exactUrl", "text"]) || !boundedString(candidate.exactUrl, MAX_URL_BYTES, true)) continue;
		try {
			const safe = sanitizeUrl(candidate.exactUrl);
			links.push({ displayUrl: safe.displayUrl, urlToken: safe.urlToken, text: clipUtf8(candidate.text, MAX_FRAGMENT_BYTES) });
		} catch (_) {
			// A malformed page-controlled href has no safe typed projection.
		}
	}
	return links;
}

async function extractTables(maxBytes) {
	const raw = await page.evaluate(
		({ maxBytes, maxTables, maxRows, maxColumns, fragmentBytes }) => {
			const encoder = new TextEncoder();
			const clip = (input, max) => {
				const value = String(input ?? "");
				if (encoder.encode(value).length <= max) return value;
				let low = 0;
				let high = value.length;
				while (low < high) {
					const middle = Math.ceil((low + high) / 2);
					if (encoder.encode(value.slice(0, middle)).length <= max) low = middle;
					else high = middle - 1;
				}
				return value.slice(0, low);
			};
			const safeText = (root, max) => {
				const parts = [];
				let remaining = max;
				const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
				for (let node = walker.nextNode(); node && remaining > 0; node = walker.nextNode()) {
					const parent = node.parentElement;
					if (!parent || parent.closest("input,textarea,select,option,[contenteditable],script,style,template,noscript")) continue;
					const part = clip(node.nodeValue, remaining);
					remaining -= encoder.encode(part).length;
					if (part) parts.push(part);
				}
				return clip(parts.join(" ").replace(/\s+/g, " ").trim(), max);
			};
			const output = [];
			let remaining = maxBytes;
			for (const table of Array.from(document.querySelectorAll("table")).slice(0, maxTables)) {
				if (remaining === 0) break;
				const caption = table.caption ? safeText(table.caption, Math.min(fragmentBytes, remaining)) : null;
				if (caption !== null) remaining -= Math.min(remaining, encoder.encode(caption).length);
				const rows = [];
				for (const row of Array.from(table.rows).slice(0, maxRows)) {
					if (remaining === 0) break;
					const cells = [];
					for (const cell of Array.from(row.cells).slice(0, maxColumns)) {
						if (remaining === 0) break;
						const text = safeText(cell, Math.min(fragmentBytes, remaining));
						remaining -= Math.min(remaining, encoder.encode(text).length);
						cells.push(text);
					}
					rows.push(cells);
				}
				output.push({ caption, rows });
			}
			return output;
		},
		{
			maxBytes,
			maxTables: MAX_TABLES,
			maxRows: MAX_TABLE_ROWS,
			maxColumns: MAX_TABLE_COLUMNS,
			fragmentBytes: MAX_FRAGMENT_BYTES,
		},
	);
	if (!Array.isArray(raw)) throw new WorkerFailure("operationFailed");
	return raw.slice(0, MAX_TABLES).map((table) => ({
		caption: typeof table.caption === "string" ? clipUtf8(table.caption, MAX_FRAGMENT_BYTES) : null,
		rows: Array.isArray(table.rows)
			? table.rows
					.slice(0, MAX_TABLE_ROWS)
					.map((row) => (Array.isArray(row) ? row.slice(0, MAX_TABLE_COLUMNS).map((cell) => clipUtf8(cell, MAX_FRAGMENT_BYTES)) : []))
			: [],
	}));
}

async function extractAccessibility(maxBytes) {
	const root = await page.evaluate(
		({ maxBytes, maxNodes, fragmentBytes }) => {
			const encoder = new TextEncoder();
			const clip = (input, max) => {
				const value = String(input ?? "");
				if (encoder.encode(value).length <= max) return value;
				let low = 0;
				let high = value.length;
				while (low < high) {
					const middle = Math.ceil((low + high) / 2);
					if (encoder.encode(value.slice(0, middle)).length <= max) low = middle;
					else high = middle - 1;
				}
				return value.slice(0, low);
			};
			let remainingNodes = maxNodes;
			let remainingBytes = maxBytes;
			const editableRole = /^(textbox|textfield|searchbox|searchfield|spinbutton|combobox|menulistpopup)$/i;
			const build = (element, suppress) => {
				if (!(element instanceof Element) || remainingNodes === 0) return null;
				remainingNodes -= 1;
				const tag = element.localName.toLowerCase();
				const role = clip(
					element.getAttribute("role") ||
						{
							a: "link",
							button: "button",
							img: "img",
							input: "textbox",
							select: "combobox",
							textarea: "textbox",
							table: "table",
							tr: "row",
							th: "columnheader",
							td: "cell",
							nav: "navigation",
							main: "main",
							form: "form",
						}[tag] ||
						"generic",
					fragmentBytes,
				);
				const editable =
					suppress ||
					["input", "textarea", "select", "option", "script", "style", "template", "noscript"].includes(tag) ||
					element.isContentEditable ||
					editableRole.test(role);
				let name = "";
				if (!editable && remainingBytes > 0) {
					name = clip(element.getAttribute("aria-label") || element.getAttribute("alt") || "", Math.min(fragmentBytes, remainingBytes));
					remainingBytes -= Math.min(remainingBytes, encoder.encode(name).length);
				}
				const children = [];
				if (!editable) {
					for (const child of element.children) {
						if (remainingNodes === 0) break;
						const built = build(child, editable);
						if (built) children.push(built);
					}
				}
				return { role, name, children };
			};
			return build(document.documentElement, false) || { role: "document", name: "", children: [] };
		},
		{ maxBytes, maxNodes: MAX_AX_NODES, fragmentBytes: MAX_FRAGMENT_BYTES },
	);
	if (!exactObject(root, ["role", "name", "children"])) throw new WorkerFailure("operationFailed");
	return root;
}

async function extractDom(maxBytes) {
	const root = await page.evaluate(
		({ maxBytes, maxNodes, fragmentBytes }) => {
			const encoder = new TextEncoder();
			const allow = new Set(["contenteditable", "role", "type"]);
			const clip = (input, max) => {
				const value = String(input ?? "");
				if (encoder.encode(value).length <= max) return value;
				let low = 0;
				let high = value.length;
				while (low < high) {
					const middle = Math.ceil((low + high) / 2);
					if (encoder.encode(value.slice(0, middle)).length <= max) low = middle;
					else high = middle - 1;
				}
				return value.slice(0, low);
			};
			let remainingNodes = maxNodes;
			let remainingBytes = maxBytes;
			const build = (element, suppress) => {
				if (!(element instanceof Element) || remainingNodes === 0) return null;
				remainingNodes -= 1;
				const tag = element.localName.toLowerCase();
				const attributes = {};
				for (const attribute of element.attributes) {
					const name = attribute.name.toLowerCase();
					if (allow.has(name) && !Object.prototype.hasOwnProperty.call(attributes, name)) {
						const value = clip(attribute.value, Math.min(fragmentBytes, remainingBytes));
						attributes[name] = value;
						remainingBytes -= Math.min(remainingBytes, encoder.encode(value).length);
					}
				}
				const editable =
					suppress || ["input", "textarea", "select", "option", "script", "style", "template", "noscript"].includes(tag) || element.isContentEditable;
				let text = null;
				if (!editable && remainingBytes > 0) {
					const pieces = [];
					for (const child of element.childNodes) {
						if (child.nodeType === Node.TEXT_NODE) pieces.push(child.nodeValue || "");
					}
					const direct = clip(pieces.join(""), Math.min(fragmentBytes, remainingBytes));
					if (direct) {
						text = direct;
						remainingBytes -= Math.min(remainingBytes, encoder.encode(direct).length);
					}
				}
				const children = [];
				for (const child of element.children) {
					if (remainingNodes === 0) break;
					const built = build(child, editable);
					if (built) children.push(built);
				}
				return { tag, attributes, text, children };
			};
			return build(document.documentElement, false) || { tag: "html", attributes: {}, text: null, children: [] };
		},
		{ maxBytes, maxNodes: MAX_DOM_NODES, fragmentBytes: MAX_FRAGMENT_BYTES },
	);
	if (!exactObject(root, ["tag", "attributes", "text", "children"])) throw new WorkerFailure("operationFailed");
	return root;
}

function validatePreflightParams(params) {
	return (
		exactObject(params, ["requestDigest", "selector"]) &&
		typeof params.requestDigest === "string" &&
		REQUEST_DIGEST.test(params.requestDigest) &&
		(params.selector === null || boundedString(params.selector, MAX_SELECTOR_BYTES, true))
	);
}

async function elementStructure(handle) {
	const structure = await handle.evaluate((element) => {
		const tag = element.localName.toLowerCase();
		if (tag === "input") {
			const type = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "type").get.call(element);
			const form = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "form").get.call(element);
			return { tag, inputType: String(type).toLowerCase(), inForm: form !== null };
		}
		if (tag === "button") {
			const type = Object.getOwnPropertyDescriptor(HTMLButtonElement.prototype, "type").get.call(element);
			const form = Object.getOwnPropertyDescriptor(HTMLButtonElement.prototype, "form").get.call(element);
			return { tag, inputType: String(type).toLowerCase(), inForm: form !== null };
		}
		return { tag, inputType: null, inForm: false };
	});
	if (!exactObject(structure, ["tag", "inputType", "inForm"])) throw new WorkerFailure("operationFailed");
	return structure;
}

async function preflight(record) {
	if (!validatePreflightParams(record.params)) throw new WorkerFailure("invalidParams");
	ensurePage();
	ensureNotCancelled(record, false);
	if (retainedBinding) throw new WorkerFailure("bindingBusy");
	const documentGeneration = mainDocumentGeneration;
	const document = await documentToken();
	if (mainDocumentGeneration !== documentGeneration) throw new WorkerFailure("documentChanged");
	let handle = null;
	let target = null;
	try {
		if (record.params.selector !== null) {
			let locator;
			let count;
			try {
				locator = page.locator(record.params.selector);
				count = await locator.count();
			} catch (_) {
				throw new WorkerFailure("missingTarget");
			}
			if (count !== 1) throw new WorkerFailure(count === 0 ? "missingTarget" : "ambiguousSelector");
			handle = await locator.elementHandle({ timeout: remainingTimeout(record) });
			if (!handle) throw new WorkerFailure("missingTarget");
			target = await elementStructure(handle);
		}
		ensureNotCancelled(record, false);
		if (mainDocumentGeneration !== documentGeneration) throw new WorkerFailure("documentChanged");
		const bindingId = crypto.randomUUID();
		retainedBinding = {
			bindingId,
			requestDigest: record.params.requestDigest,
			documentToken: document,
			documentGeneration,
			selector: record.params.selector,
			handle,
			target,
		};
		return { bindingId, documentToken: document, target };
	} catch (error) {
		await disposeBinding({ handle });
		throw error;
	}
}

function validateElementStructure(value) {
	return (
		exactObject(value, ["tag", "inputType", "inForm"]) &&
		boundedString(value.tag, 128, true) &&
		(value.inputType === null || boundedString(value.inputType, 128, true)) &&
		typeof value.inForm === "boolean"
	);
}

function sameElementStructure(left, right) {
	return left.tag === right.tag && left.inputType === right.inputType && left.inForm === right.inForm;
}

function validateWorkerAction(action) {
	if (action === null || typeof action !== "object" || Array.isArray(action) || typeof action.type !== "string") return false;
	switch (action.type) {
		case "navigate":
			return exactObject(action, ["type", "url"]) && boundedString(action.url, MAX_URL_BYTES, true);
		case "back":
		case "forward":
		case "reload":
		case "screenshot":
		case "close":
			return exactObject(action, ["type"]);
		case "fill":
			return (
				exactObject(action, ["type", "selector", "text"]) &&
				boundedString(action.selector, MAX_SELECTOR_BYTES, true) &&
				boundedString(action.text, MAX_ACTION_TEXT_BYTES)
			);
		case "activate":
		case "submitForm":
			return exactObject(action, ["type", "selector"]) && boundedString(action.selector, MAX_SELECTOR_BYTES, true);
		case "pressKey":
			return exactObject(action, ["type", "key"]) && boundedString(action.key, MAX_KEY_BYTES, true);
		case "scroll":
			return (
				exactObject(action, ["type", "deltaX", "deltaY"]) &&
				Number.isSafeInteger(action.deltaX) &&
				Number.isSafeInteger(action.deltaY) &&
				action.deltaX >= -2147483648 &&
				action.deltaX <= 2147483647 &&
				action.deltaY >= -2147483648 &&
				action.deltaY <= 2147483647
			);
		default:
			return false;
	}
}

function validateDispatchParams(params) {
	return (
		exactObject(params, ["bindingId", "requestDigest", "documentToken", "expectedTarget", "action", "maxScreenshotBytes"]) &&
		typeof params.bindingId === "string" &&
		SAFE_COMPONENT.test(params.bindingId) &&
		typeof params.requestDigest === "string" &&
		REQUEST_DIGEST.test(params.requestDigest) &&
		typeof params.documentToken === "string" &&
		DOCUMENT_TOKEN.test(params.documentToken) &&
		(params.expectedTarget === null || validateElementStructure(params.expectedTarget)) &&
		validateWorkerAction(params.action) &&
		nonnegativeInteger(params.maxScreenshotBytes, HARD_MAX_LINE_BYTES)
	);
}

function actionSelector(action) {
	return ["fill", "activate", "submitForm"].includes(action.type) ? action.selector : null;
}

async function disposeBinding(binding) {
	if (binding && binding.handle) await binding.handle.dispose().catch(() => {});
}

async function dispatchAction(record) {
	if (!validateDispatchParams(record.params)) throw new WorkerFailure("invalidParams");
	ensurePage();
	const binding = retainedBinding;
	retainedBinding = null;
	if (!binding) throw new WorkerFailure("bindingMissing");
	try {
		if (binding.bindingId !== record.params.bindingId) throw new WorkerFailure("bindingIdMismatch");
		if (binding.requestDigest !== record.params.requestDigest) throw new WorkerFailure("requestDigestMismatch");
		if (binding.documentToken !== record.params.documentToken) throw new WorkerFailure("documentChanged");
		if (actionSelector(record.params.action) !== binding.selector) throw new WorkerFailure("requestDigestMismatch");
		if (binding.documentGeneration !== mainDocumentGeneration) throw new WorkerFailure("documentChanged");
		if (binding.handle) {
			const connected = await binding.handle.evaluate((element) => element.isConnected);
			if (!connected) throw new WorkerFailure("targetDisconnected");
			const structure = await elementStructure(binding.handle);
			if (!sameElementStructure(structure, binding.target)) {
				throw new WorkerFailure("targetStructureChanged");
			}
			if (record.params.expectedTarget === null || !sameElementStructure(record.params.expectedTarget, binding.target)) {
				throw new WorkerFailure("expectedTargetMismatch");
			}
		} else if (record.params.expectedTarget !== null) {
			throw new WorkerFailure("expectedTargetMismatch");
		}
		ensureNotCancelled(record, false);
		const result = await performAction(record, binding);
		ensureNotCancelled(record);
		return result;
	} finally {
		await disposeBinding(binding);
	}
}

async function performAction(record, binding) {
	const action = record.params.action;
	let navigation = null;
	let screenshotBase64 = null;
	let targetClosed = false;
	const timeout = remainingTimeout(record);
	try {
		switch (action.type) {
			case "navigate":
				markMutatorInvoked(record);
				await page.goto(action.url, { waitUntil: "domcontentloaded", timeout });
				navigation = await pageIdentity();
				break;
			case "back":
				markMutatorInvoked(record);
				await page.goBack({ waitUntil: "domcontentloaded", timeout });
				navigation = await pageIdentity();
				break;
			case "forward":
				markMutatorInvoked(record);
				await page.goForward({ waitUntil: "domcontentloaded", timeout });
				navigation = await pageIdentity();
				break;
			case "reload":
				markMutatorInvoked(record);
				await page.reload({ waitUntil: "domcontentloaded", timeout });
				navigation = await pageIdentity();
				break;
			case "fill":
				if (!binding.handle) throw new WorkerFailure("missingTarget");
				markMutatorInvoked(record);
				await binding.handle.fill(action.text, { timeout });
				break;
			case "activate":
				if (!binding.handle) throw new WorkerFailure("missingTarget");
				markMutatorInvoked(record);
				await binding.handle.click({ timeout });
				break;
			case "submitForm":
				if (!binding.handle) throw new WorkerFailure("missingTarget");
				markMutatorInvoked(record);
				await binding.handle.evaluate((element) => {
					const form = element instanceof HTMLFormElement ? element : element.form || element.closest("form");
					if (!form) throw new Error("no-form");
					if (typeof form.requestSubmit === "function") {
						if ((element instanceof HTMLButtonElement || element instanceof HTMLInputElement) && /^(submit|image)$/i.test(element.type || ""))
							form.requestSubmit(element);
						else form.requestSubmit();
					} else form.submit();
				});
				break;
			case "pressKey":
				markMutatorInvoked(record, true);
				await page.keyboard.press(action.key);
				break;
			case "scroll":
				markMutatorInvoked(record);
				await page.mouse.wheel(action.deltaX, action.deltaY);
				break;
			case "screenshot": {
				const capture = await maskedScreenshot("png", record.params.maxScreenshotBytes);
				screenshotBase64 = capture.bytes.toString("base64");
				break;
			}
			case "close":
				await stopFrameProducer();
				markMutatorInvoked(record);
				await page.close({ runBeforeUnload: false });
				targetClosed = true;
				browserClosed = true;
				break;
			default:
				throw new WorkerFailure("invalidParams");
		}
	} catch (error) {
		if (record.mutatorInvoked) {
			throw new WorkerFailure("outcomeUncertain", true, record.fatalUncertainty);
		}
		if (error instanceof WorkerFailure) throw error;
		if (record.cancelled || Date.now() >= record.deadlineAt) {
			throw new WorkerFailure("deadlineExceeded");
		}
		throw new WorkerFailure("operationFailed");
	}
	return { navigation, screenshotBase64, targetClosed };
}

async function releaseBinding(record) {
	const params = record.params;
	if (!exactObject(params, ["bindingId"]) || typeof params.bindingId !== "string" || !SAFE_COMPONENT.test(params.bindingId)) {
		throw new WorkerFailure("invalidParams");
	}
	ensureNotCancelled(record, false);
	if (retainedBinding && retainedBinding.bindingId === params.bindingId) {
		const binding = retainedBinding;
		retainedBinding = null;
		await disposeBinding(binding);
	}
	return ack();
}

function retainDownload(download) {
	if (browserClosed || shuttingDown || downloads.size >= maxActiveDownloads) {
		download.cancel().catch(() => {});
		return;
	}
	const downloadId = crypto.randomUUID();
	const record = { downloadId, download, staging: false, cancelled: false };
	downloads.set(downloadId, record);
	let sourceUrl = "about:blank";
	try {
		sourceUrl = sanitizeUrl(String(download.url())).displayUrl;
	} catch (_) {}
	const suggestedFilename = clipUtf8(download.suggestedFilename() || "download", MAX_FRAGMENT_BYTES);
	emitEvent({
		type: "DownloadBegin",
		downloadId,
		suggestedFilename,
		sourceUrl,
		expectedBytes: null,
	});
}

async function stageDownload(record) {
	const params = record.params;
	if (!exactObject(params, ["downloadId"]) || typeof params.downloadId !== "string" || !SAFE_COMPONENT.test(params.downloadId)) {
		throw new WorkerFailure("invalidParams");
	}
	ensureNotCancelled(record, false);
	const retained = downloads.get(params.downloadId);
	if (!retained || retained.staging) throw new WorkerFailure("downloadUnknown");
	retained.staging = true;
	const directory = path.join(downloadRoot, params.downloadId);
	let canonicalDirectory;
	try {
		const metadata = fs.lstatSync(directory);
		if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("unsafe");
		canonicalDirectory = fs.realpathSync(directory);
		if (!canonicalDirectory.startsWith(downloadRoot + path.sep)) throw new Error("escape");
	} catch (_) {
		retained.staging = false;
		throw new WorkerFailure("downloadRejected");
	}
	const destination = path.join(canonicalDirectory, "payload");
	let file = null;
	let stream = null;
	let receivedBytes = 0;
	let nextProgress = PROGRESS_INTERVAL_BYTES;
	try {
		stream = await retained.download.createReadStream();
		if (!stream) throw new WorkerFailure("downloadRejected");
		file = await fs.promises.open(destination, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
		for await (const chunk of stream) {
			if (record.cancelled || retained.cancelled || Date.now() >= record.deadlineAt) {
				throw new WorkerFailure("outcomeUncertain", true, false);
			}
			receivedBytes += chunk.length;
			if (receivedBytes > maxDownloadFileBytes || stagedDownloadBytes + receivedBytes > maxDownloadTotalBytes) {
				throw new WorkerFailure("boundExceeded");
			}
			let offset = 0;
			while (offset < chunk.length) {
				const written = await file.write(chunk, offset, chunk.length - offset, null);
				if (!written || written.bytesWritten <= 0) throw new WorkerFailure("operationFailed");
				offset += written.bytesWritten;
			}
			if (receivedBytes >= nextProgress) {
				emitEvent(
					{
						type: "DownloadProgress",
						downloadId: params.downloadId,
						state: "inProgress",
						receivedBytes,
					},
					true,
				);
				nextProgress = receivedBytes + PROGRESS_INTERVAL_BYTES;
			}
		}
		await file.sync();
		await file.close();
		file = null;
		stagedDownloadBytes += receivedBytes;
		downloads.delete(params.downloadId);
		return { downloadId: params.downloadId, receivedBytes };
	} catch (error) {
		if (file) await file.close().catch(() => {});
		if (stream && typeof stream.destroy === "function") stream.destroy();
		await fs.promises.unlink(destination).catch(() => {});
		await retained.download.cancel().catch(() => {});
		downloads.delete(params.downloadId);
		emitEvent({
			type: "DownloadProgress",
			downloadId: params.downloadId,
			state: record.cancelled || retained.cancelled ? "cancelled" : "failed",
			receivedBytes,
		});
		if (error instanceof WorkerFailure) throw error;
		throw new WorkerFailure("operationFailed");
	}
}

async function cancelDownload(record) {
	const params = record.params;
	if (!exactObject(params, ["downloadId"]) || typeof params.downloadId !== "string" || !SAFE_COMPONENT.test(params.downloadId)) {
		throw new WorkerFailure("invalidParams");
	}
	const retained = downloads.get(params.downloadId);
	if (!retained) return ack();
	retained.cancelled = true;
	await retained.download.cancel().catch(() => {});
	downloads.delete(params.downloadId);
	emitEvent({
		type: "DownloadProgress",
		downloadId: params.downloadId,
		state: "cancelled",
		receivedBytes: 0,
	});
	return ack();
}

async function maskedScreenshot(format, byteLimit) {
	ensurePage();
	const masks = [];
	let maskedRuntimeValueRegions = 0;
	for (const frame of page.frames()) {
		if (frame.isDetached()) continue;
		const mask = frame.locator(MASK_SELECTOR);
		const count = await mask.count();
		masks.push(mask);
		maskedRuntimeValueRegions = Math.min(maskedRuntimeValueRegions + count, 0xffffffff);
	}
	const options = {
		type: format,
		animations: "disabled",
		caret: "hide",
		mask: masks,
		maskColor: "#000000",
		fullPage: false,
	};
	if (format === "jpeg") options.quality = 60;
	const bytes = await page.screenshot(options);
	if (bytes.length > byteLimit) throw new WorkerFailure("boundExceeded");
	return { bytes, maskedRuntimeValueRegions };
}

async function captureFrame() {
	if (!frameProducerRunning || frameCapture || stdoutBlocked || browserClosed || !page || page.isClosed()) return;
	frameCapture = (async () => {
		const capture = await maskedScreenshot("jpeg", maxDecodedFrameBytes);
		const encodedLength = Math.ceil(capture.bytes.length / 3) * 4;
		if (encodedLength > maxEncodedFrameBytes) throw new WorkerFailure("boundExceeded");
		const digest = sha256(capture.bytes);
		if (digest === lastFrameDigest || stdoutBlocked || !frameProducerRunning) return;
		const jpegBase64 = capture.bytes.toString("base64");
		if (Buffer.byteLength(jpegBase64, "ascii") > maxEncodedFrameBytes) throw new WorkerFailure("boundExceeded");
		if (
			emitEvent(
				{
					type: "Frame",
					capturedAt: Date.now(),
					jpegBase64,
					keyFrame: true,
					maskedRuntimeValueRegions: capture.maskedRuntimeValueRegions,
				},
				true,
			)
		)
			lastFrameDigest = digest;
	})();
	try {
		await frameCapture;
	} finally {
		frameCapture = null;
	}
}

function scheduleFrame() {
	if (!frameProducerRunning || shuttingDown) return;
	frameTimer = setTimeout(async () => {
		frameTimer = null;
		const scheduledCapture = async () => {
			try {
				await captureFrame();
			} catch (_) {
				// A failed capture is a dropped observation, never a page error event.
			}
		};
		serial = serial.then(scheduledCapture, scheduledCapture);
		await serial;
		scheduleFrame();
	}, FRAME_INTERVAL_MS);
	frameTimer.unref();
}

async function stopFrameProducer() {
	frameProducerRunning = false;
	if (frameTimer) clearTimeout(frameTimer);
	frameTimer = null;
	if (frameCapture) await frameCapture.catch(() => {});
}

async function stopFrames(record) {
	if (!exactObject(record.params, [])) throw new WorkerFailure("invalidParams");
	ensureNotCancelled(record, false);
	await stopFrameProducer();
	return ack();
}

async function closeBrowser(record) {
	if (!exactObject(record.params, [])) throw new WorkerFailure("invalidParams");
	ensureNotCancelled(record, false);
	await stopFrameProducer();
	if (retainedBinding) {
		const binding = retainedBinding;
		retainedBinding = null;
		await disposeBinding(binding);
	}
	for (const retained of downloads.values()) {
		retained.cancelled = true;
		await retained.download.cancel().catch(() => {});
	}
	downloads.clear();
	if (context) await context.close().catch(() => {});
	context = null;
	page = null;
	browserClosed = true;
	return ack();
}

async function shutdown(record) {
	if (!exactObject(record.params, [])) throw new WorkerFailure("invalidParams");
	shuttingDown = true;
	await stopFrameProducer();
	if (retainedBinding) {
		const binding = retainedBinding;
		retainedBinding = null;
		await disposeBinding(binding);
	}
	for (const retained of downloads.values()) await retained.download.cancel().catch(() => {});
	downloads.clear();
	if (context) await context.close().catch(() => {});
	context = null;
	page = null;
	browserClosed = true;
	return ack();
}

class BoundedJsonLines {
	constructor(onValue) {
		this.onValue = onValue;
		this.fragments = [];
		this.bytes = 0;
	}

	push(chunk) {
		let offset = 0;
		while (offset < chunk.length) {
			const newline = chunk.indexOf(0x0a, offset);
			const end = newline === -1 ? chunk.length : newline;
			const length = end - offset;
			if (this.bytes + length > maxLineBytes || this.bytes + length > HARD_MAX_LINE_BYTES) {
				hardExit();
				return;
			}
			if (length > 0) {
				this.fragments.push(chunk.subarray(offset, end));
				this.bytes += length;
			}
			if (newline === -1) return;
			let line = this.fragments.length === 1 ? this.fragments[0] : Buffer.concat(this.fragments, this.bytes);
			if (line.length > 0 && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
			this.fragments = [];
			this.bytes = 0;
			if (line.length === 0) {
				hardExit();
				return;
			}
			let parsed;
			try {
				parsed = JSON.parse(line.toString("utf8"));
			} catch (_) {
				hardExit();
				return;
			}
			this.onValue(parsed);
			offset = newline + 1;
		}
	}
}

const decoder = new BoundedJsonLines(receiveEnvelope);
process.stdin.on("data", (chunk) => decoder.push(chunk));
process.stdin.on("end", () => {
	if (!shutdownAcknowledged) {
		hardExit();
		return;
	}
	process.stdout.end();
});

emit({ v: VERSION, ready: READY });
