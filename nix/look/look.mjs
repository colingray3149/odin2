// odin-look: start or serve a site on the bubble's loopback, screenshot it at each width with headless
// Chromium, and print one JSON object with the shots, console errors and failed requests.
// odin-look --url U (--start CMD | --serve DIR) [--widths 390,1280] [--wait-ms 30000] --out DIR
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import net from "node:net";

const POLL_MS = 250;
const GOTO_TIMEOUT_MS = 30000;
const KILL_GRACE_MS = 2000;
const RING_BYTES = 16384;
const TAIL_CHARS = 400;
const TEXT_CHARS = 300;
const MAX_ENTRIES = 50;
const URL_SHAPE = /^http:\/\/127\.0\.0\.1:(\d+)(\/.*)?$/;

function fail(message) {
	process.stdout.write(`${JSON.stringify({ error: message })}\n`);
	const error = new Error(message);
	error.reported = true;
	throw error;
}

function parse(argv) {
	const known = new Set(["--url", "--start", "--serve", "--widths", "--wait-ms", "--out"]);
	const options = {};
	for (let index = 0; index < argv.length; index += 2) {
		const flag = argv[index];
		if (!known.has(flag) || argv[index + 1] === undefined || flag in options) {
			fail(`argument ${flag} is unknown, repeated or has no value`);
		}
		options[flag] = argv[index + 1];
	}
	if (("--start" in options) === ("--serve" in options)) fail("give exactly one of --start or --serve");
	if (!options["--out"]) fail("--out is required");
	const match = URL_SHAPE.exec(options["--url"] ?? "");
	if (!match) fail("url must be http://127.0.0.1:<port>/...");
	const widths = (options["--widths"] ?? "390,1280").split(",").map(Number);
	if (widths.some((width) => !Number.isInteger(width) || width < 320 || width > 2560)) {
		fail("widths must be integers from 320 to 2560");
	}
	return {
		url: options["--url"],
		port: Number(match[1]),
		start: options["--start"],
		serve: options["--serve"],
		widths,
		waitMs: Number(options["--wait-ms"] ?? 30000),
		out: options["--out"],
	};
}

function clip(text, limit) {
	const value = String(text ?? "");
	return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

function launchServer(options) {
	const [program, args] = options.serve
		? ["python3", ["-m", "http.server", String(options.port), "--bind", "127.0.0.1", "--directory", options.serve]]
		: ["bash", ["-c", options.start]];
	const child = spawn(program, args, { detached: true, stdio: ["ignore", "pipe", "pipe"] });
	child.unref();
	const server = { child, ring: "", exited: null, stopped: false };
	const keep = (chunk) => {
		server.ring = (server.ring + chunk.toString()).slice(-RING_BYTES);
	};
	child.stdout.on("data", keep);
	child.stderr.on("data", keep);
	child.on("exit", (code, signal) => {
		server.exited = code ?? signal ?? "unknown";
	});
	child.on("error", (error) => {
		server.exited = error.message;
	});
	return server;
}

function stopServer(server) {
	if (server.stopped) return Promise.resolve();
	server.stopped = true;
	if (!server.child.pid) return Promise.resolve();
	return new Promise((resolve) => {
		const group = -server.child.pid;
		const kill = (signal) => {
			try {
				process.kill(group, signal);
			} catch {
				// The group is already gone.
			}
		};
		kill("SIGTERM");
		setTimeout(() => {
			// The shell may exit while a grandchild ignores TERM; stop the whole group.
			kill("SIGKILL");
			resolve();
		}, KILL_GRACE_MS);
	});
}

function listening(port) {
	return new Promise((resolve) => {
		const socket = net.connect({ host: "127.0.0.1", port });
		socket.once("connect", () => {
			socket.destroy();
			resolve(true);
		});
		socket.once("error", () => resolve(false));
	});
}

async function waitForServer(server, options) {
	const deadline = Date.now() + options.waitMs;
	while (Date.now() < deadline) {
		if (server.exited !== null) {
			fail(`the dev command exited ${server.exited} before listening: ${clip(server.ring.slice(-TAIL_CHARS), TAIL_CHARS)}`);
		}
		if (await listening(options.port)) return;
		await new Promise((resolve) => setTimeout(resolve, POLL_MS));
	}
	await stopServer(server);
	fail(
		`the dev server did not listen on 127.0.0.1:${options.port} within ${Math.round(options.waitMs / 1000)} s; its last output: ${server.ring.slice(-TAIL_CHARS)}`,
	);
}

async function shoot(browser, options, width, report) {
	const context = await browser.newContext({ viewport: { width, height: width < 600 ? 844 : 900 }, deviceScaleFactor: 1 });
	const page = await context.newPage();
	const note = (list, entry) => {
		if (list.length < MAX_ENTRIES) list.push(entry);
	};
	page.on("console", (message) => {
		const type = message.type();
		if (type === "error" || type === "warning") note(report.console, { width, type, text: clip(message.text(), TEXT_CHARS) });
	});
	page.on("pageerror", (error) => note(report.console, { width, type: "pageerror", text: clip(error.message, TEXT_CHARS) }));
	page.on("requestfailed", (request) =>
		note(report.failed, { width, url: clip(request.url(), TEXT_CHARS), error: clip(request.failure()?.errorText, TEXT_CHARS) }),
	);
	page.on("response", (response) => {
		if (response.status() >= 400) note(report.failed, { width, url: clip(response.url(), TEXT_CHARS), status: response.status() });
	});
	try {
		await page.goto(options.url, { waitUntil: "networkidle", timeout: GOTO_TIMEOUT_MS });
	} catch {
		note(report.console, { width, type: "error", text: "the page did not settle within 30 s" });
	}
	const file = path.join(options.out, `look-${width}.png`);
	await page.screenshot({ path: file });
	report.shots.push({
		width,
		title: clip(await page.title(), TEXT_CHARS),
		path: path.posix.join(options.outRelative, `look-${width}.png`),
	});
	await context.close();
}

const options = parse(process.argv.slice(2));
options.outRelative = options.out;
if (path.isAbsolute(options.out) || options.out.split(/[/\\]/).includes("..")) {
	fail("--out must stay inside the capsule");
}
options.out = path.resolve(options.out);
mkdirSync(options.out, { recursive: true });
const { chromium } = createRequire(import.meta.url)(process.env.ODIN_LOOK_PLAYWRIGHT);
const server = launchServer(options);
let browser;
try {
	await waitForServer(server, options);
	browser = await chromium.launch({
		executablePath: process.env.ODIN_LOOK_CHROMIUM,
		args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
	});
	const report = { url: options.url, shots: [], console: [], failed: [] };
	for (const width of options.widths) await shoot(browser, options, width, report);
	await browser.close();
	await stopServer(server);
	process.stdout.write(`${JSON.stringify(report)}\n`);
	process.exitCode = 0;
} catch (error) {
	await browser?.close().catch(() => {});
	if (!error?.reported) {
		process.stdout.write(
			`${JSON.stringify({ error: `Chromium could not look at ${options.url}: ${clip(error?.message, TAIL_CHARS)}` })}\n`,
		);
	}
	process.exitCode = 2;
} finally {
	await stopServer(server);
}
