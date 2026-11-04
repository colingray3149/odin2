import { afterEach, beforeEach, expect, jest, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { initThemeSync, theme } from "../omp/theme/theme";
import { App } from "../src/app";
import type { BridgeMessage, SeatInfo, ViewCommand } from "../src/protocol";
import { fakeTui, plain as strip } from "./support";

initThemeSync("nerd", false, "cyber-blossom", "cyber-blossom");

const saved: Record<string, string | undefined> = {};
let testState: string;
beforeEach(() => {
	for (const name of ["XDG_STATE_HOME", "HOME"]) saved[name] = process.env[name];
	testState = fs.mkdtempSync(path.join(os.tmpdir(), "odin-view-"));
	process.env.XDG_STATE_HOME = testState;
	process.env.HOME = "/home/owner";
});
afterEach(() => {
	for (const [name, value] of Object.entries(saved)) {
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
	fs.rmSync(testState, { recursive: true, force: true });
});

function view() {
	const sent: ViewCommand[] = [];
	const bridge = { up: true };
	const { state, tui } = fakeTui();
	const quits: (number | undefined)[] = [];
	const app = new App(tui, command => (sent.push(command), bridge.up), code => quits.push(code));
	const plain = () => strip(app.render(100));
	const key = (data: string) => (state.focused && state.focused !== app.editor && state.focused.handleInput ? state.focused.handleInput(data) : state.input(data));
	return { app, sent, plain, quits, key, bridge };
}

const sinmara = (...sessions: string[]): SeatInfo => ({
	id: "sinmara",
	name: "Sinmara",
	state: "online",
	models: ["gateway/grok"],
	sessions: sessions.map(id => ({ id, state: "idle", model: "gateway/grok" })),
});

const seats = (conversation: string | null, ...sessions: string[]): BridgeMessage => ({
	t: "seats",
	seats: [sinmara(...sessions)],
	conversation,
});

const said = (session: string, seq: number, text: string): BridgeMessage => ({ t: "event", session, seq, kind: "user", text });

test("Sinmara's conversation rolling over keeps what the old session showed and follows the new one", () => {
	const { app, sent, plain } = view();
	app.onMessage(seats("a", "a"));
	app.onMessage({ t: "reset", session: "a" });
	app.onMessage(said("a", 1, "from discord before the rollover"));
	// The old vehicle retires before its successor opens: no live session for a moment, and the screen keeps it.
	app.onMessage(seats("a"));
	expect(plain()).toContain("from discord before the rollover");
	app.onMessage(seats("b", "b"));
	expect(sent).toEqual([
		{ t: "watch", session: "a" },
		{ t: "watch", session: "b" },
	]);
	// The bridge replays the old session's tail ahead of the new one.
	app.onMessage({ t: "reset", session: "b", previous: "a" });
	app.onMessage(said("a", 1, "from discord before the rollover"));
	app.onMessage({ t: "event", session: "b", seq: 0, kind: "note", text: "continues in a new session (b)" });
	app.onMessage(said("b", 1, "from discord after it"));
	app.onMessage(said("c", 1, "another session's line"));
	const screen = plain();
	expect(screen.indexOf("before the rollover")).toBeLessThan(screen.indexOf("continues in a new session"));
	expect(screen.indexOf("continues in a new session")).toBeLessThan(screen.indexOf("after it"));
	expect(screen).not.toContain("another session's line");
});

test("a session the conversation left gives way to the one carrying it, even while both are live", () => {
	const { app, sent } = view();
	app.onMessage(seats("a", "a"));
	app.onMessage(seats("b", "a", "b"));
	expect(sent.at(-1)).toEqual({ t: "watch", session: "b" });
});

test("/model shows the seat's models and greys a signed-in model no seat may run", () => {
	const { app, sent, plain } = view();
	app.onMessage(seats("a", "a"));
	app.editor.onSubmit?.("/model");
	const catalog = sent.at(-1);
	expect(catalog).toEqual({ t: "catalog", id: expect.any(String), seat: "sinmara" });
	if (catalog?.t !== "catalog") return;
	app.onMessage({
		t: "catalog",
		id: catalog.id,
		seat: "sinmara",
		rows: [
			{
				selector: "gateway/grok",
				name: "Grok 4.7",
				strengths: "the default agent lane",
				tier: "frontier",
				seatAllowed: true,
				reason: "",
				contextWindow: 500000,
				inputPerMillion: "2",
				outputPerMillion: "6",
				billing: "subscription",
			},
			{
				selector: "openai-codex/gpt-6-sol",
				name: "GPT-6-Sol",
				strengths: "",
				tier: "",
				seatAllowed: false,
				reason: "no gateway lane declared",
				contextWindow: 272000,
				inputPerMillion: "2",
				outputPerMillion: "10",
				billing: "",
			},
		],
	});
	const screen = plain();
	expect(screen).toContain("Seat-allowed");
	expect(screen).toContain("Grok 4.7");
	expect(screen).toContain("Signed in, not for seats");
	expect(screen).toContain("no gateway lane declared");
});

test("the overview shows each seat, approval, Claude session and CI repo on its own line, with the computers on top", () => {
	const { app, plain, key } = view();
	const minutes = (n: number) => new Date(Date.now() - n * 60_000).toISOString();
	app.onMessage({
		t: "seats",
		seats: [
			{
				id: "sinmara",
				name: "Sinmara",
				state: "online",
				models: ["gateway/grok"],
				sessions: [
					{
						id: "s1",
						state: "running",
						model: "gateway/grok",
						updatedAt: minutes(12),
						quietSeconds: 600,
						pendingPermissionCount: 0,
					},
				],
			},
			{ id: "rig", name: "Rig", state: "idle", models: [], sessions: [] },
		],
		claude: [
			{
				id: "claude:9a4a5c6e-1f2e-4c31-9d2a-3b2c1a0b9c8d",
				state: "running",
				model: "claude",
				title: "glm overview",
				updatedAt: minutes(30),
				quietSeconds: 600,
				pendingPermissionCount: 0,
				compacted: true,
			},
		],
		conversation: null,
	});
	app.onMessage({
		t: "approvals",
		rows: [
			{
				id: "ap_1",
				issuer: "rig",
				capability: "kube.workload.stop",
				target: "pod heat-sim",
				requestedAt: minutes(5),
			},
		],
	});
	app.onMessage({
		t: "claudeLocal",
		device: "pc",
		rows: [
			{
				id: "b27e63eb-2e1a-4417-87e2-83c721627c55",
				name: "colin-d0",
				status: "idle",
				cwd: "/home/owner/wt/glm-overview",
				branch: "glm/overview",
				compacted: true,
			},
			{ id: "2", name: "colin-d1", status: "idle", cwd: "/home/ownerx/other", branch: null, compacted: false },
		],
	});
	app.onMessage({
		t: "ci",
		rows: [
			{ repo: "odin-owner/odin", status: "completed", conclusion: "success", branch: "main", updatedAt: minutes(180) },
			{ repo: "odin-owner/dotfiles", status: null, conclusion: null, branch: null, updatedAt: null, error: "failed to get runs: HTTP 404: Not Found" },
		],
	});
	key("\t"); // Sinmara's session → the Claude pod
	key("\t"); // → Models
	key("\t"); // → the overview, last in the cycle
	app.onMessage({
		t: "compute",
		snapshot: { hosts: [{ node: "pc", host: "pc", error: "unreachable" }] },
	});
	const screen = plain();
	const line = (...needles: string[]) => screen.split("\n").find(row => needles.every(needle => row.includes(needle)));
	expect(line("Sinmara", "running", "grok", "quiet 12m")).toBeDefined();
	expect(line("Rig")).toBeDefined();
	expect(line("rig", "kube.workload.stop", "pod heat-sim", "waiting 5m")).toBeDefined();
	expect(line("glm overview", "running", "compacted")).toBeDefined();
	expect(line("colin-d0", "pc:~/wt/glm-overview", "glm/overview", "compacted")).toBeDefined();
	expect(line("colin-d1", "pc:/home/ownerx/other")).toBeDefined();
	expect(line("odin-owner/odin", "main", "success", "3h")).toBeDefined();
	expect(line("odin-owner/dotfiles", "HTTP 404")).toBeDefined();
	// The computers come first on the page, then the approvals the owner is asked to decide.
	expect(screen.indexOf("Computers")).toBeLessThan(screen.indexOf("Approvals"));
	expect(line("pc", "unreachable")).toBeDefined();
});

test("a busy local Claude session reads as working, an idle one as idle", () => {
	const { app, plain, key } = view();
	app.onMessage(seats(null));
	const local = (name: string, status: string) => ({ id: name, name, status, cwd: "/tmp", branch: null, compacted: false });
	app.onMessage({ t: "claudeLocal", device: "pc", rows: [local("colin-fc", "busy"), local("colin-57", "idle")] });
	key("\t"); // → Models
	key("\t"); // → the overview
	const line = (name: string) => plain().split("\n").find(row => row.includes(name)) ?? "";
	expect(line("colin-fc")).toContain(`${theme.status.running} colin-fc busy`);
	expect(line("colin-57")).toContain(`${theme.status.enabled} colin-57 idle`);
});

test("a prompting turn is turn-in-progress, and its silence still counts", () => {
	const { app, key } = view();
	const minutes = (n: number) => new Date(Date.now() - n * 60_000).toISOString();
	app.onMessage({
		t: "seats",
		seats: [
			{
				id: "sinmara",
				name: "Sinmara",
				state: "online",
				models: [],
				sessions: [
					{ id: "s1", state: "prompting", model: "gateway/grok", updatedAt: minutes(12), quietSeconds: 600, pendingPermissionCount: 0 },
				],
			},
		],
		claude: [{ id: "claude:1", state: "prompting", model: "claude", title: "glm work", updatedAt: minutes(12), quietSeconds: 600 }],
		conversation: null,
	});
	key("\t"); // Sinmara's session → the Claude session
	key("\t"); // → Models
	key("\t"); // → the overview, last in the cycle
	const lines = app.render(100).join("\n").split("\n");
	const seat = lines.find(l => l.includes("Sinmara"))!;
	expect(seat).toContain(theme.status.running);
	expect(seat).toContain("quiet 12m");
	const claude = lines.find(l => l.includes("glm work"))!;
	expect(claude).toContain(theme.status.running);
	expect(claude).toContain("quiet 12m");
});

test("a cancelled run is not a failure, a workflow that failed to start is, and no runs is not a broken line", () => {
	const { app, key } = view();
	app.onMessage(seats(null, "s1"));
	const minutes = (n: number) => new Date(Date.now() - n * 60_000).toISOString();
	app.onMessage({
		t: "ci",
		rows: [
			{ repo: "a/fail", status: "completed", conclusion: "failure", branch: null, updatedAt: minutes(3) },
			{ repo: "b/cancelled", status: "completed", conclusion: "cancelled", branch: null, updatedAt: minutes(3) },
			{ repo: "c/empty", status: "no runs", conclusion: null, branch: null, updatedAt: null },
			{ repo: "d/workflow", status: "completed", conclusion: "startup_failure", branch: null, updatedAt: minutes(3) },
		],
	});
	key("\t"); // → Models
	key("\t"); // → the overview, last in the cycle
	const lines = app.render(100).join("\n").split("\n");
	expect(lines.find(l => l.includes("a/fail"))).toContain(theme.status.error);
	const cancelled = lines.find(l => l.includes("b/cancelled"))!;
	expect(cancelled).toContain(theme.status.disabled);
	expect(cancelled).not.toContain(theme.status.error);
	const empty = lines.find(l => l.includes("c/empty"))!;
	expect(empty).toContain("no runs");
	expect(empty).not.toContain(theme.status.disabled);
	expect(lines.find(l => l.includes("d/workflow"))).toContain(theme.status.error);
});

test("a Claude tab asks for its transcript and folds the page", () => {
	const { app, sent, plain } = view();
	const id = "claude:9a4a5c6e-1f2e-4c31-9d2a-3b2c1a0b9c8d";
	app.onMessage({
		t: "seats",
		seats: [],
		claude: [{ id, state: "open", model: "claude", title: "glm work" }],
		conversation: null,
	});
	expect(sent.at(-1)).toEqual({ t: "claude", session: id, since: 0, request: `1:${id}:0` });
	expect(plain()).toContain("reading this Claude session");
	app.onMessage({
		t: "claudeTranscript",
		request: `1:${id}:0`,
		session: id,
		events: [{ cursor: 1, kind: "backend", payload: { type: "user", message: { content: "fix the driver" } } }],
		nextCursor: 1,
		hasMore: true,
	});
	expect(plain()).toContain("fix the driver");
	expect(sent.at(-1)).toEqual({ t: "claude", session: id, since: 1, request: `1:${id}:1` });
	app.onMessage({
		t: "claudeTranscript",
		request: `1:${id}:1`,
		session: id,
		events: [{ cursor: 1, kind: "backend", payload: { type: "user", message: { content: "fix the driver" } } }],
		nextCursor: 1,
		hasMore: false,
	});
	expect(plain().match(/fix the driver/g)).toHaveLength(1);
});

test("returning to a Claude tab replays it and ignores responses from the previous selection", () => {
	const { app, sent, plain, key } = view();
	const id = "claude:00000000-0000-0000-0000-000000000042";
	app.onMessage({ t: "seats", seats: [], claude: [{ id, state: "open", model: "claude" }], conversation: null });
	const first = sent.at(-1);
	if (first?.t !== "claude") throw new Error("no transcript request");
	key("\t"); // Models
	key("\t"); // Overview
	key("\t"); // Capabilities, the last tab
	key("\t"); // Claude, rebuilt from its first page
	const current = sent.at(-1);
	if (current?.t !== "claude") throw new Error("no new transcript request");
	expect(current.since).toBe(0);
	expect(current.request).not.toBe(first.request);
	const page = {
		t: "claudeTranscript" as const, session: id,
		events: [{ cursor: 1, kind: "backend", payload: { type: "user", message: { content: "replayed line" } } }],
		nextCursor: 1, hasMore: false,
	};
	app.onMessage({ ...page, request: first.request });
	expect(plain()).not.toContain("replayed line");
	app.onMessage({ ...page, request: current.request });
	expect(plain()).toContain("replayed line");
});

test("the status bar names the day the spend figure covers", () => {
	const { app, plain } = view();
	app.onMessage(seats(null, "s1"));
	app.onMessage({
		t: "spend",
		day: "2026-10-21",
		usdCents: 183,
		includedCents: 0,
		tokens: 1,
		seats: { sinmara: { usdCents: 183, includedCents: 1210, tokens: 1 } },
	});
	expect(plain()).toContain("$1.83 +$12.10 incl. on 10-21");
});

test("tabbing between two tabs with no transcript shows each tab's own line", () => {
	const { app, key, plain } = view();
	app.onMessage({
		t: "seats",
		seats: [sinmara()],
		claude: [{ id: "claude:1", state: "running", model: "claude", title: "glm work" }],
		conversation: null,
	});
	expect(plain()).toContain("no live session for this seat");
	key("\t"); // Sinmara with no session → the Claude session
	expect(plain()).toContain("reading this Claude session");
	expect(plain()).not.toContain("no live session for this seat");
});

test("a prompting turn's quiet badge keeps counting while it runs, and the counting stops when it ends", () => {
	jest.useFakeTimers();
	try {
		const { state, tui } = fakeTui();
		const app = new App(tui, () => true, () => {});
		const seat = (state: string): BridgeMessage => ({
			t: "seats",
			seats: [
				{
					id: "sinmara",
					name: "Sinmara",
					state: "online",
					models: [],
					sessions: [{ id: "s1", state, model: "gateway/grok", updatedAt: new Date(Date.now() - 12 * 60_000).toISOString(), quietSeconds: 600, pendingPermissionCount: 0 }],
				},
			],
			conversation: null,
		});
		app.onMessage(seat("prompting"));
		const before = state.renders;
		jest.advanceTimersByTime(3000);
		expect(state.renders).toBeGreaterThan(before);
		app.onMessage(seat("idle"));
		const idle = state.renders;
		jest.advanceTimersByTime(5000);
		expect(state.renders).toBe(idle);
	} finally {
		jest.useRealTimers();
	}
});

test("ctrl+r shows the whole turn behind the owner's words and behind a routine line", () => {
	const { app, plain, key } = view();
	app.onMessage(seats("s1", "s1"));
	const context = "[the owner's local time: Wednesday 2026-10-21 09:09 PDT (America/Los_Angeles)] [You are running on gateway/grok]";
	app.onMessage(said("s1", 1, `${context}\nWhat's on my calendar today?`));
	app.onMessage(said("s1", 2, `${context}\n[Routine odinschool-watch from the harness. The owner scheduled it for now: "check". The governed tools carry it out.]`));
	expect(plain()).toContain("What's on my calendar today?");
	expect(plain()).toContain("Routine odinschool-watch");
	expect(plain()).not.toContain("You are running on");
	expect(plain()).not.toContain("governed tools");
	key("\x12"); // ctrl+r
	expect(plain()).toContain("[the owner's local time: Wednesday 2026-10-21 09:09 PDT");
	expect(plain().replace(/\s+/g, " ")).toContain("The governed tools carry it out");
});

test("a Claude tab open between Odin's prompts reads as open, with no quiet badge", () => {
	const { app, plain, key } = view();
	const tab = {
		id: "claude:a4d49346-467b-4045-a6ee-ab39d071e5d0",
		state: "open",
		model: "claude",
		title: "odinschool-driver",
		updatedAt: new Date(Date.now() - 52 * 3600_000).toISOString(),
		quietSeconds: 600,
		pendingPermissionCount: 0,
	};
	app.onMessage({ t: "seats", seats: [sinmara("s1")], claude: [tab], conversation: "s1" });
	expect(plain()).not.toContain("quiet");
	key("\t");
	key("\t"); // → Models
	key("\t"); // → the overview
	expect(plain()).toContain(`${theme.status.enabled} odinschool-driver open`);
});

test("the overview aligns live seats and groups offline seats", () => {
	const { app, plain, key } = view();
	const seat = (id: string, name: string, state: string, sessions: SeatInfo["sessions"] = []): SeatInfo => ({ id, name, state, models: [], sessions });
	app.onMessage({
		t: "seats",
		seats: [
			seat("sinmara", "Sinmara", "online", [{ id: "s1", state: "idle", model: "gateway/grok" }]),
			seat("kubert", "Kubert", "online", [{ id: "k1", state: "running", model: "gateway/astra" }]),
			seat("architect", "Architect", "offline"),
			seat("scribe", "Scribe", "offline"),
		],
		conversation: "s1",
	});
	key("\t");
	key("\t"); // → Models
	key("\t"); // → the overview
	const lines = plain().split("\n");
	const seats = lines.slice(lines.findIndex(line => line.includes("Seats")));
	const sinmara = seats.find(line => line.includes("Sinmara"))!;
	const kubert = seats.find(line => line.includes("Kubert"))!;
	expect(sinmara.indexOf("idle")).toBe(kubert.indexOf("running"));
	expect(sinmara.indexOf("grok")).toBe(kubert.indexOf("astra"));
	expect(plain()).toContain("Architect · Scribe offline");
});

test("the overview names each seat's spend today and the whole day's in its status bar", () => {
	const { app, plain, key } = view();
	app.onMessage(seats("s1", "s1"));
	app.onMessage({
		t: "spend",
		day: "2026-10-21",
		usdCents: 5841,
		includedCents: 0,
		tokens: 1,
		seats: {
			sinmara: { usdCents: 3180, includedCents: 0, tokens: 1 },
			"colin (own sessions)": { usdCents: 2100, includedCents: 0, tokens: 1 },
		},
	});
	expect(plain()).toContain("$31.80 on 10-21"); // Sinmara's tab: her own
	key("\t"); // → Models
	key("\t"); // → the overview
	const lines = plain().split("\n");
	expect(lines.find(line => line.includes("Sinmara") && line.includes("idle"))).toContain("$31.80");
	expect(lines.at(-1)).toContain("$58.41 on 10-21");
});

test("/model shows a long model name whole", () => {
	const { app, sent, plain } = view();
	app.onMessage({ t: "seats", seats: [{ ...sinmara("a"), models: ["gateway/astra"] }], conversation: "a" });
	app.editor.onSubmit?.("/model");
	const catalog = sent.at(-1);
	if (catalog?.t !== "catalog") throw new Error("no catalog request");
	app.onMessage({
		t: "catalog",
		id: catalog.id,
		seat: "sinmara",
		rows: [
			{
				selector: "gateway/astra",
				name: "GPT-6 Astra · ChatGPT Pro (Codex)",
				strengths: "reads images",
				tier: "frontier",
				seatAllowed: true,
				reason: "",
				contextWindow: 272000,
				inputPerMillion: "0",
				outputPerMillion: "0",
				billing: "subscription",
			},
		],
	});
	expect(plain()).toContain("GPT-6 Astra · ChatGPT Pro (Codex)");
});

test("the overview lists Odin's pods: a running one with its age, an ended one with its run time", () => {
	const { app, plain, key } = view();
	const minutes = (n: number) => new Date(Date.now() - n * 60_000).toISOString();
	app.onMessage(seats("s1", "s1"));
	app.onMessage({
		t: "pods",
		rows: [
			{ name: "heat-sim", state: "running", seat: "kubert", node: null, startedAt: minutes(4), finishedAt: null, status: null },
			{ name: "floyds-times", state: "succeeded", seat: "kubert", node: null, startedAt: minutes(422), finishedAt: minutes(421), status: null },
		],
	});
	key("\t"); // → Models
	key("\t"); // → the overview
	const screen = plain();
	expect(screen).toContain("Pods");
	expect(screen).toMatch(/heat-sim\s+running\s+kubert\s+for 4m/);
	expect(screen).toMatch(/floyds-times\s+succeeded\s+kubert\s+ran 1m · 7h ago/);
});

test("a running script pod shows its label, progress and summary; a pending one names its node", () => {
	const { app, plain, key } = view();
	const seconds = (n: number) => new Date(Date.now() - n * 1000).toISOString();
	app.onMessage(seats("s1", "s1"));
	app.onMessage({
		t: "pods",
		rows: [
			{
				name: "sweep-64",
				state: "running",
				seat: "kubert",
				node: "pc",
				startedAt: seconds(300),
				finishedAt: null,
				status: { at: seconds(12), progress: 0.42, summary: "grid 64^2 cycle 1200 residual 3.1e-04" },
			},
			{ name: "sweep-128", state: "pending", seat: "kubert", node: "mini", startedAt: null, finishedAt: null, status: null },
		],
	});
	key("\t"); // → Models
	key("\t"); // → the overview
	const screen = plain();
	expect(screen).toMatch(/sweep-64\s+running\s+kubert\s+pc\s+for 5m/);
	expect(screen).toContain("42%");
	expect(screen).toContain("grid 64^2 cycle 1200 residual 3.1e-04");
	expect(screen).toContain("12s ago");
	expect(screen).toMatch(/sweep-128\s+pending\s+kubert\s+mini/);
	expect(screen).toContain("waiting for mini");
});

test("a deploy restarts the view, but never over a draft, a message still sending, or a model change still committing", () => {
	const { app, sent, quits, key } = view();
	app.onMessage(seats("a", "a"));
	app.onMessage({ t: "reset", session: "a" });
	app.editor.setText("half a thought");
	app.onMessage({ t: "updated", exit: 75 });
	expect(quits).toEqual([]);
	app.editor.setText("");
	app.editor.onSubmit?.("are you there?");
	const say = sent.find(command => command.t === "say");
	app.onMessage({ t: "updated", exit: 75 });
	expect(quits).toEqual([]);
	app.onMessage(said("a", 1, `[the owner via odin view] ${say?.t === "say" ? say.text : ""}`));
	app.editor.onSubmit?.("/model");
	const catalog = sent.find(command => command.t === "catalog");
	if (catalog?.t !== "catalog") throw new Error("catalog was not requested");
	app.onMessage({
		t: "catalog",
		id: catalog.id,
		seat: "sinmara",
		rows: [
			{ selector: "gateway/grok", name: "grok", strengths: "", tier: "", seatAllowed: true, reason: "", contextWindow: 1, inputPerMillion: "0", outputPerMillion: "0", billing: "" },
			{ selector: "gateway/other", name: "other", strengths: "", tier: "", seatAllowed: true, reason: "", contextWindow: 1, inputPerMillion: "0", outputPerMillion: "0", billing: "" },
		],
	});
	app.onMessage({ t: "updated", exit: 75 });
	expect(quits).toEqual([]);
	key("\x1b");
	app.onMessage({
		t: "seats",
		seats: [{ ...sinmara("a"), models: ["gateway/grok", "gateway/other"] }],
		conversation: "a",
	});
	app.editor.onSubmit?.("/model");
	const again = sent.filter(command => command.t === "catalog").at(-1);
	if (again?.t !== "catalog") throw new Error("catalog was not requested again");
	app.onMessage({
		t: "catalog",
		id: again.id,
		seat: "sinmara",
		rows: [
			{ selector: "gateway/grok", name: "grok", strengths: "", tier: "", seatAllowed: true, reason: "", contextWindow: 1, inputPerMillion: "0", outputPerMillion: "0", billing: "" },
			{ selector: "gateway/other", name: "other", strengths: "", tier: "", seatAllowed: true, reason: "", contextWindow: 1, inputPerMillion: "0", outputPerMillion: "0", billing: "" },
		],
	});
	key("\x1b[B");
	key("\r");
	const model = sent.find(command => command.t === "model");
	expect(model).toMatchObject({ t: "model", model: "gateway/other" });
	app.onMessage({ t: "updated", exit: 75 });
	expect(quits).toEqual([]);
	app.onMessage({ t: "done", id: model?.t === "model" ? model.id : "", ok: true, text: "switched" });
	app.onMessage({ t: "updated", exit: 75 });
	expect(quits).toEqual([75]);
});

test("a quiet reply shows no bubble, and a reply after the token keeps its words", () => {
	const { app, plain } = view();
	const quiet = "<silent>";
	const token = (seq: number, text: string): BridgeMessage => ({
		t: "event",
		session: "a",
		seq,
		kind: "assistant",
		text,
		quiet,
	});

	app.onMessage(seats("a", "a"));
	app.onMessage({ t: "reset", session: "a" });
	app.onMessage(said("a", 1, "what's on tomorrow?"));
	app.onMessage(token(2, "CS 121A at 1."));
	const beforeQuiet = plain();
	app.onMessage({ t: "event", session: "a", seq: 3, kind: "delta", text: quiet.slice(0, 4), quiet });
	expect(plain()).toBe(beforeQuiet);
	app.onMessage({ t: "event", session: "a", seq: 4, kind: "delta", text: quiet.slice(4), quiet });
	expect(plain()).toBe(beforeQuiet);
	app.onMessage(token(5, quiet));
	expect(plain()).toBe(beforeQuiet);
	app.onMessage(token(6, `${quiet} — Nothing new in that one.`));
	const screen = plain();
	expect(screen).toContain("CS 121A at 1.");
	expect(screen).not.toContain(quiet);
	expect(screen).toContain("Nothing new in that one.");
});

test("the models page shows the one model book, and a draft survives a new view", () => {
	const first = view();
	first.app.onMessage(seats("a", "a"));
	first.key("\t");
	expect(first.sent.at(-1)).toEqual({ t: "models" });
	first.app.onMessage({
		t: "models",
		board: {
			accounts: [],
			classes: [{ class: "fast", order: [{ lane: "goat-flash" }], serving: "goat-flash" }],
			note: "one book",
		},
	});
	expect(first.plain()).toContain("now goat-flash");
	first.app.editor.setText("unsent line");
	const second = view();
	expect(second.app.editor.getText()).toBe("unsent line");
});

test("a model book error settles the tab with its cause and F5 retries", () => {
	const { app, sent, plain, key } = view();
	app.onMessage(seats("a", "a"));
	key("\t");
	app.onMessage({ t: "models", note: "Huginn is unreachable" });
	const failed = plain();
	expect(failed).toContain("Model book unavailable: Huginn is unreachable · F5 to retry");
	expect(failed).not.toContain("reading the model book");
	const asked = sent.length;
	key("\x1b[15~"); // F5
	expect(sent.length).toBe(asked + 1);
	expect(sent.at(-1)).toEqual({ t: "models" });
});

test("a failed compute snapshot says why instead of a dim none, and a later snapshot replaces it", () => {
	const { app, key, plain } = view();
	app.onMessage(seats(null, "s1"));
	key("\t"); // → Models
	key("\t"); // → the overview, which asks for compute samples
	app.onMessage({ t: "compute", error: "computeUnavailable: no enabled enrolled host declares this node's placement" });
	const failed = plain();
	expect(failed).toContain("Computers");
	expect(failed).toContain("computeUnavailable: no enabled enrolled host declares this node's placement");
	app.onMessage({
		t: "compute",
		snapshot: {
			hosts: [
				{
					node: "pc",
					host: "pc",
					sample: {
						node: "pc",
						sampledAt: new Date().toISOString(),
						cpuPercent: 12,
						memoryUsedBytes: 8 * 1024 ** 3,
						memoryTotalBytes: 32 * 1024 ** 3,
						storageUsedBytes: 400 * 1024 ** 3,
						storageTotalBytes: 1000 * 1024 ** 3,
						temperatureCelsius: 46,
						gpus: [],
						models: [],
						modelsNote: null,
						pods: [],
					},
				},
			],
		},
	});
	const recovered = plain();
	expect(recovered).toContain("cpu 12%");
	expect(recovered).not.toContain("computeUnavailable");
});

test("the Capabilities tab is last, renders red/gray/green rows with their detail, F5 sends one refresh and keeps the draft", () => {
	const { app, sent, plain, key } = view();
	app.onMessage(seats("a", "a"));
	app.editor.setText("unsent draft");
	key("\t"); // → Models
	key("\t"); // → Overview
	key("\t"); // → Capabilities, the last tab
	const bar = plain().split("\n")[0] ?? "";
	expect(bar.indexOf("Overview")).toBeLessThan(bar.indexOf("Capabilities"));
	expect(bar.trimEnd().endsWith("Capabilities")).toBe(true);
	expect(plain()).toContain("reading the capabilities…");
	const at = new Date().toISOString();
	const minutes = (n: number) => new Date(Date.now() - n * 60_000).toISOString();
	app.onMessage({
		t: "features",
		value: {
			evaluatedAt: at,
			tested: { sha: "abcdef1234567", at: minutes(180), inherited: false },
			live: { registryRevision: 12, commit: "1234567890abcdef" },
			counts: { capabilities: 3, tested: 1 },
			rows: [
				{ id: "brain.read", title: "brain.read", area: "brain", service: false, status: "green", label: "Tested at abcdef1", checks: [{ check: "odin-omp host_tools::operations::dispatch_brain::governed_brain_search", state: "pass", detail: "passed at abcdef1" }] },
				{ id: "brain.search", title: "brain.search", area: "brain", service: false, status: "gray", label: "Untested", checks: [] },
				{ id: "task.read", title: "task.read", area: "delegate", service: false, status: "red", label: "Broken: odin-omp host_tools::delegation::tests::a_gone: named test absent at abcdef1", checks: [{ check: "odin-omp host_tools::delegation::tests::a_gone", state: "fail", detail: "named test absent at abcdef1" }] },
				{ id: "authority", title: "Odin authority daemon", area: "services", service: true, status: "green", label: "Up", checks: [{ check: "unit:mini user odind.service", state: "pass", detail: "active" }] },
			],
		},
	});
	const screen = plain();
	expect(screen).toContain("Capabilities · 1 of 3 tested · tested abcdef1 3h · live r12 1234567 · evaluated ");
	const line = (title: string) => screen.split("\n").find(row => row.includes(title)) ?? "";
	expect(line("brain.read")).toContain("● brain.read Tested at abcdef1");
	expect(line("brain.search")).toContain("○ brain.search Untested");
	expect(line("task.read")).toContain("✕ task.read Broken: ");
	expect(line("Odin authority daemon")).toContain("● Odin authority daemon Up");
	// A row that is not green shows its check's detail on a line of its own; a green row shows none.
	expect(screen.split("\n").some(row => row.trim() === "odin-omp host_tools::delegation::tests::a_gone: named test absent at abcdef1")).toBe(true);
	expect(screen).not.toContain("unit:mini user odind.service: active");
	// F5 sends one refresh, shows it, and the draft stays in the composer.
	const asked = sent.length;
	key("\x1b[15~");
	expect(sent.length).toBe(asked + 1);
	expect(sent.at(-1)).toEqual({ t: "features" });
	expect(plain()).toContain("refreshing…");
	expect(plain()).toContain("F5 refresh");
	expect(app.editor.getText()).toBe("unsent draft");
	app.onMessage({ t: "features", value: { evaluatedAt: at, tested: null, live: { registryRevision: 13, commit: null }, counts: { capabilities: 0, tested: 0 }, rows: [] } });
	expect(plain()).not.toContain("refreshing…");
	expect(plain()).toContain("not tested");
	expect(plain()).toContain("no capabilities declared");
	expect(app.editor.getText()).toBe("unsent draft");
});

test("F2 shows the latest injected context for the seat tab, and a message may start with the letter i", () => {
	const { app, sent, plain, key } = view();
	app.onMessage(seats("s1", "s1"));
	expect(key("i")).toBeUndefined(); // the composer keeps every printable key
	expect(sent.some(command => command.t === "context")).toBe(false);
	key("\x1bOQ"); // F2
	expect(sent.at(-1)).toEqual({ t: "context", session: "s1" });
	expect(plain()).toContain("reading the trace");
	app.onMessage({
		t: "context",
		session: "s1",
		record: {
			at: "2026-10-30T10:00:00Z",
			turn: null,
			kind: "rollover",
			blocks: [{ label: "rollover brief", tokens: 812, sources: ["artifact-1"], text: "the brief line" }],
		},
	});
	expect(plain()).toContain("rollover brief (≈812 tokens)");
	expect(plain()).not.toContain("the brief line");
	key("\r");
	expect(plain()).toContain("the brief line");
	key("\x1bOQ");
	expect(plain()).not.toContain("injected context");
});

test("a slash line other than /model reaches Sinmara, and a line the bridge cannot take comes back to the composer", () => {
	const { app, sent, plain, bridge } = view();
	app.onMessage(seats("a", "a"));
	app.editor.onSubmit?.("/clear");
	expect(sent.at(-1)).toMatchObject({ t: "say", text: "/clear" });
	expect(plain()).toContain("sending to Sinmara");
	bridge.up = false;
	app.editor.onSubmit?.("are you there?");
	expect(app.editor.getText()).toBe("are you there?");
	expect(plain()).toContain("not sent: the bridge is not running");
});

test("ctrl+c clears a draft; on an empty composer it quits only when pressed twice, and ctrl+d quits only an empty one", () => {
	const draft = view();
	draft.app.onMessage(seats("a", "a"));
	draft.app.editor.setText("a draft");
	draft.key("\x03");
	expect(draft.app.editor.getText()).toBe("");
	expect(draft.quits).toEqual([]);
	draft.app.editor.setText("keep me");
	draft.key("\x04");
	expect(draft.quits).toEqual([]);
	draft.app.editor.setText(""); // a new view recalls the saved draft

	const { app, plain, quits, key } = view();
	app.onMessage(seats("a", "a"));
	key("\x03");
	expect(plain()).toContain("ctrl+c again to quit");
	expect(quits).toEqual([]);
	key("\x03");
	expect(quits).toEqual([undefined]);
	key("\x04");
	expect(quits).toEqual([undefined, undefined]);
});

test("a page taller than the terminal opens at its top, scrolls from there and keeps its place when the roster changes", () => {
	const { app, plain, key } = view();
	app.onMessage(seats("a", "a"));
	const ci = Array.from({ length: 40 }, (_, n) => ({ repo: `org/repo-${String(n).padStart(2, "0")}`, status: "completed", conclusion: "success", branch: null, updatedAt: null }));
	app.onMessage({ t: "ci", rows: ci });
	key("\t"); // → Models
	key("\t"); // → the overview
	expect(plain()).toContain("Approvals");
	expect(plain()).not.toContain("repo-39");
	key("\x1b[6~"); // page down
	key("\x1b[6~");
	key("\x1b[6~");
	expect(plain()).toContain("repo-39");
	expect(plain()).not.toContain("Approvals");
	app.onMessage(seats("a", "a")); // a roster change while reading
	expect(plain()).toContain("repo-39");
	key("\x1b[H"); // home
	expect(plain()).toContain("Approvals");
	expect(plain()).toContain("lines below");
});

test("a dead bridge says why in the status bar, and its replacement is told what to watch again", () => {
	const { app, sent, plain } = view();
	app.onMessage(seats("a", "a"));
	app.bridgeDied("bridge exited (1): no pairing");
	expect(plain()).toContain("bridge exited (1): no pairing");
	sent.length = 0;
	app.onMessage({ t: "link", ok: true });
	app.onMessage(seats("a", "a"));
	expect(sent).toContainEqual({ t: "watch", session: "a" });
});

test("the models page keeps missing usage unknown and says an estimated limit is not a cap", () => {
	const { app, plain, key } = view();
	app.onMessage(seats("a", "a"));
	key("\t");
	app.onMessage({
		t: "models",
		board: {
			accounts: [
				{
					account: "codex",
					provider: "openai",
					billing: "subscription",
					lanes: ["astra"],
					windows: [
						{ span: "day", usd_limit: 20, usd_used: null },
						{ span: "month", requests_limit: 205000, requests_used: 40, requests_estimate: true },
						{ span: "week", requests_limit: 100, requests_used: 7 },
					],
				},
			],
			classes: [],
			note: "",
		},
	});
	const screen = plain();
	expect(screen).toContain("per day unknown of $20");
	expect(screen).not.toContain("$0.00");
	expect(screen).toContain("per month 40 requests; estimated throughput 205000 (not a cap)");
	expect(screen).toContain("per week 7 of 100 requests");
});
