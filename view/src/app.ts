// The view: seat bar, the watched session's transcript, the working loader, the composer to Sinmara and a status bar,
// laid out to fill the terminal exactly.
import { formatNumber } from "@oh-my-pi/pi-utils";
import { Editor } from "../omp/components/editor";
import { Loader } from "../omp/components/loader";
import { SelectList } from "../omp/components/select-list";
import { matchesKey } from "../omp/keys";
import { parseSgrMouse } from "../omp/mouse";
import { shimmerText } from "../omp/theme/shimmer";
import { getEditorTheme, getSelectListTheme, theme } from "../omp/theme/theme";
import type { Component, TUI } from "../omp/tui";
import { truncateToWidth, visibleWidth, wrapLiteralLine } from "../omp/utils";
import type { ApprovalRow, BridgeMessage, CatalogRow, CiRow, ComputeSample, FeaturesValue, IncidentRow, InjectionRecord, LocalClaude, ModelBoard, PodRow, SeatInfo, SessionInfo, ViewCommand } from "./protocol";
import { quietBadge, shortModel, spentLabel, spoken } from "./protocol";
import { boardRows } from "./board";
import { featureRows } from "./features";
import { computeRows, hostRow } from "./compute";
import { foldClaudePage } from "./claude";
import { overviewRows } from "./overview";
import { contextLabel, pendingBubble, renderBlock, runningJobRow, stateStyle } from "./render";
import { Transcript } from "./transcript";
import * as fs from "node:fs";
import * as path from "node:path";
import { getStateDir } from "@oh-my-pi/pi-utils/dirs";

const SINMARA = "sinmara";
const OVERVIEW = "overview";
const NOTICE_MS = 10_000;
/** A repaint a moment after a notice expires, so it clears without waiting for the next event. */
const REPAINT_SLACK_MS = 50;
const QUIT_WINDOW_MS = 1000;
/** Ages and running jobs count up once a second. */
const TICK_MS = 1000;
/** A spend figure the bridge has not refreshed for this long goes dim. */
const SPEND_FRESH_MS = 3 * 60_000;
const WHEEL_LINES = 3;
const MODELS = "models";
const CAPABILITIES = "capabilities";
/** The bridge names a Claude Code tab's session with this prefix (`claude_line` in odin-cli's view.rs). */
const isClaude = (session: string | undefined): session is string => session?.startsWith("claude:") === true;
/** The composer's unsent line, beside the view log, read when saved so a relocated state dir is the one restored. */
function draftFile(): string {
	return path.join(getStateDir(), "view-draft.txt");
}

interface Entry {
	seat: SeatInfo;
	session: SessionInfo | undefined;
	label: string;
}

interface Pending {
	id: string;
	text: string;
}

/** Every seat with a live session (one entry per session), Sinmara always and first, her conversation's session first. */
function seatEntries(seats: readonly SeatInfo[], conversation?: string, claude: readonly SessionInfo[] = []): Entry[] {
	const ordered = [...seats].sort((a, b) =>
		a.id === SINMARA ? -1 : b.id === SINMARA ? 1 : a.name.localeCompare(b.name),
	);
	const entries: Entry[] = [];
	for (const seat of ordered) {
		if (seat.sessions.length === 0) {
			if (seat.id === SINMARA) entries.push({ seat, session: undefined, label: seat.name });
			continue;
		}
		const carries = (session: SessionInfo) => Number(seat.id === SINMARA && session.id === conversation);
		const sessions = [...seat.sessions].sort((a, b) => carries(b) - carries(a));
		sessions.forEach((session, i) => {
			const label = seat.sessions.length > 1 ? `${seat.name}·${i + 1}` : seat.name;
			entries.push({ seat, session, label });
		});
	}
	for (const session of claude) {
		entries.push({
			seat: { id: "claude", name: "Claude", state: session.state, models: [], sessions: [session] },
			session,
			label: session.title || "Claude",
		});
	}
	// The model book, the overview, then the capabilities, last in the tab cycle.
	entries.push({
		seat: { id: MODELS, name: "Models", state: "online", models: [], sessions: [] },
		session: undefined,
		label: "Models",
	});
	entries.push({
		seat: { id: OVERVIEW, name: "Overview", state: "online", models: [], sessions: [] },
		session: undefined,
		label: "Overview",
	});
	entries.push({
		seat: { id: CAPABILITIES, name: "Capabilities", state: "online", models: [], sessions: [] },
		session: undefined,
		label: "Capabilities",
	});
	return entries;
}
function rememberDraft(text: string): void {
	try {
		const file = draftFile();
		fs.mkdirSync(path.dirname(file), { recursive: true });
		if (text.length === 0) fs.rmSync(file, { force: true });
		else {
			const temporary = `${file}.${process.pid}.tmp`;
			fs.writeFileSync(temporary, text, { mode: 0o600 });
			fs.renameSync(temporary, file);
		}
	} catch {
		// A draft that cannot be written still sits in the composer until this process exits.
	}
}

function recalledDraft(): string {
	try {
		return fs.readFileSync(draftFile(), "utf8");
	} catch {
		return "";
	}
}

/** Strengths, window and cost beside a selectable model, plus "current". */
function modelDetail(row: CatalogRow | undefined, current: boolean): string | undefined {
	const parts: string[] = [];
	if (current) parts.push("current");
	if (row?.tier) parts.push(row.tier);
	if (row?.strengths) parts.push(row.strengths);
	if (row && row.contextWindow > 0) parts.push(formatNumber(row.contextWindow));
	if (row && (row.inputPerMillion !== "0" || row.outputPerMillion !== "0")) {
		parts.push(`$${row.inputPerMillion}/$${row.outputPerMillion} per M`);
	}
	return parts.length > 0 ? parts.join(" · ") : undefined;
}

export class App implements Component {
	#seats: SeatInfo[] = [];
	#entries: Entry[] = [];
	#claude: SessionInfo[] = [];
	#selected: { seat: string; session: string | undefined } = { seat: SINMARA, session: undefined };
	#transcript: Transcript | undefined;
	#pending: Pending[] = [];
	#link: { ok: boolean; text: string } | undefined;
	#bridgeDown: string | undefined;
	#spend: Extract<BridgeMessage, { t: "spend" }> | undefined;
	/** When the spend line arrived; a figure the bridge stopped refreshing goes dim. */
	#spendAt = 0;
	#models: { rows?: string[]; error?: string } | undefined;
	/** The Capabilities tab's last evaluation, and the note on the last refresh that failed. */
	#features: { value?: FeaturesValue; note?: string } | undefined;
	/** An F5 refresh is out: the tab says so until the bridge answers. */
	#featuresWaiting = false;
	#notice: { text: string; until: number } | undefined;
	#scroll = 0;
	/** Transcript rows at the last render, so a scrolled view can hold its place. */
	#shownRows = 0;
	#expanded = false;
	/** The injected-context panel (F2) on a seat tab: open, the record the bridge sent for its session, and whether block texts show. */
	#contextOpen = false;
	#context: { session: string; record?: InjectionRecord; note?: string } | undefined;
	#contextExpanded = false;
	/** The session carrying Sinmara's conversation (the bridge's `conversation`), and the ones it rolled over from. */
	#conversation: string | undefined;
	readonly #former = new Set<string>();
	#lastCtrlC = 0;
	#picker: SelectList | undefined;
	/** The seat whose picker is open, so the header names it. */
	#pickerSeat: string | undefined;
	/** The catalog request the open picker is waiting on. */
	#catalogWait: { id: string; seat: string } | undefined;
	/** A model change is committing: its `done` arrives after the registry publish. */
	#modelWait: string | undefined;
	#rowsMemo: { key: string; rows: string[] } | undefined;
	/** A restarted bridge watches nothing until told again. */
	#rewatch = false;
	/** Re-renders each second while background jobs run, so their ages count up. */
	#jobTicker: ReturnType<typeof setInterval> | undefined;
	/** Re-renders while a running seat turn can cross quietSeconds with no new event. */
	#quietTicker: ReturnType<typeof setInterval> | undefined;
	/** The overview's own data: waiting approvals, open incidents, Odin's pods, this device's Claude sessions, CI lines. */
	#approvals: ApprovalRow[] = [];
	#incidents: IncidentRow[] = [];
	#pods: PodRow[] = [];
	#localClaude: LocalClaude | undefined;
	#ci: { rows: CiRow[]; note?: string } | undefined;
	#board: ModelBoard | null | undefined;
	#boardNote: string | null | undefined;
	/** The newest compute sample per node, held while the overview page is open. */
	readonly #compute = new Map<string, ComputeSample>();
	/** The compute sampling state the bridge was last told; undefined after a bridge restart. */
	#computeActive: boolean | undefined = false;
	/** Why the whole compute snapshot failed, when the authority could not answer. */
	#computeError: string | undefined;
	/** Claude pages already folded, keyed by session, so a cursor is never applied twice. */
	readonly #claudeSeen: Record<string, number> = {};
	/** The page already asked for, so a seat poll does not read the host twice. */
	#claudeFlight: string | undefined;
	#claudeEpoch = 0;
	#claudeNote: string | undefined;

	readonly editor: Editor;
	readonly #loader: Loader;

	constructor(
		readonly tui: TUI,
		readonly send: (command: ViewCommand) => boolean,
		/** Exits the view with `code`. The bridge's `updated` status asks `odin view` to replace itself with the installed one. */
		readonly quit: (code?: number) => void,
	) {
		this.editor = new Editor(getEditorTheme());
		this.editor.setBorderStyle("claude");
		this.editor.placeholder = () => `message ${this.#conversationSeat()?.name ?? ""}`.trimEnd();
		this.editor.onSubmit = text => this.#submit(text);
		this.editor.onChange = text => rememberDraft(text);
		const draft = recalledDraft();
		if (draft) this.editor.setText(draft);
		this.editor.setTopBorderProvider(() => this.#composerChip());
		const shimmer = Object.assign((text: string) => shimmerText(text, theme), { animated: true as const });
		this.#loader = new Loader(tui, text => theme.fg("accent", text), shimmer, "Working…", theme.spinnerFrames);
		this.#loader.stop();
		tui.addInputListener(data => this.#onKey(data));
		// Mouse reports on, so the wheel scrolls the transcript (the terminal's own scrollback holds nothing of it).
		// Native text selection becomes Shift+drag.
		tui.setInlineMouseTrackingProvider(() => true);
		tui.setFocus(this.editor);
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Bridge messages
	// ---------------------------------------------------------------------------------------------------------------

	onMessage(message: BridgeMessage): void {
		switch (message.t) {
			case "link":
				this.#link = { ok: message.ok, text: message.ok ? (message.text ?? "") : (message.cause ?? message.text ?? "link down") };
				this.#bridgeDown = undefined;
				// A restarted bridge samples nothing until told again: re-ask for what the open page needs.
				if (message.ok && this.#computeActive === undefined) this.#setComputeActive(this.#selected.seat === OVERVIEW);
				break;
			case "seats":
				this.#seats = message.seats;
				this.#claude = message.claude ?? [];
				this.#followConversation(message.conversation ?? undefined);
				this.#entries = seatEntries(message.seats, this.#conversation, this.#claude);
				this.#bridgeDown = undefined;
				this.#reselect();
				if (this.#selected.seat === MODELS) this.send({ t: "models" });
				const watched = this.#selected.session;
				if (isClaude(watched) && this.#claude.some(session => session.id === watched)) {
					this.#askClaude(watched, this.#claudeSeen[watched] ?? 0);
				}
				break;
			case "reset":
				if (message.session === this.#selected.session) {
					const state = this.#transcript?.state ?? "";
					this.#transcript = new Transcript(this.#selected.seat, message.session, message.previous ?? undefined);
					this.#transcript.state = state;
					this.#scroll = 0;
				}
				break;
			case "event": {
				const transcript = this.#transcript;
				if (!transcript || (message.session !== transcript.session && message.session !== transcript.previous)) break;
				transcript.apply(message);
				if (message.kind === "user" && transcript.seat === SINMARA) this.#settlePending(message.text);
				break;
			}
			case "spend":
				this.#spend = message;
				this.#spendAt = Date.now();
				break;
			case "modelRows":
				this.#models = { rows: message.rows ?? this.#models?.rows, error: message.error };
				break;
			case "features":
				this.#features = { value: message.value ?? this.#features?.value, note: message.note };
				this.#featuresWaiting = false;
				break;
			case "models":
				this.#board = message.board ?? null;
				this.#boardNote = message.note ?? null;
				break;
			case "approvals":
				this.#approvals = message.rows;
				break;
			case "incidents":
				this.#incidents = message.rows;
				break;
			case "pods":
				this.#pods = message.rows;
				break;
			case "claudeLocal":
				this.#localClaude = message;
				break;
			case "ci":
				this.#ci = message;
				break;
			case "compute":
				// A snapshot is the whole fleet. A miss replaces that host; a host
				// no longer declared is gone. Previous gauges are not kept.
				if (this.#selected.seat !== OVERVIEW) break;
				this.#compute.clear();
				if ("error" in message) {
					this.#computeError = message.error;
					break;
				}
				this.#computeError = undefined;
				for (const host of message.snapshot.hosts) this.#compute.set(host.node, hostRow(host));
				break;
			case "claudeTranscript":
				this.#applyClaude(message);
				break;
			case "context":
				// Only the open panel's session takes it; a late answer for another tab is dropped.
				if (this.#contextOpen && message.session === this.#selected.session) {
					this.#context = { session: message.session, record: message.record, note: message.note };
				}
				break;
			case "updated":
				// Again on the next slow tick. A draft, a say still in flight, an open
				// model picker, or a model change still committing would be lost.
				if (this.editor.getText().length === 0 && this.#pending.length === 0 && !this.#picker && !this.#modelWait) this.quit(message.exit);
				break;
			case "done":
				if (message.id === this.#modelWait) this.#modelWait = undefined;
				if (!message.ok) this.#pending = this.#pending.filter(p => p.id !== message.id);
				this.#setNotice(
					message.ok
						? `${theme.fg("success", theme.status.success)} ${message.text}`
						: `${theme.fg("error", theme.status.error)} ${theme.fg("error", message.text)}`,
				);
				break;
			case "catalog":
				this.#showPicker(message);
				break;
		}
		this.#syncLoader();
		this.#syncJobTicker();
		this.#syncQuietTicker();
		this.tui.requestRender();
	}

	/** Ask the bridge for compute samples only while the overview is open; a failed send is retried on the next change. */
	#setComputeActive(active: boolean): void {
		if (this.#computeActive === active) return;
		if (!active) {
			this.#compute.clear();
			this.#computeError = undefined;
		}
		if (this.send({ t: "compute", active })) this.#computeActive = active;
	}

	#syncJobTicker(): void {
		if (this.#jobTicker || !this.#transcript?.runningJobs().length) return;
		this.#jobTicker = setInterval(() => {
			if (!this.#transcript?.runningJobs().length) {
				clearInterval(this.#jobTicker);
				this.#jobTicker = undefined;
			}
			this.tui.requestRender();
		}, TICK_MS);
	}

	/** A turn in progress (running or prompting) with no pending permission. Seat and Claude badges are age versus updatedAt. */
	#syncQuietTicker(): void {
		const watching = () =>
			this.#selected.seat === OVERVIEW || // the overview's ages count up too
			this.#entries.some(entry => {
				const session = entry.session;
				return (
					session?.quietSeconds != null &&
					(session.state === "running" || session.state === "prompting") &&
					(session.pendingPermissionCount ?? 0) === 0
				);
			});
		if (!watching()) {
			if (this.#quietTicker) {
				clearInterval(this.#quietTicker);
				this.#quietTicker = undefined;
			}
			return;
		}
		if (this.#quietTicker) return;
		this.#quietTicker = setInterval(() => {
			if (!watching()) {
				clearInterval(this.#quietTicker);
				this.#quietTicker = undefined;
			}
			this.tui.requestRender();
		}, TICK_MS);
	}

	bridgeDied(cause: string): void {
		this.#bridgeDown = cause;
		this.#rewatch = true;
		this.#loader.stop();
		// Its replacement samples nothing until the open page asks again.
		this.#computeActive = undefined;
		this.tui.requestRender();
	}

	/**
	 * Sinmara's conversation moved to a successor session (her context filled up, or her composition changed). The
	 * view follows it; the bridge replays the old session's tail ahead of the new one.
	 */
	#followConversation(next: string | undefined): void {
		const previous = this.#conversation;
		if (!next || next === previous) return;
		this.#conversation = next;
		if (previous) this.#former.add(previous);
	}

	/**
	 * Keep the selection on its seat: same session if it still lives, else that seat's newest, else the first entry.
	 * On Sinmara, a session her conversation has left gives way to the one carrying it now.
	 */
	#reselect(): void {
		const { seat, session } = this.#selected;
		const conversation =
			seat === SINMARA ? this.#entries.find(e => e.seat.id === SINMARA && e.session?.id === this.#conversation) : undefined;
		const left = seat === SINMARA && (session === undefined || this.#former.has(session));
		const entry =
			(left ? conversation : undefined) ??
			this.#entries.find(e => e.seat.id === seat && e.session?.id === session) ??
			conversation ??
			this.#entries.find(e => e.seat.id === seat) ??
			this.#entries[0];
		if (entry) this.#select(entry);
	}

	#select(entry: Entry): void {
		const session = entry.session?.id;
		const changed = entry.seat.id !== this.#selected.seat || session !== this.#selected.session;
		this.#selected = { seat: entry.seat.id, session };
		if (changed) this.#contextOpen = false;
		this.#setComputeActive(entry.seat.id === OVERVIEW);
		if (!changed && !this.#rewatch) return;
		this.#rewatch = false;
		// The seat's session ended and no successor is live yet: keep showing what it showed.
		if (!session && this.#transcript?.seat === entry.seat.id) return;
		this.#scroll = 0;
		const claude = isClaude(session);
		if (claude) {
			this.#claudeSeen[session] = 0;
			this.#claudeEpoch++;
			this.#claudeFlight = undefined;
		}
		this.#transcript = session ? new Transcript(entry.seat.id, session) : undefined;
		if (this.#transcript) this.#transcript.state = entry.session?.state ?? "";
		this.#claudeNote = undefined;
		if (session && !claude) this.send({ t: "watch", session });
		if (claude && session) this.#askClaude(session, 0);
		if (entry.seat.id === MODELS && !this.#board) this.send({ t: "models" });
	}

	/** One bounded page of the selected Claude session, after the cursor already shown. */
	#askClaude(session: string, since: number): void {
		const flight = `${this.#claudeEpoch}:${session}:${since}`;
		if (this.#claudeFlight === flight) return;
		this.#claudeFlight = flight;
		this.send({ t: "claude", session, since, request: flight });
	}

	#applyClaude(message: Extract<BridgeMessage, { t: "claudeTranscript" }>): void {
		if (message.request !== this.#claudeFlight) return;
		this.#claudeFlight = undefined;
		if (message.session !== this.#selected.session) return;
		const transcript = this.#transcript;
		if (!transcript) return;
		const shown = this.#claudeSeen[message.session] ?? 0;
		foldClaudePage(transcript, message.events, shown);
		this.#claudeSeen[message.session] = Math.max(shown, message.nextCursor);
		this.#claudeNote = message.error ?? message.note;
		if (message.hasMore && !message.error && message.nextCursor > shown) this.#askClaude(message.session, message.nextCursor);
	}

	#settlePending(text: string): void {
		const i = this.#pending.findIndex(p => text.includes(p.text));
		if (i !== -1) this.#pending.splice(i, 1);
	}

	/** The watched seat is mid-turn. */
	#working(): boolean {
		return this.#transcript?.state === "running" && !this.#bridgeDown;
	}

	#syncLoader(): void {
		if (this.#working()) this.#loader.start();
		else this.#loader.stop();
	}

	#setNotice(text: string): void {
		this.#notice = { text, until: Date.now() + NOTICE_MS };
		setTimeout(() => this.tui.requestRender(), NOTICE_MS + REPAINT_SLACK_MS);
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Input
	// ---------------------------------------------------------------------------------------------------------------

	#onKey(data: string): { consume: boolean } | undefined {
		const consumed = { consume: true };
		if (data.startsWith("\x1b[<")) {
			// Mouse reports: the wheel scrolls; clicks and motion do nothing.
			const wheel = parseSgrMouse(data)?.wheel;
			if (wheel && !this.#picker) {
				this.#scrollBy(-wheel * WHEEL_LINES);
				this.tui.requestRender();
			}
			return consumed;
		}
		if (this.#picker) return undefined; // The model picker owns the keyboard until Enter or Esc.
		const empty = this.editor.getText().length === 0;
		if (matchesKey(data, "ctrl+c")) {
			const now = Date.now();
			if (!empty) this.editor.setText("");
			else if (now - this.#lastCtrlC < QUIT_WINDOW_MS) this.quit();
			else this.#setNotice(theme.fg("dim", "ctrl+c again to quit"));
			this.#lastCtrlC = now;
		} else if (matchesKey(data, "ctrl+d") && empty) {
			this.quit();
		} else if (matchesKey(data, "tab") || matchesKey(data, "shift+tab")) {
			this.#cycle(matchesKey(data, "tab") ? 1 : -1);
		} else if (matchesKey(data, "pageUp")) {
			this.#scrollBy(Math.max(1, this.#transcriptHeight() - 2));
		} else if (matchesKey(data, "pageDown")) {
			this.#scrollBy(-Math.max(1, this.#transcriptHeight() - 2));
		} else if (matchesKey(data, "ctrl+up")) {
			this.#scrollBy(WHEEL_LINES);
		} else if (matchesKey(data, "ctrl+down")) {
			this.#scrollBy(-WHEEL_LINES);
		} else if (matchesKey(data, "home") && empty) {
			this.#scroll = this.#isPage() ? 0 : Number.MAX_SAFE_INTEGER; // render clamps it to the far end
		} else if (matchesKey(data, "end") && empty) {
			this.#scroll = this.#isPage() ? Number.MAX_SAFE_INTEGER : 0;
		} else if (matchesKey(data, "f2") && this.#seatTab()) {
			this.#toggleContext();
		} else if (matchesKey(data, "enter") && empty && this.#contextOpen) {
			this.#contextExpanded = !this.#contextExpanded;
		} else if (matchesKey(data, "f5") && this.#selected.seat === MODELS) {
			this.send({ t: "models" }); // The model book settles with its cause; F5 asks again.
		} else if (matchesKey(data, "f5") && this.#selected.seat === CAPABILITIES) {
			// The authority evaluates now; the next features message settles the tab.
			this.#featuresWaiting = this.send({ t: "features" });
		} else if (matchesKey(data, "ctrl+r")) {
			// Not ctrl+o (OMP's key): Zellij takes ctrl+g/p/t/n/h/s/o/q/b and most alt keys.
			this.#expanded = !this.#expanded;
		} else {
			return undefined;
		}
		this.tui.requestRender();
		return consumed;
	}

	/** A seat's own session tab: not the overview, the model book, Capabilities or a Claude session. */
	#seatTab(): boolean {
		const { seat, session } = this.#selected;
		return session !== undefined && seat !== OVERVIEW && seat !== MODELS && seat !== CAPABILITIES && !isClaude(session);
	}

	/** Opens the panel and asks the bridge for the session's latest record; closing keeps nothing. */
	#toggleContext(): void {
		this.#contextOpen = !this.#contextOpen;
		this.#context = undefined;
		this.#contextExpanded = false;
		const session = this.#selected.session;
		if (this.#contextOpen && session) this.send({ t: "context", session });
	}

	/** The injected-context panel: the latest injection's blocks with labels and token estimates; Enter shows their text. */
	#contextRows(width: number): string[] {
		const rows = [theme.fg("borderMuted", theme.boxRound.horizontal.repeat(width))];
		const title = theme.fg("accent", "injected context");
		rows.push(truncateToWidth(` ${title} ${theme.fg("dim", "F2 closes · enter shows the text")}`, width));
		const context = this.#context;
		if (!context) return [...rows, truncateToWidth(` ${theme.fg("dim", "reading the trace…")}`, width)];
		if (!context.record) return [...rows, truncateToWidth(` ${theme.fg("dim", context.note ?? "no injected context recorded")}`, width)];
		const { record } = context;
		const turn = record.turn === null ? "" : ` turn ${record.turn}`;
		rows.push(truncateToWidth(` ${theme.fg("dim", `${record.at} · ${record.kind}${turn}`)}`, width));
		for (const block of record.blocks) {
			const sources = block.sources.length ? ` · ${block.sources.join(", ")}` : "";
			rows.push(truncateToWidth(` ${block.label} (≈${block.tokens} tokens)${theme.fg("dim", sources)}`, width));
			if (this.#contextExpanded) {
				for (const line of block.text.split("\n")) rows.push(truncateToWidth(`    ${theme.fg("dim", line)}`, width));
			}
		}
		return rows;
	}

	/** A page (overview, models, capabilities) reads from its top; a transcript sits on the composer. */
	#isPage(): boolean {
		return [OVERVIEW, MODELS, CAPABILITIES].includes(this.#selected.seat);
	}

	/** Up by `lines` (down when negative); `#scroll` counts rows away from the anchor, so a page moves the other way. */
	#scrollBy(lines: number): void {
		const furthest = Math.max(0, this.#transcriptRows(this.tui.terminal.columns).length - this.#transcriptHeight());
		this.#scroll = Math.max(0, Math.min(furthest, this.#scroll + (this.#isPage() ? -lines : lines)));
	}

	#cycle(step: number): void {
		if (this.#entries.length === 0) return;
		const at = this.#entries.findIndex(
			e => e.seat.id === this.#selected.seat && e.session?.id === this.#selected.session,
		);
		const next = this.#entries[(at + step + this.#entries.length) % this.#entries.length]!;
		this.#select(next);
		this.#syncLoader();
	}

	#submit(text: string): void {
		if (!text) return;
		// /model is the view's own picker; any other line, a slash command included, is Sinmara's to read.
		if (text === "/model" || text.startsWith("/model ")) {
			this.#requestCatalog(text === "/model" ? SINMARA : text.slice("/model ".length).trim());
			return;
		}
		const id = crypto.randomUUID();
		if (!this.send({ t: "say", id, text })) {
			this.#setNotice(theme.fg("error", `${theme.status.error} not sent: the bridge is not running`));
			this.editor.setText(text);
			return;
		}
		this.editor.addToHistory(text);
		rememberDraft("");
		this.#pending.push({ id, text });
		this.#scroll = 0;
		this.tui.requestRender();
	}

	#conversationSeat(): SeatInfo | undefined {
		return this.#seats.find(s => s.id === SINMARA);
	}

	/** The session carrying her conversation, else her newest. */
	#conversationSession(): SessionInfo | undefined {
		const sessions = this.#conversationSeat()?.sessions ?? [];
		return sessions.find(s => s.id === this.#conversation) ?? sessions[0];
	}

	#requestCatalog(seatId: string): void {
		if (!seatId || !this.#seats.some(seat => seat.id === seatId)) {
			this.#setNotice(theme.fg("error", `${theme.status.error} ${seatId || "that"} is not a seat`));
			return;
		}
		const id = crypto.randomUUID();
		this.#catalogWait = { id, seat: seatId };
		if (!this.send({ t: "catalog", id, seat: seatId })) {
			this.#catalogWait = undefined;
			this.#setNotice(theme.fg("error", `${theme.status.error} not sent: the bridge is not running`));
		}
	}

	#showPicker(message: Extract<BridgeMessage, { t: "catalog" }>): void {
		if (this.#catalogWait?.id !== message.id) return;
		const seatId = this.#catalogWait.seat;
		this.#catalogWait = undefined;
		const seat = this.#seats.find(s => s.id === seatId);
		if (!seat) return;
		if (message.note) {
			this.#setNotice(theme.fg("warning", `${theme.status.warning} ${message.note}`));
		}
		const current = seat.sessions[0]?.model;
		const bySelector: Record<string, CatalogRow> = {};
		for (const row of message.rows) bySelector[row.selector] = row;
		const items: { value: string; label: string; description?: string; disabled?: boolean }[] = [
			{ value: "", label: "Seat-allowed", disabled: true },
		];
		if (seat.models.length === 0) {
			items.push({ value: "", label: "this seat declares no models", disabled: true });
		}
		for (const selector of seat.models) {
			const row = bySelector[selector];
			items.push({
				value: selector,
				label: row?.name || selector,
				description: modelDetail(row, selector === current),
			});
		}
		// omp failed: the cause is the notice, and only the declared list shows.
		if (!message.note) {
			const greyed = message.rows.filter(row => !seat.models.includes(row.selector));
			if (greyed.length > 0) {
				items.push({ value: "", label: "Signed in, not for seats", disabled: true });
				for (const row of greyed) {
					items.push({
						value: row.selector,
						label: row.name || row.selector,
						description: row.reason || `not in ${seat.name}'s models`,
						disabled: true,
					});
				}
			}
		}
		// Names like "GPT-6 Astra · ChatGPT Pro (Codex)" run past the list's default 32-column label.
		const picker = new SelectList(items, Math.min(12, items.length), getSelectListTheme(), {
			minPrimaryColumnWidth: 12,
			maxPrimaryColumnWidth: 48,
		});
		const at = items.findIndex(item => item.value === current);
		if (at !== -1) picker.setSelectedIndex(at);
		const close = () => {
			this.#picker = undefined;
			this.#pickerSeat = undefined;
			this.tui.setFocus(this.editor);
			this.tui.requestRender();
		};
		picker.onSelect = item => {
			close();
			if (!item.value || item.value === current) return;
			const id = crypto.randomUUID();
			if (this.send({ t: "model", id, seat: seatId, model: item.value })) {
				this.#modelWait = id;
				this.#setNotice(theme.fg("dim", `${theme.status.pending} switching ${seat.name} to ${item.value}…`));
			} else {
				this.#setNotice(theme.fg("error", `${theme.status.error} not sent: the bridge is not running`));
			}
		};
		picker.onCancel = close;
		this.#picker = picker;
		this.#pickerSeat = seatId;
		this.tui.setFocus(picker);
		this.tui.requestRender();
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Layout
	// ---------------------------------------------------------------------------------------------------------------

	#composerChip(): { content: string; width: number } {
		const model = shortModel(this.#conversationSession()?.model);
		const content = ` ${theme.fg("accent", `→ ${SINMARA}`)}${model ? theme.fg("dim", " · ") + theme.fg("statusLineModel", model) : ""} `;
		return { content, width: visibleWidth(content) };
	}

	#seatBar(width: number): string {
		if (this.#entries.length === 0) return truncateToWidth(` ${theme.fg("dim", "waiting for seats…")}`, width);
		const parts = this.#entries.map(entry => {
			const { glyph, color } = stateStyle(entry.session?.state ?? entry.seat.state);
			const model = shortModel(entry.session?.model);
			const badge = quietBadge(entry.session);
			const text = ` ${theme.fg(color, glyph)} ${entry.label}${model ? ` ${theme.fg("dim", model)}` : ""}${badge ? ` ${theme.fg("warning", badge)}` : ""} `;
			const selected = entry.seat.id === this.#selected.seat && entry.session?.id === this.#selected.session;
			return selected ? theme.bg("selectedBg", theme.bold(text)) : text;
		});
		return truncateToWidth(parts.join(" "), width);
	}

	#statusBar(width: number): string {
		const sep = theme.fg("dim", theme.sep.dot);
		const parts: string[] = [];
		const transcript = this.#transcript;
		const entry = this.#entries.find(
			e => e.seat.id === this.#selected.seat && e.session?.id === this.#selected.session,
		);
		const model = shortModel(transcript?.usage?.model ?? entry?.session?.model);
		if (model) parts.push(theme.fg("statusLineModel", `${theme.icon.model} ${model}`));
		const context = contextLabel(transcript?.usage);
		if (context) parts.push(context);
		if (transcript && (transcript.totals.input || transcript.totals.output)) {
			parts.push(
				theme.fg(
					"muted",
					`${theme.icon.input} ${formatNumber(transcript.totals.input)} ${theme.icon.output} ${formatNumber(transcript.totals.output)}`,
				),
			);
		}
		// The overview's figure is the whole day's, every seat and the owner's own sessions.
		const spend = this.#selected.seat === OVERVIEW ? this.#spend : this.#spend?.seats[this.#selected.seat];
		if (spend && this.#spend) {
			const fresh = Date.now() - this.#spendAt < SPEND_FRESH_MS;
			parts.push(
				theme.fg(
					fresh ? "statusLineSpend" : "muted",
					`${theme.icon.cost} ${spentLabel(spend)} on ${this.#spend.day.slice(5)}`,
				),
			);
		}
		if (this.#bridgeDown) parts.push(theme.fg("error", `${theme.status.error} ${this.#bridgeDown}`));
		else if (!this.#link) parts.push(theme.fg("dim", "connecting to Huginn…"));
		else if (!this.#link.ok) parts.push(theme.fg("error", `${theme.status.error} ${this.#link.text}`));
		const left = ` ${parts.join(sep)}`;
		const f5 = this.#selected.seat === CAPABILITIES ? "F5 refresh · " : "";
		const hint = theme.fg("dim", `tab seat · ${f5}wheel/pgup scroll · ctrl+r details `);
		const room = width - visibleWidth(left) - visibleWidth(hint);
		return room >= 2 ? left + " ".repeat(room) + hint : truncateToWidth(left, width);
	}

	#transcriptRows(width: number): string[] {
		if (this.#selected.seat === MODELS) {
			return boardRows(this.#board, this.#boardNote, width);
		}
		if (this.#selected.seat === CAPABILITIES) {
			return featureRows(this.#features?.value, this.#features?.note, width, this.#featuresWaiting);
		}
		if (this.#selected.seat === OVERVIEW) {
			const samples = [...this.#compute.values()].sort((left, right) => left.node.localeCompare(right.node));
			const computers =
				this.#computeError && samples.length === 0
					? // The whole snapshot failed: say why, instead of a dim "none".
						[
							"",
							...wrapLiteralLine(
								` ${theme.fg("accent", "Computers")} ${theme.fg("error", theme.status.error)} ${this.#computeError}`,
								width,
							),
						]
					: computeRows(samples, width);
			return [
				...computers,
				...overviewRows(
					{
						seats: this.#seats,
						claude: this.#claude,
						approvals: this.#approvals,
						incidents: this.#incidents,
						pods: this.#pods,
						local: this.#localClaude,
						ci: this.#ci,
						spend: this.#spend?.seats,
						models: this.#models,
					},
					width,
				),
			];
		}
		const transcript = this.#transcript;
		const pending = this.#selected.seat === SINMARA ? this.#pending : [];
		const panel = this.#contextOpen ? `${this.#context?.record?.at ?? this.#context?.note ?? "-"}:${this.#contextExpanded}` : "";
		const key = `${this.#selected.seat}:${this.#selected.session}:${transcript?.session}:${transcript?.revision}:${width}:${this.#expanded}:${this.#claudeNote ?? ""}:${pending.map(p => p.id).join(",")}:${panel}`;
		if (this.#rowsMemo?.key === key) return this.#rowsMemo.rows;
		const rows: string[] = [];
		if (!transcript) {
			rows.push(` ${theme.fg("dim", this.#entries.length ? "no live session for this seat" : "")}`);
		} else if (transcript.blocks.length === 0 && isClaude(this.#selected.session)) {
			rows.push(` ${theme.fg("dim", this.#claudeNote ?? "reading this Claude session…")}`);
		} else {
			let previous: string | undefined;
			for (const block of transcript.blocks) {
				if (block.kind === "assistant" && !spoken(block.text, transcript.quiet())) continue;
				const tight = block.kind === "usage" || (block.kind === "tool" && previous === "tool");
				if (previous !== undefined && !tight) rows.push("");
				rows.push(...renderBlock(block, width, this.#expanded, transcript.quiet()));
				previous = block.kind;
			}
		}
		if (this.#claudeNote && isClaude(this.#selected.session)) rows.push(` ${theme.fg("warning", this.#claudeNote)}`);
		for (const p of pending) rows.push("", ...pendingBubble(p.text, width, this.#conversationSeat()?.name));
		if (this.#contextOpen) rows.unshift(...this.#contextRows(width));
		this.#rowsMemo = { key, rows };
		return rows;
	}

	#bottomRows(width: number): string[] {
		const rows: string[] = [];
		if (this.#working()) rows.push(...this.#loader.render(width));
		for (const job of this.#transcript?.runningJobs() ?? []) rows.push(runningJobRow(job, width));
		if (this.#notice && Date.now() < this.#notice.until) rows.push(truncateToWidth(` ${this.#notice.text}`, width));
		if (this.#picker) {
			rows.push(theme.fg("borderMuted", theme.boxRound.horizontal.repeat(width)));
			const title = this.#seats.find(seat => seat.id === this.#pickerSeat)?.name ?? "model";
			rows.push(truncateToWidth(` ${theme.fg("accent", `${title}'s model`)} ${theme.fg("dim", "enter to switch · esc to cancel")}`, width));
			rows.push(...this.#picker.render(width));
		} else {
			rows.push(...this.editor.render(width));
		}
		rows.push(this.#statusBar(width));
		return rows;
	}

	#transcriptHeight(): number {
		return Math.max(1, this.tui.terminal.rows - 1 - this.#bottomRows(this.tui.terminal.columns).length);
	}

	render(width: number): readonly string[] {
		const height = this.tui.terminal.rows;
		const bottom = this.#bottomRows(width);
		const room = Math.max(1, height - 1 - bottom.length);
		const all = this.#transcriptRows(width);
		const page = this.#isPage();
		const furthest = Math.max(0, all.length - room);
		// Scrolled up, the rows being read stay put while new ones arrive below.
		if (!page && this.#scroll > 0 && all.length > this.#shownRows) this.#scroll += all.length - this.#shownRows;
		this.#shownRows = all.length;
		this.#scroll = Math.min(this.#scroll, furthest);
		const start = page ? this.#scroll : furthest - this.#scroll;
		const view = all.slice(start, start + room);
		const below = page ? all.length - start - view.length : this.#scroll;
		if (below > 0 && view.length > 0) {
			view[view.length - 1] = truncateToWidth(
				theme.fg("dim", ` ${theme.nav.expand} ${below} lines below · ${page ? "pgdn or end for the rest" : "end to follow"}`),
				width,
			);
		}
		const pad = new Array<string>(Math.max(0, room - view.length)).fill("");
		// A transcript sits on the composer; a page reads from the top.
		const body = page ? [...view, ...pad] : [...pad, ...view];
		return [this.#seatBar(width), ...body, ...bottom].slice(0, height);
	}

	invalidate(): void {
		this.#rowsMemo = undefined;
		this.editor.invalidate?.();
	}
}
