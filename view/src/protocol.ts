// The bridge contract (VIEW-PLAN.md): one JSON object per line on the bridge's stdout (to the view) and stdin (from it).
// Unknown `t` values and unknown fields are ignored on both sides.

export interface SessionInfo {
	id: string;
	state: string;
	model: string;
	title?: string;
	updatedAt?: string;
	/** Silence threshold. Seat `[live] quiet_seconds`, or the Claude workload's. */
	quietSeconds?: number;
	/** A pending permission is not silence. */
	pendingPermissionCount?: number;
	/** The transcript shows Claude Code compacted this session. */
	compacted?: boolean;
}

export interface SeatInfo {
	id: string;
	name: string;
	state: string;
	/** Declared `provider/model` options, sorted (Huginn's roster sorts launch options). */
	models: string[];
	/** Live sessions, newest first. */
	sessions: SessionInfo[];
}

export interface CatalogRow {
	selector: string;
	name: string;
	strengths: string;
	/** Tier tag from the lane's model card; empty when none is declared. */
	tier: string;
	seatAllowed: boolean;
	/** Why no seat may run it. Empty when `seatAllowed`. */
	reason: string;
	contextWindow: number;
	inputPerMillion: string;
	outputPerMillion: string;
	billing: string;
}

/** An approval waiting in Huginn's read model. */
export interface ApprovalRow {
	id: string;
	issuer: string;
	capability: string;
	target: string;
	requestedAt: string;
}

/** An open incident card: a failed unit, a crash-looping pod, a seat's raise. */
export interface IncidentRow {
	id: string;
	/** info, warning, error, critical. */
	severity: string;
	summary: string;
	since: string;
}

/** One of Odin's pods: live, or ended within the last day. */
export interface PodRow {
	/** Its run label, else its workload profile, else its Kubernetes name. */
	name: string;
	/** pending, scheduling, running, succeeded, failed, suspended, terminating, unknown. */
	state: string;
	seat: string;
	/** The node its pod is bound to, once it has one. */
	node: string | null;
	startedAt: string | null;
	finishedAt: string | null;
	/** The newest ODIN-STATUS report of a monitored script pod. */
	status: PodStatusRow | null;
}

/** A script pod's newest status report: when the pod printed it, and what it said. */
export interface PodStatusRow {
	at: string;
	/** A fraction from 0 to 1, when the report has one. */
	progress: number | null;
	summary: string | null;
}

/** One Claude Code session running on the device the view is on. */
export interface LocalClaudeRow {
	id: string;
	name: string;
	status: string;
	cwd: string;
	branch: string | null;
	compacted: boolean;
}

/** This device's Claude Code sessions, labelled with the device's name. */
export interface LocalClaude {
	device: string;
	rows: LocalClaudeRow[];
}

/** One GPU in a node's compute sample. */
export interface ComputeGpu {
	name: string;
	utilizationPercent: number | null;
	memoryUsedBytes: number | null;
	memoryTotalBytes: number | null;
	temperatureCelsius: number | null;
}

/** One model runtime a node's sample saw. Unit activity is not readiness. */
export interface ComputeModel {
	name: string;
	/** Served model id when the backend listed one. */
	loaded?: string | null;
	runtime: string;
	/** systemd ActiveState, kept separate from readiness. */
	unit?: string;
	/** Backend health answered ready. Never inferred from `unit`. */
	ready?: boolean;
	state: string;
}

/** One pod a node's sample saw. */
export interface ComputePod {
	name: string;
	node: string;
	state: string;
}

/** One node's compute sample: the collector's newest reading while the overview is open. */
export interface ComputeSample {
	node: string;
	sampledAt: string;
	cpuPercent: number | null;
	memoryUsedBytes: number | null;
	memoryTotalBytes: number | null;
	storageUsedBytes: number | null;
	storageTotalBytes: number | null;
	temperatureCelsius: number | null;
	gpus: ComputeGpu[];
	models: ComputeModel[];
	/** Why the model rows are absent, when this host's declarations could not be read. */
	modelsNote: string | null;
	/** Why pod rows are absent. Null with an empty list means the node has none. */
	podsNote?: string | null;
	pods: ComputePod[];
	/** Set when this host missed the snapshot. Gauges are absent, not stale. */
	error?: string | null;
}

/** One declared host in a fleet snapshot: a sample, or the reason it missed. */
export interface ComputeHost {
	node: string;
	host: string;
	sample?: ComputeSample;
	error?: string;
}

/** One frame of a Claude session's bounded transcript page (the ClaudeReadReply event). */
export interface ClaudeFrame {
	cursor: number;
	kind: string;
	payload: unknown;
}

/** One window of the one model book (`Reading::board`). */
export interface ModelWindow {
	span: string;
	usd_limit?: number | null;
	/** Null when the gateway recorded no usage for the window: unknown, never zero. */
	usd_used?: number | null;
	requests_limit?: number | null;
	requests_used?: number | null;
	/** The request limit is estimated throughput, not a cap. */
	requests_estimate?: boolean;
}

/** One account on the one model book. */
export interface ModelAccount {
	account: string;
	provider: string;
	billing: string;
	monthly_usd?: number | null;
	renews?: string | null;
	lanes: string[];
	windows: ModelWindow[];
	held?: string | null;
}

/** One class on the one model book, in declaration order. */
export interface ModelClass {
	class: string;
	order: { lane: string; held?: string | null }[];
	serving: string;
}

/** The one usage board: accounts, windows, holds and classes. No second accounting source. */
export interface ModelBoard {
	accounts: ModelAccount[];
	classes: ModelClass[];
	note: string;
}

/** One test or probe a Capabilities row names, as the authority evaluated it. */
export interface FeatureCheckRow {
	check: string;
	/** pass, fail or unknown. */
	state: "pass" | "fail" | "unknown";
	detail: string;
}

/** One Capabilities row: a capability (title is its id) or a service. `status` is the tone: green (tested, or up), gray (untested or unknown), red (broken). */
export interface FeatureRow {
	id: string;
	title: string;
	/** The capability's toolset, or "services". */
	area: string;
	service: boolean;
	status: "green" | "gray" | "red";
	label: string;
	checks: FeatureCheckRow[];
}

/** The authority's `Status/features` object: the evaluation, the deployed tested sha, the capability counts and the live registry. */
export interface FeaturesValue {
	evaluatedAt: string;
	tested: { sha: string | null; at: string | null; inherited: boolean } | null;
	live: { registryRevision: number; commit: string | null };
	counts: { capabilities: number; tested: number };
	rows: FeatureRow[];
}

/** The authority's `Status/knowledge` object: kb-status's status.json, or only `error` when odind cannot read it. */
export interface KnowledgeValue {
	evaluated_at?: string;
	error?: string | null;
	counts?: { parts: number; green: number; paused: number; behind: number; red: number; grey: number };
	parts?: { id: string; title: string; area: string; kind: string; state: "green" | "paused" | "behind" | "red" | "grey"; text: string }[];
	recent?: { ts?: string; actor?: string; op?: string; path?: string; note?: string }[];
}

/** One mission on the authority's `Status/missions` board. */
export interface MissionRow {
	run: string;
	label: string;
	stage: string;
	node?: string | null;
	workload?: string | null;
	failure?: string | null;
	updatedAt: string;
	sampleAt?: string | null;
	lastSample?: Record<string, unknown> | null;
	series?: Record<string, number[]> | null;
	checkpoints: number;
	renderers: string[];
	openRenders: number;
	frame?: { artifact: string; mediaType?: string; renderer: string; seq: number; simTimeUs?: number | null; at: string } | null;
}

export interface MissionsValue {
	rows: MissionRow[];
}

/** One declared repo's newest CI run, or why it could not be read. */
/** One open seat session's own plan: its objective and to-do list, as the seat keeps it. */
export interface PlanRow {
	seat: string;
	session: string;
	objective: string;
	todos: { id: string; title: string; status: string }[];
}

export interface CiRow {
	repo: string;
	status: string | null;
	conclusion: string | null;
	branch: string | null;
	updatedAt: string | null;
	error?: string;
}

export type EventBody =
	| {
			kind: "user";
			text: string;
			/** A job report turn (reports due together share one): each job, whether it went through, how long it ran
			 *  by its own clock, and its report's first line. */
			jobs?: { job: string; ok: boolean; seconds?: number | null; line: string }[];
	  }
	| { kind: "delta"; text: string; /** Hermes's quiet reply token, sent once per reply line. */ quiet?: string }
	| { kind: "assistant"; text: string; /** Hermes's quiet reply token, sent once per reply line. */ quiet?: string }
	| { kind: "thinking"; text: string }
	| { kind: "toolStart"; id: string; name: string; args: unknown }
	| { kind: "toolEnd"; id: string; text: string; isError: boolean; /** The call became this background job. */ job?: string | null }
	| {
			kind: "usage";
			model: string;
			input: number;
			output: number;
			cacheRead: number;
			cacheWrite: number;
			contextTokens: number;
			contextWindow: number | null;
	  }
	| { kind: "state"; state: string; reason?: string | null }
	| { kind: "error"; text: string }
	| { kind: "note"; text: string };

export type LiveEvent = EventBody & { session: string; seq: number; at?: string };

/** Owner-facing reply text. `quiet` is hermes's token, carried on the reply line: a prefix or suffix of it, and the
 *  punctuation beside a leading one, is not shown. A reply that is only the token, or still streaming toward it, is empty. */
export function spoken(text: string, quiet: string | undefined): string {
	if (!quiet) return text.trim();
	let rest = text.trim();
	if (quiet.startsWith(rest)) return "";
	if (rest.startsWith(quiet)) rest = rest.slice(quiet.length).replace(/^[\s\u2014\u2013\-:,.]+/, "");
	if (rest.endsWith(quiet)) rest = rest.slice(0, -quiet.length).trimEnd();
	return rest;
}

/** One block of an injection: what the brain or the rollover put into a seat's context. */
export interface InjectionBlock {
	label: string;
	/** Estimated: characters divided by four. */
	tokens: number;
	/** Record ids the block carries. */
	sources: string[];
	text: string;
}

/** One injection into a session's context, as the authority traced it. */
export interface InjectionRecord {
	at: string;
	turn: number | null;
	kind: "epoch" | "turn" | "rollover" | "fresh";
	blocks: InjectionBlock[];
}

export interface LaneBudget {
	lane: string;
	windowDays: number;
	coreHours: { used: number; cap: number | null };
	gpuHours: { used: number; cap: number | null };
	computeUsd: { used: number; cap: number | null };
}

export type BridgeMessage =
	| { t: "link"; ok: boolean; text?: string; cause?: string }
	| { t: "seats"; seats: SeatInfo[]; /** Claude session projections, not seat sessions. */ claude?: SessionInfo[]; /** The session carrying Sinmara's conversation. */ conversation?: string | null }
	| { t: "reset"; session: string; seat?: string; /** Replayed first: the session the conversation rolled over from. */ previous?: string | null }
	| ({ t: "event" } & LiveEvent)
	| { t: "spend"; day: string; usdCents: number; includedCents: number; tokens: number; seats: Record<string, Spent> }
	| { t: "budgets"; lanes: LaneBudget[] }
	| { t: "modelRows"; rows?: string[]; error?: string }
	| { t: "approvals"; rows: ApprovalRow[] }
	| { t: "incidents"; rows: IncidentRow[] }
	| { t: "pods"; rows: PodRow[] }
	| { t: "claudeLocal"; device: string; rows: LocalClaudeRow[] }
	| { t: "ci"; rows: CiRow[]; /** Why the repo list itself could not be read. */ note?: string }
	| { t: "plans"; rows: PlanRow[] }
	| { t: "done"; id: string; ok: boolean; text: string }
	/** A deploy replaced the installed odin: the view exits with `exit` and `odin view` starts the new one. */
	| { t: "updated"; exit: number }
	| { t: "catalog"; id: string; seat: string; note?: string; rows: CatalogRow[] }
	| { t: "claudeTranscript"; request: string; session: string; events: ClaudeFrame[]; nextCursor: number; hasMore: boolean; error?: string; note?: string }
	| { t: "compute"; snapshot: { hosts: ComputeHost[] } }
	| { t: "compute"; error: string }
	| { t: "models"; board?: ModelBoard; note?: string }
	| { t: "context"; session: string; record?: InjectionRecord; note?: string }
	| { t: "features"; value?: FeaturesValue; note?: string }
	| { t: "knowledge"; value?: KnowledgeValue }
	| { t: "missions"; value: MissionsValue }
	| { t: "frame"; run: string; artifact: string; mediaType?: string | null; data?: string; error?: string };

export type ViewCommand =
	| { t: "watch"; session: string }
	| { t: "say"; id: string; text: string }
	| { t: "model"; id: string; seat: string; model: string }
	| { t: "catalog"; id: string; seat: string }
	| { t: "claude"; session: string; since: number; request: string }
	/** Ask the bridge to keep sending compute samples, or to stop; sampled only while the overview is open. */
	| { t: "compute"; active: boolean }
	| { t: "models" }
	| { t: "context"; session: string }
	| { t: "features" }
	/** The Missions tab opened, closed or moved: the bridge polls the board and sends the open mission's frames. */
	| { t: "missions"; open: boolean; run?: string }
	| { t: "render" | "pause" | "resume"; id: string; run: string };

/** One spend figure: dollars billed, and subscription use at list price that the plan already pays. */
export interface Spent {
	usdCents: number;
	includedCents: number;
	tokens: number;
}

export function spentLabel(spent: Spent): string {
	const dollars = (cents: number) => `$${(cents / 100).toFixed(2)}`;
	return spent.includedCents > 0 ? `${dollars(spent.usdCents)} +${dollars(spent.includedCents)} incl.` : dollars(spent.usdCents);
}

/** `gateway/grok` → `grok`. */
export function shortModel(model: string | undefined): string {
	if (!model) return "";
	const slash = model.lastIndexOf("/");
	return slash === -1 ? model : model.slice(slash + 1);
}

/** `quiet 45s`, `quiet 12m`, `quiet 2h 05m`. */
function quietLabel(seconds: number): string {
	const whole = Math.max(0, Math.floor(seconds));
	if (whole < 60) return `quiet ${whole}s`;
	const minutes = Math.floor(whole / 60);
	if (minutes < 60) return `quiet ${minutes}m`;
	const hours = Math.floor(minutes / 60);
	const rest = minutes % 60;
	return rest === 0 ? `quiet ${hours}h` : `quiet ${hours}h ${String(rest).padStart(2, "0")}m`;
}

/**
 * Badge text for one row, or "" when it is not quiet.
 * Quiet only while a turn is in progress (running or prompting), no
 * permission is pending, and the silence since `updatedAt` is at least
 * `quietSeconds`. Seat and Claude rows use the same fields; a
 * silence-only tick does not need a new projection.
 */
export function quietBadge(session: SessionInfo | undefined, now = Date.now()): string {
	if (!session || session.quietSeconds == null) return "";
	if (session.state !== "running" && session.state !== "prompting") return "";
	if ((session.pendingPermissionCount ?? 0) > 0) return "";
	if (!session.updatedAt) return "";
	const updated = Date.parse(session.updatedAt);
	if (Number.isNaN(updated)) return "";
	const age = Math.floor((now - updated) / 1000);
	return age >= session.quietSeconds ? quietLabel(age) : "";
}
