// The overview page: approvals waiting on the owner first, open incidents, then every seat working or quiet with its spend today, Odin's
// own plans, pods, Claude sessions with their branch and compaction, and one CI line per declared repo. One plain line per item,
// columns aligned, in the Cyber Blossom palette.
import { theme } from "../omp/theme/theme";
import type { ApprovalRow, CiRow, IncidentRow, LocalClaude, PlanRow, PodRow, SeatInfo, SessionInfo, Spent } from "./protocol";
import { quietBadge, shortModel, spentLabel } from "./protocol";
import { formatDuration, stateStyle } from "./render";
import { wrapCells } from "./compute";
import { ago, podStyle, row, table } from "./layout";

/** Cells in a script pod's progress bar. */
const BAR = 10;

/** A script pod's detail lines under its row: what a pending pod waits for, then its progress, summary and report age. */
function podDetail(pod: PodRow, width: number, now: number): string[] {
	const waiting = pod.state === "pending" ? theme.fg("warning", `waiting for ${pod.node ?? "placement"}`) : "";
	const status = pod.status;
	if (!status) return wrapCells(width, [waiting], "   ");
	let bar = "";
	if (status.progress !== null) {
		const fraction = Math.min(1, Math.max(0, status.progress));
		const filled = Math.round(fraction * BAR);
		bar = `${theme.fg("accent", "█".repeat(filled))}${theme.fg("dim", "░".repeat(BAR - filled))} ${Math.round(fraction * 100)}%`;
	}
	const age = ago(status.at, now);
	return wrapCells(width, [waiting, bar, status.summary ? theme.fg("dim", status.summary) : "", age ? theme.fg("dim", `${age} ago`) : ""], "   ");
}

/** The overview body. Ages are computed here, so a re-render refreshes them. */
export function overviewRows(
	input: {
		seats: readonly SeatInfo[];
		claude: readonly SessionInfo[];
		approvals: readonly ApprovalRow[];
		incidents: readonly IncidentRow[];
		pods: readonly PodRow[];
		local: LocalClaude | undefined;
		ci: { rows: readonly CiRow[]; note?: string } | undefined;
		/** The open seat sessions' own plans. */
		plans?: readonly PlanRow[];
		/** Today's gateway spend per seat id. */
		spend?: Record<string, Spent>;
		/** The authority's model book, rendered by the same reader as `odin models`. */
		models?: { rows?: readonly string[]; error?: string };
	},
	width: number,
	now = Date.now(),
): string[] {
	const rows: string[] = [];
	const section = (title: string) => rows.push("", ` ${theme.fg("accent", title)}`);
	const none = () => rows.push(` ${theme.fg("dim", "none")}`);

	section("Approvals");
	if (input.approvals.length === 0) none();
	for (const approval of input.approvals) {
		const age = ago(approval.requestedAt, now);
		rows.push(
			row(
				width,
				theme.fg("warning", theme.status.pending),
				theme.bold(approval.issuer),
				approval.capability,
				theme.fg("dim", `on ${approval.target}${age ? ` · waiting ${age}` : ""}`),
			),
		);
	}

	// Shown only while one is open.
	if (input.incidents.length > 0) section("Incidents");
	for (const incident of input.incidents) {
		const age = ago(incident.since, now);
		const color = incident.severity === "info" ? "muted" : incident.severity === "warning" ? "warning" : "error";
		rows.push(row(width, theme.fg(color, theme.status.error), incident.summary, theme.fg("dim", `${incident.severity}${age ? ` · ${age}` : ""}`)));
	}

	section("Seats");
	if (input.seats.length === 0) none();
	// Offline seats with nothing live share one line.
	const offline = input.seats.filter(seat => seat.sessions.length === 0 && seat.state === "offline");
	const seatLines = input.seats
		.filter(seat => !offline.includes(seat))
		.map(seat => {
			const session = seat.sessions[0];
			const { glyph, color } = stateStyle(session?.state ?? seat.state);
			const badge = seat.sessions.map(session => quietBadge(session, now)).find(Boolean);
			const spent = input.spend?.[seat.id];
			return [
				theme.fg(color, glyph),
				theme.bold(seat.name),
				theme.fg("dim", session?.state ?? seat.state),
				theme.fg("dim", shortModel(session?.model)),
				spent ? theme.fg("statusLineSpend", spentLabel(spent)) : "",
				badge ? theme.fg("warning", badge) : "",
			];
		});
	rows.push(...table(width, seatLines));
	if (offline.length > 0) {
		rows.push(
			row(width, theme.fg("muted", theme.status.disabled), theme.fg("dim", `${offline.map(seat => seat.name).join(" · ")} offline`)),
		);
	}

	// Shown only while a seat keeps a to-do list: each seat's objective, then its to-dos.
	if ((input.plans?.length ?? 0) > 0) section("Plans");
	for (const plan of input.plans ?? []) {
		const done = plan.todos.filter(todo => todo.status === "completed").length;
		rows.push(row(width, theme.fg("accent", theme.status.pending), theme.bold(plan.seat), plan.objective, theme.fg("dim", `${done}/${plan.todos.length} done`)));
		for (const todo of plan.todos) {
			const color = todo.status === "blocked" ? "error" : todo.status === "active" ? "warning" : "dim";
			rows.push(row(width, "  ", theme.fg(color, todo.status), todo.status === "completed" || todo.status === "cancelled" ? theme.fg("dim", todo.title) : todo.title));
		}
	}

	section("Pods");
	const pods = input.pods;
	if (pods.length === 0) none();
	const podLines = table(
		width,
		pods.map(pod => {
			const { glyph, color } = podStyle(pod.state);
			const ran = pod.startedAt && pod.finishedAt ? Date.parse(pod.finishedAt) - Date.parse(pod.startedAt) : Number.NaN;
			const when = pod.finishedAt
				? `${Number.isNaN(ran) ? "" : `ran ${formatDuration(ran / 1000)} · `}${ago(pod.finishedAt, now)} ago`
				: pod.startedAt
					? `for ${ago(pod.startedAt, now)}`
					: "";
			return [
				theme.fg(color, glyph),
				theme.bold(pod.name),
				theme.fg(color === "muted" ? "dim" : color, pod.state),
				theme.fg("dim", pod.seat),
				theme.fg("dim", pod.node ?? ""),
				theme.fg("dim", when),
			];
		}),
	);
	pods.forEach((pod, i) => rows.push(podLines[i]!, ...podDetail(pod, width, now)));

	section("Claude");
	if (input.claude.length === 0 && (input.local?.rows.length ?? 0) === 0) none();
	const claudeLines = input.claude.map(session => {
		const { glyph, color } = stateStyle(session.state);
		const badge = quietBadge(session, now);
		return [
			theme.fg(color, glyph),
			theme.bold(session.title || "Claude"),
			theme.fg("dim", session.state),
			"",
			"",
			[badge && theme.fg("warning", badge), session.compacted && theme.fg("dim", "compacted")].filter(Boolean).join(" "),
		];
	});
	const home = process.env.HOME;
	for (const session of input.local?.rows ?? []) {
		const { glyph, color } = stateStyle(session.status);
		const cwd = home && (session.cwd === home || session.cwd.startsWith(`${home}/`)) ? `~${session.cwd.slice(home.length)}` : session.cwd;
		claudeLines.push([
			theme.fg(color, glyph),
			theme.bold(session.name),
			theme.fg("dim", session.status),
			theme.fg("dim", `${input.local?.device}:${cwd}`),
			session.branch ? theme.fg("statusLineModel", session.branch) : "",
			session.compacted ? theme.fg("dim", "compacted") : "",
		]);
	}
	rows.push(...table(width, claudeLines));

	section("Models and usage");
	if (input.models?.error) rows.push(row(width, theme.fg("error", input.models.error)));
	else if (!input.models?.rows?.length) rows.push(row(width, theme.fg("dim", "model book not read yet")));
	for (const line of input.models?.rows ?? []) rows.push(row(width, line));

	section("CI");
	if (input.ci?.note) {
		rows.push(row(width, theme.fg("error", `${theme.status.error} ${input.ci.note}`)));
	} else if ((input.ci?.rows.length ?? 0) === 0) {
		none();
	}
	for (const line of input.ci?.rows ?? []) {
		if (line.error) {
			rows.push(row(width, theme.fg("error", `${theme.status.error} ${line.repo}: gh ${line.error}`)));
			continue;
		}
		// A cancelled or skipped run is not a failure, and a repo with no
		// runs is not a broken CI line.
		let glyph = theme.status.disabled;
		let color: "accent" | "success" | "error" | "muted" = "muted";
		if (line.status === "in_progress" || line.status === "queued") {
			glyph = theme.status.running;
			color = "accent";
		} else if (line.status === "no runs") {
			glyph = "";
		} else if (line.status === "completed") {
			if (line.conclusion === "success") {
				glyph = theme.status.enabled;
				color = "success";
			} else if (["failure", "startup_failure", "timed_out", "action_required"].includes(line.conclusion ?? "")) {
				glyph = theme.status.error;
				color = "error";
			}
		}
		const age = ago(line.updatedAt, now);
		rows.push(
			row(
				width,
				glyph && theme.fg(color, glyph),
				theme.bold(line.repo),
				line.branch ? theme.fg("dim", line.branch) : false,
				theme.fg(color, line.conclusion || line.status || ""),
				age && theme.fg("dim", age),
			),
		);
	}
	return rows;
}
