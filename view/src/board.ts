// The overview's model/usage pane. Rows come only from the one model book (`Reading::board` via Huginn Models).
import { theme } from "../omp/theme/theme";
import { row } from "./layout";
import type { ModelBoard, ModelWindow } from "./protocol";

function money(window: ModelWindow): string {
	if (window.usd_limit == null) return "";
	const used = window.usd_used == null ? "unknown" : `$${window.usd_used.toFixed(2)}`;
	return `${used} of $${window.usd_limit}`;
}

function requests(window: ModelWindow): string {
	const limit = window.requests_limit;
	if (limit == null) return "";
	const used = window.requests_used ?? "unknown";
	return window.requests_estimate ? `${used} requests; estimated throughput ${limit} (not a cap)` : `${used} of ${limit} requests`;
}

/** Classes in declaration order, then each plan with its windows and hold. Same words as `odin models`. */
export function boardRows(board: ModelBoard | null | undefined, note: string | null | undefined, width: number): string[] {
	const rows: string[] = ["", ` ${theme.fg("accent", "Models")}`];
	if (note) rows.push(row(width, theme.fg("error", `Model book unavailable: ${note} · F5 to retry`)));
	if (!board) {
		if (!note) rows.push(row(width, theme.fg("dim", "reading the model book…")));
		return rows;
	}
	rows.push(row(width, theme.fg("dim", "first lane with room serves")));
	for (const item of board.classes) {
		const order = item.order
			.map(lane => (lane.held ? `${lane.lane} (held: ${lane.held})` : lane.lane))
			.join(", ");
		rows.push(row(width, `${theme.bold(item.class)} ${theme.fg("dim", order)} ${theme.fg("accent", `now ${item.serving}`)}`));
	}
	for (const account of board.accounts) {
		const cost = account.monthly_usd != null ? `, $${account.monthly_usd}/month` : "";
		const renews = account.renews ? `, renews ${account.renews}` : "";
		const held = account.held ? theme.fg("warning", ` held: ${account.held}`) : "";
		rows.push(
			row(
				width,
				`${theme.bold(account.account)} ${theme.fg("dim", `${account.provider} (${account.billing}${cost}${renews})`)} ${account.lanes.join(", ")}${held}`,
			),
		);
		for (const window of account.windows) {
			const figure = [money(window), requests(window)].filter(Boolean).join(", ");
			if (!figure) continue;
			rows.push(row(width, theme.fg("statusLineSpend", `per ${window.span} ${figure}`)));
		}
	}
	if (board.note) rows.push(row(width, theme.fg("dim", board.note)));
	return rows;
}
