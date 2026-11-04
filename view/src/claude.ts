// Folds one Claude session's bounded transcript page into the same blocks a seat transcript uses.
// The page is Huginn's ClaudeReadReply: events after a stable cursor, never a local file read.
import type { ClaudeFrame } from "./protocol";
import { Transcript } from "./transcript";

/** Text Claude Code stored on a content block, or "". */
function blockText(block: unknown): string {
	if (!block || typeof block !== "object") return "";
	const value = block as { type?: string; text?: string; thinking?: string; name?: string; input?: unknown };
	if (value.type === "text" || value.type === "thinking") return value.text ?? value.thinking ?? "";
	return "";
}

function contentText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content.map(blockText).filter(Boolean).join("\n");
}

/** A Claude Code jsonl frame, or an Odin driver event, as one transcript block. */
function applyFrame(transcript: Transcript, frame: ClaudeFrame): void {
	const payload = frame.payload;
	if (!payload || typeof payload !== "object") {
		transcript.apply({ kind: "note", text: frame.kind });
		return;
	}
	const record = payload as Record<string, unknown>;
	const type = typeof record.type === "string" ? record.type : frame.kind;
	const message = record.message && typeof record.message === "object" ? (record.message as Record<string, unknown>) : undefined;
	if (type === "user" || record.role === "user") {
		const content = message?.content ?? record.content;
		if (Array.isArray(content)) {
			for (const block of content) {
				if (!block || typeof block !== "object" || block.type !== "tool_result") continue;
				transcript.apply({
					kind: "toolEnd",
					id: String(block.tool_use_id ?? "tool"),
					text: contentText(block.content),
					isError: block.is_error === true,
				});
			}
		}
		const text = contentText(message?.content ?? record.content ?? record.text);
		if (text) transcript.apply({ kind: "user", text });
		return;
	}
	if (type === "assistant" || record.role === "assistant") {
		const content = message?.content ?? record.content;
		if (Array.isArray(content)) {
			for (const block of content) {
				if (!block || typeof block !== "object") continue;
				const item = block as { type?: string; text?: string; thinking?: string; id?: string; name?: string; input?: unknown };
				if (item.type === "thinking" && item.thinking) transcript.apply({ kind: "thinking", text: item.thinking });
				else if (item.type === "text" && item.text) transcript.apply({ kind: "assistant", text: item.text });
				else if (item.type === "tool_use" && item.name) {
					transcript.apply({ kind: "toolStart", id: item.id ?? item.name, name: item.name, args: item.input });
				}
			}
			return;
		}
		const text = contentText(content);
		if (text) transcript.apply({ kind: "assistant", text });
		return;
	}
	if (type === "tool_result" || type === "user_tool_result") {
		transcript.apply({
			kind: "toolEnd",
			id: String(record.tool_use_id ?? record.id ?? "tool"),
			text: contentText(record.content ?? record.text),
			isError: record.is_error === true,
		});
		return;
	}
	if (type === "system" && record.subtype === "compact_boundary") {
		transcript.apply({ kind: "note", text: "Claude compacted this session" });
		return;
	}
	if (record.isCompactSummary === true) {
		const text = contentText(message?.content ?? record.content ?? record.summary);
		transcript.apply({ kind: "note", text: text || "compacted summary" });
		return;
	}
	if (type === "result" || type === "error") {
		const text = typeof record.result === "string" ? record.result : typeof record.error === "string" ? record.error : type;
		if (type === "error" || record.is_error === true) transcript.apply({ kind: "error", text });
		else transcript.apply({ kind: "note", text });
		return;
	}
	if (type.startsWith("host_tab_")) {
		transcript.apply({ kind: "note", text: type.replaceAll("_", " ") });
	}
}

/** The page's frames after `after`, in cursor order. A repeated page does not fold lines already shown. */
export function foldClaudePage(transcript: Transcript, events: readonly ClaudeFrame[], after = 0): void {
	const ordered = events.filter(frame => frame.cursor > after).sort((a, b) => a.cursor - b.cursor);
	for (const frame of ordered) applyFrame(transcript, frame);
}
