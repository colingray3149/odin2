import { expect, test } from "bun:test";
import { initThemeSync } from "../omp/theme/theme";
import { foldClaudePage } from "../src/claude";
import type { ClaudeFrame } from "../src/protocol";
import { Transcript } from "../src/transcript";

initThemeSync("nerd", false, "cyber-blossom", "cyber-blossom");

const frame = (cursor: number, payload: unknown): ClaudeFrame => ({ cursor, kind: "backend", payload });

test("a Claude session's frames fold into the blocks a seat transcript shows, in cursor order and never twice", () => {
	const t = new Transcript("claude", "claude:1");
	const frames = [
		frame(4, { type: "user", message: { content: [{ type: "tool_result", tool_use_id: "t1", content: "3 files", is_error: false }] } }),
		frame(1, { type: "user", message: { content: "fix the driver" } }),
		frame(2, {
			type: "assistant",
			message: {
				content: [
					{ type: "thinking", thinking: "look at it" },
					{ type: "text", text: "On it." },
					{ type: "tool_use", id: "t1", name: "Bash", input: { command: "ls" } },
				],
			},
		}),
		frame(5, { type: "system", subtype: "compact_boundary" }),
		frame(6, { type: "error", error: "rate limited" }),
		frame(7, { type: "host_tab_opened" }),
	];
	foldClaudePage(t, frames);
	expect(t.blocks).toMatchObject([
		{ kind: "user", text: "fix the driver" },
		{ kind: "thinking", text: "look at it" },
		{ kind: "assistant", text: "On it." },
		{ kind: "tool", id: "t1", name: "Bash", status: "success", result: "3 files" },
		{ kind: "note", text: "Claude compacted this session" },
		{ kind: "note", text: "rate limited", error: true },
		{ kind: "note", text: "host tab opened" },
	]);
	foldClaudePage(t, frames, 7);
	expect(t.blocks).toHaveLength(7); // a page read again after its last cursor adds nothing
});
