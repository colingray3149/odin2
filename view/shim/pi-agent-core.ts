// Stand-in for the `@oh-my-pi/pi-agent-core` names the vendored TUI imports.
// ThinkingLevel matches OMP v18.13.2 `packages/agent/src/thinking.ts`
// (`Effort` values from `packages/catalog/src/effort.ts`).

/**
 * Agent-local thinking selector.
 *
 * `off` disables reasoning, while `inherit` defers to a higher-level selector.
 */
export const ThinkingLevel = {
	Inherit: "inherit",
	Off: "off",
	Minimal: "minimal",
	Low: "low",
	Medium: "medium",
	High: "high",
	XHigh: "xhigh",
	Max: "max",
} as const;

export type ThinkingLevel = (typeof ThinkingLevel)[keyof typeof ThinkingLevel];
export type ResolvedThinkingLevel = Exclude<ThinkingLevel, "inherit">;
