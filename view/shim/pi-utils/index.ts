// Stand-in for the `@oh-my-pi/pi-utils` root: only the names the vendored TUI imports.
export * from "./color";
export * from "./dirs";
export * from "./format";
export * as logger from "./logger";
export * from "./loop-phase";
export * from "./sanitize-text";
export * from "./slugify";

/** OMP's display tab width (packages/utils/src/tab-spacing.ts). */
export const DEFAULT_TAB_WIDTH = 3;

export function $which(name: string, env?: { PATH?: string }): string | null {
	return Bun.which(name, env?.PATH ? { PATH: env.PATH } : undefined);
}
