// Stand-in for OMP's env module: the five helpers the TUI reads.
export const $env: Record<string, string> = Bun.env as Record<string, string>;

export function $flag(name: string, def = false): boolean {
	const value = $env[name]?.trim().toLowerCase();
	if (!value) return def;
	return value === "1" || value === "true" || value === "yes" || value === "on";
}

export function isWsl(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): boolean {
	return platform === "linux" && Boolean(env.WSL_DISTRO_NAME || env.WSL_INTEROP);
}

/** True under `bun test`, so tests never paint or probe the real terminal. */
export function isBunTestRuntime(): boolean {
	return Bun.env.NODE_ENV === "test" || Bun.env.BUN_ENV === "test";
}

export function isTerminalHeadless(): boolean {
	return isBunTestRuntime();
}
