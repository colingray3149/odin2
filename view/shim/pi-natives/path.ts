// Stand-in for `@oh-my-pi/pi-natives/path` (`packages/natives/native/path.d.ts` at e996e1c).
// The addon is Windows-only; other platforms keep the path unchanged.

/** Expand Windows 8.3 components without resolving symlinks or junctions. Load the addon only on Windows. */
export function expandWindowsLongPath(path: string): string {
	return path;
}

/** Get the existing Windows 8.3 spelling. Load the addon only on Windows; preserve paths on other platforms. */
export function getWindowsShortPath(path: string): string {
	return path;
}
