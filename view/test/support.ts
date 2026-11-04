// What the view's tests share: the screen without its colours, and a terminal stand-in that records renders and input.
import type { TUI } from "../omp/tui";

export function plain(lines: string | readonly string[]): string {
	return (typeof lines === "string" ? lines : lines.join("\n")).replace(/\x1b\[[0-9;]*m/g, "");
}

export function fakeTui(rows = 30, columns = 100) {
	const state = {
		renders: 0,
		input: (_data: string): { consume: boolean } | undefined => undefined,
		focused: undefined as { handleInput?(data: string): void } | undefined,
	};
	const tui = {
		terminal: { rows, columns },
		addInputListener(listener: typeof state.input) {
			state.input = listener;
		},
		setInlineMouseTrackingProvider() {},
		setFocus(component: typeof state.focused) {
			state.focused = component;
		},
		requestRender() {
			state.renders++;
		},
		requestComponentRender() {},
	};
	return { state, tui: tui as unknown as TUI };
}
