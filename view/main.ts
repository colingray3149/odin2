// odin view: Odin's terminal frontend. `odin view` sets ODIN_VIEW_BRIDGE and runs this with bun.
import { App } from "./src/app";
import { Bridge, bridgeArgv, bridgeLogPath } from "./src/bridge";
import { ProcessTerminal } from "./omp/terminal";
import { initThemeSync } from "./omp/theme/theme";
import { TUI } from "./omp/tui";

let argv: string[];
try {
	argv = bridgeArgv();
} catch (err) {
	console.error(`odin view: ${err instanceof Error ? err.message : String(err)}`);
	process.exit(2);
}

// OMP's look in the Cyber Blossom palette (pink accent, blue secondary; the palette is a copy of the fleet's
// modules/home/colors.nix), on dark and light terminals alike.
initThemeSync("nerd", false, "cyber-blossom", "cyber-blossom");
const tui = new TUI(new ProcessTerminal());
let bridge: Bridge | undefined;

const quit = (code = 0) => {
	bridge?.stop();
	tui.stop();
	process.exit(code);
};

const app = new App(tui, command => bridge?.send(command) ?? false, quit);
bridge = new Bridge(
	argv,
	bridgeLogPath(),
	message => app.onMessage(message),
	cause => app.bridgeDied(cause),
);
tui.addChild(app);
tui.start();
bridge.start();
