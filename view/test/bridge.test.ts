import { afterEach, beforeEach, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Bridge, bridgeArgv } from "../src/bridge";
import type { BridgeMessage } from "../src/protocol";

let dir: string;
beforeEach(() => {
	dir = fs.mkdtempSync(path.join(os.tmpdir(), "odin-bridge-"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

/** A child that runs `script` under the same bun that runs the tests. */
const child = (script: string) => [process.execPath, "-e", script];
const log = () => path.join(dir, "bridge.log");

test("a message the view cannot handle is logged and the ones after it still arrive", async () => {
	const seen: string[] = [];
	const done = Promise.withResolvers<void>();
	const bridge = new Bridge(
		child(`for (const t of ["poison", "next", "last"]) console.log(JSON.stringify({ t })); setTimeout(() => {}, 60_000)`),
		log(),
		(message: BridgeMessage) => {
			if (message.t === ("poison" as string)) throw new Error("no snapshot");
			seen.push(message.t);
			if (seen.length === 2) done.resolve();
		},
		() => {},
	);
	bridge.start();
	await done.promise;
	bridge.stop();
	expect(seen).toEqual(["next", "last"]);
	expect(fs.readFileSync(log(), "utf8")).toContain("poison message failed: no snapshot");
});

test("a bridge that exits is reported with the last line of its log, refuses commands while down, and starts again", async () => {
	const exits: string[] = [];
	const twice = Promise.withResolvers<void>();
	let refused: boolean | undefined;
	const bridge = new Bridge(
		child(`console.error("no pairing for this device"); process.exit(3)`),
		log(),
		() => {},
		cause => {
			exits.push(cause);
			refused ??= bridge.send({ t: "models" });
			if (exits.length === 2) twice.resolve();
		},
		10,
	);
	bridge.start();
	await twice.promise;
	bridge.stop();
	expect(exits[0]).toBe("bridge exited (3): no pairing for this device");
	expect(refused).toBe(false);
	expect(exits).toHaveLength(2); // the second start ran the same child again
});

test("the bridge argv must be a JSON array of strings, and its absence says how to start the view", () => {
	expect(bridgeArgv({ ODIN_VIEW_BRIDGE: '["odin","view","--bridge"]' })).toEqual(["odin", "view", "--bridge"]);
	expect(() => bridgeArgv({})).toThrow("start the view with `odin view`");
	expect(() => bridgeArgv({ ODIN_VIEW_BRIDGE: "odin view" })).toThrow("is not JSON");
	expect(() => bridgeArgv({ ODIN_VIEW_BRIDGE: '["odin", 1]' })).toThrow("non-empty JSON array of strings");
});
