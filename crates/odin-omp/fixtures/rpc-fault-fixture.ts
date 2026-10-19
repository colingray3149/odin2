/**
 * Odin RPC transport fault fixture.
 *
 * A minimal, deterministic stdin/stdout peer run under Bun by the conformance
 * probe (`CaseContext::fault_spec`) to source frames the real pinned OMP can
 * never emit: unknown future frame types, malformed JSON, invalid UTF-8,
 * oversized physical lines, and corrupt v2 chunk trains.
 *
 * The fixture is protocol-faithful at startup — it emits the exact `ready`
 * frame shape of the pinned harness (same advertised limits) and answers the
 * fixed `negotiate_protocol` round-trip — so the host's process boundary
 * reaches its ready state, after which the case injects faults byte-exactly:
 *
 * - `{ "id": ..., "type": "fixture_emit", "lines": ["...", ...] }`
 *   Acknowledged with a normal `response` frame, then each string is written
 *   verbatim plus `\n`. Any JSON-representable fault goes through this
 *   channel.
 * - `{ "id": ..., "type": "fixture_emit_bytes", "base64": "..." }`
 *   Acknowledged, then the decoded bytes are written verbatim (no newline
 *   added): invalid UTF-8, unterminated lines, NUL bytes.
 * - `{ "id": ..., "type": "fixture_emit_fault", "fault":
 *   "physical_oversize" | "reassembled_invalid_utf8" }` acknowledges, then
 *   emits the named fixed-size fault (caller-controlled sizes are forbidden).
 * - `{ "id": ..., "type": "negotiate_protocol", "protocolVersion": 2 }`
 *   answers `{ success: true, data: { protocolVersion: 2 } }`, mirroring the
 *   pinned handshake; any other version is refused.
 * - Anything else receives a typed `success: false` response; the fixture
 *   never silently swallows a command.
 *
 * stdin EOF ends the process with status 0 once stdout has drained (natural
 * event-loop exit, no explicit `process.exit`). No network, no files, no
 * clocks.
 */

/** The pinned transport limits, advertised exactly as the real harness does. */
const MAX_FRAME_BYTES = 1_048_576;
const MAX_REASSEMBLED_BYTES = 67_108_864;
/** Input is one physical v1 command frame, including its newline. */
const MAX_COMMAND_BYTES = MAX_FRAME_BYTES;
/** A corrupt train may exceed the valid 256 chunks, but remains finite. */
const MAX_EMIT_LINES = 512;
/** Caller-supplied output never exceeds one maximal logical frame. */
const MAX_EMIT_BYTES = MAX_REASSEMBLED_BYTES;
const EMPTY_BUFFER = Buffer.alloc(0);

/** One JSONL protocol frame on stdout. */
function writeFrame(frame: Record<string, unknown>): void {
	process.stdout.write(`${JSON.stringify(frame)}\n`);
}

/** Acknowledge a fixture command, echoing its id. */
function ack(id: string | undefined, command: string, data?: Record<string, unknown>): void {
	writeFrame({ id, type: "response", command, success: true, ...(data === undefined ? {} : { data }) });
}

function refuse(id: string | undefined, command: string, error: string): void {
	writeFrame({ id, type: "response", command, success: false, error });
}

function readyFrame(): Record<string, unknown> {
	return {
		type: "ready",
		protocolVersion: 1,
		supportedProtocolVersions: [1, 2],
		maxFrameBytes: MAX_FRAME_BYTES,
		maxReassembledFrameBytes: MAX_REASSEMBLED_BYTES,
	};
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Canonical padded standard base64 only; Buffer's permissive decoder is not enough. */
function decodeBase64(value: string): Buffer | undefined {
	if (value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
		return undefined;
	}
	const decoded = Buffer.from(value, "base64");
	return decoded.toString("base64") === value ? decoded : undefined;
}

/** Handle one stdin line: a JSON fixture command. */
function handleLine(line: string): void {
	let frame: unknown;
	try {
		frame = JSON.parse(line);
	} catch {
		refuse(undefined, "unknown", "fixture could not parse the command line as JSON");
		return;
	}
	if (!isRecord(frame) || typeof frame.type !== "string") {
		refuse(undefined, "unknown", "fixture command must be an object with a string type");
		return;
	}
	const id = typeof frame.id === "string" ? frame.id : undefined;

	switch (frame.type) {
		case "negotiate_protocol":
			if (frame.protocolVersion !== 2) {
				refuse(id, "negotiate_protocol", `Unsupported RPC protocol version: ${String(frame.protocolVersion)}`);
			} else {
				ack(id, "negotiate_protocol", { protocolVersion: 2 });
			}
			return;

		case "fixture_emit": {
			const lines = frame.lines;
			if (!Array.isArray(lines) || !lines.every(entry => typeof entry === "string")) {
				refuse(id, "fixture_emit", "fixture_emit requires lines: string[]");
				return;
			}
			if (lines.length > MAX_EMIT_LINES) {
				refuse(id, "fixture_emit", `fixture_emit exceeds ${MAX_EMIT_LINES} lines`);
				return;
			}
			const emittedBytes = lines.reduce((total, entry) => total + Buffer.byteLength(entry) + 1, 0);
			if (!Number.isSafeInteger(emittedBytes) || emittedBytes > MAX_EMIT_BYTES) {
				refuse(id, "fixture_emit", `fixture_emit exceeds ${MAX_EMIT_BYTES} bytes`);
				return;
			}
			ack(id, "fixture_emit", { emitted: lines.length, byteLength: emittedBytes });
			for (const entry of lines) {
				process.stdout.write(`${entry}\n`);
			}
			return;
		}

		case "fixture_emit_bytes": {
			if (typeof frame.base64 !== "string") {
				refuse(id, "fixture_emit_bytes", "fixture_emit_bytes requires canonical base64");
				return;
			}
			const bytes = decodeBase64(frame.base64);
			if (!bytes) {
				refuse(id, "fixture_emit_bytes", "fixture_emit_bytes requires canonical base64");
				return;
			}
			if (bytes.length > MAX_EMIT_BYTES) {
				refuse(id, "fixture_emit_bytes", `fixture_emit_bytes exceeds ${MAX_EMIT_BYTES} bytes`);
				return;
			}
			ack(id, "fixture_emit_bytes", { byteLength: bytes.length });
			process.stdout.write(bytes);
			return;
		}

		case "fixture_emit_fault":
			if (frame.fault === "physical_oversize") {
				ack(id, "fixture_emit_fault", { fault: frame.fault });
				process.stdout.write(Buffer.alloc(MAX_FRAME_BYTES, 0x78));
				process.stdout.write("\n");
				return;
			}
			if (frame.fault === "reassembled_invalid_utf8") {
				ack(id, "fixture_emit_fault", { fault: frame.fault });
				const payload = Buffer.alloc(MAX_FRAME_BYTES, 0x78);
				payload[payload.length - 1] = 0xff;
				const count = 4;
				for (let index = 0; index < count; index += 1) {
					const start = index * (MAX_FRAME_BYTES / count);
					writeFrame({
						type: "rpc_chunk",
						chunkId: "odin-fixture-invalid-utf8",
						index,
						count,
						byteLength: MAX_FRAME_BYTES,
						data: payload.subarray(start, start + MAX_FRAME_BYTES / count).toString("base64"),
					});
				}
				return;
			}
			refuse(
				id,
				"fixture_emit_fault",
				"fixture_emit_fault requires physical_oversize or reassembled_invalid_utf8",
			);
			return;

		default:
			refuse(id, frame.type, "unknown fixture command");
	}
}

// Startup: the ready frame comes first, before any command is read.
writeFrame(readyFrame());

const decoder = new TextDecoder("utf-8", { fatal: true });
let segments: Buffer[] = [];
let lineBytes = 0;
let discardingOversize = false;

/** Consume stdin without ever accumulating more than one physical command frame. */
async function consumeInput(): Promise<void> {
	for await (const input of process.stdin) {
		const chunk = Buffer.isBuffer(input) ? input : Buffer.from(input);
		let offset = 0;
		while (offset < chunk.length) {
			const newline = chunk.indexOf(0x0a, offset);
			const end = newline === -1 ? chunk.length : newline;
			const segment = chunk.subarray(offset, end);
			if (!discardingOversize) {
				if (lineBytes + segment.length + 1 > MAX_COMMAND_BYTES) {
					segments = [];
					lineBytes = 0;
					discardingOversize = true;
				} else if (segment.length > 0) {
					segments.push(segment);
					lineBytes += segment.length;
				}
			}
			if (newline === -1) break;

			if (discardingOversize) {
				refuse(undefined, "unknown", `fixture command exceeds ${MAX_COMMAND_BYTES} bytes`);
			} else {
				const bytes = lineBytes === 0 ? EMPTY_BUFFER : Buffer.concat(segments, lineBytes);
				try {
					handleLine(decoder.decode(bytes));
				} catch {
					refuse(undefined, "unknown", "fixture command is not valid UTF-8");
				}
			}
			segments = [];
			lineBytes = 0;
			discardingOversize = false;
			offset = newline + 1;
		}
	}

	if (discardingOversize) {
		refuse(undefined, "unknown", `unterminated fixture command exceeds ${MAX_COMMAND_BYTES} bytes`);
	} else if (lineBytes > 0) {
		refuse(undefined, "unknown", "fixture command line is not newline terminated");
	}
}

await consumeInput();
