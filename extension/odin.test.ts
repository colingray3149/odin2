import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import odin, { readRootTarget } from "./odin.ts";

type Entry = { type: string; data: unknown };

/** Sets the variables for the length of `run` (undefined deletes one) and restores every one, even when `run` throws. */
function withEnv<T>(env: Record<string, string | undefined>, run: () => T): T {
  const saved = Object.keys(env).map((name) => [name, process.env[name]] as const);
  const set = (values: ReadonlyArray<readonly [string, string | undefined]>) => {
    for (const [name, value] of values) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  };
  const restore = () => set(saved);
  set(Object.entries(env));
  let result: T;
  try {
    result = run();
  } catch (error) {
    restore();
    throw error;
  }
  if (result instanceof Promise) return result.finally(restore) as T;
  restore();
  return result;
}

/** How one journal write fails: by throwing, or by rejecting after the call returned. */
type Failure = "throw" | "reject";

/** The harness the extension is loaded into: it records the journal, and `active` starts as every tool the harness has. */
function makePi(available: string[], fails?: (type: string) => Failure | undefined) {
  const handlers = new Map<string, Function>();
  const entries: Entry[] = [];
  let active = [...available];
  const harness: Pick<ExtensionAPI, "getAllTools" | "getActiveTools" | "setActiveTools" | "appendEntry"> = {
    getAllTools: () => available.map((name) => ({ name })),
    getActiveTools: () => active,
    setActiveTools: async (names) => {
      active = names;
    },
    appendEntry: (type, data) => {
      const failure = fails?.(type);
      if (failure === "throw") throw new Error("disk full");
      if (failure === "reject") return Promise.reject(new Error("disk full"));
      entries.push({ type, data });
    },
  };
  const pi = { ...harness, on: (name: string, handler: Function) => void handlers.set(name, handler) };
  return { pi: pi as unknown as ExtensionAPI, handlers, entries, active: () => active };
}

/** The extension loaded with the host's declaration of `issued` tools, of which the harness has `available`. */
function fixture(available: string[], issued: string[], hostUriSchemes?: string, env: Record<string, string | undefined> = {}) {
  const f = makePi(available);
  const base = { ODIN_HOST_TOOLS: issued.join(","), ODIN_HOST_URI_SCHEMES: hostUriSchemes, ODIN_READ_PATHS: undefined, ODIN_READ_ROOTS: undefined, ODIN_CONTEXT_BUDGET: undefined };
  withEnv({ ...base, ...env }, () => odin(f.pi));
  return f;
}
const ctx = { sessionManager: { getSessionId: () => "fixture" } };


test("a declared shell wraps a command once; a command already in the wrapper form is left as the model sent it", async () => {
  // OMP bakes a revised input into the model's own history, so the model copies
  // the wrapper; wrapping it again nests quotes on every turn.
  const f = fixture(["capsule_eval_run", "bash"], ["capsule_eval_run"]);
  const gate = f.handlers.get("tool_call")!;
  await withEnv({ ODIN_SHELL: "1" }, async () => {
    expect(await gate({ toolName: "bash", input: { command: "echo 'a' && pwd" } }, ctx)).toEqual({ input: { command: "/bin/bash -c 'echo '\\''a'\\'' && pwd'" } });
    expect(await gate({ toolName: "bash", input: { command: "/bin/bash -c 'echo '\\''a'\\'' && pwd'" } }, ctx)).toBeUndefined();
    // Anything after the quoted body would run outside the shell bubble: wrap it.
    expect(await gate({ toolName: "bash", input: { command: "/bin/bash -c 'ls' && rm x" } }, ctx)).toEqual({
      input: { command: "/bin/bash -c '/bin/bash -c '\\''ls'\\'' && rm x'" },
    });
  });
});

const DUTIES = ["seat_ask_kubert", "seat_ask_gungnir", "terminal_read", "huginn_read"];
const SURFACES = [
  { name: "browser and delegation lifecycle", issued: ["browser_observe", "task_create", "task_read"] },
  { name: "duty asks and reads", issued: DUTIES },
  { name: "kube reads", issued: ["kube_snapshot_read", "kube_health_read", "kube_workload_summarize"] },
  { name: "toolsets with no compiled name table", issued: ["brain", "calendar", "files", "delegate", "coord_assist"] },
];

test("the lock leaves exactly the declared tools active, turn after turn: each stays callable and nothing else the harness has", async () => {
  for (const surface of SURFACES) {
    const extras = ["bash", "seat_ask_architect", "web_read"].filter((name) => !surface.issued.includes(name));
    const f = fixture([...surface.issued, ...extras], surface.issued);
    for (let turn = 0; turn < 2; turn++) {
      await f.handlers.get("before_agent_start")!({}, ctx);
      expect(f.active().sort()).toEqual([...surface.issued].sort());
    }
    const gate = f.handlers.get("tool_call")!;
    for (const name of surface.issued) expect(await gate({ toolName: name, input: {} }, ctx)).toBeUndefined();
    for (const name of extras) expect(await gate({ toolName: name, input: {} }, ctx)).toMatchObject({ block: true });
  }
});

test("a declared tool the harness does not have rejects the turn instead of hiding broken delegation", async () => {
  const f = fixture([], ["task_read"]);
  await expect(f.handlers.get("before_agent_start")!({}, ctx)).rejects.toThrow(/governed tool surface mismatch.*task_read/);
});

test("a launch without the host's tool listing fails closed and names it", () => {
  const f = makePi(["task_read"]);
  expect(() => withEnv({ ODIN_HOST_TOOLS: undefined }, () => odin(f.pi))).toThrow("host-issued tool listing is missing");
});

const HOST_URI_SCHEMES = "approval,odin-artifact,atlas,brain,incident,lane,run";

const ITEM = `brain://blake3:${"a".repeat(64)}`;

test("declared host URI schemes admit the read tool for canonical host URIs only", async () => {
  await f.handlers.get("before_agent_start")!({}, ctx);
  const gate = f.handlers.get("tool_call")!;
  for (const path of [ITEM, `${ITEM}:0:512`, "atlas://", "approval://some-approval-id", "lane://sinmara.file.in", "odin-artifact://5"]) {
    expect(await gate({ toolName: "read", input: { path } }, ctx)).toBeUndefined();
  }
  for (const path of [
    // local, web and other schemes stay refused; artifact:// is OMP's own store, never a host scheme
    "/etc/passwd",
    "file:///etc/passwd",
    "https://example.com/notes",
    "artifact://5",
    // scheme case is canonical: upper or mixed case is refused, not folded
    "BRAIN://x",
    // multi-target forms the harness would split
    `${ITEM};/etc/passwd`,
    `${ITEM},${ITEM}`,
    `${ITEM} /etc/passwd`,
    // shapes outside the canonical identifier
    "brain://a%2Fb",
    "brain://a/../b",
    "brain://a?q=1",
    `brain://${"a".repeat(129)}`,
    `brain://${"a".repeat(64)}\u0000`,
  ]) {
    expect(await gate({ toolName: "read", input: { path } }, ctx)).toMatchObject({ block: true });
  }
  for (const input of [{}, { path: 7 }, { path: ITEM, url: "https://example.com/notes" }, [ITEM]]) {
    expect(await gate({ toolName: "read", input }, ctx)).toMatchObject({ block: true });
  }
});

test("a scheme the host did not declare is refused even though the read tool is active", async () => {
  await f.handlers.get("before_agent_start")!({}, ctx);
  const gate = f.handlers.get("tool_call")!;
  expect(await gate({toolName:"read",input:{path:ITEM}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:"atlas://some-node"}}, ctx)).toMatchObject({block:true});
  expect(await gate({toolName:"read",input:{path:"lane://sinmara.file.in"}}, ctx)).toMatchObject({block:true});
});

test("native read refuses web URLs and names web_read", async () => {
  const f = fixture(["web_read", "read"], ["web_read"], HOST_URI_SCHEMES);
  await f.handlers.get("before_agent_start")!({}, ctx);
  const gate = f.handlers.get("tool_call")!;
  for (const url of ["https://arxiv.org/abs/2510.00001", "http://example.com/"]) {
    const refused = await gate({toolName:"read",input:{path:url}}, ctx);
    expect(refused).toMatchObject({block:true});
    expect(refused.reason).toContain("web_read");
  }
});

test("native read refuses an artifact:// reference and names the files artifact op", async () => {
  const f = fixture(["files", "read"], ["files"], HOST_URI_SCHEMES);
  await f.handlers.get("before_agent_start")!({}, ctx);
  const refused = await f.handlers.get("tool_call")!({toolName:"read",input:{path:"artifact://1"}}, ctx);
  expect(refused).toMatchObject({block:true});
  expect(refused.reason).toContain("files tool's artifact op");
});

test("a workload pod reads exactly its staged launch-input files, and a declared path outside the staging mount stops the launch", async () => {
  const f = fixture(["artifact_read", "read", "bash"], ["artifact_read"], HOST_URI_SCHEMES, {
    ODIN_READ_PATHS: "/var/run/odin/staging/input-2",
  });
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active().sort()).toEqual(["artifact_read", "read"]);
  const gate = f.handlers.get("tool_call")!;
  const read = (path: string) => gate({ toolName: "read", input: { path } }, ctx);
  expect(await read("/var/run/odin/staging/input-2")).toBeUndefined();
  expect(await read("/var/run/odin/staging/input-2:raw")).toBeUndefined();
  // Paging the staged file is allowed: each selector form the harness names.
  for (const paged of [
    "/var/run/odin/staging/input-2:10-20",
    "/var/run/odin/staging/input-2:7",
    "/var/run/odin/staging/input-2:raw:1-5",
    "/var/run/odin/staging/input-2:1-5:raw",
  ]) {
    expect(await read(paged)).toBeUndefined();
  }
  for (const refused of [
    "/var/run/odin/staging/input-0",
    "/var/run/odin/staging/input-0:10-20",
    "/var/run/odin/staging/input-2/../input-0",
    "/var/run/odin/staging/input-2:1-",
    "/var/run/odin/staging/input-2:raw:7",
    "/var/run/odin/staging/input-2:1:2:3",
    "/etc/passwd",
    "file:///var/run/odin/staging/input-2",
  ]) {
    expect(await read(refused)).toMatchObject({ block: true });
  }
  expect(await gate({ toolName: "read", input: { path: "/var/run/odin/staging/input-2", offset: 1 } }, ctx)).toMatchObject({ block: true });
  expect(String(((await read("/tmp/x")) as { reason: string }).reason)).toContain("/var/run/odin/staging/input-2");
  expect(() => fixture(["read"], [], undefined, { ODIN_READ_PATHS: "/var/run/odin/staging/input-2,/etc/passwd" })).toThrow(
    /ODIN_READ_PATHS names \/etc\/passwd/,
  );
});

test("without a host URI declaration the read tool stays stripped and refused", async () => {
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(await f.handlers.get("tool_call")!({toolName:"read",input:{path:ITEM}}, ctx)).toMatchObject({block:true});
});

/** The extension loaded with a context budget; `fails` makes chosen journal writes fail. */
function budgetFixture(
  budget: string | undefined,
  currentModel: { provider: string; id: string; api?: string; tokenizer?: string; input?: string[] } | undefined,
  fails?: (type: string) => Failure | undefined,
) {
  const f = makePi(["task_read"], fails);
  withEnv(
    { ODIN_HOST_TOOLS: "task_read", ODIN_HOST_URI_SCHEMES: undefined, ODIN_READ_PATHS: undefined, ODIN_CONTEXT_BUDGET: budget },
    () => odin(f.pi),
  );
  const aborts: string[] = [];
  const requestCtx = {
    sessionManager: { getSessionId: () => "fixture" },
    abort: () => {
      aborts.push("abort");
    },
    models: { current: () => currentModel },
  };
  return { handlers: f.handlers, entries: f.entries, aborts, ctx: requestCtx };
}

function sizedPayload(bytes: number, outputTokens = 100) {
  // Pure 'x' content makes the serialized byte length exactly computable;
  // max_tokens is the openai-completions output bound the guard reads.
  const overhead = Buffer.byteLength(
    JSON.stringify({ messages: [{ role: "user", content: "" }], max_tokens: outputTokens }),
    "utf8",
  );
  return { messages: [{ role: "user", content: "x".repeat(bytes - overhead) }], max_tokens: outputTokens };
}

const GUARD = "before_provider_request";

const MARKER = "odin.context_refusal.v1";

const MODEL = { provider: "gateway", id: "herald-model", api: "openai-completions" };

// Keep marker validation aligned with crates/odin-omp/src/bridge/contracts.rs.

const REFUSAL_CODES = new Set([
  "window_exceeded",
  "model_identity_mismatch",
  "declaration_unusable",
  "api_unresolved",
  "payload_not_json",
  "payload_uncountable",
  "media_uncountable",
  "output_unboundable",
  "output_uncappable",
  "envelope_invalid",
]);

const REFUSAL_NUMERIC_FIELDS = [
  "request_bytes",
  "requested_output",
  "reserve",
  "window",
  "input_tokens",
];

function strictParseMarker(message: string): Record<string, unknown> | null {
  if (!message.startsWith(`${MARKER}|`)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(message.slice(MARKER.length + 1));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const record: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(parsed)) record[key] = value;
  if (typeof record.code !== "string" || !REFUSAL_CODES.has(record.code)) return null;
  if (typeof record.reason !== "string" || record.reason.length === 0) return null;
  for (const field of REFUSAL_NUMERIC_FIELDS) {
    if (field in record && typeof record[field] !== "number") return null;
  }
  return record;
}

function markerOf(error: unknown): { code: string; reason: string } {
  const message = error instanceof Error ? error.message : String(error);
  const parsed = strictParseMarker(message);
  expect(parsed).not.toBeNull();
  return { code: parsed!.code as string, reason: parsed!.reason as string };
}

async function expectRefusal(f: ReturnType<typeof budgetFixture>, payload: unknown): Promise<{ code: string; reason: string }> {
  let parsed: { code: string; reason: string } | undefined;
  await expect(
    f.handlers.get(GUARD)!({ payload }, f.ctx).then(
      () => { throw new Error("expected a refusal, got pass-through"); },
      (error: unknown) => { parsed = markerOf(error); },
    ),
  ).resolves.toBeUndefined();
  expect(f.aborts).toEqual(["abort"]);
  expect(f.entries.some((entry) => entry.type === "odin.extension.context_refusal")).toBe(true);
  return parsed!;
}

test("without a declared budget the request guard is inert", async () => {
  const f = budgetFixture(undefined, MODEL);
  expect(await f.handlers.get(GUARD)!({ payload: sizedPayload(4000) }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
});

test("a fitting complete request passes byte-untouched", async () => {
  const f = budgetFixture("gateway|herald-model|10000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const payload = sizedPayload(9000);
  expect(Buffer.byteLength(JSON.stringify(payload), "utf8")).toBe(9000);
  expect(await f.handlers.get(GUARD)!({ payload }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
});

test("the exact window boundary fits: bytes + the narrowed output cap == window is allowed", async () => {
  // A request whose own cap fits the reserve is counted at its OWN cap
  // (100), never at the reserve: 9000 + 100 == 9100 is the exact boundary.
  const f = budgetFixture("gateway|herald-model|9100|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  expect(await f.handlers.get(GUARD)!({ payload: sizedPayload(9000, 100) }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
  const g = budgetFixture("gateway|herald-model|9099|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const refusal = await expectRefusal(g, sizedPayload(9000, 100));
  expect(refusal.code).toBe("window_exceeded");
  expect(refusal.reason).toContain("9100");
});

test("an omitted output bound gets the declared reserve inserted as the request's own cap", async () => {
  const f = budgetFixture("gateway|herald-model|10000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const payload = sizedPayload(9000);
  delete (payload as Record<string, unknown>).max_tokens;
  const result = (await f.handlers.get(GUARD)!({ payload }, f.ctx)) as Record<string, unknown>;
  expect(result.max_completion_tokens).toBe(500);
  // the caller's payload object is not mutated; everything else preserved.
  expect("max_completion_tokens" in payload).toBe(false);
  expect(result.messages).toEqual(payload.messages);
  expect(f.aborts).toEqual([]);
});

test("an api that cannot omit its required output bound is refused when it is absent", async () => {
  const f = budgetFixture("gateway|herald-model|9600|500|odin.tokenizer.utf8-bytes.v1", { provider: "gateway", id: "herald-model", api: "anthropic-messages" });
  const payload = sizedPayload(9000);
  delete (payload as Record<string, unknown>).max_tokens;
  const refusal = await expectRefusal(f, payload);
  expect(refusal.code).toBe("output_unboundable");
});

test("an api with no known output field is refused as unboundable", async () => {
  const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", { provider: "gateway", id: "herald-model", api: "ollama-chat" });
  const refusal = await expectRefusal(f, sizedPayload(1000));
  expect(refusal.code).toBe("output_unboundable");
});

test("an over-asking output request is narrowed to the effective reserve, not counted at its demand", async () => {
  // Budget the narrowed output reserve, not the larger requested limit.
  const f = budgetFixture("gateway|herald-model|20000|6144|odin.tokenizer.utf8-bytes.v1", MODEL);
  const payload = sizedPayload(9000, 65536);
  const result = (await f.handlers.get(GUARD)!({ payload }, f.ctx)) as Record<string, unknown>;
  expect(result.max_tokens).toBe(6144);
  expect(payload.max_tokens).toBe(65536);
  expect(f.aborts).toEqual([]);
  // An over-ask that STILL busts the window after narrowing refuses and
  // reports both the requested and narrowed numbers.
  const g = budgetFixture("gateway|herald-model|9000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const refusal = await expectRefusal(g, sizedPayload(9000, 65536));
  expect(refusal.code).toBe("window_exceeded");
  expect(refusal.reason).toContain("narrowed to the 500 effective reserve");
  const entry = g.entries[0].data as Record<string, unknown>;
  expect(entry.requested_output).toBe(65536);
  // The counted bytes are the POST-clamp payload ("65536" -> "500").
  expect(entry.request_bytes).toBe(
    Buffer.byteLength(JSON.stringify({ ...sizedPayload(9000, 65536), max_tokens: 500 }), "utf8"),
  );
  expect(entry.input_tokens).toBe(entry.request_bytes);
});

test("an over-window request with an inserted output cap omits the absent numeric field", async () => {
  const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const payload = sizedPayload(9000);
  delete (payload as Record<string, unknown>).max_tokens;
  let message = "";
  await expect(
    f.handlers.get(GUARD)!({ payload }, f.ctx).catch((error: unknown) => {
      message = error instanceof Error ? error.message : String(error);
    }),
  ).resolves.toBeUndefined();
  const parsed = strictParseMarker(message);
  expect(parsed).not.toBeNull();
  expect(parsed!.code).toBe("window_exceeded");
  expect("requested_output" in parsed!).toBe(false);
  // Byte mode reports the same honest number in both units: the declared
  // byte identity counts one token per byte.
  expect(parsed!.input_tokens).toBe(parsed!.request_bytes);
  expect(parsed!.request_bytes).toBe(
    Buffer.byteLength(JSON.stringify({ ...payload, max_completion_tokens: 500 }), "utf8"),
  );
  expect(parsed!.reserve).toBe(500);
  expect(parsed!.window).toBe(8000);
});

test("an oversized first request is refused honestly before any dispatch", async () => {
  const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const refusal = await expectRefusal(f, sizedPayload(9000));
  expect(refusal.code).toBe("window_exceeded");
  // The request's own 100-token cap fits the reserve, so the allowance is
  // its own 100: 9000 + 100 = 9100 exceeds the 8000 window.
  expect(refusal.reason).toContain("9100");
  expect(refusal.reason).toContain("8000");
  const data = f.entries[0].data as {
    request_bytes: number;
    input_tokens: number;
    window: number;
    reserve: number;
    code: string;
  };
  expect(data.request_bytes).toBe(9000);
  expect(data.input_tokens).toBe(9000);
  expect(data.reserve).toBe(500);
  expect(data.window).toBe(8000);
  expect(data.code).toBe("window_exceeded");
});

test("the refusal rides the wire marker and the terminal even when journaling fails", async () => {
  const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", MODEL, () => "throw");
  const seen: string[] = [];
  const original = console.error;
  console.error = (message: string) => {
    seen.push(message);
  };
  let refusal: { code: string } | undefined;
  try {
    await f.handlers.get(GUARD)!({ payload: sizedPayload(9000) }, f.ctx).then(
      () => {
        throw new Error("expected a refusal, got pass-through");
      },
      (error: unknown) => {
        refusal = markerOf(error);
      },
    );
  } finally {
    console.error = original;
  }
  expect(refusal!.code).toBe("window_exceeded");
  expect(f.aborts).toEqual(["abort"]);
  expect(seen.some((line) => line.includes("journal entry failed"))).toBe(true);
  expect(seen.some((line) => line.includes("context request refused"))).toBe(true);
});

test("an in-tool-loop growth that crosses the window is refused on that request", async () => {
  const f = budgetFixture("gateway|herald-model|14000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  expect(await f.handlers.get(GUARD)!({ payload: sizedPayload(13000) }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
  const refusal = await expectRefusal(f, sizedPayload(14000));
  expect(refusal.code).toBe("window_exceeded");
});

test("a request on a model other than the declared identity is refused, never guarded by a foreign window", async () => {
  const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", { provider: "gateway", id: "other-model", api: "openai-completions" });
  const refusal = await expectRefusal(f, sizedPayload(100));
  expect(refusal.code).toBe("model_identity_mismatch");
  expect(refusal.reason).toContain("gateway/herald-model");
  expect(refusal.reason).toContain("gateway/other-model");
});

test("a declared model switch is guarded by its own lane's window, never refused as foreign", async () => {
  const lanes = "gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1;gateway|switch-model|20000|500|odin.tokenizer.utf8-bytes.v1";
  const switched = { provider: "gateway", id: "switch-model", api: "openai-completions" };
  const f = budgetFixture(lanes, switched);
  expect(await f.handlers.get(GUARD)!({ payload: sizedPayload(9000) }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
  expect((await expectRefusal(budgetFixture(lanes, switched), sizedPayload(21000))).code).toBe("window_exceeded");
  expect((await expectRefusal(budgetFixture(lanes, MODEL), sizedPayload(9000))).code).toBe("window_exceeded");
  const undeclared = await expectRefusal(budgetFixture(lanes, { provider: "gateway", id: "other-model", api: "openai-completions" }), sizedPayload(100));
  expect(undeclared.code).toBe("model_identity_mismatch");
  expect(undeclared.reason).toContain("gateway/switch-model");
  const oneBadLane = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1;gateway|switch-model|0|0|odin.tokenizer.utf8-bytes.v1", MODEL);
  expect((await expectRefusal(oneBadLane, sizedPayload(100))).code).toBe("declaration_unusable");
});

test("an unresolved request model or api is refused rather than guessed", async () => {
  const noModel = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", undefined);
  expect((await expectRefusal(noModel, sizedPayload(100))).code).toBe("model_identity_mismatch");
  const noApi = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", { provider: "gateway", id: "herald-model" });
  expect((await expectRefusal(noApi, sizedPayload(100))).code).toBe("api_unresolved");
});

test("a malformed host budget declaration fails closed, naming nothing it cannot count with", async () => {
  for (const budget of [
    "gateway|herald-model|0|0|odin.tokenizer.utf8-bytes.v1",
    "gateway|herald-model|8000",
    "gateway|herald-model|800|900|odin.tokenizer.utf8-bytes.v1",
    "gateway|herald-model|8000|500|odin.tokenizer.gpt4.v9",
    "gateway|herald-model|8000|500|constructor",
  ]) {
    const f = budgetFixture(budget, MODEL);
    expect((await expectRefusal(f, sizedPayload(100))).code).toBe("declaration_unusable");
    await f.handlers.get("session_start")!({}, f.ctx);
    expect(f.entries.filter((entry) => entry.type === "odin.extension.context_budget")).toEqual([]);
  }
});

test("session start journals each declared lane once, with the counter its tokenizer names", async () => {
  const f = budgetFixture(
    "gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1;gateway|local-model|9000|600|odin.tokenizer.qwen3.v1;gateway|hosted-model|500000|8000|odin.tokenizer.estimate.v1",
    MODEL,
  );
  await f.handlers.get("session_start")!({}, f.ctx);
  const lanes = f.entries.filter((entry) => entry.type === "odin.extension.context_budget").map((entry) => entry.data);
  expect(lanes).toMatchObject([
    { model: "herald-model", window: 8000, reserve: 500, counter: "bytes" },
    { model: "local-model", window: 9000, reserve: 600, counter: "qwen3" },
    { model: "hosted-model", window: 500000, reserve: 8000, counter: "estimate" },
  ]);
});

test("an estimate lane admits a 480 KB request in its 500k window, then calibrates its ratio from the provider's usage", async () => {
  const f = budgetFixture("gateway|herald-model|500000|8000|odin.tokenizer.estimate.v1", MODEL);
  // Uncalibrated: one token per four bytes, so 480 KB is 120 000 tokens.
  expect(await f.handlers.get(GUARD)!({ payload: sizedPayload(480_000) }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
  // 2 000 000 bytes estimate to 500 000 tokens: with the 100-token allowance, past the window.
  const refusal = await expectRefusal(budgetFixture("gateway|herald-model|500000|8000|odin.tokenizer.estimate.v1", MODEL), sizedPayload(2_000_000));
  expect(refusal.code).toBe("window_exceeded");
  expect(refusal.reason).toContain("estimated tokens");
  // The response reports 480 000 bytes as 240 000 input tokens (100 000 fresh, 140 000 cached): 0.5 tokens per byte from here on.
  await f.handlers.get("after_provider_response")?.({ requestId: "req-est", headers: {} }, f.ctx);
  await f.handlers.get("message_end")?.({
    message: { role: "assistant", responseId: "resp-est", content: [], usage: { input: 100_000, cacheRead: 140_000, cacheWrite: 0 }, stopReason: "stop" },
  }, f.ctx);
  const link = f.entries.filter((entry) => entry.type === "odin.extension.model_request_link").at(-1)!.data as { estimate: Record<string, unknown> };
  expect(link.estimate).toMatchObject({ lane: "gateway/herald-model", request_bytes: 480_000, tokens_per_byte: 0.25, observed_input_tokens: 240_000 });
  expect((await expectRefusal(f, sizedPayload(1_000_000))).code).toBe("window_exceeded");
});

const NATIVE_BUDGET = "gateway|herald-model|16384|6144|odin.tokenizer.qwen3.v1";

const QWEN3_MODEL = { provider: "gateway", id: "herald-model", api: "openai-completions", tokenizer: "qwen3" };

test("a native lane refuses a model whose tokenizer family is missing or foreign, never guessing", async () => {
  const unresolved = budgetFixture(NATIVE_BUDGET, { provider: "gateway", id: "herald-model", api: "openai-completions" });
  const refusal = await expectRefusal(unresolved, sizedPayload(100));
  expect(refusal.code).toBe("model_identity_mismatch");
  expect(refusal.reason).toContain("qwen3");
  expect(refusal.reason).toContain("unresolved");
  const foreign = budgetFixture(NATIVE_BUDGET, { provider: "gateway", id: "herald-model", api: "openai-completions", tokenizer: "glm5" });
  expect((await expectRefusal(foreign, sizedPayload(100))).code).toBe("model_identity_mismatch");
  // The byte lane demands no family: its counting is family-independent.
  const byteLane = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  expect(await byteLane.handlers.get(GUARD)!({ payload: sizedPayload(100) }, byteLane.ctx)).toBeUndefined();
});

test("a native lane counts the whole request with the pinned qwen3 engine, reported beside the byte length", async () => {
  // The same platform-specific native addon the guard uses statically;
  // resolved here to compute self-consistent expectations (no magic
  // counts, no /4 guesses).
  const natives = await import("@oh-my-pi/pi-natives");
  const busterCount = natives.countTokens(
    JSON.stringify(sizedPayload(60000)),
    natives.Encoding.Qwen3,
  );
  const f = budgetFixture(`gateway|herald-model|${busterCount - 1}|6144|odin.tokenizer.qwen3.v1`, QWEN3_MODEL);
  const payload = sizedPayload(2000);
  delete (payload as Record<string, unknown>).max_tokens;
  expect(await f.handlers.get(GUARD)!({ payload }, f.ctx)).toMatchObject({ max_completion_tokens: 6144 });
  expect(f.aborts).toEqual([]);
  const windowBuster = sizedPayload(60000);
  const refusal = await expectRefusal(f, windowBuster);
  expect(refusal.code).toBe("window_exceeded");
  // Journal fields are JSON numbers by the strict marker contract.
  const entry = f.entries.find((item) => item.type === "odin.extension.context_refusal")!.data as { input_tokens: number; request_bytes: number };
  const expected = natives.countTokens(
    JSON.stringify({ ...sizedPayload(60000) }),
    natives.Encoding.Qwen3,
  );
  expect(entry.input_tokens).toBe(expected);
  expect(entry.request_bytes).toBe(Buffer.byteLength(JSON.stringify(sizedPayload(60000)), "utf8"));
  expect(entry.input_tokens).toBeGreaterThan(0);
  expect(entry.input_tokens).toBeLessThanOrEqual(entry.request_bytes);
  expect(refusal.reason).toContain("qwen3 tokens");
}, 30_000); // loads the real qwen3 tokenizer, which takes longer than bun's 5 s on a loaded machine

test("the native lane's exact window boundary is the native count plus the effective cap", async () => {
  const natives = await import("@oh-my-pi/pi-natives");
  const payload = sizedPayload(2000);
  const serialized = JSON.stringify(payload);
  const counted = natives.countTokens(serialized, natives.Encoding.Qwen3);
  const reserve = 100;
  // The request's own 100-token cap fits the reserve: the allowance is
  // its own 100, and counted + 100 is the exact boundary in NATIVE units.
  const fits = budgetFixture(`gateway|herald-model|${counted + 100}|${reserve}|odin.tokenizer.qwen3.v1`, QWEN3_MODEL);
  expect(await fits.handlers.get(GUARD)!({ payload: { ...payload } }, fits.ctx)).toBeUndefined();
  expect(fits.aborts).toEqual([]);
  const busts = budgetFixture(`gateway|herald-model|${counted + 99}|${reserve}|odin.tokenizer.qwen3.v1`, QWEN3_MODEL);
  const refusal = await expectRefusal(busts, { ...payload });
  expect(refusal.code).toBe("window_exceeded");
  expect(refusal.reason).toContain(`${counted + 100}`);
});

test("a native lane's inserted cap is counted after insertion", async () => {
  const natives = await import("@oh-my-pi/pi-natives");
  const payload = sizedPayload(60000);
  delete (payload as Record<string, unknown>).max_tokens;
  // The inserted shape mirrors the guard exactly: the payload WITHOUT its
  // deleted bound plus the inserted max_completion_tokens — never a spread
  // that resurrects the deleted field.
  const expectedAfterInsert = natives.countTokens(
    JSON.stringify({ ...payload, max_completion_tokens: 6144 }),
    natives.Encoding.Qwen3,
  );
  const f = budgetFixture(`gateway|herald-model|${expectedAfterInsert - 1}|6144|odin.tokenizer.qwen3.v1`, QWEN3_MODEL);
  const refusal = await expectRefusal(f, payload);
  expect(refusal.code).toBe("window_exceeded");
  const entry = f.entries[0].data as Record<string, unknown>;
  expect(entry.input_tokens).toBe(expectedAfterInsert);
}, 30_000); // tokenizes 60 KB natively; seconds on a loaded machine

test("an uncountable provider payload is refused, never passed through", async () => {
  const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const circular: Record<string, unknown> = {};
  circular.self = circular;
  expect((await expectRefusal(f, circular)).code).toBe("payload_uncountable");
  const nonObject = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  expect((await expectRefusal(nonObject, "plain string")).code).toBe("payload_not_json");
});

test("each api refuses its own provider media parts, remote or inline", async () => {
  // Only the parts each provider's own wire types define as media are
  // media; every shape below sits in that api's real content position.
  const cases: Array<{ api: string; part: unknown }> = [
    { api: "openai-completions", part: { type: "image_url", image_url: { url: "https://example.com/huge.png" } } },
    { api: "openai-completions", part: { type: "input_audio", input_audio: { data: "AAAA", format: "wav" } } },
    { api: "openai-completions", part: { type: "file", file: { file_id: "file-abc123" } } },
    { api: "google-generative-ai", part: { inlineData: { mimeType: "image/png", data: "AAAA" } } },
    { api: "google-generative-ai", part: { fileData: { fileUri: "https://example.com/f.pdf" } } },
    { api: "google-vertex", part: { inline_data: { mime_type: "image/png", data: "AAAA" } } },
    { api: "anthropic-messages", part: { type: "image", source: { type: "base64", media_type: "image/png", data: "AAAA" } } },
    { api: "anthropic-messages", part: { type: "image", source: { type: "url", url: "https://example.com/huge.png" } } },
    { api: "anthropic-messages", part: { type: "document", source: { type: "file", file_id: "file-abc123" } } },
  ];
  for (const { api, part } of cases) {
    const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", { provider: "gateway", id: "herald-model", api });
    let payload: Record<string, unknown>;
    if (api === "openai-completions") {
      payload = { ...sizedPayload(1000), messages: [{ role: "user", content: [{ type: "text", text: "look" }, part] }] };
    } else if (api.startsWith("google")) {
      payload = { contents: [{ role: "user", parts: [{ text: "look" }, part] }] };
    } else {
      payload = { model: "herald-model", max_tokens: 100, messages: [{ role: "user", content: [{ type: "text", text: "look" }, part] }] };
    }
    expect((await expectRefusal(f, payload)).code).toBe("media_uncountable");
  }
});

test("an inline chat image counts a fixed 8192 tokens on a byte lane and is traced by digest", async () => {
  const image = { type: "image_url", image_url: { url: `data:image/jpeg;base64,${"A".repeat(50_000)}` } };
  const payload = { messages: [{ role: "user", content: [{ type: "text", text: "look" }, image] }], max_tokens: 100 };
  const textBytes = Buffer.byteLength(
    JSON.stringify({ messages: [{ role: "user", content: [{ type: "text", text: "look" }] }], max_tokens: 100 }),
    "utf8",
  );
  const fits = budgetFixture(`gateway|herald-model|${textBytes + 8192 + 100}|500|odin.tokenizer.utf8-bytes.v1`, MODEL);
  expect(await fits.handlers.get(GUARD)!({ payload }, fits.ctx)).toBeUndefined();
  expect(fits.aborts).toEqual([]);
  const trace = JSON.stringify(fits.entries.find((entry) => entry.type === "odin.extension.model_request")?.data);
  expect(trace).not.toContain("AAAAAAAA");
  expect(trace).toContain("(50023 bytes)");
  const busts = budgetFixture(`gateway|herald-model|${textBytes + 8192 + 99}|500|odin.tokenizer.utf8-bytes.v1`, MODEL);
  const refusal = await expectRefusal(busts, payload);
  expect(refusal.code).toBe("window_exceeded");
  const native = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.qwen3.v1", QWEN3_MODEL);
  expect((await expectRefusal(native, payload)).code).toBe("media_uncountable");
});

test("a model without image input reads one relayable line per image; a vision model keeps them", async () => {
  const image = { type: "image", data: "AAAA", mimeType: "image/jpeg" };
  const messages = [
    { role: "user", content: [{ type: "text", text: "my notes" }, image] },
    { role: "toolResult", content: [{ type: "text", text: "{}" }, image] },
    { role: "user", content: "no image" },
  ];
  const blind = budgetFixture(undefined, { ...MODEL, input: ["text"] });
  const seen = (await blind.handlers.get("context")!({ messages }, blind.ctx)) as { messages: Array<{ content: unknown }> };
  const line = "[Odin: an image was here, but this model (gateway/herald-model) cannot see images; say so in one line instead of guessing what it shows]";
  expect(seen.messages[0].content).toEqual([{ type: "text", text: "my notes" }, { type: "text", text: line }]);
  expect(seen.messages[1].content).toEqual([{ type: "text", text: "{}" }, { type: "text", text: line }]);
  expect(seen.messages[2]).toBe(messages[2]);
  const vision = budgetFixture(undefined, { ...MODEL, input: ["text", "image"] });
  const kept = (await vision.handlers.get("context")!({ messages }, vision.ctx)) as { messages: unknown[] };
  expect(kept.messages).toEqual(messages);
});

test("a google generative-ai/vertex cap is read from params.config.maxOutputTokens, never a top-level generationConfig", async () => {
  const model = { provider: "gateway", id: "herald-model", api: "google-generative-ai" };
  // google-shared.ts passes SDK params to onPayload, so the cap belongs on params.config.
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", model);
  const payload = {
    contents: [{ role: "user", parts: [{ text: "x".repeat(1000) }] }],
    config: { temperature: 0.5, maxOutputTokens: 65536 },
  };
  const result = (await f.handlers.get(GUARD)!({ payload }, f.ctx)) as Record<string, unknown>;
  const config = result.config as Record<string, unknown>;
  expect(config.maxOutputTokens).toBe(500);
  expect(config.temperature).toBe(0.5);
  expect((payload.config as Record<string, unknown>).maxOutputTokens).toBe(65536);
  expect(f.aborts).toEqual([]);
  // A fitting request with its own cap on config passes UNTOUCHED (no
  // rewrite, and no phantom cap inserted on a top-level generationConfig).
  const g = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", model);
  const fitting = {
    contents: [{ role: "user", parts: [{ text: "x".repeat(1000) }] }],
    config: { temperature: 0.5, maxOutputTokens: 500 },
  };
  expect(await g.handlers.get(GUARD)!({ payload: fitting }, g.ctx)).toBeUndefined();
  expect(g.aborts).toEqual([]);
});

test("an omitted google direct/vertex cap is inserted on config, preserving every other field", async () => {
  const model = { provider: "gateway", id: "herald-model", api: "google-vertex" };
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", model);
  const payload = {
    contents: [{ role: "user", parts: [{ text: "x".repeat(1000) }] }],
    config: { temperature: 0.7, topP: 0.9 },
  };
  const result = (await f.handlers.get(GUARD)!({ payload }, f.ctx)) as Record<string, unknown>;
  const config = result.config as Record<string, unknown>;
  expect(config.maxOutputTokens).toBe(500);
  expect(config.temperature).toBe(0.7);
  expect(config.topP).toBe(0.9);
  // paramsToWireBody ignores a top-level generationConfig.
  expect("generationConfig" in result).toBe(false);
  expect("maxOutputTokens" in (payload.config as Record<string, unknown>)).toBe(false);
  expect(f.aborts).toEqual([]);
});

test("a gemini-cli cap is read from request.generationConfig and narrowed there, preserving the envelope", async () => {
  const model = { provider: "gateway", id: "herald-model", api: "google-gemini-cli" };
  // Pinned google-gemini-cli.ts: onPayload receives {project, model,
  // request}; the cap lives on request.generationConfig. The over-ask is
  // narrowed on that exact field, inside the envelope, caller untouched.
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", model);
  const over = {
    project: "p",
    model: "m",
    request: {
      generationConfig: { temperature: 0.5, maxOutputTokens: 65536 },
      contents: [{ role: "user", parts: [{ text: "x".repeat(1000) }] }],
    },
  };
  const result = (await f.handlers.get(GUARD)!({ payload: over }, f.ctx)) as Record<string, unknown>;
  const request = result.request as Record<string, unknown>;
  expect((request.generationConfig as Record<string, unknown>).maxOutputTokens).toBe(500);
  expect((request.generationConfig as Record<string, unknown>).temperature).toBe(0.5);
  expect((over.request.generationConfig as Record<string, unknown>).maxOutputTokens).toBe(65536);
  expect(f.aborts).toEqual([]);
  // An omitted cap is inserted on request.generationConfig; project,
  // model, sibling request fields, and the caller's object survive.
  const g = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", model);
  const omit = {
    project: "p",
    model: "m",
    request: {
      safetySettings: [{ category: "HARM_CATEGORY_X", threshold: "BLOCK_NONE" }],
      contents: [{ role: "user", parts: [{ text: "x".repeat(1000) }] }],
    },
  };
  const omittedResult = (await g.handlers.get(GUARD)!({ payload: omit }, g.ctx)) as Record<string, unknown>;
  const omittedRequest = omittedResult.request as Record<string, unknown>;
  expect(omittedResult.project).toBe("p");
  expect(omittedResult.model).toBe("m");
  expect("generationConfig" in omittedResult).toBe(false);
  expect("generationConfig" in omit.request).toBe(false);
  expect(omittedRequest.safetySettings).toEqual(omit.request.safetySettings);
  expect(g.aborts).toEqual([]);
});

test("responses input_image with a string image_url and provider-file parts are uncountable media", async () => {
  // convertResponsesInputImage emits either a string image_url or a file_id.
  for (const part of [
    { type: "input_image", detail: "auto", image_url: "https://example.com/huge.png" },
    { type: "input_image", detail: "auto", image_url: `data:image/png;base64,${"A".repeat(512)}` },
    { type: "input_image", detail: "auto", file_id: "file-abc123" },
    { type: "input_file", file_id: "file-xyz789" },
  ]) {
    const f = budgetFixture(
      "gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1",
      { provider: "gateway", id: "herald-model", api: "openai-responses" },
    );
    const payload = {
      model: "herald-model",
      input: [{ role: "user", content: [{ type: "input_text", text: "look" }, part] }],
    };
    expect((await expectRefusal(f, payload)).code).toBe("media_uncountable");
  }
});

test("the inserted output cap's own bytes count toward the window, not just the payload's", async () => {
  const payload = sizedPayload(9000);
  delete (payload as Record<string, unknown>).max_tokens;
  // Count the inserted cap's bytes because the provider receives the rewritten payload.
  const outgoingBytes = Buffer.byteLength(
    JSON.stringify({ ...payload, max_completion_tokens: 500 }),
    "utf8",
  );
  expect(outgoingBytes).toBeGreaterThan(9000);
  // A window sized exactly from the outgoing bytes plus the reserve fits;
  // the guard returns the capped payload it counted.
  const g = budgetFixture(`gateway|herald-model|${outgoingBytes + 500}|500|odin.tokenizer.utf8-bytes.v1`, MODEL);
  const result = (await g.handlers.get(GUARD)!({ payload: { ...payload } }, g.ctx)) as Record<string, unknown>;
  expect(result.max_completion_tokens).toBe(500);
  expect(g.aborts).toEqual([]);
  const tight = budgetFixture("gateway|herald-model|9500|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const refusal = await expectRefusal(tight, { ...payload });
  expect(refusal.code).toBe("window_exceeded");
  expect(refusal.reason).toContain(String(outgoingBytes + 500));
});

test("tool schema media examples, defaults, and enums are bounded text, not media", async () => {
  // A JSON-schema position can DESCRIBE or even exemplify media without
  // carrying any: only provider content positions are scanned for media.
  const mediaShapes = [
    { type: "image_url", image_url: { url: "https://example.com/huge.png" } },
    { type: "input_image", image_url: "https://example.com/huge.png" },
    { type: "input_image", file_id: "file-abc123" },
    { type: "file", file: { file_id: "file-abc123" } },
    { type: "image", source: { type: "url", url: "https://example.com/huge.png" } },
    { inlineData: { mimeType: "image/png", data: "AAAA" } },
    { fileData: { fileUri: "https://example.com/f.pdf" } },
    { file_uri: "https://example.com/f.pdf" },
  ];
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const payload = {
    ...sizedPayload(1000),
    tools: [
      {
        type: "function",
        function: {
          name: "fetch_attachment",
          description: "fetch a provider attachment by id",
          parameters: {
            type: "object",
            properties: {
              file_id: { type: "string", examples: mediaShapes },
              image_url: { type: "object", default: mediaShapes },
            },
            anyOf: [{ type: "object", properties: { q: { enum: mediaShapes } } }],
          },
        },
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "reply",
        schema: { type: "object", properties: { x: { examples: mediaShapes } } },
      },
    },
  };
  expect(await f.handlers.get(GUARD)!({ payload }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
});

test("media-shaped non-content fields stay countable text, never media refusals", async () => {
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const payload = {
    ...sizedPayload(1000),
    metadata: { file_uri: "https://example.com/f.pdf", image_url: "https://example.com/huge.png" },
    user: "u_123",
  };
  expect(await f.handlers.get(GUARD)!({ payload }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
});

test("computer-use screenshot output inside responses input is uncountable media", async () => {
  // The one structured tool-output position a provider renders as media
  // (pinned openai-responses-wire.ts): image_url on computer_call_output.
  // Chat file parts and anthropic url/file sources are covered by the
  // per-api media test above.
  const g = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", {
    provider: "gateway",
    id: "herald-model",
    api: "openai-responses",
  });
  const shot = {
    model: "herald-model",
    input: [
      {
        type: "computer_call_output",
        call_id: "c1",
        output: { type: "computer_screenshot", image_url: "https://example.com/huge.png" },
      },
    ],
  };
  expect((await expectRefusal(g, shot)).code).toBe("media_uncountable");
});

test("google functionCall and functionResponse JSON is text: media-shaped keys inside never refuse", async () => {
  const model = { provider: "gateway", id: "herald-model", api: "google-generative-ai" };
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", model);
  // The payload carries its own bound: a passing request returns
  // UNTOUCHED (undefined), proving the JSON inside tool calls is text.
  const payload = {
    config: { maxOutputTokens: 100 },
    contents: [
      { role: "user", parts: [{ text: "find it" }] },
      {
        role: "model",
        parts: [
          {
            functionCall: {
              name: "search",
              args: { source: { id: "s1" }, image_url: "https://example.com/huge.png", fileData: { fileUri: "https://example.com/f.pdf" } },
            },
          },
        ],
      },
      {
        role: "user",
        parts: [
          {
            functionResponse: {
              name: "search",
              response: {
                source: { id: "rec-1", byteStart: 0 },
                image_url: "https://example.com/huge.png",
                inlineData: { mimeType: "image/png", data: "AAAA" },
              },
            },
          },
        ],
      },
    ],
  };
  expect(await f.handlers.get(GUARD)!({ payload }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
  // an actual media PART in the same contents position still refuses
  const g = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", model);
  const withPart = {
    contents: [{ role: "user", parts: [{ text: "look" }, { inlineData: { mimeType: "image/png", data: "AAAA" } }] }],
  };
  expect((await expectRefusal(g, withPart)).code).toBe("media_uncountable");
});

test("tool-call history carrying media-shaped JSON strings stays countable text", async () => {
  const resultJson = '{"source":{"id":"rec-1"},"image_url":"https://example.com/huge.png"}';
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const chat = {
    ...sizedPayload(200),
    messages: [
      { role: "user", content: "run it" },
      { role: "assistant", tool_calls: [{ id: "c1", type: "function", function: { name: "search", arguments: resultJson } }] },
      { role: "tool", tool_call_id: "c1", content: resultJson },
    ],
  };
  expect(await f.handlers.get(GUARD)!({ payload: chat }, f.ctx)).toBeUndefined();
  const g = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", { provider: "gateway", id: "herald-model", api: "openai-responses" });
  const responses = {
    model: "m",
    max_output_tokens: 100,
    input: [
      { role: "user", content: [{ type: "input_text", text: "run it" }] },
      { type: "function_call", call_id: "c1", name: "search", arguments: resultJson },
      { type: "function_call_output", call_id: "c1", output: resultJson },
    ],
  };
  expect(await g.handlers.get(GUARD)!({ payload: responses }, g.ctx)).toBeUndefined();
});

test("a present-but-malformed output bound is refused, never silently replaced by the reserve", async () => {
  // The pinned producers emit the bound as a number or omit the field; a present malformed value is an
  // unknown shape and fails closed. One case per api shape, and an invalid alternate field is not ignored.
  const hi = [{ role: "user", content: "hi" }];
  const cases: Array<{ api: string; payload: Record<string, unknown> }> = [
    { api: "openai-completions", payload: { ...sizedPayload(500), max_tokens: "all" } },
    { api: "openai-completions", payload: { ...sizedPayload(500), max_tokens: 1.5 } },
    { api: "openai-completions", payload: { ...sizedPayload(500), max_completion_tokens: 100, max_tokens: "all" } },
    { api: "openai-responses", payload: { model: "m", input: "hello", max_output_tokens: null } },
    { api: "anthropic-messages", payload: { model: "m", max_tokens: "many", messages: hi } },
    { api: "google-generative-ai", payload: { contents: hi, config: "static" } },
    { api: "google-gemini-cli", payload: { project: "p", model: "m", request: "nope" } },
  ];
  for (const { api, payload } of cases) {
    const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", { provider: "gateway", id: "herald-model", api });
    expect((await expectRefusal(f, payload)).code).toBe("output_unboundable");
  }
});

test("the harness transport-injected write tool stays active but never executes; any other extra tool fails the session closed", async () => {
  // The harness re-adds `write` after setActiveTools; the lock tolerates it and the gate refuses its dispatch.
  const f = fixture(["task_read", "write"], ["task_read"]);
  await f.handlers.get("before_agent_start")!({}, ctx);
  const refusal = (await f.handlers.get("tool_call")!({ toolName: "write", input: {} }, ctx)) as { block: boolean; reason: string };
  expect(refusal.block).toBe(true);
  expect(refusal.reason).toContain('"write"');
  expect(refusal.reason).toContain("not one of this session's governed tools");
  // The harness refuses to deactivate this one, so it stays active.
  const stuck = makePi(["task_read", "sneaky_tool"]);
  stuck.pi.setActiveTools = async () => {};
  withEnv({ ODIN_HOST_TOOLS: "task_read", ODIN_HOST_URI_SCHEMES: undefined, ODIN_READ_PATHS: undefined, ODIN_CONTEXT_BUDGET: undefined }, () => odin(stuck.pi));
  await expect(stuck.handlers.get("before_agent_start")!({}, ctx)).rejects.toThrow(/governed tool surface mismatch.*sneaky_tool/);
});

const WRITE_TOOL_ENTRY = { type: "function", function: { name: "write", description: "write a file", parameters: { type: "object" } } };
const ASK_TOOL_ENTRY = { type: "function", function: { name: "seat_ask_kubert", description: "ask kubert", parameters: { type: "object" } } };

test("a budgeted provider request carries only the governed surface: the harness-injected write is pruned and recorded as pruned", async () => {
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const payload = { ...sizedPayload(9000), tools: [WRITE_TOOL_ENTRY, ASK_TOOL_ENTRY] };
  const result = (await f.handlers.get(GUARD)!({ payload }, f.ctx)) as Record<string, unknown>;
  expect((result.tools as Array<{ function: { name: string } }>).map((tool) => tool.function.name)).toEqual(["seat_ask_kubert"]);
  expect(payload.tools).toHaveLength(2); // the caller's payload is never mutated
  expect(JSON.stringify(f.entries)).not.toContain('"name":"write"');
  // A request without injected tools stays byte-untouched.
  const clean = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  expect(await clean.handlers.get(GUARD)!({ payload: sizedPayload(9000) }, clean.ctx)).toBeUndefined();
});

test("an unbudgeted provider request is pruned the same way, and what is recorded is what is sent", async () => {
  const f = budgetFixture(undefined, MODEL);
  const payload = { messages: [{ role: "user", content: "hello" }], tools: [WRITE_TOOL_ENTRY, ASK_TOOL_ENTRY], max_tokens: 20 };
  const sent = (await f.handlers.get(GUARD)!({ type: GUARD, payload }, f.ctx)) as { tools: unknown[] };
  expect(sent.tools).toEqual([ASK_TOOL_ENTRY]);
  const recorded = f.entries.find((entry) => entry.type === "odin.extension.model_request")?.data as {
    payload_digest: string;
    blocks: Array<{ role: string; body?: unknown }>;
  };
  expect(recorded.blocks.find((block) => block.role === "tools")?.body).toEqual([ASK_TOOL_ENTRY]);
  expect(recorded.blocks.find((block) => block.role === "history")?.body).toEqual(payload.messages);
  const untouched = budgetFixture(undefined, MODEL);
  expect(await untouched.handlers.get(GUARD)!({ type: GUARD, payload: { messages: payload.messages } }, untouched.ctx)).toBeUndefined();
});

test("each stored block carries its serialized size, and a system message with memory links stays guidance", async () => {
  const f = budgetFixture(undefined, MODEL);
  const system = { role: "system", content: `core memory brain://blake3:${"a".repeat(64)}` };
  const payload = { messages: [system, { role: "user", content: "hello" }], tools: [{ name: "task_read" }], max_tokens: 20 };
  await f.handlers.get(GUARD)?.({ type: GUARD, payload }, f.ctx);
  const data = f.entries.find((entry) => entry.type === "odin.extension.model_request")?.data as { blocks: Array<{ role: string; bytes: number }> };
  const bytes = (role: string) => data.blocks.find((block) => block.role === role)?.bytes;
  expect(bytes("guidance")).toBe(Buffer.byteLength(JSON.stringify([system])));
  expect(bytes("tools")).toBe(Buffer.byteLength(JSON.stringify(payload.tools)));
  expect(bytes("memory")).toBeUndefined();
});

test("injected memory is counted in the request that adds it, from user messages only", async () => {
  const f = budgetFixture(undefined, MODEL);
  const link = `brain://blake3:${"a".repeat(64)}`;
  const system = { role: "system", content: "guidance" };
  const injected = { role: "user", content: `evidence ${link}\n\nq1` };
  const quoted = { role: "assistant", content: `see ${link}` };
  const plain = { role: "user", content: "q2" };
  const added = { role: "user", content: `evidence ${link}\n\nq3` };
  const turn1 = [system, injected];
  const turn2 = [...turn1, quoted, plain];
  const turn3 = [...turn2, { role: "assistant", content: "a2" }, added];
  for (const messages of [turn1, turn2, turn3]) {
    await f.handlers.get(GUARD)?.({ type: GUARD, payload: { messages } }, f.ctx);
  }
  const memory = f.entries
    .filter((entry) => entry.type === "odin.extension.model_request")
    .map((entry) => (entry.data as { blocks: Array<{ role: string; bytes: number }> }).blocks.find((block) => block.role === "memory")?.bytes);
  expect(memory).toEqual([Buffer.byteLength(JSON.stringify([injected])), undefined, Buffer.byteLength(JSON.stringify([added]))]);
});

type StoredBlock = { role: string; sha256: string; body?: unknown };

type RequestData = {
  call_id: string;
  payload_digest: string;
  blocks: StoredBlock[];
  skeleton: { messages: { blob: string } };
};

type LinkData = { call_id?: string; response_id?: string; trace_error?: string };

function storedBodies(entries: Array<{ type: string; data: unknown }>): Map<string, unknown> {
  const bodies = new Map<string, unknown>();
  for (const entry of entries) {
    if (entry.type !== "odin.extension.model_request" || entry.data === null || typeof entry.data !== "object" || Array.isArray(entry.data)) continue;
    const data = entry.data as RequestData;
    if (!Array.isArray(data.blocks)) continue;
    for (const block of data.blocks) {
      if (block === null || typeof block !== "object" || typeof block.sha256 !== "string" || !("body" in block)) continue;
      const digest = createHash("sha256").update(JSON.stringify(block.body), "utf8").digest("hex");
      if (digest !== block.sha256) throw new Error(`stored body hash ${digest} != ${block.sha256}`);
      bodies.set(block.sha256, block.body);
    }
  }
  return bodies;
}

function reconstructHistory(digest: string, bodies: Map<string, unknown>): unknown[] {
  const body = bodies.get(digest);
  if (body === undefined) throw new Error(`missing stored body ${digest}`);
  if (Array.isArray(body)) return body;
  if (body !== null && typeof body === "object" && "prefix" in body && "suffix" in body) {
    const node = body as { prefix: unknown; suffix: unknown };
    if (typeof node.prefix !== "string" || !Array.isArray(node.suffix)) {
      throw new Error("history body is neither an array nor a chain node");
    }
    return [...reconstructHistory(node.prefix, bodies), ...node.suffix];
  }
  throw new Error("history body is neither an array nor a chain node");
}

function requestCapture(data: unknown): {
  callId: string;
  payloadDigest: string;
  blocks: StoredBlock[];
  messagesBlob: string;
} {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("model request entry is not a capture");
  }
  const request = data as RequestData;
  if (typeof request.call_id !== "string" || typeof request.payload_digest !== "string" || !Array.isArray(request.blocks)) {
    throw new Error("model request entry is not a capture");
  }
  const messages = request.skeleton?.messages;
  if (messages === undefined || typeof messages.blob !== "string") {
    throw new Error("model request skeleton has no messages blob");
  }
  for (const block of request.blocks) {
    if (block === null || typeof block !== "object" || typeof block.role !== "string" || typeof block.sha256 !== "string") {
      throw new Error("stored block is not an object");
    }
  }
  return {
    callId: request.call_id,
    payloadDigest: request.payload_digest,
    blocks: request.blocks,
    messagesBlob: messages.blob,
  };
}

function linkCapture(data: unknown): { callId?: string; responseId?: string; traceError?: string } {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("link entry is not an object");
  }
  const link = data as LinkData;
  if ("call_id" in link && link.call_id !== undefined && typeof link.call_id !== "string") throw new Error("call_id is not a string");
  if ("response_id" in link && link.response_id !== undefined && typeof link.response_id !== "string") throw new Error("response_id is not a string");
  if ("trace_error" in link && link.trace_error !== undefined && typeof link.trace_error !== "string") throw new Error("trace_error is not a string");
  return {
    callId: typeof link.call_id === "string" ? link.call_id : undefined,
    responseId: typeof link.response_id === "string" ? link.response_id : undefined,
    traceError: typeof link.trace_error === "string" ? link.trace_error : undefined,
  };
}

test("growing history is a stored chain and an identical retry reuses the node", async () => {
  const f = budgetFixture(undefined, MODEL);
  const one = [{ role: "user", content: "one" }];
  const two = [...one, { role: "assistant", content: "two" }];
  const three = [...two, { role: "user", content: "three" }];
  for (const messages of [one, two, three, three]) {
    await f.handlers.get(GUARD)?.({ type: GUARD, payload: { messages } }, f.ctx);
  }
  const requests = f.entries.filter((entry) => entry.type === "odin.extension.model_request");
  expect(requests).toHaveLength(4);
  const typed = requests.map((entry) => requestCapture(entry.data));
  expect(new Set(typed.map((entry) => entry.callId)).size).toBe(4);
  const bodies = storedBodies(f.entries);
  const firstHistory = typed[0].blocks.find((block) => block.role === "history");
  expect(firstHistory?.body).toEqual(one);
  expect(typed[0].messagesBlob).toBe(firstHistory?.sha256);
  const secondHistory = typed[1].blocks.find((block) => block.role === "history" && block.body !== undefined);
  expect(secondHistory?.body).toEqual({ prefix: typed[0].messagesBlob, suffix: [two[1]] });
  const thirdHistory = typed[2].blocks.find((block) => block.role === "history" && block.body !== undefined);
  expect(Array.isArray(thirdHistory?.body)).toBe(false);
  expect(thirdHistory?.body).toEqual({ prefix: typed[1].messagesBlob, suffix: [three[2]] });
  expect(reconstructHistory(typed[2].messagesBlob, bodies)).toEqual(three);
  expect(typed[3].messagesBlob).toBe(typed[2].messagesBlob);
  expect(typed[3].blocks.some((block) => block.role === "history" && block.body !== undefined)).toBe(false);
});

test("a failed append, thrown or rejected, does not advance capture state", async () => {
  for (const how of ["throw", "reject"] as const) {
    let failing = true;
    const f = budgetFixture(undefined, MODEL, (type) => {
      if (!failing || type !== "odin.extension.model_request") return undefined;
      failing = false;
      return how;
    });
    await f.handlers.get(GUARD)?.({ type: GUARD, payload: { messages: [{ role: "user", content: "one" }] } }, f.ctx);
    expect(f.entries).toHaveLength(0);
    const second = [{ role: "user", content: "one" }, { role: "assistant", content: "two" }];
    await f.handlers.get(GUARD)?.({ type: GUARD, payload: { messages: second } }, f.ctx);
    const recorded = f.entries.find((entry) => entry.type === "odin.extension.model_request");
    if (recorded === undefined) throw new Error(`second capture was not stored after a ${how}`);
    // The first node was never stored, so the second request stores the full history rather than a suffix against it.
    expect(requestCapture(recorded.data).blocks.find((block) => block.role === "history")?.body).toEqual(second);
  }
});

test("a failed append drops the previous attempt so a later response is not linked to it", async () => {
  let captures = 0;
  const f = budgetFixture(undefined, MODEL, (type) => (type === "odin.extension.model_request" && ++captures === 2 ? "throw" : undefined));
  await f.handlers.get(GUARD)?.({ type: GUARD, payload: { messages: [{ role: "user", content: "one" }] } }, f.ctx);
  const first = requestCapture(f.entries.find((entry) => entry.type === "odin.extension.model_request")?.data);
  await f.handlers.get(GUARD)?.({ type: GUARD, payload: { messages: [{ role: "user", content: "two" }] } }, f.ctx);
  expect(f.entries.filter((entry) => entry.type === "odin.extension.model_request")).toHaveLength(1);
  await f.handlers.get("after_provider_response")?.({ requestId: "req-b" }, f.ctx);
  const links = f.entries.filter((entry) => entry.type === "odin.extension.model_request_link");
  expect(links).toHaveLength(1);
  const link = linkCapture(links[0].data);
  expect(link.callId).toBeUndefined();
  expect(link.traceError).toContain("no captured request");
  expect(JSON.stringify(links[0].data)).not.toContain(first.callId);
});

test("a response or message with nothing to link to is journaled as a trace error, not dropped", async () => {
  const f = budgetFixture(undefined, MODEL);
  await f.handlers.get("after_provider_response")?.({ requestId: "req-stray" }, f.ctx);
  await f.handlers.get("message_end")?.({ message: { role: "assistant", responseId: "resp-stray", content: [] } }, f.ctx);
  await f.handlers.get(GUARD)?.({ type: GUARD, payload: { messages: [{ role: "user", content: "hi" }] } }, f.ctx);
  await f.handlers.get("after_provider_response")?.({}, f.ctx); // no requestId
  await f.handlers.get("message_end")?.({ message: { role: "assistant", content: [] } }, f.ctx); // no responseId
  const errors = f.entries.filter((entry) => entry.type === "odin.extension.model_request_link").map((entry) => (entry.data as { trace_error?: string }).trace_error);
  expect(errors).toEqual([
    "provider response arrived with no captured request",
    "assistant message has no linked provider request",
    "provider response has no requestId",
    "assistant message has no linked provider requestId; assistant message has no responseId",
  ]);
});

test("a response links the current attempt, not an abandoned identical payload", async () => {
  const f = budgetFixture(undefined, MODEL);
  const payload = { messages: [{ role: "user", content: "same" }] };
  await f.handlers.get(GUARD)?.({ type: GUARD, payload }, f.ctx);
  await f.handlers.get(GUARD)?.({ type: GUARD, payload }, f.ctx);
  const requests = f.entries.filter((entry) => entry.type === "odin.extension.model_request");
  const first = requestCapture(requests[0].data);
  const second = requestCapture(requests[1].data);
  expect(first.callId).not.toBe(second.callId);
  expect(first.payloadDigest).toBe(second.payloadDigest);
  await f.handlers.get("after_provider_response")?.({
    requestId: "req-b",
    headers: {
      "x-litellm-model-name": "groq/openai/gpt-oss-120b",
      "x-litellm-model-group": "free-fast",
      "x-litellm-attempted-fallbacks": "1",
      "x-litellm-call-id": "call-gw",
    },
  }, f.ctx);
  const afterResponse = f.entries.filter((entry) => entry.type === "odin.extension.model_request_link");
  const linked = afterResponse[0].data as Record<string, unknown>;
  expect(linked.served_model).toBe("groq/openai/gpt-oss-120b");
  expect(linked.model_group).toBe("free-fast");
  expect(linked.attempted_fallbacks).toBe("1");
  expect(linked.gateway_call_id).toBe("call-gw");
  expect(linked.served_model).not.toBe(MODEL.id);
  expect(linked.call_id).toBe(second.callId);
  await f.handlers.get("message_end")?.({
    message: { role: "assistant", responseId: "resp-1", content: [], usage: {}, stopReason: "stop" },
  }, f.ctx);
  const afterEnd = f.entries.filter((entry) => entry.type === "odin.extension.model_request_link");
  const ended = linkCapture(afterEnd[1].data);
  expect(ended.callId).toBe(second.callId);
  expect(ended.responseId).toBe("resp-1");
  await f.handlers.get("after_provider_response")?.({ requestId: "req-stray" }, f.ctx);
  const afterStray = f.entries.filter((entry) => entry.type === "odin.extension.model_request_link");
  const stray = linkCapture(afterStray[2].data);
  expect(stray.callId).toBeUndefined();
  expect(stray.traceError).toContain("no captured request");
});

test("read opens a file inside the seat's own folders and nothing a link leads out to", () => {
  const base = realpathSync(mkdtempSync("/tmp/odin-read-"));
  const folder = `${base}/Documents`;
  mkdirSync(folder);
  writeFileSync(`${folder}/notes.md`, "one\ntwo\n");
  writeFileSync(`${base}/secret`, "no");
  symlinkSync(`${base}/secret`, `${folder}/escape`);
  const roots = [folder];
  expect(readRootTarget({ path: `${folder}/notes.md` }, roots)).toBe(`${folder}/notes.md`);
  expect(readRootTarget({ path: `${folder}/notes.md:1-2` }, roots)).toBe(`${folder}/notes.md:1-2`);
  expect(readRootTarget({ path: `${folder}/escape` }, roots)).toBeNull();
  expect(readRootTarget({ path: `${base}/secret` }, roots)).toBeNull();
  expect(readRootTarget({ path: "Documents/notes.md" }, roots)).toBeNull();
  expect(readRootTarget({ path: `${folder}/notes.md` }, [])).toBeNull();
});
