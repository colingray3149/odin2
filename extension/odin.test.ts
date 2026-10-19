import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import odin from "./odin.ts";

function fixture(capabilities: string, available: string[], issued: string[], hostUriSchemes?: string) {
  const old = process.env.ODIN_CAPABILITIES;
  const oldTools = process.env.ODIN_HOST_TOOLS;
  const oldSchemes = process.env.ODIN_HOST_URI_SCHEMES;
  process.env.ODIN_HOST_TOOLS = issued.join(",");
  process.env.ODIN_CAPABILITIES = capabilities;
  if (hostUriSchemes === undefined) delete process.env.ODIN_HOST_URI_SCHEMES;
  else process.env.ODIN_HOST_URI_SCHEMES = hostUriSchemes;
  const handlers = new Map<string, Function>();
  let active = [...available];
  const pi = {
    on: (name: string, handler: Function) => handlers.set(name, handler),
    getAllTools: () => available.map(name => ({name})),
    getActiveTools: () => active,
    setActiveTools: async (names: string[]) => { active = names; },
    appendEntry: () => {},
  };
  odin(pi as never);
  if (old === undefined) delete process.env.ODIN_CAPABILITIES;
  else process.env.ODIN_CAPABILITIES = old;
  if (oldTools === undefined) delete process.env.ODIN_HOST_TOOLS;
  else process.env.ODIN_HOST_TOOLS = oldTools;
  if (oldSchemes === undefined) delete process.env.ODIN_HOST_URI_SCHEMES;
  else process.env.ODIN_HOST_URI_SCHEMES = oldSchemes;
  return { handlers, active: () => active };
}
const ctx = { sessionManager: { getSessionId: () => "fixture" } };

test("admitted browser and delegation lifecycle tools survive the governed surface lock; native shell does not", async () => {
  const f = fixture("browser.observe,task.create,task.read", ["browser_observe", "task_create", "task_read", "bash"], ["browser_observe", "task_create", "task_read"]);
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active().sort()).toEqual(["browser_observe", "task_create", "task_read"]);
  expect(await f.handlers.get("tool_call")!({toolName:"bash",input:{}}, ctx)).toMatchObject({block:true});
});

test("admitted hermes duty surface survives the governed lock; cross-seat asks and reads stay callable", async () => {
  const duties = ["seat_ask_kubert", "seat_ask_gungnir", "seat_ask_architect", "terminal_read", "huginn_read"];
  const f = fixture(
    "seat.ask.kubert,seat.ask.gungnir,seat.ask.architect,terminal.read,huginn.read",
    [...duties, "bash"],
    duties,
  );
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active().sort()).toEqual([...duties].sort());
  const ask = await f.handlers.get("tool_call")!({toolName:"seat_ask_kubert",input:{}}, ctx);
  expect(ask).toBeUndefined();
  expect(await f.handlers.get("tool_call")!({toolName:"bash",input:{}}, ctx)).toMatchObject({block:true});
});

test("undeclared duty tool cannot activate through an unrelated capability listing", async () => {
  const f = fixture("task.read", ["task_read", "seat_ask_kubert"], ["task_read"]);
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active()).toEqual(["task_read"]);
  expect(await f.handlers.get("tool_call")!({toolName:"seat_ask_kubert",input:{}}, ctx)).toMatchObject({block:true});
});

test("admitted kubert operations surface survives the governed lock; kube reads stay callable", async () => {
  const kube = ["kube_snapshot_read", "kube_health_read", "kube_workload_summarize"];
  const f = fixture("kube.snapshot.read,kube.health.read,kube.workload.summarize", [...kube, "bash"], kube);
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active().sort()).toEqual([...kube].sort());
  const read = await f.handlers.get("tool_call")!({toolName:"kube_snapshot_read",input:{}}, ctx);
  const health = await f.handlers.get("tool_call")!({toolName:"kube_health_read",input:{}}, ctx);
  expect(health).toBeUndefined();
  expect(read).toBeUndefined();
  expect(await f.handlers.get("tool_call")!({toolName:"bash",input:{}}, ctx)).toMatchObject({block:true});
});

test("eval source digest is computed from exact UTF-8 source before host dispatch, preserving all other limits", async () => {
  const f = fixture("capsule.eval.run", ["capsule_eval_run"], ["capsule_eval_run"]);
  const input = { source: "print('héllo')\n", source_sha256: "0".repeat(64), timeout_ms: 1000, interpreter: "python" };
  const result = await f.handlers.get("tool_call")!({toolName:"capsule_eval_run",input}, ctx);
  expect(result.input).toEqual({...input,source_sha256:createHash("sha256").update(input.source).digest("hex")});
  expect(input.source_sha256).toBe("0".repeat(64));
});

test("digest convenience cannot activate an undeclared eval capability", async () => {
  const f = fixture("task.read", ["task_read"], ["task_read"]);
  expect(await f.handlers.get("tool_call")!({toolName:"capsule_eval_run",input:{source:"print(1)"}}, ctx)).toMatchObject({block:true});
});

test("missing admitted lifecycle tool rejects turn rather than hiding broken delegation", async () => {
  const f = fixture("task.read", [], ["task_read"]);
  await expect(f.handlers.get("before_agent_start")!({}, ctx)).rejects.toThrow();
});

test("a declaration-derived tool needs no compiled capability name table", async () => {
  const f = fixture("coord.assist", ["coord_assist", "bash"], ["coord_assist"]);
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active()).toEqual(["coord_assist"]);
  expect(await f.handlers.get("tool_call")!({toolName:"coord_assist",input:{}}, ctx)).toBeUndefined();
  expect(await f.handlers.get("tool_call")!({toolName:"bash",input:{}}, ctx)).toMatchObject({block:true});
});

const HOST_URI_SCHEMES = "approval,odin-artifact,atlas,brain,incident,lane,run";
const ITEM = `brain://blake3:${"a".repeat(64)}`;

test("declared host URI schemes admit the read tool for canonical host URIs only", async () => {
  const f = fixture("email.read,huginn.read", ["email_read", "huginn_read", "read", "bash"], ["email_read", "huginn_read"], HOST_URI_SCHEMES);
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active().sort()).toEqual(["email_read", "huginn_read", "read"]);
  const gate = f.handlers.get("tool_call")!;
  expect(await gate({toolName:"read",input:{path:ITEM}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:`${ITEM}:0:512`}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:"atlas://"}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:"approval://some-approval-id"}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:"incident://incident-1"}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:"lane://sinmara.file.in"}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:"run://run-1"}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:"odin-artifact://5"}}, ctx)).toBeUndefined();
  for (const path of [
    // local, web, and unrelated readings stay refused
    "/etc/passwd",
    "file:///etc/passwd",
    "https://example.com/notes",
    "local://notes.md",
    "ssh://host/etc/passwd",
    "memory://local-note",
    "readme.md",
    // artifact:// is OMP's own built-in store, never a host scheme
    "artifact://5",
    // scheme case is canonical: upper/mixed case is refused, not folded
    "BRAIN://x",
    "Brain://x",
    `${ITEM.slice(0, 5).toUpperCase()}${ITEM.slice(5)}`,
    // multi-target, delimiter, and non-canonical shapes refused
    `${ITEM}, /etc/passwd`,
    `${ITEM} /etc/passwd`,
    `${ITEM};${ITEM}`,
    `${ITEM};/etc/passwd`,
    `${ITEM},${ITEM}`,
    `brain://a%3Bb`,
    `brain://a%2Fb`,
    "brain://a/../b",
    "brain://a\\b",
    "brain://a@b",
    "brain://a?q=1",
    "brain://a#f",
    `brain://${"a".repeat(129)}`,
    `brain://${"a".repeat(64)}\u0000`,
  ]) {
    expect(await gate({toolName:"read",input:{path}}, ctx)).toMatchObject({block:true});
  }
  for (const input of [
    {},
    {path: 7},
    {path: ITEM, url: "https://example.com/notes"},
    {path: ITEM, raw: true},
    [ITEM],
  ]) {
    expect(await gate({toolName:"read",input}, ctx)).toMatchObject({block:true});
  }
  expect(await gate({toolName:"bash",input:{}}, ctx)).toMatchObject({block:true});
});

test("a scheme the host did not declare is refused even though the read tool is active", async () => {
  const f = fixture("email.read", ["email_read", "read"], ["email_read"], "brain");
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active().sort()).toEqual(["email_read", "read"]);
  const gate = f.handlers.get("tool_call")!;
  expect(await gate({toolName:"read",input:{path:ITEM}}, ctx)).toBeUndefined();
  expect(await gate({toolName:"read",input:{path:"atlas://some-node"}}, ctx)).toMatchObject({block:true});
  expect(await gate({toolName:"read",input:{path:"lane://sinmara.file.in"}}, ctx)).toMatchObject({block:true});
});

test("native read refuses web URLs and names web_read", async () => {
  const f = fixture("web.read", ["web_read", "read"], ["web_read"], HOST_URI_SCHEMES);
  await f.handlers.get("before_agent_start")!({}, ctx);
  const gate = f.handlers.get("tool_call")!;
  for (const url of ["https://arxiv.org/abs/2510.00001", "http://example.com/"]) {
    const refused = await gate({toolName:"read",input:{path:url}}, ctx);
    expect(refused).toMatchObject({block:true});
    expect(refused.reason).toContain("web_read");
  }
});

test("a workload pod reads exactly its staged launch-input files", async () => {
  process.env.ODIN_READ_PATHS = "/var/run/odin/staging/input-2,/etc/passwd";
  const f = fixture("artifact.read", ["artifact_read", "read", "bash"], ["artifact_read"], HOST_URI_SCHEMES);
  delete process.env.ODIN_READ_PATHS;
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active().sort()).toEqual(["artifact_read", "read"]);
  const gate = f.handlers.get("tool_call")!;
  const read = (path: string) => gate({toolName:"read",input:{path}}, ctx);
  expect(await read("/var/run/odin/staging/input-2")).toBeUndefined();
  expect(await read("/var/run/odin/staging/input-2:raw")).toBeUndefined();
  for (const refused of [
    "/var/run/odin/staging/input-0",
    "/var/run/odin/staging/input-1",
    "/var/run/odin/staging/input-2/../input-0",
    "/var/run/odin/staging/input-2:10-20",
    "/etc/passwd",
    "/state/x",
    "file:///var/run/odin/staging/input-2",
  ]) {
    expect(await read(refused)).toMatchObject({block:true});
  }
  expect(await gate({toolName:"read",input:{path:"/var/run/odin/staging/input-2", offset:1}}, ctx)).toMatchObject({block:true});
  const refusal = await read("/tmp/x");
  expect(String((refusal as {reason: string}).reason)).toContain("/var/run/odin/staging/input-2");
});

test("a session without declared egress hosts still refuses every web URL", async () => {
  const f = fixture("email.read", ["email_read", "read"], ["email_read"], HOST_URI_SCHEMES);
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(await f.handlers.get("tool_call")!({toolName:"read",input:{path:"https://arxiv.org/"}}, ctx)).toMatchObject({block:true});
});

test("without a host URI declaration the read tool stays stripped and refused", async () => {
  const f = fixture("email.read", ["email_read", "read", "bash"], ["email_read"]);
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active()).toEqual(["email_read"]);
  expect(await f.handlers.get("tool_call")!({toolName:"read",input:{path:ITEM}}, ctx)).toMatchObject({block:true});
});

function budgetFixture(budget: string | undefined, currentModel: { provider: string; id: string; api?: string; tokenizer?: string } | undefined) {
  const oldBudget = process.env.ODIN_CONTEXT_BUDGET;
  if (budget === undefined) delete process.env.ODIN_CONTEXT_BUDGET;
  else process.env.ODIN_CONTEXT_BUDGET = budget;
  process.env.ODIN_HOST_TOOLS = "task_read";
  process.env.ODIN_CAPABILITIES = "task.read";
  const handlers = new Map<string, Function>();
  const entries: Array<{ type: string; data: unknown }> = [];
  const aborts: string[] = [];
  const pi = {
    on: (name: string, handler: Function) => handlers.set(name, handler),
    getAllTools: () => [{ name: "task_read" }],
    getActiveTools: () => ["task_read"],
    setActiveTools: async (_names: string[]) => {},
    appendEntry: (type: string, data: unknown) => { entries.push({ type, data }); },
  };
  odin(pi as never);
  if (oldBudget === undefined) delete process.env.ODIN_CONTEXT_BUDGET;
  else process.env.ODIN_CONTEXT_BUDGET = oldBudget;
  const requestCtx = {
    sessionManager: { getSessionId: () => "fixture" },
    abort: () => { aborts.push("abort"); },
    models: { current: () => currentModel },
  };
  return { handlers, entries, aborts, ctx: requestCtx };
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

test("the refusal rides the wire marker even when journaling fails", async () => {
  const oldBudget = process.env.ODIN_CONTEXT_BUDGET;
  process.env.ODIN_CONTEXT_BUDGET = "gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1";
  process.env.ODIN_HOST_TOOLS = "task_read";
  const handlers = new Map<string, Function>();
  const aborts: string[] = [];
  const pi = {
    on: (name: string, handler: Function) => handlers.set(name, handler),
    getAllTools: () => [{ name: "task_read" }],
    getActiveTools: () => ["task_read"],
    setActiveTools: async (_names: string[]) => {},
    appendEntry: () => { throw new Error("journal store is down"); },
  };
  odin(pi as never);
  if (oldBudget === undefined) delete process.env.ODIN_CONTEXT_BUDGET;
  else process.env.ODIN_CONTEXT_BUDGET = oldBudget;
  const seen: string[] = [];
  const original = console.error;
  console.error = (message: string) => { seen.push(message); };
  let refusal: { code: string } | undefined;
  try {
    await handlers.get(GUARD)!({ payload: sizedPayload(9000) }, {
      sessionManager: { getSessionId: () => "fixture" },
      abort: () => { aborts.push("abort"); },
      models: { current: () => MODEL },
    }).then(
      () => { throw new Error("expected a refusal, got pass-through"); },
      (error: unknown) => { refusal = markerOf(error); },
    );
  } finally {
    console.error = original;
  }
  expect(refusal!.code).toBe("window_exceeded");
  expect(aborts).toEqual(["abort"]);
  expect(seen.some((line) => line.includes("journal entry failed"))).toBe(true);
  expect(seen.some((line) => line.includes("context request refused"))).toBe(true);
});

test("the refusal is visible on the terminal stderr", async () => {
  const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const seen: string[] = [];
  const original = console.error;
  console.error = (message: string) => { seen.push(message); };
  try {
    await f.handlers.get(GUARD)!({ payload: sizedPayload(9000) }, f.ctx).catch(() => {});
  } finally {
    console.error = original;
  }
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

test("a malformed host budget declaration fails closed", async () => {
  for (const budget of [
    "gateway|herald-model|0|0|odin.tokenizer.utf8-bytes.v1",
    "gateway|herald-model|8000",
    "gateway|herald-model|800|900|odin.tokenizer.utf8-bytes.v1",
    "gateway||8000|500",
    "gateway|herald-model|8000|500|odin.tokenizer.gpt4.v9",
    "gateway|herald-model|8000|500|",
    "gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1|extra",
  ]) {
    const f = budgetFixture(budget, MODEL);
    expect((await expectRefusal(f, sizedPayload(100))).code).toBe("declaration_unusable");
  }
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
});

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
});

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
    { api: "openai-completions", part: { type: "image_url", image_url: { url: `data:image/png;base64,${"A".repeat(512)}` } } },
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

test("a text-only request whose tool schema merely names media fields still passes", async () => {
  // Tool JSON schemas DESCRIBE arguments; a property named file_id or
  // image_url is text, not media. Only actual provider content parts —
  // discriminated types or real media payload shapes — are uncountable.
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const payload = {
    ...sizedPayload(1000),
    tools: [
      {
        type: "function",
        function: {
          name: "fetch_attachment",
          parameters: {
            type: "object",
            properties: {
              file_id: { type: "string", description: "provider file to fetch" },
              image_url: { type: "object", properties: { url: { type: "string" } } },
              inlineData: { type: "object", properties: { mimeType: { type: "string" } } },
              fileData: { type: "object", properties: { fileUri: { type: "object" } } },
              file_uri: { type: "string" },
            },
          },
        },
      },
    ],
  };
  expect(await f.handlers.get(GUARD)!({ payload }, f.ctx)).toBeUndefined();
  expect(f.aborts).toEqual([]);
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
  // The pinned producers emit the bound as a number or omit the field
  // entirely; a present malformed value is an unknown shape and fails
  // closed instead of being treated as an omission and overwritten.
  const cases: Array<{ api: string; payload: Record<string, unknown> }> = [
    { api: "openai-completions", payload: { ...sizedPayload(500), max_tokens: "all" } },
    { api: "openai-completions", payload: { ...sizedPayload(500), max_tokens: 1.5 } },
    { api: "openai-completions", payload: { ...sizedPayload(500), max_tokens: -5 } },
    { api: "openai-completions", payload: { ...sizedPayload(500), max_completion_tokens: { large: true }, max_tokens: 200 } },
    { api: "openai-completions", payload: { ...sizedPayload(500), max_completion_tokens: 100, max_tokens: "all" } },
    { api: "openai-completions", payload: { ...sizedPayload(500), max_tokens: null } },
    { api: "openai-responses", payload: { model: "m", input: "hello", max_output_tokens: null } },
    { api: "openai-responses", payload: { model: "m", input: "hello", max_output_tokens: "many" } },
    { api: "anthropic-messages", payload: { model: "m", max_tokens: "many", messages: [{ role: "user", content: "hi" }] } },
    {
      api: "google-generative-ai",
      payload: { contents: [{ role: "user", parts: [{ text: "hi" }] }], config: "static" },
    },
    {
      api: "google-generative-ai",
      payload: { contents: [{ role: "user", parts: [{ text: "hi" }] }], config: { maxOutputTokens: "500" } },
    },
    {
      api: "google-gemini-cli",
      payload: { project: "p", model: "m", request: "nope" },
    },
    {
      api: "google-gemini-cli",
      payload: {
        project: "p",
        model: "m",
        request: { contents: [{ role: "user", parts: [{ text: "hi" }] }], generationConfig: { maxOutputTokens: -1 } },
      },
    },
  ];
  for (const { api, payload } of cases) {
    const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", { provider: "gateway", id: "herald-model", api });
    expect((await expectRefusal(f, payload)).code).toBe("output_unboundable");
  }
});

test("a non-serializable payload without its own output bound is still refused as uncountable", async () => {
  // The cap insert is a shallow copy with no traversal; the fail-closed
  // serialization guard is the byte count that follows — a payload the
  // wire cannot carry is refused as uncountable, never dispatched.
  const f = budgetFixture("gateway|herald-model|8000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const circular: Record<string, unknown> = { note: "x" };
  circular.self = circular;
  expect((await expectRefusal(f, circular)).code).toBe("payload_uncountable");
});

test("an envelope persisted in history loses its envelope and memory block before the provider", async () => {
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const header = "[Untrusted memory — evidence retrieved for this turn]";
  const entry = "- (observed) stale evidence";
  const manifest = { v: 1, turn: "turn:e1:old:1", header, note: null, entries: [{ text: entry }] };
  const envelope = `<odin-turn v1>\n${JSON.stringify(manifest)}\n</odin-turn>\n`;
  const messages = [
    { role: "user", content: `${envelope}facts\n\n${header}\n${entry}\n\nq1` },
    { role: "assistant", content: "a1" },
    { role: "user", content: [{ type: "text", text: `${envelope}${header}\n${entry}\n\nq2` }] },
    { role: "user", content: "q3" },
  ];
  const result = (await f.handlers.get("context")!({ messages }, f.ctx)) as {
    messages: Array<{ content: unknown }>;
  };
  expect(result.messages[0].content).toBe("facts\n\nq1");
  expect(result.messages[2].content).toEqual([{ type: "text", text: "q2" }]);
  expect(result.messages[3]).toBe(messages[3]);
  expect(messages[0].content).toContain("stale evidence");
});

test("the harness transport-injected write tool stays active but never executes (governed law holds)", async () => {
  // The harness re-adds `write` after setActiveTools; mimic that without admitting dispatch.
  const oldTools = process.env.ODIN_HOST_TOOLS;
  process.env.ODIN_HOST_TOOLS = "task_read";
  process.env.ODIN_CAPABILITIES = "task.read";
  delete process.env.ODIN_HOST_URI_SCHEMES;
  const handlers = new Map<string, Function>();
  const active = ["task_read", "write"];
  const pi = {
    on: (name: string, handler: Function) => handlers.set(name, handler),
    getAllTools: () => active.map(name => ({name})),
    getActiveTools: () => [...active],
    setActiveTools: async (_names: string[]) => {},
    appendEntry: () => {},
  };
  odin(pi as never);
  process.env.ODIN_HOST_TOOLS = oldTools === undefined ? "" : oldTools;
  // The session does NOT fail closed on the known injection...
  await handlers.get("before_agent_start")!({}, ctx);
  // ...and the injected tool never executes: the refusal is a PLAIN FACT
  // (what the tool is and where delegation actually lives), never a
  // connection-style error the model must interpret.
  const refusal = (await handlers.get("tool_call")!({toolName:"write",input:{}}, ctx)) as { block: boolean; reason: string };
  expect(refusal).toMatchObject({block:true});
  expect(refusal.reason).toContain('fact: "write" is not one of this session\'s governed tools');
  expect(refusal.reason).toContain("seat's governed ask tool");
  expect(refusal.reason).toContain("This is not a connection or availability problem");
  expect(refusal.reason).not.toContain("refusing connections");
  // Any OTHER undeclared extra still fails the session closed (the
  // harness here refuses to deactivate it, so it stays active).
  process.env.ODIN_HOST_TOOLS = "task_read";
  process.env.ODIN_CAPABILITIES = "task.read";
  delete process.env.ODIN_HOST_URI_SCHEMES;
  const handlers2 = new Map<string, Function>();
  const stuck = ["task_read", "sneaky_tool"];
  const pi2x = {
    on: (name: string, handler: Function) => handlers2.set(name, handler),
    getAllTools: () => stuck.map(name => ({name})),
    getActiveTools: () => [...stuck],
    setActiveTools: async (_names: string[]) => {},
    appendEntry: () => {},
  };
  odin(pi2x as never);
  process.env.ODIN_HOST_TOOLS = oldTools === undefined ? "" : oldTools;
  await expect(handlers2.get("before_agent_start")!({}, ctx)).rejects.toThrow(
    /governed tool surface mismatch.*sneaky_tool/,
  );
});

test("the provider request carries only the governed surface: the harness-injected write is pruned, delegation tools survive", async () => {
  const f = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  const writeEntry = { type: "function", function: { name: "write", description: "write a file", parameters: { type: "object" } } };
  const askEntry = { type: "function", function: { name: "seat_ask_kubert", description: "ask kubert", parameters: { type: "object" } } };
  const payload = {
    ...sizedPayload(9000),
    tools: [writeEntry, askEntry],
  };
  const result = (await f.handlers.get(GUARD)!({ payload }, f.ctx)) as Record<string, unknown>;
  expect(result).toBeDefined();
  const names = (result.tools as Array<{ function: { name: string } }>).map((t) => t.function.name);
  expect(names).toEqual(["seat_ask_kubert"]);
  expect(JSON.stringify(result)).not.toContain('"write"');
  // The caller's payload object is never mutated.
  expect(payload.tools).toHaveLength(2);
  // A clean request without injected tools stays byte-untouched.
  const clean = budgetFixture("gateway|herald-model|100000|500|odin.tokenizer.utf8-bytes.v1", MODEL);
  expect(await clean.handlers.get(GUARD)!({ payload: sizedPayload(9000) }, clean.ctx)).toBeUndefined();
  expect(clean.aborts).toEqual([]);
});

function indexedFixture(issued: string[], index: unknown) {
  const saved = { tools: process.env.ODIN_HOST_TOOLS, index: process.env.ODIN_TOOL_INDEX };
  process.env.ODIN_HOST_TOOLS = issued.join(",");
  process.env.ODIN_TOOL_INDEX = JSON.stringify(index);
  const handlers = new Map<string, Function>();
  const registered = new Map<string, { execute: Function }>();
  const available = [...issued, "bash"];
  let active = [...available];
  const chain: Record<string, Function> = {};
  for (const method of ["min", "max", "describe", "regex", "nullable"]) chain[method] = () => chain;
  const pi = {
    on: (name: string, handler: Function) => handlers.set(name, handler),
    registerTool: (tool: { name: string; execute: Function }) => {
      registered.set(tool.name, tool);
      available.push(tool.name);
    },
    zod: { object: () => chain, string: () => chain },
    getAllTools: () => available.map(name => ({ name })),
    getActiveTools: () => active,
    setActiveTools: async (names: string[]) => { active = names; },
    appendEntry: () => {},
  };
  try {
    odin(pi as never);
  } finally {
    if (saved.tools === undefined) delete process.env.ODIN_HOST_TOOLS;
    else process.env.ODIN_HOST_TOOLS = saved.tools;
    if (saved.index === undefined) delete process.env.ODIN_TOOL_INDEX;
    else process.env.ODIN_TOOL_INDEX = saved.index;
  }
  return { handlers, registered, active: () => [...active].sort() };
}

const fleetIndex = {
  always: ["task_read"],
  tools: [
    { name: "task_read", group: "task", summary: "Reads a delegated task" },
    { name: "fleet_drain", group: "fleet", summary: "Drains a node of its pods" },
    { name: "fleet_restore", group: "fleet", summary: "Restores a drained node" },
  ],
};

test("a seat's always set is listed; the search finds granted tools and lists their group for the session", async () => {
  const f = indexedFixture(["task_read", "fleet_drain", "fleet_restore"], fleetIndex);
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active()).toEqual(["odin_kernel_search", "task_read"]);
  const search = f.registered.get("odin_kernel_search")!;
  const found = await search.execute("call-1", { query: "drain a node" });
  expect(found.content[0].text).toContain("fleet_drain (fleet)");
  expect(found.details.found[0]).toBe("fleet_drain");
  expect(f.active()).toEqual(["fleet_drain", "fleet_restore", "odin_kernel_search", "task_read"]);
  expect(await f.handlers.get("tool_call")!({ toolName: "fleet_restore", input: {} }, ctx)).toBeUndefined();
  await f.handlers.get("before_agent_start")!({}, ctx);
  expect(f.active()).toContain("fleet_drain");
  const shell = await search.execute("call-2", { query: "bash shell" });
  expect(shell.details.found).toEqual([]);
  expect(await f.handlers.get("tool_call")!({ toolName: "bash", input: {} }, ctx)).toMatchObject({ block: true });
});

test("an index naming a tool outside the grant fails closed", () => {
  expect(() => indexedFixture(["task_read"], fleetIndex)).toThrow(/ungranted tool "fleet_drain"/);
});

test("the outgoing payload is recorded after pruning, including an unbudgeted call", async () => {
  const unbudgeted = budgetFixture(undefined, MODEL);
  const payload = { messages: [{ role: "user", content: "hello" }], tools: [{ name: "write" }, { name: "task_read" }], max_tokens: 20 };
  const returned = await unbudgeted.handlers.get(GUARD)?.({ type: GUARD, payload }, unbudgeted.ctx);
  if (returned !== undefined) throw new Error("an unbudgeted call must stay untouched");
  const recorded = unbudgeted.entries.find((entry) => entry.type === "odin.extension.model_request");
  if (recorded === undefined) throw new Error("unbudgeted call was not captured");
  const data = recorded.data as { payload_digest: string; blocks: Array<{ role: string; sha256: string; body?: unknown }> };
  if (data.payload_digest.length !== 64) throw new Error("payload digest is not sha256");
  const history = data.blocks.find((block) => block.role === "history");
  if (JSON.stringify(history?.body) !== JSON.stringify(payload.messages)) {
    throw new Error(`history body ${JSON.stringify(history?.body)} != messages`);
  }

  const budgeted = budgetFixture("gateway|herald-model|100000|100|odin.tokenizer.utf8-bytes.v1", MODEL);
  const rewritten = await budgeted.handlers.get(GUARD)?.({ type: GUARD, payload }, budgeted.ctx) as { tools?: Array<{ name: string }> };
  if (rewritten?.tools?.some((tool) => tool.name === "write")) throw new Error("pruned write tool was still returned");
  const second = budgeted.entries.find((entry) => entry.type === "odin.extension.model_request");
  if (second === undefined) throw new Error("budgeted call was not captured");
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

test("a failed append does not advance capture state", async () => {
  const oldBudget = process.env.ODIN_CONTEXT_BUDGET;
  const oldHost = process.env.ODIN_HOST_TOOLS;
  const oldCaps = process.env.ODIN_CAPABILITIES;
  delete process.env.ODIN_CONTEXT_BUDGET;
  process.env.ODIN_HOST_TOOLS = "task_read";
  process.env.ODIN_CAPABILITIES = "task.read";
  const handlers = new Map<string, Function>();
  const entries: Array<{ type: string; data: unknown }> = [];
  let fail = true;
  try {
    odin({
      on: (name: string, handler: Function) => handlers.set(name, handler),
      getAllTools: () => [{ name: "task_read" }],
      getActiveTools: () => ["task_read"],
      setActiveTools: async (_names: string[]) => {},
      appendEntry: (type: string, data: unknown) => {
        if (fail && type === "odin.extension.model_request") {
          fail = false;
          throw new Error("disk full");
        }
        entries.push({ type, data });
      },
    } as never);
    const ctx = {
      sessionManager: { getSessionId: () => "fixture" },
      abort: () => {},
      models: { current: () => MODEL },
    };
    await handlers.get(GUARD)?.({ type: GUARD, payload: { messages: [{ role: "user", content: "one" }] } }, ctx);
    expect(entries).toHaveLength(0);
    const second = [{ role: "user", content: "one" }, { role: "assistant", content: "two" }];
    await handlers.get(GUARD)?.({ type: GUARD, payload: { messages: second } }, ctx);
    const recorded = entries.find((entry) => entry.type === "odin.extension.model_request");
    if (recorded === undefined) throw new Error("second capture was not stored");
    const history = requestCapture(recorded.data).blocks.find((block) => block.role === "history");
    expect(history?.body).toEqual(second);
  } finally {
    if (oldBudget === undefined) delete process.env.ODIN_CONTEXT_BUDGET;
    else process.env.ODIN_CONTEXT_BUDGET = oldBudget;
    if (oldHost === undefined) delete process.env.ODIN_HOST_TOOLS;
    else process.env.ODIN_HOST_TOOLS = oldHost;
    if (oldCaps === undefined) delete process.env.ODIN_CAPABILITIES;
    else process.env.ODIN_CAPABILITIES = oldCaps;
  }
});

test("a failed append drops the previous attempt so a later response is not linked to it", async () => {
  const oldBudget = process.env.ODIN_CONTEXT_BUDGET;
  const oldHost = process.env.ODIN_HOST_TOOLS;
  const oldCaps = process.env.ODIN_CAPABILITIES;
  delete process.env.ODIN_CONTEXT_BUDGET;
  process.env.ODIN_HOST_TOOLS = "task_read";
  process.env.ODIN_CAPABILITIES = "task.read";
  const handlers = new Map<string, Function>();
  const entries: Array<{ type: string; data: unknown }> = [];
  let captures = 0;
  try {
    odin({
      on: (name: string, handler: Function) => handlers.set(name, handler),
      getAllTools: () => [{ name: "task_read" }],
      getActiveTools: () => ["task_read"],
      setActiveTools: async (_names: string[]) => {},
      appendEntry: (type: string, data: unknown) => {
        if (type === "odin.extension.model_request") {
          captures += 1;
          if (captures === 2) throw new Error("disk full");
        }
        entries.push({ type, data });
      },
    } as never);
    const ctx = {
      sessionManager: { getSessionId: () => "fixture" },
      abort: () => {},
      models: { current: () => MODEL },
    };
    await handlers.get(GUARD)?.({ type: GUARD, payload: { messages: [{ role: "user", content: "one" }] } }, ctx);
    const captured = entries.find((entry) => entry.type === "odin.extension.model_request");
    if (captured === undefined) throw new Error("first capture was not stored");
    const first = requestCapture(captured.data);
    await handlers.get(GUARD)?.({ type: GUARD, payload: { messages: [{ role: "user", content: "two" }] } }, ctx);
    expect(entries.filter((entry) => entry.type === "odin.extension.model_request")).toHaveLength(1);
    await handlers.get("after_provider_response")?.({ requestId: "req-b" }, ctx);
    const links = entries.filter((entry) => entry.type === "odin.extension.model_request_link");
    expect(links).toHaveLength(1);
    if (links[0].data === null || typeof links[0].data !== "object" || Array.isArray(links[0].data)) {
      throw new Error("link data is not an object");
    }
    expect("call_id" in links[0].data).toBe(false);
    const link = linkCapture(links[0].data);
    expect(link.callId).toBeUndefined();
    expect(link.traceError).toContain("no captured request");
    expect(JSON.stringify(links[0].data)).not.toContain(first.callId);
  } finally {
    if (oldBudget === undefined) delete process.env.ODIN_CONTEXT_BUDGET;
    else process.env.ODIN_CONTEXT_BUDGET = oldBudget;
    if (oldHost === undefined) delete process.env.ODIN_HOST_TOOLS;
    else process.env.ODIN_HOST_TOOLS = oldHost;
    if (oldCaps === undefined) delete process.env.ODIN_CAPABILITIES;
    else process.env.ODIN_CAPABILITIES = oldCaps;
  }
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
  await f.handlers.get("after_provider_response")?.({ requestId: "req-b" }, f.ctx);
  const afterResponse = f.entries.filter((entry) => entry.type === "odin.extension.model_request_link");
  expect(linkCapture(afterResponse[0].data).callId).toBe(second.callId);
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
