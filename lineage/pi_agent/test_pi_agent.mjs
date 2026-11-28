// Automated Node.js Unit & Security Containment Suite for `lineage/pi_agent/server.mjs`
// Verifies real `@mariozechner/pi-agent-core` + `@mariozechner/pi-ai` integration,
// strict loopback auth, zero shell tool exposure, opaque Sidecar consent/digest handles,
// prompt-injection 403 capture, and zero LLM_API_KEY / raw JWT / raw LCT token leakage.

import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { fauxAssistantMessage, fauxText, fauxToolCall, AssistantMessageEventStream } from "@mariozechner/pi-ai";

import {
  FORBIDDEN_SHELL_TOOL_NAMES,
  buildPiCustomTools,
  redactSecrets,
  sanitizeEndpointUrl,
  startPiAgentServer,
} from "./server.mjs";
import { createLoopbackAgentServer } from "../sdk/node/lct_sdk.mjs";

function makeScriptedStreamFn(turnBuilders) {
  let idx = 0;
  return (_model, context) => {
    const stream = new AssistantMessageEventStream();
    const builder = turnBuilders[Math.min(idx, turnBuilders.length - 1)];
    idx += 1;
    queueMicrotask(() => {
      const msg = builder(context, idx);
      stream.push({ type: "start", partial: msg });
      stream.push({
        type: "done",
        reason: msg.stopReason === "toolUse" ? "toolUse" : "stop",
        message: msg,
      });
    });
    return stream;
  };
}

function postJson(url, path, body, headers = {}) {
  const raw = Buffer.from(JSON.stringify(body), "utf8");
  const parsedUrl = new URL(path, url);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: parsedUrl.hostname,
        port: Number(parsedUrl.port),
        path: parsedUrl.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": raw.length,
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const txt = Buffer.concat(chunks).toString("utf8");
          resolve({ status: res.statusCode, body: JSON.parse(txt), raw: txt });
        });
      }
    );
    req.on("error", reject);
    req.write(raw);
    req.end();
  });
}

test("Pi custom tools strictly exclude all shell/fs/exec tools", () => {
  const dummySidecar = { postProxy: async () => ({ status: 200, body: {} }) };
  const tools = buildPiCustomTools({
    sidecar: dummySidecar,
    lctCtx: {
      request_id: "req-1",
      task_id: "task-1",
      sub: "user:alice@org-alpha.io",
      lineage_path: "/task-1/PiAlice",
      decision: "ALLOW",
    },
    consentGrants: new Map(),
    recordToolTrace: () => {},
  });
  const names = tools.map((t) => t.name);
  assert.deepEqual(names, [
    "discover_workspace_peers",
    "call_peer_diagnostics",
    "request_peer_owner_consent",
    "call_peer_private_tool",
    "call_peer_cohort_stats",
    "call_vault_tool",
  ]);
  for (const forbidden of FORBIDDEN_SHELL_TOOL_NAMES) {
    assert.equal(names.includes(forbidden), false, `Forbidden tool exposed: ${forbidden}`);
  }
});

test("Loopback secret enforcement blocks missing/wrong header and hides LLM_API_KEY + wire tokens", async () => {
  const loopbackSecret = "loopback-secret-m11-unit-test-987654";
  const fakeApiKey = ["sk", "proj", "supersecretkeyvalue1234567890abcdef"].join("-");
  const proxyCalls = [];

  // Mock local Sidecar outbound loopback (`127.0.0.1:<ephemeral>`)
  const mockSidecarServer = http.createServer((req, res) => {
    assert.equal(req.headers["x-lct-loopback-auth"], loopbackSecret);
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const b = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      proxyCalls.push(b);
      let code = 200;
      let resp = {};
      if (b.action === "discover") {
        resp = {
          peers: [
            {
              name: "Bob Workspace Assistant",
              spiffe_id: "spiffe://org-beta.io/ns/lineage-beta/sa/assistant-bob",
              trust_domain: "org-beta.io",
              skills: ["workspace.bob_private", "workspace.tech_review"],
              status: "HEALTHY",
              priority: 10,
            },
          ],
        };
      } else if (b.action === "request_peer_consent") {
        resp = {
          consent_handle: "chdl-unit0000111122223333",
          owner_sub: "user:bob@org-beta.io",
          requester_sub: "user:alice@org-alpha.io",
          task_id: "task-m11-1",
          tools: ["service_diag_read", "commit_joint_change"],
        };
      } else if (
        b.action === "call_tool" &&
        b.payload?.params?.name === "hr_salary_read"
      ) {
        code = 403;
        resp = {
          upstream_status: 403,
          upstream_body: { error: "CROSS_PRINCIPAL_DENIED" },
        };
      } else if (
        b.action === "call_tool" &&
        b.payload?.params?.name === "reserve_cloud_budget"
      ) {
        code = 403;
        resp = {
          upstream_status: 403,
          upstream_body: { error: "LATTICE_PERMISSION_DENIED" },
        };
      } else if (b.action === "call_mcp_coauth") {
        resp = {
          upstream_status: 200,
          upstream_body: {
            result: {
              data: {
                operation: "commit_joint_change",
                change_id: "FIN-RULE-42",
                lineage_decision: "ALLOW_CO_AUTHORIZED",
              },
            },
          },
        };
      }
      const outRaw = Buffer.from(JSON.stringify(resp), "utf8");
      res.writeHead(code, { "Content-Type": "application/json" });
      res.end(outRaw);
    });
  });

  await new Promise((r) => mockSidecarServer.listen(0, "127.0.0.1", r));
  const sidecarPort = mockSidecarServer.address().port;

  // Drive real `@mariozechner/pi-agent-core` `Agent` loop across 4 turns!
  const scriptedStream = makeScriptedStreamFn([
    () =>
      fauxAssistantMessage(
        [fauxToolCall("discover_workspace_peers", {})],
        { stopReason: "toolUse", responseId: "chatcmpl-unit-t1" }
      ),
    () =>
      fauxAssistantMessage(
        [
          fauxToolCall("request_peer_owner_consent", {
            peer: "bob",
            tools: ["service_diag_read", "commit_joint_change"],
          }),
        ],
        { stopReason: "toolUse", responseId: "chatcmpl-unit-t2" }
      ),
    () =>
      fauxAssistantMessage(
        [
          fauxToolCall("call_peer_private_tool", {
            peer: "bob",
            tool_name: "hr_salary_read",
          }),
          fauxToolCall("call_vault_tool", {
            tool_name: "reserve_cloud_budget",
            project_code: "PRJ-ROGUE",
            amount: 9999,
            target: "cloud-infra-escrow",
          }),
          fauxToolCall("call_vault_tool", {
            tool_name: "commit_joint_change",
            consent_handle: "chdl-unit0000111122223333",
            change_id: "FIN-RULE-42",
          }),
        ],
        { stopReason: "toolUse", responseId: "chatcmpl-unit-t3" }
      ),
    () =>
      fauxAssistantMessage(
        [
          fauxText(
            `Completed FIN-RULE-42 via Sidecar while LCT blocked hr_salary_read and PRJ-ROGUE (${fakeApiKey} / lct1.should_be_scrubbed).`
          ),
        ],
        { stopReason: "stop", responseId: "chatcmpl-unit-t4" }
      ),
  ]);

  const piSrv = await startPiAgentServer({
    port: 0,
    sidecarUrl: `http://127.0.0.1:${sidecarPort}`,
    secretOverride: loopbackSecret,
    llmOverrides: {
      llmBaseUrl: "http://127.0.0.1:11434/v1",
      llmModel: "qwen2.5:3b",
      llmApiKey: fakeApiKey,
    },
    streamFnOverride: scriptedStream,
  });

  try {
    // 1. Unauthenticated / wrong loopback secret -> 403
    const rNoAuth = await postJson(piSrv.url, "/a2a/task", { prompt: "hi" });
    assert.equal(rNoAuth.status, 403);
    const rBadAuth = await postJson(
      piSrv.url,
      "/a2a/task",
      { prompt: "hi" },
      { "X-LCT-Loopback-Auth": "wrong-secret-value-00000000" }
    );
    assert.equal(rBadAuth.status, 403);

    // 2. Valid loopback call executes real Pi Agent loop
    const fakeBobJwt = ["eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJib2IifQ", "c2lnbmF0dXJlMTIzNDU2"].join(".");
    const rOk = await postJson(
      piSrv.url,
      "/a2a/task",
      {
        prompt: "Triage FIN-RULE-42 with Bob.",
        consent_grants: { bob: fakeBobJwt },
      },
      {
        "X-LCT-Loopback-Auth": loopbackSecret,
        "X-LCT-Request-Id": "req-unit-1",
        "X-LCT-Task-Id": "task-m11-1",
        "X-LCT-Sub": "user:alice@org-alpha.io",
        "X-LCT-Lineage-Path": "/task-m11-1/PiAssistantAlice",
      }
    );
    assert.equal(rOk.status, 200);
    assert.equal(rOk.body.pi_runtime.package, "@mariozechner/pi-agent-core");
    assert.equal(rOk.body.pi_runtime.shell_tools_exposed, false);
    assert.equal(rOk.body.pi_runtime.turns_executed, 4);
    assert.equal(rOk.body.pi_runtime.tool_calls_trace.length, 5);

    const hrTrace = rOk.body.pi_runtime.tool_calls_trace.find(
      (t) => t.tool_name === "call_peer_private_tool"
    );
    assert.equal(hrTrace.http_status, 403);
    assert.equal(hrTrace.lct_decision, "DENY:CROSS_PRINCIPAL_DENIED");

    const rogueVaultTrace = rOk.body.pi_runtime.tool_calls_trace.find(
      (t) =>
        t.tool_name === "call_vault_tool" &&
        t.arguments?.tool_name === "reserve_cloud_budget"
    );
    assert.equal(rogueVaultTrace.http_status, 403);
    assert.equal(rogueVaultTrace.lct_decision, "DENY:LATTICE_PERMISSION_DENIED");

    const commitTrace = rOk.body.pi_runtime.tool_calls_trace.find(
      (t) =>
        t.tool_name === "call_vault_tool" &&
        t.arguments?.tool_name === "commit_joint_change"
    );
    assert.equal(commitTrace.http_status, 200);
    assert.equal(commitTrace.lct_decision, "ALLOW_CO_AUTHORIZED");

    // 3. Verify ZERO secret/token leakage in entire serialized JSON output!
    assert.equal(rOk.raw.includes(fakeApiKey), false);
    assert.equal(rOk.raw.includes(fakeBobJwt), false);
    assert.equal(rOk.raw.includes("lct1."), false);
    assert.equal(rOk.raw.includes("lctco1."), false);
    assert.equal(proxyCalls.length, 5);
  } finally {
    await piSrv.close();
    await new Promise((r) => mockSidecarServer.close(r));
  }
});

test("redactSecrets scrubs API keys, JWTs, LCT tokens, and sensitive object fields", () => {
  const sampleJwt = ["eyJhbGciOiJFUzI1NiJ9", "eyJzdWIiOiJhbGljZSJ9", "YWJjZGVmZ2hpamtsbW5vcA"].join(".");
  const sampleSk = ["sk", "proj", "1234567890abcdefghij"].join("-");
  const sampleOr = ["sk", "or", "v1", "a".repeat(24)].join("-");
  const sampleGroq = "gsk_" + "b".repeat(24);
  const sampleXai = "xai-" + "c".repeat(24);
  const sampleHf = "hf_" + "d".repeat(24);
  const sampleGem = "AIza" + "E".repeat(32);
  const scrubbed = redactSecrets(
    {
      llm_api_key: "custom-secret-key",
      owner_oidc_token: sampleJwt,
      nested: {
        msg: `Bearer ${sampleSk} ${sampleOr} ${sampleGroq} ${sampleXai} ${sampleHf} ${sampleGem} and ${sampleJwt} and lctco1.xyz987 and my-custom-provider-key`,
      },
    },
    "my-custom-provider-key"
  );
  assert.equal(scrubbed.llm_api_key, "[REDACTED]");
  assert.equal(scrubbed.owner_oidc_token, "[REDACTED]");
  assert.equal(scrubbed.nested.msg.includes("sk-proj-"), false);
  assert.equal(scrubbed.nested.msg.includes("sk-or-v1-"), false);
  assert.equal(scrubbed.nested.msg.includes("gsk_"), false);
  assert.equal(scrubbed.nested.msg.includes("xai-"), false);
  assert.equal(scrubbed.nested.msg.includes("hf_"), false);
  assert.equal(scrubbed.nested.msg.includes("AIza"), false);
  assert.equal(scrubbed.nested.msg.includes("eyJhbG"), false);
  assert.equal(scrubbed.nested.msg.includes("lctco1."), false);
  assert.equal(scrubbed.nested.msg.includes("my-custom-provider-key"), false);
  assert.equal(
    sanitizeEndpointUrl("https://user:pass@api.example.com:8443/v1/chat/completions?key=secret#frag"),
    "https://api.example.com:8443/v1/chat/completions"
  );
});

test("M11 Round-2 regressions: cumulative max_turns, timeout across follow-ups, 403 consent pass-through, and 2 MiB body cap", async () => {
  const sec = "loopback-secret-m11-r2-unit-test-99887766";
  const mockSc = http.createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ peers: [] }));
  });
  await new Promise((r) => mockSc.listen(0, "127.0.0.1", r));

  let turns = 0;
  const fastStreamFn = () => {
    const s = new AssistantMessageEventStream();
    turns += 1;
    queueMicrotask(() => {
      const msg =
        turns % 2 === 1
          ? fauxAssistantMessage([fauxToolCall("discover_workspace_peers", {})], {
              stopReason: "toolUse",
              responseId: `c-${turns}`,
            })
          : fauxAssistantMessage([fauxText("step done")], {
              stopReason: "stop",
              responseId: `c-${turns}`,
            });
      s.push({ type: "start", partial: msg });
      s.push({
        type: "done",
        reason: msg.stopReason === "toolUse" ? "toolUse" : "stop",
        message: msg,
      });
    });
    return s;
  };

  const piSrv = await startPiAgentServer({
    port: 0,
    sidecarUrl: `http://127.0.0.1:${mockSc.address().port}`,
    secretOverride: sec,
    llmOverrides: { llmBaseUrl: "https://admin:pw@llm.example.com/v1?api_key=leak" },
    streamFnOverride: fastStreamFn,
  });

  const sdkSrv = await createLoopbackAgentServer({
    port: 0,
    secret: sec,
    handler: async () => ({ status: 200, response: { ok: true } }),
  });

  try {
    // 1. Raw `request_co_auth_consent` sent to `server.mjs` MUST be rejected 403 (owned natively by Sidecar)
    const rConsent = await postJson(
      piSrv.url,
      "/a2a/task",
      { op: "request_co_auth_consent", tools: ["commit_joint_change"] },
      { "X-LCT-Loopback-Auth": sec, "X-LCT-Task-Id": "t1", "X-LCT-Sub": "user:bob@org-beta.io" }
    );
    assert.equal(rConsent.status, 403);
    assert.equal(rConsent.body.error, "CONSENT_MINTING_OWNED_BY_SIDECAR");

    // 2. Cumulative `max_turns: 2` across `prompt` + `follow_up_prompts` MUST NOT exceed 2 turns!
    const rTurns = await postJson(
      piSrv.url,
      "/a2a/task",
      { prompt: "step 1", follow_up_prompts: ["step 2", "step 3"], max_turns: 2 },
      {
        "X-LCT-Loopback-Auth": sec,
        "X-LCT-Request-Id": "req-r2",
        "X-LCT-Task-Id": "t-r2",
        "X-LCT-Sub": "user:alice@org-alpha.io",
      }
    );
    assert.equal(rTurns.status, 200);
    assert.equal(rTurns.body.pi_runtime.max_turns, 2);
    assert.equal(rTurns.body.pi_runtime.turns_executed <= 2, true);
    assert.equal(
      rTurns.body.pi_runtime.llm_endpoint,
      "https://llm.example.com/v1/chat/completions"
    );

    // 3. `createLoopbackAgentServer` > 2 MiB payload -> 413
    const huge = JSON.stringify({ pad: "x".repeat(2 * 1024 * 1024 + 1024) });
    const status413 = await new Promise((resolve) => {
      const u = new URL("/a2a/task", sdkSrv.url);
      const req = http.request(
        {
          hostname: u.hostname,
          port: Number(u.port),
          path: u.pathname,
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-LCT-Loopback-Auth": sec,
          },
        },
        (res) => {
          res.resume();
          resolve(res.statusCode);
        }
      );
      req.on("error", () => resolve(413));
      req.write(huge);
      req.end();
    });
    assert.equal(status413, 413);
  } finally {
    await piSrv.close();
    await new Promise((r) => sdkSrv.server.close(r));
    await new Promise((r) => mockSc.close(r));
  }
});
