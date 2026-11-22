// Zero-Dependency Node.js 18+ Sidecar Adapter for Lineage Capability Tree (LCT)
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";

export const DEFAULT_SECRET_FILE = "/var/run/lct-loopback/secret";
export const DEFAULT_SIDECAR_OUTBOUND_URL = "http://127.0.0.1:8081";

export function loadLoopbackSecret(secretFile = "") {
  const inline = (process.env.LCT_LOOPBACK_SECRET || "").trim();
  if (inline) {
    if (inline.length < 16) {
      throw new Error("LCT_LOOPBACK_SECRET must be at least 16 characters");
    }
    return inline;
  }
  const targetPath =
    secretFile || process.env.LCT_LOOPBACK_SECRET_FILE || DEFAULT_SECRET_FILE;
  const secret = fs.readFileSync(targetPath, "utf8").trim();
  if (secret.length < 16) {
    throw new Error(`Loopback secret from ${targetPath} must be >= 16 chars`);
  }
  return secret;
}

export function verifyLoopbackHeader(provided, expected) {
  if (
    typeof provided !== "string" ||
    typeof expected !== "string" ||
    !provided ||
    !expected
  ) {
    return false;
  }
  const bA = Buffer.from(provided, "utf8");
  const bB = Buffer.from(expected, "utf8");
  const dA = crypto.createHash("sha256").update(bA).digest();
  const dB = crypto.createHash("sha256").update(bB).digest();
  const digestOk = crypto.timingSafeEqual(dA, dB);
  const lenOk = (bA.length ^ bB.length) === 0;
  return Boolean(Number(digestOk) & Number(lenOk));
}

export function extractLCTContext(headers) {
  return {
    request_id: String(headers["x-lct-request-id"] || "").trim(),
    task_id: String(headers["x-lct-task-id"] || "").trim(),
    sub: String(headers["x-lct-sub"] || "").trim(),
    lineage_path: String(headers["x-lct-lineage-path"] || "").trim(),
    decision: String(headers["x-lct-decision"] || "ALLOW").trim() || "ALLOW",
  };
}

export function buildPermissionLattice({
  tools = [],
  methods = ["initialize", "tools/call", "tools/list"],
  maxAmount = null,
  numericBounds = {},
  allowedScopes = null,
  allowedTargets = null,
  paramWhitelist = {},
  maxCalls = 10,
} = {}) {
  return {
    tools,
    methods,
    max_amount: maxAmount,
    numeric_bounds: numericBounds,
    allowed_scopes: allowedScopes,
    allowed_targets: allowedTargets,
    param_whitelist: paramWhitelist,
    max_calls: maxCalls,
  };
}

export class LCTSidecarClient {
  constructor(loopbackSecret, sidecarOutboundUrl = DEFAULT_SIDECAR_OUTBOUND_URL) {
    this.loopbackSecret = loopbackSecret;
    this.proxyUrl = new URL(
      "/v1/proxy/call",
      sidecarOutboundUrl.endsWith("/") ? sidecarOutboundUrl : `${sidecarOutboundUrl}/`
    );
  }

  postProxy(body, timeoutMs = 35000) {
    const raw = Buffer.from(JSON.stringify(body), "utf8");
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: this.proxyUrl.hostname,
          port: Number(this.proxyUrl.port || 8081),
          path: this.proxyUrl.pathname,
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": raw.length,
            "X-LCT-Loopback-Auth": this.loopbackSecret,
          },
          timeout: timeoutMs,
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const txt = Buffer.concat(chunks).toString("utf8");
            let parsed;
            try {
              parsed = JSON.parse(txt);
            } catch {
              parsed = { raw: txt };
            }
            resolve({ status: res.statusCode || 500, body: parsed });
          });
        }
      );
      req.on("timeout", () => {
        req.destroy(new Error("Sidecar loopback request timed out"));
      });
      req.on("error", reject);
      req.write(raw);
      req.end();
    });
  }

  callMCPTool(requestId, targetUrl, toolName, toolArgs = {}) {
    return this.postProxy({
      action: "call_tool",
      request_id: requestId,
      target_url: targetUrl,
      timeout: 25.0,
      payload: {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: toolName,
          arguments: toolArgs,
        },
      },
    });
  }

  delegateAgent({
    requestId,
    payload = {},
    permissions = null,
    requiredSkill = null,
    delegateSpiffeId = null,
    delegateJkt = null,
    targetUrl = null,
    hopSegment = "NodeSubHop",
    taskPath = "/a2a/task",
    usePruneAndGraft = false,
  }) {
    const body = {
      action: "delegate_agent",
      request_id: requestId,
      payload,
      task_path: taskPath,
      use_prune_and_graft: usePruneAndGraft,
      timeout: 30.0,
    };
    if (permissions) body.permissions = permissions;
    if (requiredSkill) body.required_skill = requiredSkill;
    if (delegateSpiffeId) body.delegate_spiffe_id = delegateSpiffeId;
    if (delegateJkt) body.delegate_jkt = delegateJkt;
    if (targetUrl) body.target_url = targetUrl;
    if (hopSegment) body.hop_segment = hopSegment;
    return this.postProxy(body);
  }
}

export function createLoopbackAgentServer({ port = 9001, secret, handler }) {
  const sendJson = (res, code, obj) => {
    const raw = Buffer.from(JSON.stringify(obj), "utf8");
    res.writeHead(code, {
      "Content-Type": "application/json",
      "Content-Length": raw.length,
    });
    res.end(raw);
  };

  const server = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      sendJson(res, 200, { status: "ok", lang: "node" });
      return;
    }
    const provided = req.headers["x-lct-loopback-auth"];
    if (!verifyLoopbackHeader(Array.isArray(provided) ? provided[0] : provided, secret)) {
      sendJson(res, 403, { error: "direct_loopback_bypass_blocked" });
      return;
    }
    if (req.method !== "POST" || !["/a2a/task", "/a2a", "/"].includes(req.url || "")) {
      sendJson(res, 404, { error: "route_not_found" });
      return;
    }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      try {
        const rawTxt = Buffer.concat(chunks).toString("utf8") || "{}";
        const body = JSON.parse(rawTxt);
        const lctCtx = extractLCTContext(req.headers);
        const { status, response } = await handler(lctCtx, body);
        sendJson(res, status, response);
      } catch (err) {
        sendJson(res, 500, { error: String(err?.message || err) });
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      const actualPort = typeof addr === "object" && addr ? addr.port : port;
      resolve({ server, url: `http://127.0.0.1:${actualPort}` });
    });
  });
}
