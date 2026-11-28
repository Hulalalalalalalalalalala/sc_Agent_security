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

export async function waitForLoopbackSecret(secretFile = "", maxWaitMs = 45000) {
  const inline = (process.env.LCT_LOOPBACK_SECRET || "").trim();
  if (inline) {
    return loadLoopbackSecret(secretFile);
  }
  const targetPath =
    secretFile || process.env.LCT_LOOPBACK_SECRET_FILE || DEFAULT_SECRET_FILE;
  const deadline = Date.now() + maxWaitMs;
  let lastErr = null;
  while (Date.now() < deadline) {
    try {
      if (fs.existsSync(targetPath)) {
        const secret = fs.readFileSync(targetPath, "utf8").trim();
        if (secret.length >= 16) {
          return secret;
        }
      }
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw (
    lastErr ||
    new Error(`Timed out waiting for shared loopback secret at ${targetPath}`)
  );
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

  discoverPeers({ skill = null, trustDomain = null, onlyHealthy = true } = {}) {
    const body = {
      action: "discover",
      only_healthy: Boolean(onlyHealthy),
    };
    if (skill) body.skill = String(skill);
    if (trustDomain) body.trust_domain = String(trustDomain);
    return this.postProxy(body);
  }

  requestPeerConsent({
    requestId,
    requiredSkill = null,
    delegateSpiffeId = null,
    trustDomain = null,
    tools = [],
    ownerOidcToken,
    numericBounds = null,
    allowedTargets = null,
    paramWhitelist = null,
    maxCalls = 6,
    handshakeHopSegment = "ConsentHandshake",
    consentHopSegment = null,
  }) {
    const body = {
      action: "request_peer_consent",
      request_id: requestId,
      tools,
      owner_oidc_token: ownerOidcToken,
      max_calls: maxCalls,
      handshake_hop_segment: handshakeHopSegment,
      timeout: 20.0,
    };
    if (requiredSkill) body.required_skill = requiredSkill;
    if (delegateSpiffeId) body.delegate_spiffe_id = delegateSpiffeId;
    if (trustDomain) body.trust_domain = trustDomain;
    if (numericBounds) body.numeric_bounds = numericBounds;
    if (allowedTargets) body.allowed_targets = allowedTargets;
    if (paramWhitelist) body.param_whitelist = paramWhitelist;
    if (consentHopSegment) body.consent_hop_segment = consentHopSegment;
    return this.postProxy(body);
  }

  callMCPTool(
    requestId,
    targetUrl,
    toolName,
    toolArgs = {},
    {
      requiredSkill = null,
      targetSpiffeId = null,
      targetTrustDomain = null,
      idempotencyKey = null,
      redactDigestJws = false,
      timeoutSec = 25.0,
    } = {}
  ) {
    const body = {
      action: "call_tool",
      request_id: requestId,
      timeout: timeoutSec,
      redact_digest_jws: Boolean(redactDigestJws),
      payload: {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: toolName,
          arguments: toolArgs,
        },
      },
    };
    if (targetUrl) body.target_url = targetUrl;
    if (requiredSkill) body.required_skill = requiredSkill;
    if (targetSpiffeId) body.target_spiffe_id = targetSpiffeId;
    if (targetTrustDomain) body.target_trust_domain = targetTrustDomain;
    if (idempotencyKey) body.idempotency_key = idempotencyKey;
    return this.postProxy(body);
  }

  callMCPToolCoAuth({
    requestId,
    consentHandle,
    toolName,
    toolArgs = {},
    requiredSkill = null,
    targetSpiffeId = null,
    targetTrustDomain = null,
    idempotencyKey = null,
    redactDigestJws = true,
    timeoutSec = 25.0,
  }) {
    const body = {
      action: "call_mcp_coauth",
      request_id: requestId,
      consent_handle: consentHandle,
      timeout: timeoutSec,
      redact_digest_jws: Boolean(redactDigestJws),
      payload: {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: toolName,
          arguments: toolArgs,
        },
      },
    };
    if (requiredSkill) body.required_skill = requiredSkill;
    if (targetSpiffeId) body.target_spiffe_id = targetSpiffeId;
    if (targetTrustDomain) body.target_trust_domain = targetTrustDomain;
    if (idempotencyKey) body.idempotency_key = idempotencyKey;
    return this.postProxy(body);
  }

  callPeerCoAuth({
    requestId,
    consentHandle,
    payload = {},
    permissions = null,
    requiredSkill = null,
    delegateSpiffeId = null,
    trustDomain = null,
    hopSegment = "NodeCoAuthHop",
    taskPath = "/a2a/task",
    idempotencyKey = null,
  }) {
    const body = {
      action: "call_peer_coauth",
      request_id: requestId,
      consent_handle: consentHandle,
      payload,
      task_path: taskPath,
      use_prune_and_graft: false,
      timeout: 30.0,
    };
    if (permissions) body.permissions = permissions;
    if (requiredSkill) body.required_skill = requiredSkill;
    if (delegateSpiffeId) body.delegate_spiffe_id = delegateSpiffeId;
    if (trustDomain) body.trust_domain = trustDomain;
    if (hopSegment) body.hop_segment = hopSegment;
    if (idempotencyKey) body.idempotency_key = idempotencyKey;
    return this.postProxy(body);
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
    const MAX_BODY_BYTES = 2 * 1024 * 1024;
    const chunks = [];
    let totalBytes = 0;
    let bodyTooLarge = false;
    req.on("data", (c) => {
      if (bodyTooLarge) return;
      totalBytes += c.length;
      if (totalBytes > MAX_BODY_BYTES) {
        bodyTooLarge = true;
        sendJson(res, 413, { error: "payload_too_large", max_bytes: MAX_BODY_BYTES });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", async () => {
      if (bodyTooLarge) return;
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
