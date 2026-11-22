// Runnable Reference Node.js 18+ Agent Behind `LineageSidecar` (`127.0.0.1:9001`)
import {
  DEFAULT_SIDECAR_OUTBOUND_URL,
  LCTSidecarClient,
  createLoopbackAgentServer,
  loadLoopbackSecret,
} from "./lct_sdk.mjs";

function parseArg(flag, fallback) {
  const idx = process.argv.indexOf(flag);
  if (idx !== -1 && idx + 1 < process.argv.length) {
    return process.argv[idx + 1];
  }
  return fallback;
}

const port = Number(parseArg("--port", "9001"));
const sidecarUrl = parseArg("--sidecar-url", DEFAULT_SIDECAR_OUTBOUND_URL);
const secretFile = parseArg("--secret-file", "");

const secret = loadLoopbackSecret(secretFile);
const client = new LCTSidecarClient(secret, sidecarUrl);

const { server, url } = await createLoopbackAgentServer({
  port,
  secret,
  handler: async (lctCtx, body) => {
    const op = String(body.op || "echo");
    if (op === "call_tool") {
      const { status, body: out } = await client.callMCPTool(
        lctCtx.request_id,
        String(body.target_url),
        String(body.tool_name),
        body.arguments || {}
      );
      return {
        status,
        response: {
          lang: "node",
          lct_context: lctCtx,
          sidecar_result: out,
        },
      };
    }
    if (op === "delegate_agent") {
      const { status, body: out } = await client.delegateAgent({
        requestId: lctCtx.request_id,
        payload: body.payload || {},
        permissions: body.permissions || null,
        requiredSkill: body.required_skill || null,
        delegateSpiffeId: body.delegate_spiffe_id || null,
        delegateJkt: body.delegate_jkt || null,
        targetUrl: body.target_url || null,
        hopSegment: body.hop_segment || "NodeSubHop",
      });
      return {
        status,
        response: {
          lang: "node",
          lct_context: lctCtx,
          sidecar_result: out,
        },
      };
    }
    return {
      status: 200,
      response: {
        lang: "node",
        lct_context: lctCtx,
        echo: body,
      },
    };
  },
});

console.log(`[node-lct-agent] Listening strictly on ${url}`);
process.on("SIGTERM", () => server.close(() => process.exit(0)));
process.on("SIGINT", () => server.close(() => process.exit(0)));
