import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.concurrent.Executors;

/**
 * Zero-External-Dependency JDK 17+ Sidecar Adapter for Lineage Capability Tree (LCT).
 *
 * Contract:
 * 1. Reads shared tmpfs secret from /var/run/lct-loopback/secret (LCT_LOOPBACK_SECRET_FILE).
 * 2. Binds business server strictly to 127.0.0.1:9001.
 * 3. Verifies X-LCT-Loopback-Auth in constant time via MessageDigest.isEqual.
 * 4. Calls http://127.0.0.1:8081/v1/proxy/call for attenuated delegate_agent & call_tool.
 */
public final class LCTSidecarClient {
    public static final String DEFAULT_SECRET_FILE = "/var/run/lct-loopback/secret";
    public static final String DEFAULT_SIDECAR_OUTBOUND_URL = "http://127.0.0.1:8081";

    private final byte[] expectedSecretBytes;
    private final String expectedSecret;
    private final URI proxyUri;
    private final HttpClient httpClient;

    public record LCTContext(
            String requestId,
            String taskId,
            String sub,
            String lineagePath,
            String decision
    ) {}

    public LCTSidecarClient(String loopbackSecret, String sidecarOutboundUrl) {
        if (loopbackSecret == null || loopbackSecret.trim().length() < 16) {
            throw new IllegalArgumentException("Loopback secret must be >= 16 characters");
        }
        this.expectedSecret = loopbackSecret.trim();
        this.expectedSecretBytes = this.expectedSecret.getBytes(StandardCharsets.UTF_8);
        String base = (sidecarOutboundUrl == null || sidecarOutboundUrl.isBlank())
                ? DEFAULT_SIDECAR_OUTBOUND_URL
                : sidecarOutboundUrl.replaceAll("/+$", "");
        this.proxyUri = URI.create(base + "/v1/proxy/call");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .proxy(ProxySelector.of(null))
                .build();
    }

    public static String loadLoopbackSecret(String secretFile) throws IOException {
        String inline = System.getenv("LCT_LOOPBACK_SECRET");
        if (inline != null && !inline.trim().isEmpty()) {
            String trimmed = inline.trim();
            if (trimmed.length() < 16) {
                throw new IllegalArgumentException("LCT_LOOPBACK_SECRET must be >= 16 chars");
            }
            return trimmed;
        }
        String path = (secretFile != null && !secretFile.isBlank())
                ? secretFile
                : System.getenv().getOrDefault("LCT_LOOPBACK_SECRET_FILE", DEFAULT_SECRET_FILE);
        String val = Files.readString(Path.of(path), StandardCharsets.UTF_8).trim();
        if (val.length() < 16) {
            throw new IllegalArgumentException("Loopback secret in " + path + " must be >= 16 chars");
        }
        return val;
    }

    public boolean verifyLoopbackHeader(String providedHeader) {
        if (providedHeader == null || providedHeader.isEmpty()) {
            return false;
        }
        try {
            byte[] providedBytes = providedHeader.getBytes(StandardCharsets.UTF_8);
            byte[] dProv = MessageDigest.getInstance("SHA-256").digest(providedBytes);
            byte[] dExp = MessageDigest.getInstance("SHA-256").digest(this.expectedSecretBytes);
            boolean digestOk = MessageDigest.isEqual(dProv, dExp);
            boolean lenOk = (providedBytes.length ^ this.expectedSecretBytes.length) == 0;
            return digestOk & lenOk;
        } catch (Exception e) {
            return false;
        }
    }

    public static LCTContext extractContext(Headers headers) {
        String reqId = firstOrEmpty(headers, "X-LCT-Request-Id");
        String taskId = firstOrEmpty(headers, "X-LCT-Task-Id");
        String sub = firstOrEmpty(headers, "X-LCT-Sub");
        String path = firstOrEmpty(headers, "X-LCT-Lineage-Path");
        String dec = firstOrEmpty(headers, "X-LCT-Decision");
        return new LCTContext(reqId, taskId, sub, path, dec.isEmpty() ? "ALLOW" : dec);
    }

    private static String firstOrEmpty(Headers headers, String key) {
        String v = headers.getFirst(key);
        return v == null ? "" : v.trim();
    }

    private static String jsonEscape(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        out.append(String.format("\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }

    public HttpResponse<String> callMCPTool(
            String requestId,
            String targetUrl,
            String toolName,
            String rawArgumentsJson
    ) throws IOException, InterruptedException {
        String argsJson = (rawArgumentsJson == null || rawArgumentsJson.isBlank()) ? "{}" : rawArgumentsJson;
        String payloadJson = "{"
                + "\"action\":\"call_tool\","
                + "\"request_id\":\"" + jsonEscape(requestId) + "\","
                + "\"target_url\":\"" + jsonEscape(targetUrl) + "\","
                + "\"timeout\":25.0,"
                + "\"payload\":{"
                + "\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"" + jsonEscape(toolName) + "\",\"arguments\":" + argsJson + "}"
                + "}}";
        return postRawProxyJson(payloadJson);
    }

    public HttpResponse<String> delegateAgent(
            String requestId,
            String requiredSkill,
            String rawPermissionsJson,
            String rawTaskPayloadJson,
            String hopSegment
    ) throws IOException, InterruptedException {
        String hop = (hopSegment == null || hopSegment.isBlank()) ? "JavaSubHop" : hopSegment;
        StringBuilder sb = new StringBuilder("{")
                .append("\"action\":\"delegate_agent\",")
                .append("\"request_id\":\"").append(jsonEscape(requestId)).append("\",")
                .append("\"required_skill\":\"").append(jsonEscape(requiredSkill)).append("\",")
                .append("\"hop_segment\":\"").append(jsonEscape(hop)).append("\",")
                .append("\"task_path\":\"/a2a/task\",")
                .append("\"timeout\":30.0,")
                .append("\"payload\":").append(rawTaskPayloadJson == null ? "{}" : rawTaskPayloadJson);
        if (rawPermissionsJson != null && !rawPermissionsJson.isBlank()) {
            sb.append(",\"permissions\":").append(rawPermissionsJson);
        }
        sb.append("}");
        return postRawProxyJson(sb.toString());
    }

    public HttpResponse<String> postRawProxyJson(String jsonBody) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(this.proxyUri)
                .timeout(Duration.ofSeconds(35))
                .header("Content-Type", "application/json")
                .header("X-LCT-Loopback-Auth", this.expectedSecret)
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();
        return this.httpClient.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static void sendJson(HttpExchange ex, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("APP_PORT", "9001"));
        String sidecarUrl = System.getenv().getOrDefault("SIDECAR_OUTBOUND_URL", DEFAULT_SIDECAR_OUTBOUND_URL);
        String secret = loadLoopbackSecret(null);
        LCTSidecarClient client = new LCTSidecarClient(secret, sidecarUrl);

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 64);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/healthz", ex -> sendJson(ex, 200, "{\"status\":\"ok\",\"lang\":\"java\"}"));
        server.createContext("/a2a/task", ex -> {
            String provided = ex.getRequestHeaders().getFirst("X-LCT-Loopback-Auth");
            if (!client.verifyLoopbackHeader(provided)) {
                sendJson(ex, 403, "{\"error\":\"direct_loopback_bypass_blocked\"}");
                return;
            }
            LCTContext ctx = extractContext(ex.getRequestHeaders());
            String resp = "{"
                    + "\"lang\":\"java\","
                    + "\"task_id\":\"" + jsonEscape(ctx.taskId()) + "\","
                    + "\"sub\":\"" + jsonEscape(ctx.sub()) + "\","
                    + "\"lineage_path\":\"" + jsonEscape(ctx.lineagePath()) + "\""
                    + "}";
            sendJson(ex, 200, resp);
        });
        server.start();
        System.out.println("[java-lct-agent] Listening strictly on http://127.0.0.1:" + port);
    }
}
