package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"lctsdk/lctsdk"
)

type taskPayload struct {
	Op               string                     `json:"op"`
	TargetURL        string                     `json:"target_url"`
	ToolName         string                     `json:"tool_name"`
	Arguments        map[string]any             `json:"arguments"`
	Payload          map[string]any             `json:"payload"`
	Permissions      *lctsdk.PermissionLattice  `json:"permissions"`
	RequiredSkill    string                     `json:"required_skill"`
	DelegateSpiffeID string                     `json:"delegate_spiffe_id"`
	DelegateJKT      string                     `json:"delegate_jkt"`
	HopSegment       string                     `json:"hop_segment"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func main() {
	port := flag.Int("port", 9001, "Loopback port on 127.0.0.1")
	sidecarURL := flag.String("sidecar-url", lctsdk.DefaultSidecarOutboundURL, "LineageSidecar outbound URL")
	secretFile := flag.String("secret-file", "", "Path to shared loopback secret file")
	flag.Parse()

	secret, err := lctsdk.LoadLoopbackSecret(*secretFile)
	if err != nil {
		log.Fatalf("failed to load LCT loopback secret: %v", err)
	}
	client := lctsdk.NewSidecarClient(secret, *sidecarURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "lang": "go"})
	})
	mux.HandleFunc("/a2a/task", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}
		lctCtx, _ := lctsdk.FromContext(r.Context())
		var reqBody taskPayload
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}

		switch reqBody.Op {
		case "call_tool":
			code, out, err := client.CallMCPTool(
				r.Context(),
				lctCtx.RequestID,
				reqBody.TargetURL,
				reqBody.ToolName,
				reqBody.Arguments,
			)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, code, map[string]any{
				"lang":           "go",
				"lct_context":    lctCtx,
				"sidecar_result": out,
			})
		case "delegate_agent":
			hop := reqBody.HopSegment
			if hop == "" {
				hop = "GoSubHop"
			}
			code, out, err := client.DelegateAgent(r.Context(), lctsdk.DelegateRequest{
				RequestID:        lctCtx.RequestID,
				Payload:          reqBody.Payload,
				Permissions:      reqBody.Permissions,
				RequiredSkill:    reqBody.RequiredSkill,
				DelegateSpiffeID: reqBody.DelegateSpiffeID,
				DelegateJKT:      reqBody.DelegateJKT,
				TargetURL:        reqBody.TargetURL,
				HopSegment:       hop,
			})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, code, map[string]any{
				"lang":           "go",
				"lct_context":    lctCtx,
				"sidecar_result": out,
			})
		default:
			writeJSON(w, http.StatusOK, map[string]any{
				"lang":        "go",
				"lct_context": lctCtx,
				"op":          reqBody.Op,
			})
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	fmt.Printf("[go-lct-agent] Listening strictly on http://%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, client.HandlerMiddleware(mux)))
}
