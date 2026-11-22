// Package lctsdk implements the zero-external-dependency Go Sidecar Adapter for
// Lineage Capability Tree (LCT) 2/2 Kubernetes Pods (`127.0.0.1:9001` <-> `127.0.0.1:8081`).
package lctsdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	DefaultSecretFile         = "/var/run/lct-loopback/secret"
	DefaultSidecarOutboundURL = "http://127.0.0.1:8081"
)

// LCTContext holds verified lineage identity headers injected by LineageSidecar.
type LCTContext struct {
	RequestID   string `json:"request_id"`
	TaskID      string `json:"task_id"`
	Sub         string `json:"sub"`
	LineagePath string `json:"lineage_path"`
	Decision    string `json:"decision"`
}

type ctxKey struct{}

// ContextWithLCT attaches LCTContext to a standard Go context.Context.
func ContextWithLCT(ctx context.Context, lct LCTContext) context.Context {
	return context.WithValue(ctx, ctxKey{}, lct)
}

// FromContext extracts LCTContext from a request context.Context.
func FromContext(ctx context.Context) (LCTContext, bool) {
	v, ok := ctx.Value(ctxKey{}).(LCTContext)
	return v, ok
}

// PermissionLattice matches LineageSidecar's exact PermissionLattice.from_dict JSON schema.
type PermissionLattice struct {
	Tools          []string            `json:"tools"`
	Methods        []string            `json:"methods"`
	MaxAmount      *float64            `json:"max_amount"`
	NumericBounds  map[string]float64  `json:"numeric_bounds"`
	AllowedScopes  []string            `json:"allowed_scopes"`
	AllowedTargets []string            `json:"allowed_targets"`
	ParamWhitelist map[string][]string `json:"param_whitelist"`
	MaxCalls       int                 `json:"max_calls"`
}

// NewPermissionLattice constructs a normalized PermissionLattice struct ready for attenuation.
func NewPermissionLattice(tools []string, maxAmount *float64, targets []string, maxCalls int) *PermissionLattice {
	if maxCalls <= 0 {
		maxCalls = 10
	}
	return &PermissionLattice{
		Tools:          tools,
		Methods:        []string{"initialize", "tools/call", "tools/list"},
		MaxAmount:      maxAmount,
		NumericBounds:  map[string]float64{},
		AllowedTargets: targets,
		ParamWhitelist: map[string][]string{},
		MaxCalls:       maxCalls,
	}
}

// LoadLoopbackSecret reads the shared tmpfs loopback secret created by lct-sidecar.
func LoadLoopbackSecret(secretFile string) (string, error) {
	if inline := strings.TrimSpace(os.Getenv("LCT_LOOPBACK_SECRET")); inline != "" {
		if len(inline) < 16 {
			return "", errors.New("LCT_LOOPBACK_SECRET must be at least 16 characters")
		}
		return inline, nil
	}
	path := secretFile
	if path == "" {
		path = os.Getenv("LCT_LOOPBACK_SECRET_FILE")
	}
	if path == "" {
		path = DefaultSecretFile
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read loopback secret %q: %w", path, err)
	}
	secret := strings.TrimSpace(string(raw))
	if len(secret) < 16 {
		return "", fmt.Errorf("loopback secret from %q must be at least 16 characters", path)
	}
	return secret, nil
}

// VerifyLoopbackHeader checks X-LCT-Loopback-Auth in constant time without leaking expected length.
func VerifyLoopbackHeader(provided, expected string) bool {
	if provided == "" || expected == "" {
		return false
	}
	h1 := sha256.Sum256([]byte(provided))
	h2 := sha256.Sum256([]byte(expected))
	digestMatch := subtle.ConstantTimeCompare(h1[:], h2[:])
	lenMatch := subtle.ConstantTimeEq(int32(len(provided)), int32(len(expected)))
	return (digestMatch & lenMatch) == 1
}

// ExtractContext reads verified X-LCT-* headers from an inbound HTTP request.
func ExtractContext(r *http.Request) LCTContext {
	dec := strings.TrimSpace(r.Header.Get("X-LCT-Decision"))
	if dec == "" {
		dec = "ALLOW"
	}
	return LCTContext{
		RequestID:   strings.TrimSpace(r.Header.Get("X-LCT-Request-Id")),
		TaskID:      strings.TrimSpace(r.Header.Get("X-LCT-Task-Id")),
		Sub:         strings.TrimSpace(r.Header.Get("X-LCT-Sub")),
		LineagePath: strings.TrimSpace(r.Header.Get("X-LCT-Lineage-Path")),
		Decision:    dec,
	}
}

// SidecarClient communicates with the co-located lct-sidecar over 127.0.0.1:8081.
type SidecarClient struct {
	LoopbackSecret string
	ProxyURL       string
	HTTPClient     *http.Client
}

// NewSidecarClient creates a proxy-immune loopback HTTP client for LineageSidecar.
func NewSidecarClient(secret, outboundURL string) *SidecarClient {
	if outboundURL == "" {
		outboundURL = DefaultSidecarOutboundURL
	}
	return &SidecarClient{
		LoopbackSecret: secret,
		ProxyURL:       strings.TrimRight(outboundURL, "/") + "/v1/proxy/call",
		HTTPClient: &http.Client{
			Timeout:   40 * time.Second,
			Transport: &http.Transport{Proxy: nil},
		},
	}
}

// HandlerMiddleware protects business routes by enforcing constant-time X-LCT-Loopback-Auth.
func (c *SidecarClient) HandlerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if !VerifyLoopbackHeader(r.Header.Get("X-LCT-Loopback-Auth"), c.LoopbackSecret) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"direct_loopback_bypass_blocked"}`))
			return
		}
		ctx := ContextWithLCT(r.Context(), ExtractContext(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c *SidecarClient) postProxy(ctx context.Context, reqBody map[string]any) (int, map[string]any, error) {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ProxyURL, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LCT-Loopback-Auth", c.LoopbackSecret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(respBytes, &out); err != nil {
		out = map[string]any{"raw": string(respBytes)}
	}
	return resp.StatusCode, out, nil
}

// CallMCPTool invokes a downstream MCP tool through LineageSidecar with sender-bound DPoP + LCT.
func (c *SidecarClient) CallMCPTool(
	ctx context.Context,
	requestID, targetURL, toolName string,
	arguments map[string]any,
) (int, map[string]any, error) {
	if arguments == nil {
		arguments = map[string]any{}
	}
	body := map[string]any{
		"action":     "call_tool",
		"request_id": requestID,
		"target_url": targetURL,
		"timeout":    25.0,
		"payload": map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      toolName,
				"arguments": arguments,
			},
		},
	}
	return c.postProxy(ctx, body)
}

// DelegateRequest configures an attenuated sub-agent delegation via LineageSidecar.
type DelegateRequest struct {
	RequestID        string
	Payload          map[string]any
	Permissions      *PermissionLattice
	RequiredSkill    string
	DelegateSpiffeID string
	DelegateJKT      string
	TargetURL        string
	HopSegment       string
	TaskPath         string
	UsePruneAndGraft bool
}

// DelegateAgent attenuates the active LCT token and invokes a downstream sub-agent.
func (c *SidecarClient) DelegateAgent(ctx context.Context, d DelegateRequest) (int, map[string]any, error) {
	taskPath := d.TaskPath
	if taskPath == "" {
		taskPath = "/a2a/task"
	}
	body := map[string]any{
		"action":              "delegate_agent",
		"request_id":          d.RequestID,
		"payload":             d.Payload,
		"task_path":           taskPath,
		"use_prune_and_graft": d.UsePruneAndGraft,
		"timeout":             30.0,
	}
	if d.Permissions != nil {
		body["permissions"] = d.Permissions
	}
	if d.RequiredSkill != "" {
		body["required_skill"] = d.RequiredSkill
	}
	if d.DelegateSpiffeID != "" {
		body["delegate_spiffe_id"] = d.DelegateSpiffeID
	}
	if d.DelegateJKT != "" {
		body["delegate_jkt"] = d.DelegateJKT
	}
	if d.TargetURL != "" {
		body["target_url"] = d.TargetURL
	}
	if d.HopSegment != "" {
		body["hop_segment"] = d.HopSegment
	}
	return c.postProxy(ctx, body)
}
