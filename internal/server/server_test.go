package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/config"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/server"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/workflow"
)

const resultSecret = "synthetic-result-content-never-replayed"

type testExecutor struct{ calls atomic.Int64 }

func (e *testExecutor) Execute(context.Context, core.Dispatch) core.Execution {
	e.calls.Add(1)
	return core.Execution{Outcome: "SUCCEEDED", Raw: json.RawMessage(`{"resultType":"complete","content":[{"type":"text","text":"` + resultSecret + `"}],"structuredContent":{"value":"` + resultSecret + `"}}`)}
}
func (e *testExecutor) Reconcile(context.Context, core.Dispatch) core.Execution {
	return core.Execution{Outcome: "UNKNOWN"}
}

type testGate struct{}

func (testGate) Release(_ core.Tool, raw json.RawMessage) (json.RawMessage, error) { return raw, nil }

type harness struct {
	handler http.Handler
	exec    *testExecutor
	tokens  map[string]string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"report.read", "report.publish"}
	resources := []string{"dataset:one", "dataset:two"}
	destinations := []string{"internal"}
	input := json.RawMessage(`{"type":"object","properties":{"resource":{"type":"string"}},"required":["resource"],"additionalProperties":false}`)
	output := json.RawMessage(`{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}`)
	b := core.Bundle{Version: "test-v1", Semantics: "v1", ExpiresAt: time.Now().Add(time.Hour), Templates: []core.Template{{ID: "report-v1", Tools: names, Resources: resources, Destinations: destinations, InitialExposure: core.Exposure{Confidentiality: core.Public}, MaxCalls: 20, LifetimeSeconds: 3600}}}
	for _, name := range names {
		tool := core.Tool{Name: name, ServerID: "backend", DeploymentDigest: "sha256:" + strings.Repeat("a", 64), Endpoint: "http://127.0.0.1:9000/mcp", UpstreamName: name, TokenEnv: "SERVER_BACKEND_TOKEN", InputSchema: input, OutputSchema: output, Effect: "read", Destination: "internal", ResourceArgument: "resource", Resources: resources, SourceExposure: core.Exposure{Confidentiality: core.Restricted, Untrusted: true}, MaxInputLabel: core.Restricted, ReleaseFields: []string{"value"}, MaxResultBytes: 1024}
		if name == "report.publish" {
			tool.Effect = "write"
			tool.RequireApproval = true
		}
		b.Tools = append(b.Tools, tool)
	}
	p := core.Principal{Tenant: "finance", User: "alice", Workload: "host", Tools: names, Resources: resources, Destinations: destinations, Clearance: core.Restricted}
	cfg := config.Config{Listen: "127.0.0.1:8080", Database: "test.db", BundlePath: "bundle.json", SignaturePath: "bundle.sig", PolicyPublicKey: base64.StdEncoding.EncodeToString(pub), AuditKeyEnv: "SERVER_AUDIT_KEY", AllowedOrigins: []string{"https://console.example"}}
	tokens := map[string]string{}
	for i, role := range []string{"host", "agent", "reviewer", "foreign"} {
		actor := p
		actor.Roles = []string{role}
		switch role {
		case "reviewer":
			actor.User = "reviewer"
			actor.Workload = "console"
			actor.Roles = []string{"approver", "admin"}
		case "foreign":
			actor.User = "someone-else"
			actor.Roles = []string{"agent"}
		}
		env := "SERVER_" + strings.ToUpper(role) + "_TOKEN"
		token := strings.Repeat(string(rune('A'+i)), 40)
		t.Setenv(env, token)
		tokens[role] = token
		cfg.Credentials = append(cfg.Credentials, config.Credential{TokenEnv: env, Principal: actor})
	}
	t.Setenv("SERVER_BACKEND_TOKEN", strings.Repeat("Z", 40))
	t.Setenv("SERVER_AUDIT_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("K", 32))))
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"bundle.json": raw, "bundle.sig": []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)))} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gateway.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	executor := &testExecutor{}
	coordinator, err := workflow.Open(loaded.Database, loaded.Bundle, executor, testGate{}, loaded.AuditKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	return &harness{handler: server.New(loaded, coordinator), exec: executor, tokens: tokens}
}

func (h *harness) request(method, path, actor, body string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if actor != "" {
		request.Header.Set("Authorization", "Bearer "+h.tokens[actor])
	}
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}
func (h *harness) createWorkflow(t *testing.T) string {
	t.Helper()
	rec := h.request("POST", "/v1/workflows", "host", `{"template_id":"report-v1"}`, nil)
	if rec.Code != 201 {
		t.Fatalf("workflow: %d %s", rec.Code, rec.Body)
	}
	var wf core.Workflow
	if err := json.Unmarshal(rec.Body.Bytes(), &wf); err != nil {
		t.Fatal(err)
	}
	return wf.ID
}
func rpc(method, tool, resource string) string {
	params := map[string]any{"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": core.ProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}
	if method == "tools/call" {
		params["name"] = tool
		params["arguments"] = map[string]any{"resource": resource}
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	return string(b)
}
func rpcHeaders(method, tool, wf string) map[string]string {
	headers := map[string]string{"MCP-Protocol-Version": core.ProtocolVersion, "Mcp-Method": method, "Accept": "application/json, text/event-stream"}
	if tool != "" {
		headers["Mcp-Name"] = tool
	}
	if wf != "" {
		headers["X-Gateway-Workflow-ID"] = wf
	}
	return headers
}

func TestAuthenticationRolesOriginsAndUnsupportedMethods(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		name, method, path, actor, body string
		headers                         map[string]string
		status                          int
	}{
		{name: "unauthenticated", method: "POST", path: "/v1/workflows", body: `{}`, status: 401},
		{name: "agent cannot mint task authority", method: "POST", path: "/v1/workflows", actor: "agent", body: `{"template_id":"report-v1"}`, status: 403},
		{name: "reviewer cannot create tasks", method: "POST", path: "/v1/workflows", actor: "reviewer", body: `{"template_id":"report-v1"}`, status: 403},
		{name: "host cannot use agent interface", method: "POST", path: "/mcp", actor: "host", body: rpc("ping", "", ""), headers: rpcHeaders("ping", "", ""), status: 403},
		{name: "agent cannot approve", method: "POST", path: "/v1/operations/op_fake/approve", actor: "agent", body: `{}`, status: 403},
		{name: "host cannot approve", method: "POST", path: "/v1/operations/op_fake/approve", actor: "host", body: `{}`, status: 403},
		{name: "agent cannot read audit", method: "GET", path: "/v1/audit", actor: "agent", status: 403},
		{name: "invalid origin", method: "GET", path: "/healthz", headers: map[string]string{"Origin": "https://evil.example"}, status: 403},
		{name: "empty origin", method: "GET", path: "/healthz", headers: map[string]string{"Origin": ""}, status: 403},
		{name: "approved origin", method: "GET", path: "/healthz", headers: map[string]string{"Origin": "https://console.example"}, status: 200},
		{name: "GET MCP rejected", method: "GET", path: "/mcp", actor: "agent", status: 405},
		{name: "legacy initialize", method: "POST", path: "/mcp", actor: "agent", body: rpc("initialize", "", ""), headers: rpcHeaders("initialize", "", ""), status: 400},
		{name: "unimplemented resource", method: "POST", path: "/mcp", actor: "agent", body: rpc("resources/read", "", ""), headers: rpcHeaders("resources/read", "", ""), status: 400},
		{name: "compressed body", method: "POST", path: "/mcp", actor: "agent", body: rpc("ping", "", ""), headers: map[string]string{"Content-Encoding": "gzip"}, status: 415},
		{name: "malformed Accept", method: "POST", path: "/mcp", actor: "agent", body: rpc("ping", "", ""), headers: map[string]string{"Accept": "application/json-bogus,text/event-stream-bogus"}, status: 406},
		{name: "unacceptable JSON", method: "POST", path: "/mcp", actor: "agent", body: rpc("ping", "", ""), headers: map[string]string{"Accept": "application/json;q=0,text/event-stream"}, status: 406},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.request(tc.method, tc.path, tc.actor, tc.body, tc.headers)
			if rec.Code != tc.status {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.status, rec.Body)
			}
		})
	}
	if h.exec.calls.Load() != 0 {
		t.Fatal("rejected traffic reached resource")
	}
	rec := h.request("POST", "/mcp", "agent", rpc("server/discover", "", ""), rpcHeaders("server/discover", "", ""))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"supportedVersions":["2026-07-28"]`) {
		t.Fatalf("discovery: %d %s", rec.Code, rec.Body)
	}
}

func TestRequestBindingAndNoResultReplay(t *testing.T) {
	h := newHarness(t)
	wf := h.createWorkflow(t)
	headers := rpcHeaders("tools/call", "report.read", wf)
	rec := h.request("POST", "/mcp", "agent", rpc("tools/call", "report.read", "dataset:one"), headers)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), resultSecret) {
		t.Fatalf("initial release: %d %s", rec.Code, rec.Body)
	}
	opID := rec.Header().Get("X-Gateway-Operation-ID")
	if opID == "" {
		t.Fatal("missing operation reference")
	}
	headers["X-Gateway-Operation-ID"] = opID
	rec = h.request("POST", "/mcp", "agent", rpc("tools/call", "report.read", "dataset:two"), headers)
	if rec.Code != 409 {
		t.Fatalf("changed arguments accepted: %d %s", rec.Code, rec.Body)
	}
	rec = h.request("POST", "/mcp", "agent", rpc("tools/call", "report.read", "dataset:one"), headers)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), resultSecret) || !strings.Contains(rec.Body.String(), `"code":-32003`) {
		t.Fatalf("replay did not report status without payload: %d %s", rec.Code, rec.Body)
	}
	rec = h.request("GET", "/v1/operations/"+opID, "agent", "", nil)
	for _, secret := range []string{resultSecret, "permit_", "epoch_", h.tokens["agent"], os.Getenv("SERVER_BACKEND_TOKEN"), "http://127.0.0.1:9000/mcp"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("operation inspection leaked %q", secret)
		}
	}
	if h.exec.calls.Load() != 1 {
		t.Fatalf("resource invoked %d times", h.exec.calls.Load())
	}
	rec = h.request("GET", "/v1/operations/"+opID, "foreign", "", nil)
	if rec.Code != 404 {
		t.Fatal("foreign principal read operation")
	}
	rec = h.request("GET", "/v1/workflows/"+wf, "foreign", "", nil)
	if rec.Code != 404 {
		t.Fatal("foreign principal read workflow")
	}
	rec = h.request("GET", "/v1/audit", "reviewer", "", nil)
	if rec.Code != 200 || bytes.Contains(rec.Body.Bytes(), []byte(resultSecret)) || bytes.Contains(rec.Body.Bytes(), []byte("dataset:one")) {
		t.Fatalf("audit includes payload: %d %s", rec.Code, rec.Body)
	}
}

func TestIndependentApprovalIsExactAndSingleUse(t *testing.T) {
	h := newHarness(t)
	wf := h.createWorkflow(t)
	headers := rpcHeaders("tools/call", "report.publish", wf)
	rec := h.request("POST", "/mcp", "agent", rpc("tools/call", "report.publish", "dataset:one"), headers)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "precreation required") || h.exec.calls.Load() != 0 {
		t.Fatalf("effect without durable client reference accepted: %d %s", rec.Code, rec.Body)
	}
	rec = h.request("POST", "/v1/workflows/"+wf+"/operations", "agent", `{"tool":"report.publish","arguments":{"resource":"dataset:one"}}`, nil)
	if rec.Code != 201 {
		t.Fatalf("precreate effect: %d %s", rec.Code, rec.Body)
	}
	var op struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &op); err != nil || op.ID == "" {
		t.Fatal("operation reference unavailable")
	}
	opID := op.ID
	headers["X-Gateway-Operation-ID"] = opID
	rec = h.request("POST", "/mcp", "agent", rpc("tools/call", "report.publish", "dataset:one"), headers)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"outcome":"REQUIRE_APPROVAL"`) || h.exec.calls.Load() != 0 {
		t.Fatalf("pending approval executed: %d %s", rec.Code, rec.Body)
	}

	rec = h.request("POST", "/v1/operations/"+opID+"/approve", "reviewer", `{}`, nil)
	if rec.Code != 200 {
		t.Fatalf("reviewer could not approve: %d %s", rec.Code, rec.Body)
	}
	rec = h.request("POST", "/mcp", "agent", rpc("tools/call", "report.publish", "dataset:two"), headers)
	if rec.Code != 409 {
		t.Fatal("approval reused with changed resource")
	}
	rec = h.request("POST", "/mcp", "agent", rpc("tools/call", "report.publish", "dataset:one"), headers)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), resultSecret) {
		t.Fatalf("approved operation failed: %d %s", rec.Code, rec.Body)
	}
	rec = h.request("POST", "/v1/operations/"+opID+"/approve", "reviewer", `{}`, nil)
	if rec.Code != 403 {
		t.Fatal("consumed approval granted twice")
	}
	rec = h.request("POST", "/mcp", "agent", rpc("tools/call", "report.publish", "dataset:one"), headers)
	if strings.Contains(rec.Body.String(), resultSecret) || h.exec.calls.Load() != 1 {
		t.Fatal("approved operation redispatched or re-released")
	}
}

func TestPrecreateOperationSurvivesResponseLossWithoutDispatch(t *testing.T) {
	h := newHarness(t)
	wf := h.createWorkflow(t)
	body := `{"tool":"report.read","arguments":{"resource":"dataset:one"}}`
	rec := h.request("POST", "/v1/workflows/"+wf+"/operations", "host", body, nil)
	if rec.Code != 403 {
		t.Fatal("host token created agent candidate")
	}
	rec = h.request("POST", "/v1/workflows/"+wf+"/operations", "foreign", body, nil)
	if rec.Code != 403 {
		t.Fatal("foreign principal created candidate")
	}
	rec = h.request("POST", "/v1/workflows/"+wf+"/operations", "agent", body, nil)
	if rec.Code != 201 {
		t.Fatalf("precreate: %d %s", rec.Code, rec.Body)
	}
	var op struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &op); err != nil || op.ID == "" {
		t.Fatal("operation ID unavailable before dispatch")
	}
	if h.exec.calls.Load() != 0 || strings.Contains(rec.Body.String(), "permit_") || strings.Contains(rec.Body.String(), os.Getenv("SERVER_BACKEND_TOKEN")) {
		t.Fatal("candidate creation executed or leaked authority")
	}
	headers := rpcHeaders("tools/call", "report.read", wf)
	headers["X-Gateway-Operation-ID"] = op.ID
	rec = h.request("POST", "/mcp", "agent", rpc("tools/call", "report.read", "dataset:two"), headers)
	if rec.Code != 409 || h.exec.calls.Load() != 0 {
		t.Fatal("changed candidate dispatched")
	}
	rec = h.request("POST", "/mcp", "agent", rpc("tools/call", "report.read", "dataset:one"), headers)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), resultSecret) || h.exec.calls.Load() != 1 {
		t.Fatalf("precreated dispatch: %d %s", rec.Code, rec.Body)
	}
	// The caller retained op.ID before dispatch, so a lost tool response can be
	// resolved through this read rather than creating a duplicate business effect.
	rec = h.request("GET", "/v1/operations/"+op.ID, "agent", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"execution_status":"SUCCEEDED"`) || strings.Contains(rec.Body.String(), resultSecret) {
		t.Fatalf("status after simulated loss: %d %s", rec.Code, rec.Body)
	}
}

func TestUnsupportedVersionPreservesValidatedRequestID(t *testing.T) {
	h := newHarness(t)
	headers := rpcHeaders("ping", "", "")
	headers["MCP-Protocol-Version"] = "2025-11-25"
	body := strings.ReplaceAll(rpc("ping", "", ""), core.ProtocolVersion, "2025-11-25")
	rec := h.request("POST", "/mcp", "agent", body, headers)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"code":-32022`) || !strings.Contains(rec.Body.String(), `"id":1`) || !strings.Contains(rec.Body.String(), `"requested":"2025-11-25"`) {
		t.Fatalf("version error: %d %s", rec.Code, rec.Body)
	}
	headers = rpcHeaders("resources/read", "", "")
	rec = h.request("POST", "/mcp", "agent", rpc("resources/read", "", ""), headers)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"id":1`) {
		t.Fatalf("valid unsupported method lost correlation: %d %s", rec.Code, rec.Body)
	}
}
