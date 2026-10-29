package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
)

func manifest(endpoint string) core.Tool {
	return core.Tool{Name: "payroll.read", UpstreamName: "payroll.read", Endpoint: endpoint, TokenEnv: "TEST_RESOURCE_TOKEN", MaxResultBytes: 4096}
}
func dispatch(tool core.Tool) core.Dispatch {
	return core.Dispatch{Workflow: core.Workflow{ID: "wf_one"}, Operation: core.Operation{ID: "op_one", PermitID: "permit_one", OwnerEpoch: "epoch_one", Tool: tool, Decision: core.Decision{Outcome: core.Allow}, Candidate: core.Candidate{OperationID: "op_one", WorkflowID: "wf_one", Tool: tool.Name, Arguments: json.RawMessage(`{"resource":"payroll:2026-09","number":9007199254740993}`)}}}
}
func goodReply(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"jsonrpc":"2.0","id":"op_one","result":{"resultType":"complete","structuredContent":{"total":125000},"content":[],"isError":false}}`))
}
func TestExactDispatch(t *testing.T) {
	t.Setenv("TEST_RESOURCE_TOKEN", "backend-secret-123456789")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer backend-secret-123456789" || r.Header.Get("Mcp-Method") != "tools/call" || r.Header.Get("Mcp-Name") != "payroll.read" || r.Header.Get("MCP-Protocol-Version") != core.ProtocolVersion || r.Header.Get("Idempotency-Key") != "op_one" {
			t.Error("missing exact dispatch headers")
		}
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid body")
		}
		if !strings.Contains(string(body["params"]), "9007199254740993") {
			t.Error("numeric argument altered")
		}
		if !strings.Contains(string(body["params"]), "io.modelcontextprotocol/clientCapabilities") {
			t.Error("protocol metadata omitted")
		}
		goodReply(w)
	}))
	defer server.Close()
	tool := manifest(server.URL)
	h, err := New([]core.Tool{tool}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := h.Execute(context.Background(), dispatch(tool))
	if got.Outcome != "SUCCEEDED" || len(got.Raw) == 0 {
		t.Fatalf("unexpected execution %#v", got)
	}
	changed := dispatch(tool)
	changed.Operation.Tool.UpstreamName = "report.publish"
	if got = h.Execute(context.Background(), changed); got.Outcome != "UNKNOWN" {
		t.Fatal("mutated manifest accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("mutated operation was dispatched")
	}
}
func TestRedirectNeverFollowed(t *testing.T) {
	t.Setenv("TEST_RESOURCE_TOKEN", "backend-secret-123456789")
	var calls atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); goodReply(w) }))
	defer sink.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	tool := manifest(server.URL)
	h, err := New([]core.Tool{tool}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Execute(context.Background(), dispatch(tool)); got.Outcome != "UNKNOWN" {
		t.Fatal("redirect accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("redirect caused a second dispatch")
	}
}
func TestQuarantineTransportFailuresAreUnknown(t *testing.T) {
	t.Setenv("TEST_RESOURCE_TOKEN", "backend-secret-123456789")
	for name, reply := range map[string]string{"sse": "data: secret\n\n", "large": strings.Repeat("x", 5000), "error": `{"jsonrpc":"2.0","id":"op_one","error":{"code":-1,"message":"already wrote"}}`, "id": `{"jsonrpc":"2.0","id":"other","result":{"resultType":"complete"}}`, "mrtr": `{"jsonrpc":"2.0","id":"op_one","result":{"resultType":"input_required"}}`, "duplicate": `{"jsonrpc":"2.0","id":"op_one","id":"op_one","result":{}}`} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if name == "sse" {
					w.Header().Set("Content-Type", "text/event-stream")
				}
				w.Write([]byte(reply))
			}))
			defer server.Close()
			tool := manifest(server.URL)
			h, err := New([]core.Tool{tool}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.Execute(context.Background(), dispatch(tool)); got.Outcome != "UNKNOWN" || len(got.Raw) != 0 {
				t.Fatal("untrusted transport response exposed")
			}
		})
	}
}
func TestReconcileOnlyChecksAuthoritativeStatus(t *testing.T) {
	t.Setenv("TEST_RESOURCE_TOKEN", "backend-secret-123456789")
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("operation_id") != "op_one" {
			writes.Add(1)
			t.Error("reconciliation attempted execution")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"outcome":"SUCCEEDED","result":{"resultType":"complete","structuredContent":{"total":1}}}`))
	}))
	defer server.Close()
	tool := manifest(server.URL + "/mcp")
	tool.StatusEndpoint = server.URL + "/operations"
	h, err := New([]core.Tool{tool}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Reconcile(context.Background(), dispatch(tool)); got.Outcome != "SUCCEEDED" {
		t.Fatalf("unexpected status %#v", got)
	}
	if writes.Load() != 0 {
		t.Fatal("reconciler repeated an operation")
	}
}
func TestEndpointRestrictions(t *testing.T) {
	t.Setenv("TEST_RESOURCE_TOKEN", "backend-secret-123456789")
	for _, endpoint := range []string{"http://example.com/mcp", "http://localhost/mcp", "https://user:password@example.com/mcp", "https://example.com/mcp?url=http://evil", "https://example.com/mcp#other", "http://0.0.0.0/mcp"} {
		if _, err := New([]core.Tool{manifest(endpoint)}, time.Second); err == nil {
			t.Errorf("endpoint accepted: %s", endpoint)
		}
	}
}

func TestPersistedManifestSchemaCanonicalisationPreservesExactBinding(t *testing.T) {
	t.Setenv("TEST_RESOURCE_TOKEN", "backend-secret-123456789")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); goodReply(w) }))
	defer server.Close()
	tool := manifest(server.URL)
	tool.InputSchema = json.RawMessage(`{ "type": "object", "properties": { "resource": { "type": "string" } }, "additionalProperties": false }`)
	tool.OutputSchema = json.RawMessage(`{ "type": "object", "properties": { "total": { "type": "number" } }, "additionalProperties": false }`)
	adapter, err := New([]core.Tool{tool}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	persisted := tool
	persisted.InputSchema, err = protocol.CanonicalJSON(tool.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	persisted.OutputSchema, err = protocol.CanonicalJSON(tool.OutputSchema)
	if err != nil {
		t.Fatal(err)
	}
	if result := adapter.Execute(context.Background(), dispatch(persisted)); result.Outcome != "SUCCEEDED" {
		t.Fatalf("canonical durable manifest rejected: %#v", result)
	}
	persisted.InputSchema = json.RawMessage(`{"type":"object","properties":{"resource":{"type":"number"}},"additionalProperties":false}`)
	if result := adapter.Execute(context.Background(), dispatch(persisted)); result.Outcome != "UNKNOWN" {
		t.Fatal("changed schema semantics accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("semantically changed manifest reached resource")
	}
}
func TestPartialReplyNeverExposesPrefixOrTriggersRetry(t *testing.T) {
	t.Setenv("TEST_RESOURCE_TOKEN", "backend-secret-123456789")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":"op_one","result":{"resultType":"complete","structuredContent":{"secret":"PREFIX`))
	}))
	defer server.Close()
	tool := manifest(server.URL)
	adapter, err := New([]core.Tool{tool}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result := adapter.Execute(context.Background(), dispatch(tool)); result.Outcome != "UNKNOWN" || len(result.Raw) != 0 {
		t.Fatalf("partial response escaped quarantine: %#v", result)
	}
	if calls.Load() != 1 {
		t.Fatal("partial response triggered a retry")
	}
}
