package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/executor"
)

const readToken = "read-resource-credential-123456"
const publishToken = "publish-resource-credential-987654"

func request(tool, id, token string) *http.Request {
	args := map[string]any{"resource": "payroll:2026-09"}
	if tool == "report.publish" {
		args["destination"] = "internal-report-store"
	}
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": core.ProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("MCP-Protocol-Version", core.ProtocolVersion)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", tool)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-Gateway-Operation-ID", id)
	req.Header.Set("Idempotency-Key", id)
	return req
}
func TestReadCredentialCannotPublish(t *testing.T) {
	r, err := openResource(filepath.Join(t.TempDir(), "state.json"), readToken, publishToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", readToken} {
		reply := httptest.NewRecorder()
		r.ServeHTTP(reply, request("report.publish", "op_wrong_scope", token))
		if reply.Code != http.StatusForbidden && reply.Code != http.StatusUnauthorized {
			t.Fatalf("read credential published: %d %s", reply.Code, reply.Body)
		}
	}
	if r.state.Publications != 0 || len(r.state.Receipts) != 0 {
		t.Fatal("forbidden request caused a resource effect")
	}
	reply := httptest.NewRecorder()
	r.ServeHTTP(reply, request("payroll.read", "op_read", readToken))
	if reply.Code != http.StatusOK {
		t.Fatalf("authorised read failed: %d %s", reply.Code, reply.Body)
	}
}
func TestIdempotentEffectAndReceiptSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	r, err := openResource(path, readToken, publishToken)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		reply := httptest.NewRecorder()
		r.ServeHTTP(reply, request("report.publish", "op_publish", publishToken))
		if reply.Code != http.StatusOK {
			t.Fatalf("publication failed: %d %s", reply.Code, reply.Body)
		}
	}
	if r.state.Publications != 1 {
		t.Fatal("duplicate request repeated a business effect")
	}
	restarted, err := openResource(path, readToken, publishToken)
	if err != nil {
		t.Fatal(err)
	}
	reply := httptest.NewRecorder()
	restarted.ServeHTTP(reply, request("report.publish", "op_publish", publishToken))
	if reply.Code != http.StatusOK || restarted.state.Publications != 1 {
		t.Fatal("restart lost resource idempotency")
	}
	status := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/operations?operation_id=op_publish", nil)
	status.Header.Set("Authorization", "Bearer "+publishToken)
	reply = httptest.NewRecorder()
	restarted.ServeHTTP(reply, status)
	if reply.Code != http.StatusOK || !bytes.Contains(reply.Body.Bytes(), []byte(`"outcome":"SUCCEEDED"`)) {
		t.Fatal("authoritative status lost")
	}
	status.Header.Set("Authorization", "Bearer "+readToken)
	reply = httptest.NewRecorder()
	restarted.ServeHTTP(reply, status)
	if reply.Code != http.StatusForbidden {
		t.Fatal("read identity obtained publication receipt")
	}
}
func TestOperationCannotChangeMeaning(t *testing.T) {
	r, err := openResource(filepath.Join(t.TempDir(), "state.json"), readToken, publishToken)
	if err != nil {
		t.Fatal(err)
	}
	reply := httptest.NewRecorder()
	r.ServeHTTP(reply, request("payroll.read", "op_same", readToken))
	if reply.Code != http.StatusOK {
		t.Fatal(reply.Body.String())
	}
	reply = httptest.NewRecorder()
	r.ServeHTTP(reply, request("payroll.report", "op_same", readToken))
	if reply.Code != http.StatusConflict {
		t.Fatal("reused operation changed meaning")
	}
	if len(r.state.Receipts) != 1 {
		t.Fatal("binding mismatch caused an effect")
	}
}
func TestNoCredentialMeansNoResourceDisclosure(t *testing.T) {
	r, err := openResource(filepath.Join(t.TempDir(), "state.json"), readToken, publishToken)
	if err != nil {
		t.Fatal(err)
	}
	reply := httptest.NewRecorder()
	r.ServeHTTP(reply, request("payroll.read", "op_no_auth", "invalid"))
	if reply.Code != http.StatusUnauthorized || bytes.Contains(reply.Body.Bytes(), []byte("125000")) {
		t.Fatal("unauthenticated resource disclosure")
	}
	if len(r.state.Receipts) != 0 {
		t.Fatal("unauthenticated request executed")
	}
}

// Ground truth comes from the resource's publication count, rather than a
// gateway DENY message. A dropped reply after persistence must not retry.
func TestDroppedWriteReplyReconcilesWithoutRepeatingEffect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	r, err := openResource(path, readToken, publishToken)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			recorder := httptest.NewRecorder()
			r.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Errorf("resource rejected dispatched write: %s", recorder.Body)
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		r.ServeHTTP(w, req)
	}))
	defer server.Close()
	t.Setenv("TEST_PUBLISH_TOKEN", publishToken)
	tool := core.Tool{Name: "report.publish", UpstreamName: "report.publish", Endpoint: server.URL + "/mcp", StatusEndpoint: server.URL + "/operations", TokenEnv: "TEST_PUBLISH_TOKEN", MaxResultBytes: 4096}
	adapter, err := executor.New([]core.Tool{tool}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	d := core.Dispatch{Workflow: core.Workflow{ID: "wf_drop"}, Operation: core.Operation{ID: "op_drop", Tool: tool, PermitID: "permit_drop", OwnerEpoch: "epoch_drop", Decision: core.Decision{Outcome: core.Allow}, Candidate: core.Candidate{OperationID: "op_drop", WorkflowID: "wf_drop", Tool: "report.publish", Arguments: json.RawMessage(`{"resource":"payroll:2026-09","destination":"internal-report-store"}`)}}}
	if result := adapter.Execute(context.Background(), d); result.Outcome != "UNKNOWN" {
		t.Fatalf("dropped write reply status: %s", result.Outcome)
	}
	r.mu.Lock()
	count := r.state.Publications
	r.mu.Unlock()
	if count != 1 {
		t.Fatalf("resource ground truth publication count: %d", count)
	}
	if result := adapter.Reconcile(context.Background(), d); result.Outcome != "SUCCEEDED" || len(result.Raw) == 0 {
		t.Fatalf("authoritative reconciliation: %#v", result)
	}
	r.mu.Lock()
	count = r.state.Publications
	r.mu.Unlock()
	if count != 1 {
		t.Fatal("reconciliation repeated a business effect")
	}
}
