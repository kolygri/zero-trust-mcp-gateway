// Package server exposes authenticated host control and a narrow MCP data plane.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/config"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/workflow"
)

type Server struct {
	config      *config.Config
	coordinator *workflow.Coordinator
	slots       chan struct{}
}

func New(c *config.Config, w *workflow.Coordinator) http.Handler {
	s := &Server{config: c, coordinator: w, slots: make(chan struct{}, 32)}
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if len(r.Header.Values("Origin")) > 1 {
		fail(w, 403, "origin denied")
		return
	}
	if len(r.Header.Values("Origin")) == 1 && !slices.Contains(s.config.AllowedOrigins, r.Header.Get("Origin")) {
		fail(w, 403, "origin denied")
		return
	}
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		write(w, 200, map[string]string{"status": "alive"})
		return
	}
	if len(r.Header.Values("Authorization")) != 1 {
		fail(w, 401, "authentication required")
		return
	}
	p, ok := s.config.Authenticate(r.Header.Get("Authorization"))
	if !ok {
		fail(w, 401, "authentication required")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(w, 503, "capacity exceeded")
		return
	}
	if r.Header.Get("Content-Encoding") != "" {
		fail(w, 415, "content encoding unsupported")
		return
	}
	if r.Method == http.MethodPost {
		if len(r.Header.Values("Content-Type")) != 1 {
			fail(w, 415, "one Content-Type required")
			return
		}
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			fail(w, 415, "application/json required")
			return
		}
	}
	if r.URL.Path == "/mcp" {
		s.mcp(w, r, p)
		return
	}
	s.control(w, r, p)
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request, p core.Principal) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "POST required")
		return
	}
	if !role(p, "agent") {
		fail(w, 403, "agent role required")
		return
	}
	if !acceptsMCP(r.Header.Values("Accept")) {
		fail(w, 406, "MCP Accept types required")
		return
	}
	b, err := readBody(w, r)
	if err != nil {
		fail(w, 400, "invalid or oversized body")
		return
	}
	req, err := protocol.Parse(b, r.Header)
	if err != nil {
		var unsupported *protocol.UnsupportedVersionError
		if errors.As(err, &unsupported) {
			rpcError(w, 400, req.ID, -32022, "unsupported protocol version", map[string]any{"supported": []string{core.ProtocolVersion}, "requested": unsupported.Requested})
			return
		}
		rpcError(w, 400, req.ID, -32600, "unsupported or invalid request", nil)
		return
	}
	if req.Method == "ping" {
		rpcResult(w, req.ID, map[string]any{"resultType": "complete"})
		return
	}
	if req.Method == "server/discover" {
		rpcResult(w, req.ID, map[string]any{"resultType": "complete", "supportedVersions": []string{core.ProtocolVersion}, "capabilities": map[string]any{"tools": map[string]any{}}, "_meta": map[string]any{"io.modelcontextprotocol/serverInfo": map[string]string{"name": "zero-trust-mcp-gateway", "version": "0.1.0"}}})
		return
	}
	wfID := r.Header.Get("X-Gateway-Workflow-ID")
	if len(r.Header.Values("X-Gateway-Workflow-ID")) != 1 || wfID == "" {
		rpcError(w, 400, req.ID, -32602, "workflow reference required", nil)
		return
	}
	wf, err := s.coordinator.GetWorkflow(r.Context(), p, wfID)
	if err != nil {
		rpcError(w, 403, req.ID, -32001, "workflow unavailable", nil)
		return
	}
	if req.Method == "tools/list" {
		tools := []map[string]any{}
		for _, t := range s.config.Bundle.Tools {
			if slices.Contains(wf.Template.Tools, t.Name) && slices.Contains(p.Tools, t.Name) && slices.Contains(wf.Template.Destinations, t.Destination) && slices.Contains(p.Destinations, t.Destination) {
				tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema, "outputSchema": t.OutputSchema})
			}
		}
		rpcResult(w, req.ID, map[string]any{"resultType": "complete", "tools": tools})
		return
	}
	if req.Method != "tools/call" {
		rpcError(w, 400, req.ID, -32601, "method unsupported", nil)
		return
	}
	opID := r.Header.Get("X-Gateway-Operation-ID")
	if len(r.Header.Values("X-Gateway-Operation-ID")) > 1 {
		rpcError(w, 400, req.ID, -32602, "ambiguous operation reference", nil)
		return
	}
	if opID == "" {
		for _, tool := range s.config.Bundle.Tools {
			if tool.Name == req.Name && tool.Effect != "read" {
				rpcError(w, 400, req.ID, -32602, "operation precreation required before effects", nil)
				return
			}
		}
		op, err := s.coordinator.NewOperation(r.Context(), p, wfID, req.Name, req.Arguments)
		if err != nil {
			rpcError(w, 403, req.ID, -32001, "operation unavailable", nil)
			return
		}
		opID = op.ID
	} else {
		op, err := s.coordinator.GetOperation(r.Context(), p, opID)
		if err != nil {
			rpcError(w, 403, req.ID, -32001, "operation unavailable", nil)
			return
		}
		canonical, err := protocol.CanonicalJSON(req.Arguments)
		saved, savedErr := protocol.CanonicalJSON(op.Candidate.Arguments)
		if err != nil || savedErr != nil || op.Candidate.WorkflowID != wfID || op.Candidate.Tool != req.Name || string(canonical) != string(saved) {
			rpcError(w, 409, req.ID, -32002, "operation binding mismatch", nil)
			return
		}
	}
	result, err := s.coordinator.Execute(r.Context(), p, opID)
	if err != nil {
		rpcError(w, 503, req.ID, -32000, "execution unavailable; inspect operation before retry", map[string]string{"operation_id": opID})
		return
	}
	w.Header().Set("X-Gateway-Operation-ID", opID)
	if result.ReleaseStatus != "RELEASED" || len(result.Result) == 0 {
		rpcError(w, 200, req.ID, -32003, "operation has no newly released result; inspect recorded status", result)
		return
	}
	rpcResult(w, req.ID, result.Result)
}

func (s *Server) control(w http.ResponseWriter, r *http.Request, p core.Principal) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.URL.Path == "/v1/workflows" && r.Method == http.MethodPost {
		if !role(p, "host") {
			fail(w, 403, "trusted host role required")
			return
		}
		var input struct {
			TemplateID string `json:"template_id"`
		}
		if err := decode(w, r, &input); err != nil {
			fail(w, 400, "invalid workflow request")
			return
		}
		wf, err := s.coordinator.CreateWorkflow(r.Context(), p, input.TemplateID)
		if err != nil {
			fail(w, 403, "workflow creation denied")
			return
		}
		write(w, 201, wf)
		return
	}
	if len(parts) == 4 && parts[0] == "v1" && parts[1] == "workflows" && parts[3] == "operations" && r.Method == http.MethodPost {
		if !role(p, "agent") {
			fail(w, 403, "agent role required")
			return
		}
		var input struct {
			Tool      string          `json:"tool"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := decode(w, r, &input); err != nil || input.Tool == "" || len(input.Tool) > 128 {
			fail(w, 400, "invalid operation candidate")
			return
		}
		if len(input.Arguments) == 0 {
			input.Arguments = json.RawMessage(`{}`)
		}
		var args map[string]json.RawMessage
		if err := protocol.StrictJSON(input.Arguments, &args); err != nil || args == nil {
			fail(w, 400, "arguments must be an object")
			return
		}
		op, err := s.coordinator.NewOperation(r.Context(), p, parts[2], input.Tool, input.Arguments)
		if err != nil {
			fail(w, 403, "operation creation denied")
			return
		}
		write(w, 201, operationDisplay(op))
		return
	}
	if len(parts) == 3 && parts[0] == "v1" && parts[1] == "workflows" && r.Method == http.MethodGet {
		if !role(p, "host") && !role(p, "agent") {
			fail(w, 403, "role denied")
			return
		}
		wf, err := s.coordinator.GetWorkflow(r.Context(), p, parts[2])
		if err != nil {
			fail(w, 404, "workflow unavailable")
			return
		}
		write(w, 200, wf)
		return
	}
	if len(parts) >= 3 && parts[0] == "v1" && parts[1] == "operations" {
		id := parts[2]
		if len(parts) == 3 && r.Method == http.MethodGet {
			op, err := s.coordinator.GetOperation(r.Context(), p, id)
			if err != nil {
				fail(w, 404, "operation unavailable")
				return
			}
			// Return trusted approval display fields but never upstream credentials or evidence bytes.
			write(w, 200, operationDisplay(op))
			return
		}
		if len(parts) == 4 && r.Method == http.MethodPost && (parts[3] == "approve" || parts[3] == "reconcile") {
			if !role(p, "approver") && !role(p, "admin") {
				fail(w, 403, "independent reviewer role required")
				return
			}
			var input struct{}
			if err := decode(w, r, &input); err != nil {
				fail(w, 400, "empty JSON object required")
				return
			}
			if parts[3] == "approve" {
				a, err := s.coordinator.Approve(r.Context(), p, id)
				if err != nil {
					fail(w, 403, "approval denied")
					return
				}
				write(w, 200, a)
				return
			}
			result, err := s.coordinator.Reconcile(r.Context(), p, id)
			if err != nil {
				fail(w, 409, "reconciliation unresolved")
				return
			}
			write(w, 200, result)
			return
		}
	}
	if r.URL.Path == "/v1/audit" && r.Method == http.MethodGet {
		if !role(p, "admin") {
			fail(w, 403, "administrator role required")
			return
		}
		if err := s.coordinator.VerifyAudit(r.Context()); err != nil {
			fail(w, 503, "audit integrity check failed")
			return
		}
		events, err := s.coordinator.Audit(r.Context())
		if err != nil {
			fail(w, 503, "audit unavailable")
			return
		}
		write(w, 200, events)
		return
	}
	fail(w, 404, "endpoint unavailable")
}

func role(p core.Principal, r string) bool { return slices.Contains(p.Roles, r) }
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	b, e := readBody(w, r)
	if e != nil {
		return e
	}
	if len(b) == 0 {
		return errors.New("body required")
	}
	return protocol.StrictJSON(b, v)
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	write(w, status, map[string]string{"error": msg})
}
func rpcResult(w http.ResponseWriter, id json.RawMessage, result any) {
	write(w, 200, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}
func rpcError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string, data any) {
	write(w, status, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg, "data": data}})
}

func acceptsMCP(values []string) bool {
	types := map[string]bool{}
	for _, value := range values {
		for _, entry := range strings.Split(value, ",") {
			media, params, err := mime.ParseMediaType(strings.TrimSpace(entry))
			if err != nil {
				return false
			}
			if quality, ok := params["q"]; ok {
				q, err := strconv.ParseFloat(quality, 64)
				if err != nil || !(q >= 0 && q <= 1) {
					return false
				}
				if q == 0 {
					continue
				}
			}
			types[strings.ToLower(media)] = true
		}
	}
	return types["application/json"] && types["text/event-stream"]
}

func operationDisplay(op core.Operation) map[string]any {
	return map[string]any{"id": op.ID, "candidate": op.Candidate, "principal": op.Principal, "policy_digest": op.PolicyDigest, "request_digest": op.RequestDigest, "decision": op.Decision, "execution_status": op.Status, "release_status": op.ReleaseStatus, "expires_at": op.ExpiresAt, "server_id": op.Tool.ServerID, "deployment_digest": op.Tool.DeploymentDigest, "destination": op.Tool.Destination, "effect": op.Tool.Effect, "release_fields": op.Tool.ReleaseFields}
}
