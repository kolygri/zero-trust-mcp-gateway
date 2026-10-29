// Package executor dispatches immutable, authorised operations to approved endpoints.
package executor

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
)

const maxBound = int64(16 << 20)

type approved struct {
	tool      core.Tool
	token     string
	canonical []byte
}

// HTTP pins resolution at construction. It never consults environment proxy settings,
// follows redirects, retries an operation, or forwards the caller's credentials.
type HTTP struct {
	client *http.Client
	tools  map[string]approved
}

func New(tools []core.Tool, timeout time.Duration) (*HTTP, error) {
	if timeout <= 0 || timeout > 5*time.Minute {
		return nil, errors.New("executor timeout must be between zero and five minutes")
	}
	pins := map[string][]net.IP{}
	approvedTools := map[string]approved{}
	for _, tool := range tools {
		if _, ok := approvedTools[tool.Name]; ok {
			return nil, errors.New("duplicate tool")
		}
		if tool.Name == "" || tool.UpstreamName == "" || tool.TokenEnv == "" || tool.MaxResultBytes <= 0 || tool.MaxResultBytes > maxBound {
			return nil, errors.New("invalid executor manifest")
		}
		token := os.Getenv(tool.TokenEnv)
		if len(token) < 16 || strings.ContainsAny(token, "\r\n") {
			return nil, fmt.Errorf("dedicated backend credential %s must contain at least 16 bytes", tool.TokenEnv)
		}
		for _, endpoint := range []string{tool.Endpoint, tool.StatusEndpoint} {
			if endpoint == "" {
				continue
			}
			u, err := validateURL(endpoint)
			if err != nil {
				return nil, err
			}
			port := u.Port()
			if port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			addr := net.JoinHostPort(u.Hostname(), port)
			if _, ok := pins[addr]; ok {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", u.Hostname())
			cancel()
			if err != nil || len(ips) == 0 {
				return nil, errors.New("approved endpoint cannot be resolved")
			}
			for _, ip := range ips {
				if ip.IsUnspecified() || ip.IsMulticast() {
					return nil, errors.New("unspecified or multicast endpoint forbidden")
				}
			}
			pins[addr] = ips
		}
		b, err := json.Marshal(tool)
		if err != nil {
			return nil, errors.New("invalid executor manifest encoding")
		}
		b, err = protocol.CanonicalJSON(b)
		if err != nil {
			return nil, errors.New("invalid executor manifest encoding")
		}
		approvedTools[tool.Name] = approved{tool: tool, token: token, canonical: b}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: timeout,
		MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			ips, ok := pins[address]
			if !ok {
				return nil, errors.New("unapproved network endpoint")
			}
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			var last error
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		},
	}
	return &HTTP{client: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tools: approvedTools}, nil
}

func validateURL(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("endpoint must be an absolute approved URL without credentials, query or fragment")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("HTTP is permitted only for literal loopback endpoints")
		}
	}
	if u.Port() != "" {
		n, e := strconv.Atoi(u.Port())
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid endpoint port")
		}
	}
	return u, nil
}

func (h *HTTP) authorised(d core.Dispatch) (approved, bool) {
	a, ok := h.tools[d.Operation.Tool.Name]
	if !ok {
		return approved{}, false
	}
	actual, err := json.Marshal(d.Operation.Tool)
	if err != nil {
		return approved{}, false
	}
	actual, err = protocol.CanonicalJSON(actual)
	if err != nil {
		return approved{}, false
	}
	if subtle.ConstantTimeCompare(actual, a.canonical) != 1 || d.Operation.Candidate.Tool != a.tool.Name || d.Operation.ID == "" || d.Operation.PermitID == "" || d.Operation.OwnerEpoch == "" || d.Operation.Candidate.OperationID != d.Operation.ID || d.Operation.Candidate.WorkflowID != d.Workflow.ID || d.Operation.Decision.Outcome != core.Allow {
		return approved{}, false
	}
	return a, true
}

func (h *HTTP) Execute(ctx context.Context, d core.Dispatch) core.Execution {
	a, ok := h.authorised(d)
	if !ok {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	var args map[string]any
	if protocol.StrictJSON(d.Operation.Candidate.Arguments, &args) != nil || args == nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	body := map[string]any{"jsonrpc": "2.0", "id": d.Operation.ID, "method": "tools/call", "params": map[string]any{
		"name": a.tool.UpstreamName, "arguments": args, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": core.ProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}},
	}}
	encoded, err := json.Marshal(body)
	if err != nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tool.Endpoint, bytes.NewReader(encoded))
	if err != nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", core.ProtocolVersion)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", a.tool.UpstreamName)
	req.Header.Set("X-Gateway-Operation-ID", d.Operation.ID)
	req.Header.Set("Idempotency-Key", d.Operation.ID)
	// GetBody nil prevents the transport from replaying a request after a network error.
	req.GetBody = nil
	raw, err := h.fetch(req, a.tool.MaxResultBytes)
	if err != nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if protocol.StrictJSON(raw, &envelope) != nil || envelope.JSONRPC != "2.0" || len(envelope.Error) > 0 || len(envelope.Result) == 0 {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	id, _ := json.Marshal(d.Operation.ID)
	if !bytes.Equal(envelope.ID, id) {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	// Any resource reply is evidence only of the reported operation outcome. A tool
	// error is conservatively UNKNOWN: its side effects cannot be inferred from isError.
	var result map[string]any
	if protocol.StrictJSON(envelope.Result, &result) != nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	if flag, exists := result["isError"]; exists {
		if _, valid := flag.(bool); !valid {
			return core.Execution{Outcome: "UNKNOWN"}
		}
	}
	if result["resultType"] != "complete" || result["isError"] == true {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	return core.Execution{Outcome: "SUCCEEDED", Raw: envelope.Result}
}

func (h *HTTP) Reconcile(ctx context.Context, d core.Dispatch) core.Execution {
	a, ok := h.authorised(d)
	if !ok || a.tool.StatusEndpoint == "" {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	u, err := url.Parse(a.tool.StatusEndpoint)
	if err != nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	q := u.Query()
	q.Set("operation_id", d.Operation.ID)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/json")
	raw, err := h.fetch(req, a.tool.MaxResultBytes)
	if err != nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	var status struct {
		Outcome string          `json:"outcome"`
		Result  json.RawMessage `json:"result"`
	}
	if protocol.StrictJSON(raw, &status) != nil {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	if status.Outcome != "SUCCEEDED" && status.Outcome != "FAILED" {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	if status.Outcome == "SUCCEEDED" && len(status.Result) == 0 {
		return core.Execution{Outcome: "UNKNOWN"}
	}
	return core.Execution{Outcome: status.Outcome, Raw: status.Result}
}

func (h *HTTP) fetch(req *http.Request, limit int64) ([]byte, error) {
	res, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("unsupported upstream response")
	}
	kind, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		return nil, errors.New("upstream must return bounded JSON")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("upstream result exceeds quarantine bound")
	}
	return b, nil
}
