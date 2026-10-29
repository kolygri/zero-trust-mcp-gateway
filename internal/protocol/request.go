package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
)

var toolName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

type UnsupportedVersionError struct{ Requested string }

func (e *UnsupportedVersionError) Error() string { return "unsupported protocol version" }

type Request struct {
	ID        json.RawMessage
	Method    string
	Name      string
	Arguments json.RawMessage
}

// Parse accepts supported request shapes only. It does not grant authority.
func Parse(body []byte, headers http.Header) (Request, error) {
	var envelope struct {
		JSONRPC string                     `json:"jsonrpc"`
		ID      json.RawMessage            `json:"id"`
		Method  string                     `json:"method"`
		Params  map[string]json.RawMessage `json:"params"`
	}
	var req Request
	if err := StrictJSON(body, &envelope); err != nil {
		return req, err
	}
	if envelope.JSONRPC != "2.0" || !validID(envelope.ID) {
		return req, errors.New("invalid JSON-RPC request")
	}
	req.ID = append(json.RawMessage(nil), envelope.ID...)
	if len(headers.Values("MCP-Protocol-Version")) != 1 || headers.Get("MCP-Protocol-Version") == "" {
		return req, errors.New("protocol version header required")
	}
	if !singleHeader(headers, "Mcp-Method", envelope.Method) {
		return req, errors.New("routing method mismatch")
	}
	// Removed protocol sessions must never be mistaken for security workflow IDs.
	if headers.Get("Mcp-Session-Id") != "" {
		return req, errors.New("protocol sessions are unsupported")
	}
	var meta map[string]json.RawMessage
	if err := StrictJSON(envelope.Params["_meta"], &meta); err != nil || meta == nil {
		return req, errors.New("request metadata required")
	}
	var version string
	if err := StrictJSON(meta["io.modelcontextprotocol/protocolVersion"], &version); err != nil || version != headers.Get("MCP-Protocol-Version") {
		return req, errors.New("protocol metadata mismatch")
	}
	if version != core.ProtocolVersion {
		return req, &UnsupportedVersionError{Requested: version}
	}
	var caps map[string]json.RawMessage
	if err := StrictJSON(meta["io.modelcontextprotocol/clientCapabilities"], &caps); err != nil || caps == nil {
		return req, errors.New("client capabilities required")
	}
	// Client metadata is diagnostic only. Never propagate arbitrary metadata to a tool.
	allowed := map[string]bool{"_meta": true}
	switch envelope.Method {
	case "tools/call":
		allowed["name"] = true
		allowed["arguments"] = true
		if err := StrictJSON(envelope.Params["name"], &req.Name); err != nil || !toolName.MatchString(req.Name) {
			return req, errors.New("invalid tool name")
		}
		if !singleHeader(headers, "Mcp-Name", req.Name) {
			return req, errors.New("routing tool mismatch")
		}
		req.Arguments = envelope.Params["arguments"]
		if len(req.Arguments) == 0 {
			req.Arguments = json.RawMessage(`{}`)
		}
		var args map[string]json.RawMessage
		if err := StrictJSON(req.Arguments, &args); err != nil || args == nil {
			return req, errors.New("arguments must be an object")
		}
	case "tools/list", "ping", "server/discover":
		if len(headers.Values("Mcp-Name")) != 0 {
			return req, errors.New("unexpected tool routing header")
		}
	default:
		return req, errors.New("unsupported MCP method")
	}
	for key := range envelope.Params {
		if !allowed[key] {
			return req, errors.New("unsupported request parameter")
		}
	}
	req.ID = append(json.RawMessage(nil), envelope.ID...)
	req.Method = envelope.Method
	return req, nil
}

func singleHeader(h http.Header, key, value string) bool {
	values := h.Values(key)
	return value != "" && len(values) == 1 && values[0] == value
}

func validID(id json.RawMessage) bool {
	if len(id) == 0 || bytes.Equal(id, []byte("null")) {
		return false
	}
	if id[0] == '"' {
		var s string
		return json.Unmarshal(id, &s) == nil && len(s) > 0 && len(s) <= 128
	}
	n, err := strconv.ParseInt(string(id), 10, 64)
	return err == nil && n >= -9007199254740991 && n <= 9007199254740991
}
