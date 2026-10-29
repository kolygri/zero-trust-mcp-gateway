package protocol

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const metadata = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`

func callBody() string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"payroll.read","arguments":{"resource":"payroll:september"},` + metadata + `}}`
}
func callHeaders() http.Header {
	h := http.Header{}
	h.Set("MCP-Protocol-Version", "2026-07-28")
	h.Set("Mcp-Method", "tools/call")
	h.Set("Mcp-Name", "payroll.read")
	return h
}

func TestStrictJSONRejectsAmbiguity(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"duplicate", []byte(`{"name":"safe","name":"unsafe"}`)},
		{"escaped duplicate", []byte(`{"name":"safe","na\u006de":"unsafe"}`)},
		{"nested duplicate", []byte(`{"arguments":{"x":1,"x":2}}`)},
		{"trailing", []byte(`{} {}`)},
		{"invalid UTF8", []byte{'"', 0xff, '"'}},
		{"high surrogate", []byte(`"\ud800"`)},
		{"low surrogate", []byte(`"\udc00"`)},
		{"wrong pair", []byte(`"\ud800\u0041"`)},
		{"deep", []byte(strings.Repeat("[", MaxDepth+2) + "0" + strings.Repeat("]", MaxDepth+2))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v any
			if StrictJSON(tc.raw, &v) == nil {
				t.Fatal("accepted ambiguous JSON")
			}
		})
	}
	for _, raw := range []string{`"\ud83d\ude00"`, `"\\ud800"`, `{"amount":9007199254740993}`, `[true,null,{},[]]`} {
		var v any
		if err := StrictJSON([]byte(raw), &v); err != nil {
			t.Fatalf("valid %s: %v", raw, err)
		}
	}
	var closed struct {
		Known string `json:"known"`
	}
	if StrictJSON([]byte(`{"known":"yes","unexpected":true}`), &closed) == nil {
		t.Fatal("unknown typed field accepted")
	}
}

func TestParseExactRoutingAndSupportedShapes(t *testing.T) {
	req, err := Parse([]byte(callBody()), callHeaders())
	if err != nil || req.Name != "payroll.read" || req.Method != "tools/call" || string(req.ID) != "1" {
		t.Fatalf("valid request: %#v %v", req, err)
	}
	tests := []struct {
		name   string
		body   string
		mutate func(http.Header)
	}{
		{"method mismatch", callBody(), func(h http.Header) { h.Set("Mcp-Method", "resources/read") }},
		{"name mismatch", callBody(), func(h http.Header) { h.Set("Mcp-Name", "payroll.export") }},
		{"duplicate header", callBody(), func(h http.Header) { h.Add("Mcp-Name", "payroll.read") }},
		{"version mismatch", callBody(), func(h http.Header) { h.Set("MCP-Protocol-Version", "2025-11-25") }},
		{"metadata mismatch", strings.Replace(callBody(), `"protocolVersion":"2026-07-28"`, `"protocolVersion":"2025-11-25"`, 1), nil},
		{"null ID", strings.Replace(callBody(), `"id":1`, `"id":null`, 1), nil},
		{"fractional ID", strings.Replace(callBody(), `"id":1`, `"id":1.2`, 1), nil},
		{"unsafe numeric ID", strings.Replace(callBody(), `"id":1`, `"id":9007199254740992`, 1), nil},
		{"missing ID", strings.Replace(callBody(), `"id":1,`, "", 1), nil},
		{"batch", "[" + callBody() + "]", nil},
		{"continuation", strings.Replace(callBody(), `"params":{`, `"params":{"requestState":"untrusted",`, 1), nil},
		{"input responses", strings.Replace(callBody(), `"params":{`, `"params":{"inputResponses":{},`, 1), nil},
		{"null arguments", strings.Replace(callBody(), `{"resource":"payroll:september"}`, `null`, 1), nil},
		{"legacy session", callBody(), func(h http.Header) { h.Set("Mcp-Session-Id", "not-a-workflow") }},
		{"root field", strings.Replace(callBody(), `"jsonrpc":"2.0"`, `"jsonrpc":"2.0","result":{}`, 1), nil},
	}
	// Replace the full metadata key to avoid a test that silently changes nothing.
	tests[4].body = strings.Replace(callBody(), `io.modelcontextprotocol/protocolVersion":"2026-07-28`, `io.modelcontextprotocol/protocolVersion":"2025-11-25`, 1)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := callHeaders()
			if tc.mutate != nil {
				tc.mutate(h)
			}
			if _, err := Parse([]byte(tc.body), h); err == nil {
				t.Fatal("accepted unsupported request")
			}
		})
	}
	for _, method := range []string{"tools/list", "ping", "server/discover"} {
		h := callHeaders()
		h.Set("Mcp-Method", method)
		h.Del("Mcp-Name")
		body := `{"jsonrpc":"2.0","id":"a","method":"` + method + `","params":{` + metadata + `}}`
		if _, err := Parse([]byte(body), h); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
	}
	for _, method := range []string{"initialize", "resources/read", "prompts/get", "subscriptions/listen", "notifications/cancelled", "custom/execute"} {
		h := callHeaders()
		h.Set("Mcp-Method", method)
		h.Del("Mcp-Name")
		body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + metadata + `}}`
		if _, err := Parse([]byte(body), h); err == nil {
			t.Fatalf("unsupported %s accepted", method)
		}
	}
}

func TestCanonicalBindingPreservesNumbers(t *testing.T) {
	got, err := CanonicalJSON([]byte(`{ "z":9007199254740993,"a":{"x":1.00}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":{"x":1.00},"z":9007199254740993}` {
		t.Fatalf("lost exact numeric meaning: %s", got)
	}
	equivalent, err := CanonicalJSON([]byte(`{"a":{"x":1.00},"z":9007199254740993}`))
	if err != nil || string(got) != string(equivalent) {
		t.Fatal("object order changed binding")
	}
}

func FuzzCanonicalJSON(f *testing.F) {
	for _, seed := range []string{`{}`, callBody(), `{"x":1,"x":2}`, `"\ud800"`, `[1,2,3]`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		canonical, err := CanonicalJSON(b)
		if err != nil {
			return
		}
		if !json.Valid(canonical) {
			t.Fatal("canonical result invalid")
		}
		second, err := CanonicalJSON(canonical)
		if err != nil || string(second) != string(canonical) {
			t.Fatal("canonical encoding is not idempotent")
		}
	})
}
