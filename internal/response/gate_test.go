package response

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
)

func tool() core.Tool {
	return core.Tool{MaxResultBytes: 4096, ReleaseFields: []string{"total"}, OutputSchema: json.RawMessage(`{"type":"object","properties":{"total":{"type":"number"}},"required":["total"],"additionalProperties":false}`)}
}
func TestProjectionDiscardsAllOtherChannels(t *testing.T) {
	raw := json.RawMessage(`{"resultType":"complete","structuredContent":{"total":12,"employee_rows":[{"salary":10000}]},"content":[{"type":"text","text":"SECRET raw payroll"}],"_meta":{"link":"https://exfil.example/SECRET"},"isError":false}`)
	got, err := New().Release(tool(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET", "salary", "employee_rows", "exfil.example"} {
		if strings.Contains(string(got), secret) {
			t.Fatalf("raw channel leaked: %s", got)
		}
	}
	if !strings.Contains(string(got), `"total":12`) {
		t.Fatal("contracted value lost")
	}
}
func TestUnsupportedAndInvalidOutputQuarantined(t *testing.T) {
	for name, raw := range map[string]string{
		"binary":    `{"resultType":"complete","structuredContent":{"total":1},"content":[{"type":"image","data":"SECRET"}]}`,
		"link":      `{"resultType":"complete","structuredContent":{"total":1},"content":[{"type":"resource_link","uri":"https://example.com"}]}`,
		"missing":   `{"resultType":"complete","content":[{"type":"text","text":"SECRET"}]}`,
		"schema":    `{"resultType":"complete","structuredContent":{"total":"SECRET"}}`,
		"mrtr":      `{"resultType":"input_required","inputRequests":{},"structuredContent":{"total":1}}`,
		"failed":    `{"resultType":"complete","isError":true,"structuredContent":{"total":1}}`,
		"duplicate": `{"resultType":"complete","structuredContent":{"total":1,"total":2}}`,
		"unknown":   `{"resultType":"complete","structuredContent":{"total":1},"nextCursor":"https://evil"}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := New().Release(tool(), json.RawMessage(raw))
			if err == nil || got != nil {
				t.Fatal("unsafe result released")
			}
		})
	}
}
func TestNestedOutputMustBeClosedAndTyped(t *testing.T) {
	manifest := tool()
	manifest.ReleaseFields = []string{"report"}
	manifest.OutputSchema = json.RawMessage(`{"type":"object","properties":{"report":{"type":"object","properties":{"total":{"type":"number"}},"required":["total"],"additionalProperties":false}},"required":["report"],"additionalProperties":false}`)
	raw := json.RawMessage(`{"resultType":"complete","structuredContent":{"report":{"total":1,"salary":10000}}}`)
	if _, err := New().Release(manifest, raw); err == nil {
		t.Fatal("nested extra field released")
	}
	manifest.OutputSchema = json.RawMessage(`{"type":"object","properties":{"report":{}},"additionalProperties":false}`)
	if _, err := New().Release(manifest, raw); err == nil {
		t.Fatal("arbitrary nested object authorised")
	}
	manifest.OutputSchema = json.RawMessage(`{"type":"object","properties":{"report":{"type":"array"}},"additionalProperties":false}`)
	if _, err := New().Release(manifest, json.RawMessage(`{"resultType":"complete","structuredContent":{"report":[{"salary":10000}]}}`)); err == nil {
		t.Fatal("untyped array payload authorised")
	}
	manifest.OutputSchema = json.RawMessage(`{"type":"object","properties":{"report":{"$ref":"https://example.com/schema"}},"additionalProperties":false}`)
	if _, err := New().Release(manifest, raw); err == nil {
		t.Fatal("remote schema reference accepted")
	}
}
