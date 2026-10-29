package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
)

func fixture() (core.Bundle, core.Workflow, core.Principal, core.Candidate, core.Tool, time.Time) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	tool := core.Tool{Name: "payroll.read", Description: "Approved payroll summary", ServerID: "compute", DeploymentDigest: "sha256:" + strings.Repeat("a", 64), Endpoint: "http://127.0.0.1:9090/mcp", UpstreamName: "payroll.read", TokenEnv: "PAYROLL_TOKEN", InputSchema: json.RawMessage(`{"type":"object","properties":{"resource":{"type":"string"}},"required":["resource"],"additionalProperties":false}`), OutputSchema: json.RawMessage(`{"type":"object","properties":{"total":{"type":"number"}},"required":["total"]}`), Effect: "read", Destination: "internal-store", ResourceArgument: "resource", Resources: []string{"payroll:september"}, SourceExposure: core.Exposure{Confidentiality: core.Restricted, Untrusted: true}, MaxInputLabel: core.Restricted, ReleaseFields: []string{"total"}, MaxResultBytes: 1024}
	contract := core.Template{ID: "payroll-report-v1", Tools: []string{tool.Name}, Resources: []string{"payroll:september"}, Destinations: []string{tool.Destination}, InitialExposure: core.Exposure{Confidentiality: core.Public}, MaxCalls: 5, LifetimeSeconds: 3600}
	p := core.Principal{Tenant: "finance", User: "alice", Workload: "host", Roles: []string{"caller"}, Tools: []string{tool.Name}, Resources: []string{"payroll:september"}, Destinations: []string{tool.Destination}, Clearance: core.Restricted}
	b := core.Bundle{Version: "1", Semantics: "v1", Digest: "sha256:bundle", ExpiresAt: now.Add(time.Hour), Tools: []core.Tool{tool}, Templates: []core.Template{contract}}
	w := core.Workflow{ID: "wf", DomainID: "domain", Principal: p, Template: contract, PolicyDigest: b.Digest, Exposure: contract.InitialExposure, ExpiresAt: now.Add(time.Hour), Revision: 1}
	c := core.Candidate{OperationID: "op", WorkflowID: "wf", Revision: 1, Tool: tool.Name, Arguments: json.RawMessage(`{"resource":"payroll:september"}`)}
	return b, w, p, c, tool, now
}

func TestValidBundleAndAllow(t *testing.T) {
	b, w, p, c, tool, now := fixture()
	if err := ValidateBundle(b); err != nil {
		t.Fatal(err)
	}
	if d := Evaluate(b, w, p, c, tool, false, now); d.Outcome != core.Allow {
		t.Fatalf("valid call denied: %#v", d)
	}
}

func TestHardRulesPrecedeApproval(t *testing.T) {
	tests := []struct {
		name, reason string
		change       func(*core.Bundle, *core.Workflow, *core.Principal, *core.Candidate, *core.Tool)
	}{
		{"tenant crossing", "PRINCIPAL_MISMATCH", func(_ *core.Bundle, _ *core.Workflow, p *core.Principal, _ *core.Candidate, _ *core.Tool) {
			p.Tenant = "other"
		}},
		{"user crossing", "PRINCIPAL_MISMATCH", func(_ *core.Bundle, _ *core.Workflow, p *core.Principal, _ *core.Candidate, _ *core.Tool) {
			p.User = "other"
		}},
		{"workload crossing", "PRINCIPAL_MISMATCH", func(_ *core.Bundle, _ *core.Workflow, p *core.Principal, _ *core.Candidate, _ *core.Tool) {
			p.Workload = "other"
		}},
		{"unknown tool", "TOOL_NOT_APPROVED", func(_ *core.Bundle, _ *core.Workflow, _ *core.Principal, c *core.Candidate, _ *core.Tool) {
			c.Tool = "shell"
		}},
		{"request mutation", "TOOL_NOT_APPROVED", func(_ *core.Bundle, _ *core.Workflow, _ *core.Principal, _ *core.Candidate, t *core.Tool) {
			t.Endpoint = "http://127.0.0.1:9999/mcp"
		}},
		{"expired bundle", "POLICY_STALE", func(b *core.Bundle, _ *core.Workflow, _ *core.Principal, _ *core.Candidate, _ *core.Tool) {
			b.ExpiresAt = time.Time{}
		}},
		{"new policy", "POLICY_CHANGED", func(_ *core.Bundle, w *core.Workflow, _ *core.Principal, _ *core.Candidate, _ *core.Tool) {
			w.PolicyDigest = "old"
		}},
		{"expired workflow", "WORKFLOW_EXPIRED", func(_ *core.Bundle, w *core.Workflow, _ *core.Principal, _ *core.Candidate, _ *core.Tool) {
			w.ExpiresAt = time.Time{}
		}},
		{"tool authority revoked", "TOOL_NOT_PERMITTED", func(_ *core.Bundle, _ *core.Workflow, p *core.Principal, _ *core.Candidate, _ *core.Tool) {
			p.Tools = nil
		}},
		{"destination revoked", "DESTINATION_NOT_PERMITTED", func(_ *core.Bundle, _ *core.Workflow, p *core.Principal, _ *core.Candidate, _ *core.Tool) {
			p.Destinations = nil
		}},
		{"resource revoked", "RESOURCE_NOT_PERMITTED", func(_ *core.Bundle, _ *core.Workflow, p *core.Principal, _ *core.Candidate, _ *core.Tool) {
			p.Resources = nil
		}},
		{"resource substitution", "RESOURCE_NOT_PERMITTED", func(_ *core.Bundle, _ *core.Workflow, _ *core.Principal, c *core.Candidate, _ *core.Tool) {
			c.Arguments = json.RawMessage(`{"resource":"payroll:october"}`)
		}},
		{"unknown output clearance", "CLASSIFICATION_UNKNOWN", func(_ *core.Bundle, _ *core.Workflow, p *core.Principal, _ *core.Candidate, _ *core.Tool) {
			p.Clearance = "unknown"
		}},
		{"prospective exposure", "CLEARANCE_INSUFFICIENT", func(_ *core.Bundle, _ *core.Workflow, p *core.Principal, _ *core.Candidate, _ *core.Tool) {
			p.Clearance = core.Public
		}},
		{"unknown argument", "ARGUMENT_SCHEMA_INVALID", func(_ *core.Bundle, _ *core.Workflow, _ *core.Principal, c *core.Candidate, _ *core.Tool) {
			c.Arguments = json.RawMessage(`{"resource":"payroll:september","upload_url":"https://evil.example"}`)
		}},
		{"duplicate argument", "ARGUMENT_SCHEMA_INVALID", func(_ *core.Bundle, _ *core.Workflow, _ *core.Principal, c *core.Candidate, _ *core.Tool) {
			c.Arguments = json.RawMessage(`{"resource":"payroll:september","resource":"payroll:october"}`)
		}},
		{"quota", "QUOTA_EXHAUSTED", func(_ *core.Bundle, w *core.Workflow, _ *core.Principal, _ *core.Candidate, _ *core.Tool) {
			w.Calls = w.Template.MaxCalls
		}},
		{"domain busy", "EXPOSURE_DOMAIN_BUSY", func(_ *core.Bundle, w *core.Workflow, _ *core.Principal, _ *core.Candidate, _ *core.Tool) {
			w.Inflight = "other-op"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, w, p, c, tool, now := fixture()
			tool.RequireApproval = true
			b.Tools[0] = tool
			tc.change(&b, &w, &p, &c, &tool)
			d := Evaluate(b, w, p, c, tool, true, now)
			if d.Outcome != core.Deny || len(d.Reasons) != 1 || d.Reasons[0] != tc.reason {
				t.Fatalf("approval overrode hard rule or wrong reason: %#v", d)
			}
		})
	}
}

func TestApprovalDoesNotRelaxInformationFlow(t *testing.T) {
	b, w, p, c, tool, now := fixture()
	tool.SourceExposure.Confidentiality = core.Public
	tool.MaxInputLabel = core.Public
	tool.RequireApproval = true
	b.Tools[0] = tool
	d := Evaluate(b, w, p, c, tool, false, now)
	if d.Outcome != core.RequireApproval {
		t.Fatal(d)
	}
	if d = Evaluate(b, w, p, c, tool, true, now); d.Outcome != core.Allow {
		t.Fatal(d)
	}
	w.Exposure.Confidentiality = core.Restricted
	if d = Evaluate(b, w, p, c, tool, true, now); d.Outcome != core.Deny || d.Reasons[0] != "INFORMATION_FLOW_DENIED" {
		t.Fatal(d)
	}
}

func TestExposureJoinIsMonotonic(t *testing.T) {
	labels := []core.Label{core.Public, core.Internal, core.Confidential, core.Restricted}
	for _, a := range labels {
		for _, b := range labels {
			joined := Join(core.Exposure{Confidentiality: a, Untrusted: true}, core.Exposure{Confidentiality: b})
			if LabelRank(joined.Confidentiality) < LabelRank(a) || LabelRank(joined.Confidentiality) < LabelRank(b) || !joined.Untrusted {
				t.Fatal("exposure downgraded")
			}
		}
	}
	if joined := Join(core.Exposure{}, core.Exposure{Confidentiality: core.Public}); joined.Confidentiality != core.Restricted {
		t.Fatal("unknown exposure not restricted")
	}
}

func TestSchemaCannotFetchOrAcceptOpenArguments(t *testing.T) {
	cases := []string{
		`{"type":"object"}`,
		`{"type":"object","additionalProperties":false,"$ref":"https://evil.example/schema"}`,
		`{"type":"object","additionalProperties":false,"$schema":"https://evil.example/meta"}`,
		`{"type":"object","additionalProperties":false,"$id":"https://evil.example/schema"}`,
	}
	for _, raw := range cases {
		if _, err := compileSchema(json.RawMessage(raw), true); err == nil {
			t.Fatalf("unsafe schema accepted: %s", raw)
		}
	}
	_, _, _, _, tool, _ := fixture()
	if err := ValidateOutput(tool, json.RawMessage(`{"total":"not-a-number"}`)); err == nil {
		t.Fatal("bad output accepted")
	}
	if err := ValidateOutput(tool, json.RawMessage(`{"total":123,"employee_rows":[{"name":"secret"}]}`)); err != nil {
		t.Fatalf("valid object for projection: %v", err)
	}
}

func TestUnsafeBundleFeaturesRejected(t *testing.T) {
	tests := []struct {
		name   string
		change func(*core.Bundle)
	}{
		{"unknown effect", func(b *core.Bundle) { b.Tools[0].Effect = "unknown" }},
		{"credential URL", func(b *core.Bundle) { b.Tools[0].Endpoint = "https://user:secret@example.com/mcp" }},
		{"plaintext remote", func(b *core.Bundle) { b.Tools[0].Endpoint = "http://example.com/mcp" }},
		{"missing digest", func(b *core.Bundle) { b.Tools[0].DeploymentDigest = "latest" }},
		{"unknown label", func(b *core.Bundle) { b.Tools[0].SourceExposure.Confidentiality = "auto" }},
		{"unbound resource", func(b *core.Bundle) { b.Tools[0].ResourceArgument = "" }},
		{"empty projection", func(b *core.Bundle) { b.Tools[0].ReleaseFields = nil }},
		{"unbounded result", func(b *core.Bundle) { b.Tools[0].MaxResultBytes = 0 }},
		{"unknown semantics", func(b *core.Bundle) { b.Semantics = "v2" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _, _, _, _, _ := fixture()
			tc.change(&b)
			if ValidateBundle(b) == nil {
				t.Fatal("unsupported configuration accepted")
			}
		})
	}
}

func TestSourceCapabilityCannotCrossPublicOnlyToolBoundary(t *testing.T) {
	b, w, p, c, tool, now := fixture()
	w.Exposure.Confidentiality = core.Public
	tool.SourceExposure.Confidentiality = core.Restricted
	tool.MaxInputLabel = core.Public
	tool.RequireApproval = true
	b.Tools[0] = tool
	decision := Evaluate(b, w, p, c, tool, true, now)
	if decision.Outcome != core.Deny || decision.Reasons[0] != "INFORMATION_FLOW_DENIED" {
		t.Fatalf("restricted source authority disclosed to public-only tool: %#v", decision)
	}
}
