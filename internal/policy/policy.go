// Package policy evaluates deterministic policy without network or state writes.
package policy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var deployment = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

// LabelRank returns -1 for unknown labels; unknown never means public.
func LabelRank(label core.Label) int {
	switch label {
	case core.Public:
		return 0
	case core.Internal:
		return 1
	case core.Confidential:
		return 2
	case core.Restricted:
		return 3
	}
	return -1
}

func Join(a, b core.Exposure) core.Exposure {
	label := a.Confidentiality
	if LabelRank(a.Confidentiality) < 0 || LabelRank(b.Confidentiality) < 0 {
		label = core.Restricted
	} else if LabelRank(b.Confidentiality) > LabelRank(label) {
		label = b.Confidentiality
	}
	return core.Exposure{Confidentiality: label, Untrusted: a.Untrusted || b.Untrusted}
}

// Evaluate composes hard rules first. A human approval can satisfy an approval
// obligation only after every prohibition and current-authority check passes.
func Evaluate(bundle core.Bundle, w core.Workflow, p core.Principal, c core.Candidate, t core.Tool, approved bool, now time.Time) core.Decision {
	d := core.Decision{Outcome: core.Deny, PolicyDigest: bundle.Digest, StateRevision: w.Revision}
	deny := func(reason string) core.Decision { d.Reasons = []string{reason}; return d }
	if bundle.Digest == "" || bundle.Semantics != core.PolicySemanticsVersion || !now.Before(bundle.ExpiresAt) {
		return deny("POLICY_STALE")
	}
	if w.PolicyDigest != bundle.Digest {
		return deny("POLICY_CHANGED")
	}
	if w.ID == "" || w.DomainID == "" || w.ID != c.WorkflowID || c.OperationID == "" || c.Revision < 1 {
		return deny("INVALID_OPERATION_BINDING")
	}
	if !sameIdentity(w.Principal, p) || p.Tenant == "" || p.User == "" || p.Workload == "" {
		return deny("PRINCIPAL_MISMATCH")
	}
	if !now.Before(w.ExpiresAt) {
		return deny("WORKFLOW_EXPIRED")
	}
	var registered *core.Tool
	for i := range bundle.Tools {
		if bundle.Tools[i].Name == c.Tool {
			registered = &bundle.Tools[i]
			break
		}
	}
	if registered == nil || t.Name != c.Tool || !reflect.DeepEqual(*registered, t) {
		return deny("TOOL_NOT_APPROVED")
	}
	var contract *core.Template
	for i := range bundle.Templates {
		if bundle.Templates[i].ID == w.Template.ID {
			contract = &bundle.Templates[i]
			break
		}
	}
	if contract == nil || !reflect.DeepEqual(*contract, w.Template) {
		return deny("CONTRACT_NOT_APPROVED")
	}
	if t.Effect != "read" && t.Effect != "write" && t.Effect != "external" {
		return deny("UNKNOWN_EFFECT")
	}
	if !contains(w.Template.Tools, t.Name) || !contains(w.Principal.Tools, t.Name) || !contains(p.Tools, t.Name) {
		return deny("TOOL_NOT_PERMITTED")
	}
	if !contains(w.Template.Destinations, t.Destination) || !contains(w.Principal.Destinations, t.Destination) || !contains(p.Destinations, t.Destination) {
		return deny("DESTINATION_NOT_PERMITTED")
	}
	if LabelRank(w.Exposure.Confidentiality) < 0 || LabelRank(t.SourceExposure.Confidentiality) < 0 || LabelRank(t.MaxInputLabel) < 0 || LabelRank(p.Clearance) < 0 || LabelRank(w.Principal.Clearance) < 0 {
		return deny("CLASSIFICATION_UNKNOWN")
	}
	if LabelRank(w.Exposure.Confidentiality) < LabelRank(w.Template.InitialExposure.Confidentiality) || w.Template.InitialExposure.Untrusted && !w.Exposure.Untrusted {
		return deny("EXPOSURE_STATE_INVALID")
	}
	if LabelRank(w.Exposure.Confidentiality) > LabelRank(t.MaxInputLabel) {
		return deny("INFORMATION_FLOW_DENIED")
	}
	prospective := Join(w.Exposure, t.SourceExposure)
	if LabelRank(prospective.Confidentiality) > LabelRank(t.MaxInputLabel) {
		return deny("INFORMATION_FLOW_DENIED")
	}
	if LabelRank(prospective.Confidentiality) > LabelRank(p.Clearance) || LabelRank(prospective.Confidentiality) > LabelRank(w.Principal.Clearance) {
		return deny("CLEARANCE_INSUFFICIENT")
	}
	if err := ValidateArguments(t, c.Arguments); err != nil {
		return deny("ARGUMENT_SCHEMA_INVALID")
	}
	if t.ResourceArgument != "" {
		var arguments map[string]json.RawMessage
		if err := protocol.StrictJSON(c.Arguments, &arguments); err != nil {
			return deny("ARGUMENT_SCHEMA_INVALID")
		}
		var resource string
		if err := protocol.StrictJSON(arguments[t.ResourceArgument], &resource); err != nil || resource == "" || !contains(t.Resources, resource) || !contains(w.Template.Resources, resource) || !contains(w.Principal.Resources, resource) || !contains(p.Resources, resource) {
			return deny("RESOURCE_NOT_PERMITTED")
		}
	} else if len(t.Resources) > 0 {
		return deny("RESOURCE_BINDING_MISSING")
	}
	if w.Template.MaxCalls <= 0 || w.Calls < 0 || w.Calls >= w.Template.MaxCalls {
		return deny("QUOTA_EXHAUSTED")
	}
	if w.Inflight != "" && w.Inflight != c.OperationID {
		return deny("EXPOSURE_DOMAIN_BUSY")
	}
	if t.RequireApproval && !approved {
		d.Outcome = core.RequireApproval
		d.Reasons = []string{"APPROVAL_REQUIRED"}
		return d
	}
	d.Outcome = core.Allow
	d.Reasons = []string{"POLICY_SATISFIED"}
	return d
}

func sameIdentity(a, b core.Principal) bool {
	return a.Tenant == b.Tenant && a.User == b.User && a.Workload == b.Workload
}
func contains(items []string, s string) bool {
	for _, item := range items {
		if item == s {
			return true
		}
	}
	return false
}

// ValidateBundle rejects configuration features that this release cannot enforce.
// Schema references are local-only; remote schemas never cause outbound fetches.
func ValidateBundle(b core.Bundle) error {
	if b.Version == "" || b.Semantics != core.PolicySemanticsVersion || b.ExpiresAt.IsZero() {
		return fmt.Errorf("version, semantics v1 and expiry are required")
	}
	if len(b.Tools) == 0 || len(b.Tools) > 128 || len(b.Templates) == 0 || len(b.Templates) > 128 {
		return fmt.Errorf("bundle requires 1..128 tools and templates")
	}
	names := map[string]bool{}
	for _, t := range b.Tools {
		if !identifier.MatchString(t.Name) || names[t.Name] {
			return fmt.Errorf("invalid or duplicate tool name")
		}
		names[t.Name] = true
		if !identifier.MatchString(t.UpstreamName) || !identifier.MatchString(t.ServerID) || !deployment.MatchString(t.DeploymentDigest) || !identifier.MatchString(t.Destination) {
			return fmt.Errorf("tool %s: approved identity, deployment digest, upstream name and destination required", t.Name)
		}
		if t.Effect != "read" && t.Effect != "write" && t.Effect != "external" {
			return fmt.Errorf("tool %s: unsupported effect", t.Name)
		}
		if err := endpoint(t.Endpoint); err != nil {
			return fmt.Errorf("tool %s: %w", t.Name, err)
		}
		if t.StatusEndpoint != "" {
			if err := endpoint(t.StatusEndpoint); err != nil {
				return fmt.Errorf("tool %s status: %w", t.Name, err)
			}
		}
		if !envName.MatchString(t.TokenEnv) {
			return fmt.Errorf("tool %s: scoped credential environment name required", t.Name)
		}
		if LabelRank(t.SourceExposure.Confidentiality) < 0 || LabelRank(t.MaxInputLabel) < 0 {
			return fmt.Errorf("tool %s: unknown classification", t.Name)
		}
		if t.MaxResultBytes <= 0 || t.MaxResultBytes > 16<<20 {
			return fmt.Errorf("tool %s: result limit must be 1..16777216 bytes", t.Name)
		}
		if len(t.Resources) > 0 && t.ResourceArgument == "" || t.ResourceArgument != "" && len(t.Resources) == 0 {
			return fmt.Errorf("tool %s: resource scope and argument must be bound together", t.Name)
		}
		if err := stringSet(t.Resources); err != nil {
			return fmt.Errorf("tool %s resources: %w", t.Name, err)
		}
		if t.ResourceArgument != "" && !identifier.MatchString(t.ResourceArgument) {
			return fmt.Errorf("tool %s: invalid resource argument", t.Name)
		}
		if len(t.ReleaseFields) == 0 {
			return fmt.Errorf("tool %s: at least one explicit release field required", t.Name)
		}
		if err := stringSet(t.ReleaseFields); err != nil {
			return fmt.Errorf("tool %s release fields: %w", t.Name, err)
		}
		if _, err := compileSchema(t.InputSchema, true); err != nil {
			return fmt.Errorf("tool %s input schema: %w", t.Name, err)
		}
		if _, err := compileSchema(t.OutputSchema, false); err != nil {
			return fmt.Errorf("tool %s output schema: %w", t.Name, err)
		}
	}
	templates := map[string]bool{}
	for _, t := range b.Templates {
		if !identifier.MatchString(t.ID) || templates[t.ID] {
			return fmt.Errorf("invalid or duplicate template")
		}
		templates[t.ID] = true
		if len(t.Tools) == 0 || len(t.Destinations) == 0 || t.MaxCalls <= 0 || t.MaxCalls > 10000 || t.LifetimeSeconds <= 0 || t.LifetimeSeconds > 86400 || LabelRank(t.InitialExposure.Confidentiality) < 0 {
			return fmt.Errorf("template %s: invalid bounded scope", t.ID)
		}
		for _, tool := range t.Tools {
			if !names[tool] {
				return fmt.Errorf("template %s: unknown tool", t.ID)
			}
		}
		if err := stringSet(t.Tools); err != nil {
			return err
		}
		if err := stringSet(t.Resources); err != nil {
			return err
		}
		if err := stringSet(t.Destinations); err != nil {
			return err
		}
	}
	return nil
}

func endpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("endpoint must have a fixed host and no credentials, fragment or query")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return fmt.Errorf("endpoint requires HTTPS or explicit loopback HTTP")
	}
	return nil
}

func stringSet(values []string) error {
	seen := map[string]bool{}
	for _, v := range values {
		if v == "" || len(v) > 256 || strings.ContainsAny(v, "\r\n\x00") || seen[v] {
			return fmt.Errorf("invalid or duplicate scope value")
		}
		seen[v] = true
	}
	return nil
}
