// Package core defines the versioned, transport-independent enforcement contracts.
package core

import (
	"context"
	"encoding/json"
	"time"
)

const ProtocolVersion = "2026-07-28"
const PolicySemanticsVersion = "v1"

type Label string

const (
	Public       Label = "public"
	Internal     Label = "internal"
	Confidential Label = "confidential"
	Restricted   Label = "restricted"
)

type Exposure struct {
	Confidentiality Label `json:"confidentiality"`
	Untrusted       bool  `json:"untrusted"`
}

type Principal struct {
	Tenant       string   `json:"tenant"`
	User         string   `json:"user"`
	Workload     string   `json:"workload"`
	Roles        []string `json:"roles"`
	Tools        []string `json:"tools"`
	Resources    []string `json:"resources"`
	Destinations []string `json:"destinations"`
	Clearance    Label    `json:"clearance"`
}

type Template struct {
	ID              string   `json:"id"`
	Tools           []string `json:"tools"`
	Resources       []string `json:"resources"`
	Destinations    []string `json:"destinations"`
	InitialExposure Exposure `json:"initial_exposure"`
	MaxCalls        int      `json:"max_calls"`
	LifetimeSeconds int      `json:"lifetime_seconds"`
}

type Tool struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	ServerID         string `json:"server_id"`
	DeploymentDigest string `json:"deployment_digest"`
	Endpoint         string `json:"endpoint"`
	UpstreamName     string `json:"upstream_name"`
	TokenEnv         string `json:"token_env"`
	// StatusEndpoint is an independently authorised operation-status API, never a retry path.
	StatusEndpoint   string          `json:"status_endpoint,omitempty"`
	InputSchema      json.RawMessage `json:"input_schema"`
	OutputSchema     json.RawMessage `json:"output_schema"`
	Effect           string          `json:"effect"`
	Destination      string          `json:"destination"`
	ResourceArgument string          `json:"resource_argument,omitempty"`
	Resources        []string        `json:"resources"`
	SourceExposure   Exposure        `json:"source_exposure"`
	MaxInputLabel    Label           `json:"max_input_label"`
	RequireApproval  bool            `json:"require_approval"`
	ReleaseFields    []string        `json:"release_fields"`
	MaxResultBytes   int64           `json:"max_result_bytes"`
}

type Bundle struct {
	Version   string     `json:"version"`
	Semantics string     `json:"semantics"`
	ExpiresAt time.Time  `json:"expires_at"`
	Tools     []Tool     `json:"tools"`
	Templates []Template `json:"templates"`
	// Digest is computed from the exact verified bundle bytes, never accepted from config.
	Digest string `json:"-"`
}

type Workflow struct {
	ID           string    `json:"id"`
	DomainID     string    `json:"domain_id"`
	Principal    Principal `json:"principal"`
	Template     Template  `json:"template"`
	PolicyDigest string    `json:"policy_digest"`
	Exposure     Exposure  `json:"exposure"`
	Revision     int64     `json:"revision"`
	Calls        int       `json:"calls"`
	Inflight     string    `json:"inflight,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Candidate struct {
	OperationID string          `json:"operation_id"`
	WorkflowID  string          `json:"workflow_id"`
	Revision    int             `json:"revision"`
	Tool        string          `json:"tool"`
	Arguments   json.RawMessage `json:"arguments"`
}

type Decision struct {
	Outcome           string     `json:"outcome"`
	Reasons           []string   `json:"reason_codes"`
	RequestDigest     string     `json:"request_digest,omitempty"`
	PolicyDigest      string     `json:"policy_digest"`
	StateRevision     int64      `json:"state_revision"`
	ApprovalID        string     `json:"approval_id,omitempty"`
	ProposedCandidate *Candidate `json:"proposed_candidate,omitempty"`
}

const (
	Deny            = "DENY"
	RequireApproval = "REQUIRE_APPROVAL"
	ProposeRevision = "PROPOSE_REVISION"
	Allow           = "ALLOW"
)

type Operation struct {
	ID            string          `json:"id"`
	Candidate     Candidate       `json:"candidate"`
	Principal     Principal       `json:"principal"`
	PolicyDigest  string          `json:"policy_digest"`
	RequestDigest string          `json:"request_digest"`
	Tool          Tool            `json:"tool"`
	Decision      Decision        `json:"decision"`
	Status        string          `json:"status"`
	ReleaseStatus string          `json:"release_status"`
	PermitID      string          `json:"permit_id,omitempty"`
	OwnerEpoch    string          `json:"owner_epoch,omitempty"`
	ApprovalID    string          `json:"approval_id,omitempty"`
	ExpiresAt     time.Time       `json:"expires_at"`
	Result        json.RawMessage `json:"-"`
}

type Approval struct {
	ID            string    `json:"id"`
	OperationID   string    `json:"operation_id"`
	WorkflowID    string    `json:"workflow_id"`
	RequestDigest string    `json:"request_digest"`
	PolicyDigest  string    `json:"policy_digest"`
	ApprovedBy    string    `json:"approved_by,omitempty"`
	Consumed      bool      `json:"consumed"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Dispatch is produced only from a durably claimed server-held permit.
// Adapters must not change Candidate or forward the caller's credentials.
type Dispatch struct {
	Operation Operation
	Workflow  Workflow
}

type Execution struct {
	// Outcome is SUCCEEDED, FAILED, or UNKNOWN. FAILED requires authoritative evidence.
	Outcome string
	Raw     json.RawMessage
}

type Executor interface {
	Execute(context.Context, Dispatch) Execution
	Reconcile(context.Context, Dispatch) Execution
}

type Gate interface {
	Release(Tool, json.RawMessage) (json.RawMessage, error)
}

type CallResult struct {
	OperationID     string          `json:"operation_id"`
	Decision        Decision        `json:"decision"`
	ExecutionStatus string          `json:"execution_status"`
	ReleaseStatus   string          `json:"release_status"`
	Result          json.RawMessage `json:"result,omitempty"`
}
