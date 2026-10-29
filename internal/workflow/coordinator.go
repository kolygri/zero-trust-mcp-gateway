// Package workflow coordinates durable authority, dispatch, and release. The
// SQLite profile serializes each tenant's exposure domain, including reads.
package workflow

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/policy"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound  = errors.New("record not found or not authorised")
	ErrForbidden = errors.New("operation not authorised")
	ErrBusy      = errors.New("exposure domain has an unresolved operation")
)

type Coordinator struct {
	db       *sql.DB
	bundle   core.Bundle
	executor core.Executor
	gate     core.Gate
	key      []byte
	now      func() time.Time
}

type domain struct {
	ID       string        `json:"id"`
	Exposure core.Exposure `json:"exposure"`
	Revision int64         `json:"revision"`
	Calls    int           `json:"calls"`
	Inflight string        `json:"inflight"`
}

// Event deliberately excludes arguments, results, credentials and user text.
// The chain detects modification relative to a separately retained trusted head;
// it is not protection against an administrator rewriting the database and head.
type Event struct {
	Sequence      int64     `json:"sequence"`
	Time          time.Time `json:"time"`
	Tenant        string    `json:"tenant"`
	OperationID   string    `json:"operation_id,omitempty"`
	WorkflowID    string    `json:"workflow_id,omitempty"`
	Kind          string    `json:"kind"`
	RequestDigest string    `json:"request_digest,omitempty"`
	PolicyDigest  string    `json:"policy_digest"`
	Previous      string    `json:"previous"`
	Hash          string    `json:"hash"`
}

// Open opens a local SQLite database. It does not recover by redispatching an
// existing operation: DISPATCHED and UNKNOWN retain the durable domain slot.
// The same persistent auditKey (at least 32 random bytes) is required on restart.
func Open(path string, bundle core.Bundle, executor core.Executor, gate core.Gate, auditKey []byte) (*Coordinator, error) {
	if err := policy.ValidateBundle(bundle); err != nil {
		return nil, fmt.Errorf("invalid policy bundle: %w", err)
	}
	// RawMessage formatting is not retained by encoding/json persistence. Keep
	// the approved in-memory schemas in the same canonical representation used by
	// durable operations, while preserving the digest of the verified bundle bytes.
	bundle.Tools = append([]core.Tool(nil), bundle.Tools...)
	for i := range bundle.Tools {
		input, err := protocol.CanonicalJSON(bundle.Tools[i].InputSchema)
		if err != nil {
			return nil, err
		}
		output, err := protocol.CanonicalJSON(bundle.Tools[i].OutputSchema)
		if err != nil {
			return nil, err
		}
		bundle.Tools[i].InputSchema = input
		bundle.Tools[i].OutputSchema = output
	}
	if len(auditKey) < 32 || bundle.Digest == "" || executor == nil || gate == nil {
		return nil, errors.New("invalid coordinator configuration")
	}
	if path == "" || path == ":memory:" {
		return nil, errors.New("a durable database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	// Reserve private file permissions before SQLite opens it. Existing state is
	// tightened as well; SQLite sidecars inherit the database's permissions.
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err = os.Chmod(abs, 0600); err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: abs}).String() + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	c := &Coordinator{db: db, bundle: bundle, executor: executor, gate: gate, key: append([]byte(nil), auditKey...), now: time.Now}
	schema := []string{
		`CREATE TABLE IF NOT EXISTS coordinator_lock (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)`,
		`INSERT OR IGNORE INTO coordinator_lock(id,value) VALUES(1,0)`,
		`CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS domains (id TEXT PRIMARY KEY, data BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS workflows (id TEXT PRIMARY KEY, data BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, data BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, data BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, data BLOB NOT NULL)`,
	}
	for _, q := range schema {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	tx, err := c.begin(context.Background())
	if err != nil {
		db.Close()
		return nil, err
	}
	defer tx.Rollback()
	keyID := c.mac([]byte("database-key-verification-v1"))
	var saved string
	err = tx.QueryRow(`SELECT value FROM metadata WHERE key='key_id'`).Scan(&saved)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.Exec(`INSERT INTO metadata(key,value) VALUES('key_id',?)`, keyID)
	} else if err == nil && !hmac.Equal([]byte(saved), []byte(keyID)) {
		err = errors.New("database key does not match")
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		db.Close()
		return nil, err
	}
	if err = c.VerifyAudit(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return c, nil
}
func (c *Coordinator) Close() error { return c.db.Close() }
func (c *Coordinator) begin(ctx context.Context) (*sql.Tx, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	// Acquire SQLite's write lock before reading policy state. Independent handles
	// cannot both observe a free slot or unconsumed approval.
	if _, err = tx.ExecContext(ctx, `UPDATE coordinator_lock SET value=value WHERE id=1`); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}
func opaque(prefix string) string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure random source unavailable")
	}
	return prefix + hex.EncodeToString(b[:])
}
func (c *Coordinator) mac(b []byte) string {
	h := hmac.New(sha256.New, c.key)
	h.Write(b)
	return "hmac-sha256:" + hex.EncodeToString(h.Sum(nil))
}
func identity(a, b core.Principal) bool {
	return a.Tenant == b.Tenant && a.User == b.User && a.Workload == b.Workload && a.Tenant != "" && a.User != "" && a.Workload != ""
}
func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func reviewer(p core.Principal) bool { return has(p.Roles, "approver") || has(p.Roles, "admin") }
func rank(l core.Label) int {
	switch l {
	case core.Public:
		return 0
	case core.Internal:
		return 1
	case core.Confidential:
		return 2
	case core.Restricted:
		return 3
	}
	return 4
}
func join(a, b core.Exposure) core.Exposure {
	if rank(b.Confidentiality) > rank(a.Confidentiality) {
		a.Confidentiality = b.Confidentiality
	}
	a.Untrusted = a.Untrusted || b.Untrusted
	return a
}
func (c *Coordinator) domainID(tenant string) string {
	return c.mac([]byte("exposure-domain-v1:" + tenant))
}
func put(tx *sql.Tx, table, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO `+table+`(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, id, b)
	return err
}
func get(tx *sql.Tx, table, id string, v any) error {
	var b []byte
	if err := tx.QueryRow(`SELECT data FROM `+table+` WHERE id=?`, id).Scan(&b); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return json.Unmarshal(b, v)
}
func (c *Coordinator) loadWorkflow(tx *sql.Tx, p core.Principal, id string) (core.Workflow, error) {
	var w core.Workflow
	if err := get(tx, "workflows", id, &w); err != nil {
		return w, err
	}
	if !identity(p, w.Principal) {
		return core.Workflow{}, ErrNotFound
	}
	var d domain
	if err := get(tx, "domains", w.DomainID, &d); err != nil {
		return w, err
	}
	w.Exposure = d.Exposure
	w.Revision = d.Revision
	w.Calls = d.Calls
	w.Inflight = d.Inflight
	return w, nil
}
func (c *Coordinator) event(tx *sql.Tx, tenant, workflowID, operationID, kind, digest string) error {
	e := Event{Time: c.now().UTC(), Tenant: tenant, WorkflowID: workflowID, OperationID: operationID, Kind: kind, RequestDigest: digest, PolicyDigest: c.bundle.Digest}
	var raw []byte
	err := tx.QueryRow(`SELECT data FROM audit ORDER BY sequence DESC LIMIT 1`).Scan(&raw)
	if err == nil {
		var prev Event
		if err = json.Unmarshal(raw, &prev); err != nil {
			return err
		}
		e.Sequence = prev.Sequence + 1
		e.Previous = prev.Hash
	} else if errors.Is(err, sql.ErrNoRows) {
		e.Sequence = 1
	} else {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	e.Hash = c.mac(b)
	b, err = json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO audit(sequence,data) VALUES(?,?)`, e.Sequence, b)
	return err
}

func (c *Coordinator) CreateWorkflow(ctx context.Context, p core.Principal, templateID string) (core.Workflow, error) {
	if !has(p.Roles, "host") || p.Tenant == "" || p.User == "" || p.Workload == "" {
		return core.Workflow{}, ErrForbidden
	}
	var t core.Template
	for _, v := range c.bundle.Templates {
		if v.ID == templateID {
			t = v
			break
		}
	}
	if t.ID == "" || !c.now().Before(c.bundle.ExpiresAt) {
		return core.Workflow{}, ErrForbidden
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return core.Workflow{}, err
	}
	defer tx.Rollback()
	id := c.domainID(p.Tenant)
	var d domain
	err = get(tx, "domains", id, &d)
	if errors.Is(err, ErrNotFound) {
		d = domain{ID: id, Exposure: t.InitialExposure}
	} else if err != nil {
		return core.Workflow{}, err
	}
	if d.Inflight != "" {
		return core.Workflow{}, ErrBusy
	}
	d.Exposure = join(d.Exposure, t.InitialExposure)
	d.Revision++
	expires := c.now().Add(time.Duration(t.LifetimeSeconds) * time.Second)
	if expires.After(c.bundle.ExpiresAt) {
		expires = c.bundle.ExpiresAt
	}
	w := core.Workflow{ID: opaque("wf_"), DomainID: id, Principal: p, Template: t, PolicyDigest: c.bundle.Digest, Exposure: d.Exposure, Revision: d.Revision, Calls: d.Calls, ExpiresAt: expires}
	if err = put(tx, "domains", id, d); err != nil {
		return w, err
	}
	if err = put(tx, "workflows", w.ID, w); err != nil {
		return w, err
	}
	if err = c.event(tx, p.Tenant, w.ID, "", "WORKFLOW_CREATED", ""); err != nil {
		return w, err
	}
	return w, tx.Commit()
}
func (c *Coordinator) GetWorkflow(ctx context.Context, p core.Principal, id string) (core.Workflow, error) {
	tx, err := c.begin(ctx)
	if err != nil {
		return core.Workflow{}, err
	}
	defer tx.Rollback()
	return c.loadWorkflow(tx, p, id)
}
func (c *Coordinator) tool(name string) (core.Tool, bool) {
	for _, t := range c.bundle.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return core.Tool{}, false
}
func (c *Coordinator) binding(w core.Workflow, o core.Operation) (string, error) {
	// Bind complete manifest, authority and accepted contract, not a client trace ID.
	b, err := json.Marshal(struct {
		Principal    core.Principal
		Template     core.Template
		Candidate    core.Candidate
		Tool         core.Tool
		PolicyDigest string
		DomainID     string
	}{o.Principal, w.Template, o.Candidate, o.Tool, o.PolicyDigest, w.DomainID})
	if err != nil {
		return "", err
	}
	b, err = protocol.CanonicalJSON(b)
	if err != nil {
		return "", err
	}
	return c.mac(b), nil
}
func (c *Coordinator) NewOperation(ctx context.Context, p core.Principal, workflowID, tool string, args json.RawMessage) (core.Operation, error) {
	args, err := protocol.CanonicalJSON(args)
	if err != nil {
		return core.Operation{}, err
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return core.Operation{}, err
	}
	defer tx.Rollback()
	w, err := c.loadWorkflow(tx, p, workflowID)
	if err != nil {
		return core.Operation{}, err
	}
	t, _ := c.tool(tool)
	o := core.Operation{ID: opaque("op_"), Principal: p, PolicyDigest: c.bundle.Digest, Tool: t, Status: "RECEIVED", ReleaseStatus: "WITHHELD", ExpiresAt: w.ExpiresAt}
	o.Candidate = core.Candidate{OperationID: o.ID, WorkflowID: w.ID, Revision: 1, Tool: tool, Arguments: args}
	o.RequestDigest, err = c.binding(w, o)
	if err != nil {
		return o, err
	}
	if err = put(tx, "operations", o.ID, o); err != nil {
		return o, err
	}
	if err = c.event(tx, p.Tenant, w.ID, o.ID, "REQUEST_RECEIVED", o.RequestDigest); err != nil {
		return o, err
	}
	return o, tx.Commit()
}
func (c *Coordinator) loadOperation(tx *sql.Tx, p core.Principal, id string) (core.Operation, error) {
	var o core.Operation
	if err := get(tx, "operations", id, &o); err != nil {
		return o, err
	}
	if !identity(p, o.Principal) {
		return core.Operation{}, ErrNotFound
	}
	return o, nil
}
func (c *Coordinator) GetOperation(ctx context.Context, p core.Principal, id string) (core.Operation, error) {
	tx, err := c.begin(ctx)
	if err != nil {
		return core.Operation{}, err
	}
	defer tx.Rollback()
	var o core.Operation
	if err = get(tx, "operations", id, &o); err != nil {
		return o, err
	}
	if !(identity(p, o.Principal) && c.dataAuthority(tx, p, o)) && !c.reviewAuthority(tx, p, o) {
		return core.Operation{}, ErrNotFound
	}
	o.PermitID = ""
	o.OwnerEpoch = ""
	o.Result = nil
	return o, nil
}
func (c *Coordinator) reviewAuthority(tx *sql.Tx, p core.Principal, o core.Operation) bool {
	return reviewer(p) && p.User != o.Principal.User && c.dataAuthority(tx, p, o)
}
func (c *Coordinator) dataAuthority(tx *sql.Tx, p core.Principal, o core.Operation) bool {
	if p.User == "" || p.Workload == "" || p.Tenant != o.Principal.Tenant || !has(p.Tools, o.Candidate.Tool) || !has(p.Destinations, o.Tool.Destination) || rank(p.Clearance) > 3 || rank(p.Clearance) < rank(o.Tool.SourceExposure.Confidentiality) {
		return false
	}
	var d domain
	if get(tx, "domains", c.domainID(p.Tenant), &d) != nil || rank(p.Clearance) < rank(d.Exposure.Confidentiality) {
		return false
	}
	if o.Tool.ResourceArgument != "" {
		var args map[string]any
		if json.Unmarshal(o.Candidate.Arguments, &args) != nil {
			return false
		}
		resource, ok := args[o.Tool.ResourceArgument].(string)
		if !ok || !has(p.Resources, resource) {
			return false
		}
	}
	return true
}
func result(o core.Operation) core.CallResult {
	return core.CallResult{OperationID: o.ID, Decision: o.Decision, ExecutionStatus: o.Status, ReleaseStatus: o.ReleaseStatus}
}

func (c *Coordinator) Execute(ctx context.Context, p core.Principal, id string) (core.CallResult, error) {
	tx, err := c.begin(ctx)
	if err != nil {
		return core.CallResult{}, err
	}
	defer tx.Rollback()
	o, err := c.loadOperation(tx, p, id)
	if err != nil {
		return core.CallResult{}, err
	}
	w, err := c.loadWorkflow(tx, p, o.Candidate.WorkflowID)
	if err != nil {
		return core.CallResult{}, err
	}
	// Terminal and uncertain requests are status reads. Results are not replayed:
	// replaying bytes would require a new release decision under current authority.
	if o.Status != "RECEIVED" && o.Status != "PENDING_APPROVAL" {
		return result(o), nil
	}
	var a core.Approval
	approved := false
	if o.ApprovalID != "" {
		if err = get(tx, "approvals", o.ApprovalID, &a); err != nil {
			return result(o), err
		}
		approved = a.ApprovedBy != "" && !a.Consumed && a.RequestDigest == o.RequestDigest && a.PolicyDigest == c.bundle.Digest && c.now().Before(a.ExpiresAt)
	}
	decision := policy.Evaluate(c.bundle, w, p, o.Candidate, o.Tool, approved, c.now())
	decision.RequestDigest = o.RequestDigest
	decision.PolicyDigest = c.bundle.Digest
	decision.StateRevision = w.Revision
	if w.Inflight != "" {
		decision.Outcome = core.Deny
		decision.Reasons = []string{"EXECUTION_STATUS_UNKNOWN"}
		if w.Inflight != o.ID {
			decision.Reasons = []string{"EXPOSURE_DOMAIN_BUSY"}
		}
	}
	o.Decision = decision
	if decision.Outcome != core.Allow {
		kind := "REQUEST_DENIED"
		o.Status = "DENIED"
		if decision.Outcome == core.RequireApproval {
			o.Status = "PENDING_APPROVAL"
			kind = "APPROVAL_REQUESTED"
			if o.ApprovalID == "" {
				a = core.Approval{ID: opaque("apr_"), OperationID: o.ID, WorkflowID: w.ID, RequestDigest: o.RequestDigest, PolicyDigest: c.bundle.Digest, ExpiresAt: o.ExpiresAt}
				o.ApprovalID = a.ID
				o.Decision.ApprovalID = a.ID
				if err = c.putApproval(tx, a); err != nil {
					return result(o), err
				}
			}
			o.Decision.ApprovalID = o.ApprovalID
		}
		if err = put(tx, "operations", o.ID, o); err != nil {
			return result(o), err
		}
		if err = c.event(tx, p.Tenant, w.ID, o.ID, kind, o.RequestDigest); err != nil {
			return result(o), err
		}
		return result(o), tx.Commit()
	}
	var d domain
	if err = get(tx, "domains", w.DomainID, &d); err != nil {
		return result(o), err
	}
	if d.Inflight != "" {
		return result(o), ErrBusy
	}
	if o.Tool.RequireApproval {
		if !approved {
			return result(o), ErrForbidden
		}
		a.Consumed = true
		if err = c.putApproval(tx, a); err != nil {
			return result(o), err
		}
	}
	d.Inflight = o.ID
	d.Calls++
	d.Revision++
	d.Exposure = join(d.Exposure, o.Tool.SourceExposure)
	o.Status = "RESERVED"
	o.PermitID = opaque("permit_")
	o.OwnerEpoch = opaque("epoch_")
	if err = put(tx, "domains", d.ID, d); err != nil {
		return result(o), err
	}
	if err = put(tx, "operations", o.ID, o); err != nil {
		return result(o), err
	}
	if err = c.event(tx, p.Tenant, w.ID, o.ID, "EXECUTION_RESERVED", o.RequestDigest); err != nil {
		return result(o), err
	}
	if err = tx.Commit(); err != nil {
		return result(o), err
	}
	return c.dispatch(ctx, p, o.ID)
}
func (c *Coordinator) putApproval(tx *sql.Tx, a core.Approval) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO approvals(id,operation_id,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, a.ID, a.OperationID, b)
	return err
}

func (c *Coordinator) dispatch(ctx context.Context, p core.Principal, id string) (core.CallResult, error) {
	tx, err := c.begin(ctx)
	if err != nil {
		return core.CallResult{}, err
	}
	defer tx.Rollback()
	o, err := c.loadOperation(tx, p, id)
	if err != nil {
		return core.CallResult{}, err
	}
	w, err := c.loadWorkflow(tx, p, o.Candidate.WorkflowID)
	if err != nil {
		return result(o), err
	}
	digest, err := c.binding(w, o)
	if err != nil {
		return result(o), err
	}
	if o.Status != "RESERVED" || o.PermitID == "" || o.OwnerEpoch == "" || w.Inflight != o.ID || !hmac.Equal([]byte(digest), []byte(o.RequestDigest)) || o.PolicyDigest != c.bundle.Digest || !c.now().Before(o.ExpiresAt) || !c.now().Before(c.bundle.ExpiresAt) {
		return result(o), ErrForbidden
	}
	o.Status = "DISPATCHED"
	if err = put(tx, "operations", o.ID, o); err != nil {
		return result(o), err
	}
	if err = c.event(tx, p.Tenant, w.ID, o.ID, "DISPATCHED", o.RequestDigest); err != nil {
		return result(o), err
	}
	if err = tx.Commit(); err != nil {
		return result(o), err
	}
	// The durable claim precedes the only external call. A crash here leaves the
	// claim unresolved, even if the resource never received it.
	execution := c.executor.Execute(ctx, core.Dispatch{Operation: o, Workflow: w})
	return c.finish(context.WithoutCancel(ctx), p, o, execution)
}

func (c *Coordinator) finish(ctx context.Context, p core.Principal, dispatched core.Operation, execution core.Execution) (core.CallResult, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if execution.Outcome != "SUCCEEDED" && execution.Outcome != "FAILED" {
		execution.Outcome = "UNKNOWN"
		execution.Raw = nil
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return core.CallResult{}, err
	}
	defer tx.Rollback()
	o, err := c.loadOperation(tx, p, dispatched.ID)
	if err != nil {
		return core.CallResult{}, err
	}
	if o.OwnerEpoch != dispatched.OwnerEpoch || o.Status != "DISPATCHED" && o.Status != "UNKNOWN" && o.Status != "RESERVED" && o.Status != "SUCCEEDED" && o.Status != "FAILED" {
		return result(o), ErrForbidden
	}
	if (o.Status == "SUCCEEDED" || o.Status == "FAILED") && o.Status != execution.Outcome {
		return result(o), ErrForbidden
	}
	o.Status = execution.Outcome
	if err = put(tx, "operations", o.ID, o); err != nil {
		return result(o), err
	}
	if err = c.event(tx, p.Tenant, o.Candidate.WorkflowID, o.ID, "OUTCOME_"+execution.Outcome, o.RequestDigest); err != nil {
		return result(o), err
	}
	if err = tx.Commit(); err != nil {
		return result(o), err
	}
	if execution.Outcome == "UNKNOWN" {
		return result(o), nil
	}
	var released json.RawMessage
	releaseStatus := "UNAVAILABLE"
	resultUninspectable := false
	if execution.Outcome == "SUCCEEDED" {
		releaseStatus = "QUARANTINED"
		released, err = c.gate.Release(o.Tool, execution.Raw)
		if err == nil {
			releaseStatus = "RELEASED"
		} else {
			released = nil
			resultUninspectable = true
		}
	}
	// A successful resource effect and a release failure remain distinct facts.
	tx, err = c.begin(ctx)
	if err != nil {
		return result(o), err
	}
	defer tx.Rollback()
	w, err := c.loadWorkflow(tx, p, o.Candidate.WorkflowID)
	if err != nil {
		return result(o), err
	}
	var d domain
	if err = get(tx, "domains", w.DomainID, &d); err != nil {
		return result(o), err
	}
	if d.Inflight != o.ID {
		return result(o), ErrForbidden
	}
	if resultUninspectable {
		d.Exposure = join(d.Exposure, core.Exposure{Confidentiality: core.Restricted, Untrusted: true})
	}
	if !c.releaseAuthority(p, w, o) {
		releaseStatus = "QUARANTINED"
		released = nil
	}
	o.ReleaseStatus = releaseStatus
	o.Result = nil // Raw or projected payloads never enter the state or audit store.
	d.Inflight = ""
	d.Revision++
	if err = put(tx, "domains", d.ID, d); err != nil {
		return result(o), err
	}
	if err = put(tx, "operations", o.ID, o); err != nil {
		return result(o), err
	}
	if err = c.event(tx, p.Tenant, w.ID, o.ID, "RESULT_"+releaseStatus, o.RequestDigest); err != nil {
		return result(o), err
	}
	if err = tx.Commit(); err != nil {
		return result(o), err
	}
	r := result(o)
	r.Result = released
	return r, nil
}
func (c *Coordinator) releaseAuthority(p core.Principal, w core.Workflow, o core.Operation) bool {
	return identity(p, w.Principal) && c.now().Before(w.ExpiresAt) && c.now().Before(c.bundle.ExpiresAt) && o.PolicyDigest == c.bundle.Digest && w.PolicyDigest == c.bundle.Digest && rank(p.Clearance) <= 3 && rank(p.Clearance) >= rank(w.Exposure.Confidentiality) && has(p.Tools, o.Candidate.Tool) && has(p.Destinations, o.Tool.Destination)
}

func (c *Coordinator) Approve(ctx context.Context, p core.Principal, id string) (core.Approval, error) {
	if !reviewer(p) {
		return core.Approval{}, ErrForbidden
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return core.Approval{}, err
	}
	defer tx.Rollback()
	var o core.Operation
	if err = get(tx, "operations", id, &o); err != nil {
		return core.Approval{}, err
	}
	if !c.reviewAuthority(tx, p, o) || o.Status != "PENDING_APPROVAL" || o.PolicyDigest != c.bundle.Digest || !c.now().Before(o.ExpiresAt) || !c.now().Before(c.bundle.ExpiresAt) {
		return core.Approval{}, ErrForbidden
	}
	var a core.Approval
	if err = get(tx, "approvals", o.ApprovalID, &a); err != nil {
		return a, err
	}
	if a.Consumed || a.ApprovedBy != "" || a.RequestDigest != o.RequestDigest || a.PolicyDigest != c.bundle.Digest || !c.now().Before(a.ExpiresAt) {
		return a, ErrForbidden
	}
	// Approvers need explicit entitlement to this tool, destination and data class.
	if !c.reviewAuthority(tx, p, o) {
		return a, ErrForbidden
	}
	a.ApprovedBy = p.User
	if err = c.putApproval(tx, a); err != nil {
		return a, err
	}
	if err = c.event(tx, p.Tenant, o.Candidate.WorkflowID, o.ID, "APPROVAL_GRANTED", o.RequestDigest); err != nil {
		return a, err
	}
	return a, tx.Commit()
}

// Reconcile consults the configured authoritative status service. It never calls
// Execute, and a lease expiry never grants authority to repeat an effect.
func (c *Coordinator) Reconcile(ctx context.Context, p core.Principal, id string) (core.CallResult, error) {
	if !reviewer(p) {
		return core.CallResult{}, ErrForbidden
	}
	tx, err := c.begin(ctx)
	if err != nil {
		return core.CallResult{}, err
	}
	defer tx.Rollback()
	var o core.Operation
	if err = get(tx, "operations", id, &o); err != nil {
		return core.CallResult{}, err
	}
	current, registered := c.tool(o.Candidate.Tool)
	if !c.reviewAuthority(tx, p, o) || !registered || !reflect.DeepEqual(current, o.Tool) || !c.now().Before(c.bundle.ExpiresAt) {
		return result(o), ErrForbidden
	}
	if o.Status != "DISPATCHED" && o.Status != "UNKNOWN" && o.Status != "RESERVED" && o.Status != "SUCCEEDED" && o.Status != "FAILED" {
		return result(o), ErrForbidden
	}
	w, err := c.loadWorkflow(tx, o.Principal, o.Candidate.WorkflowID)
	if err != nil {
		return result(o), err
	}
	if w.Inflight != o.ID {
		return result(o), ErrForbidden
	}
	if o.Status == "RESERVED" {
		// The external call is possible only after dispatch atomically changes
		// RESERVED to DISPATCHED. Abort while holding the same write lock so a
		// delayed worker cannot subsequently claim this permit. Exposure, quota
		// and consumed approval remain conservative facts of the reservation.
		var d domain
		if err = get(tx, "domains", w.DomainID, &d); err != nil {
			return result(o), err
		}
		if d.Inflight != o.ID {
			return result(o), ErrForbidden
		}
		o.Status = "FAILED"
		o.ReleaseStatus = "UNAVAILABLE"
		o.Decision.Outcome = core.Deny
		o.Decision.Reasons = []string{"PRE_DISPATCH_ABORTED"}
		o.Result = nil
		d.Inflight = ""
		d.Revision++
		if err = put(tx, "operations", o.ID, o); err != nil {
			return result(o), err
		}
		if err = put(tx, "domains", d.ID, d); err != nil {
			return result(o), err
		}
		if err = c.event(tx, p.Tenant, w.ID, o.ID, "PRE_DISPATCH_ABORTED", o.RequestDigest); err != nil {
			return result(o), err
		}
		return result(o), tx.Commit()
	}
	if err = c.event(tx, p.Tenant, w.ID, o.ID, "RECONCILIATION_REQUESTED", o.RequestDigest); err != nil {
		return result(o), err
	}
	if err = tx.Commit(); err != nil {
		return result(o), err
	}
	execution := c.executor.Reconcile(ctx, core.Dispatch{Operation: o, Workflow: w})
	// Reconciliation cannot release data to an admin who impersonates the caller.
	// Original callers can fetch the status; this endpoint returns no result bytes.
	r, err := c.finish(context.WithoutCancel(ctx), o.Principal, o, execution)
	r.Result = nil
	return r, err
}

func (c *Coordinator) Audit(ctx context.Context) ([]Event, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT data FROM audit ORDER BY sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var b []byte
		var e Event
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
func (c *Coordinator) VerifyAudit(ctx context.Context) error {
	events, err := c.Audit(ctx)
	if err != nil {
		return err
	}
	previous := ""
	for i, e := range events {
		saved := e.Hash
		e.Hash = ""
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if e.Sequence != int64(i+1) || e.Previous != previous || !hmac.Equal([]byte(saved), []byte(c.mac(b))) {
			return fmt.Errorf("audit chain verification failed at sequence %d", i+1)
		}
		previous = saved
	}
	return nil
}

// Checkpoint returns a keyed chain head suitable for retention in an independent
// store. Exporting and retaining it outside this process is an operator duty.
func (c *Coordinator) Checkpoint(ctx context.Context) (string, error) {
	events, err := c.Audit(ctx)
	if err != nil {
		return "", err
	}
	if len(events) == 0 {
		return "", nil
	}
	return strings.Join([]string{fmt.Sprint(events[len(events)-1].Sequence), events[len(events)-1].Hash}, ":"), nil
}
