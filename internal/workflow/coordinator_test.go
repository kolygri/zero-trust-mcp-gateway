package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
)

type fakeExecutor struct {
	calls      atomic.Int32
	reconciles atomic.Int32
	execute    func(context.Context, core.Dispatch) core.Execution
	reconcile  func(context.Context, core.Dispatch) core.Execution
}

func (f *fakeExecutor) Execute(ctx context.Context, d core.Dispatch) core.Execution {
	f.calls.Add(1)
	if f.execute != nil {
		return f.execute(ctx, d)
	}
	return core.Execution{Outcome: "SUCCEEDED", Raw: json.RawMessage(`{"ok":true}`)}
}
func (f *fakeExecutor) Reconcile(ctx context.Context, d core.Dispatch) core.Execution {
	f.reconciles.Add(1)
	if f.reconcile != nil {
		return f.reconcile(ctx, d)
	}
	return core.Execution{Outcome: "UNKNOWN"}
}

type fakeGate struct {
	fail bool
	hook func()
}

func (g fakeGate) Release(_ core.Tool, raw json.RawMessage) (json.RawMessage, error) {
	if g.hook != nil {
		g.hook()
	}
	if g.fail {
		return nil, errors.New("uninspectable")
	}
	return raw, nil
}
func fixture(t *testing.T) (*Coordinator, core.Principal, *fakeExecutor, string) {
	t.Helper()
	e := &fakeExecutor{}
	p := core.Principal{Tenant: "tenant", User: "alice", Workload: "trusted-host", Roles: []string{"host"}, Tools: []string{"read", "send", "write"}, Resources: []string{"payroll:one"}, Destinations: []string{"internal", "external"}, Clearance: core.Restricted}
	schema := json.RawMessage(`{"type":"object","properties":{"resource":{"type":"string"}},"required":["resource"],"additionalProperties":false}`)
	tool := core.Tool{Name: "read", ServerID: "server", DeploymentDigest: "sha256:" + strings.Repeat("a", 64), Endpoint: "http://127.0.0.1:9999/mcp", UpstreamName: "read", TokenEnv: "RESOURCE_TOKEN", InputSchema: schema, OutputSchema: json.RawMessage(`{"type":"object"}`), Effect: "read", Destination: "internal", ResourceArgument: "resource", Resources: p.Resources, SourceExposure: core.Exposure{Confidentiality: core.Restricted, Untrusted: true}, MaxInputLabel: core.Restricted, ReleaseFields: []string{"ok"}, MaxResultBytes: 1024}
	send := tool
	send.Name = "send"
	send.UpstreamName = "send"
	send.Effect = "external"
	send.Destination = "external"
	send.SourceExposure = core.Exposure{Confidentiality: core.Public}
	send.MaxInputLabel = core.Public
	write := tool
	write.Name = "write"
	write.UpstreamName = "write"
	write.Effect = "write"
	write.RequireApproval = true
	b := core.Bundle{Version: "test-v1", Semantics: core.PolicySemanticsVersion, ExpiresAt: time.Now().Add(time.Hour), Digest: "sha256:test", Tools: []core.Tool{tool, send, write}, Templates: []core.Template{{ID: "report", Tools: p.Tools, Resources: p.Resources, Destinations: p.Destinations, InitialExposure: core.Exposure{Confidentiality: core.Public}, MaxCalls: 50, LifetimeSeconds: 3600}}}
	path := filepath.Join(t.TempDir(), "gateway.sqlite")
	c, err := Open(path, b, e, fakeGate{}, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, p, e, path
}
func workflowFor(t *testing.T, c *Coordinator, p core.Principal) core.Workflow {
	t.Helper()
	w, err := c.CreateWorkflow(context.Background(), p, "report")
	if err != nil {
		t.Fatal(err)
	}
	return w
}
func operationFor(t *testing.T, c *Coordinator, p core.Principal, w core.Workflow, name string) core.Operation {
	t.Helper()
	o, err := c.NewOperation(context.Background(), p, w.ID, name, json.RawMessage(`{"resource":"payroll:one"}`))
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func approver(p core.Principal) core.Principal {
	p.User = "bob"
	p.Workload = "approval-console"
	p.Roles = []string{"approver"}
	return p
}

func TestDispatchCommitAndStickyExposure(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	e.execute = func(_ context.Context, d core.Dispatch) core.Execution {
		persisted, err := c.GetOperation(ctx, p, o.ID)
		if err != nil || persisted.Status != "DISPATCHED" {
			t.Fatalf("not durably dispatched: %+v %v", persisted, err)
		}
		current, err := c.GetWorkflow(ctx, p, w.ID)
		if err != nil || current.Exposure.Confidentiality != core.Restricted || !current.Exposure.Untrusted || current.Inflight != o.ID {
			t.Fatalf("exposure not committed before dispatch: %+v %v", current, err)
		}
		return core.Execution{Outcome: "SUCCEEDED", Raw: json.RawMessage(`{"ok":true}`)}
	}
	r, err := c.Execute(ctx, p, o.ID)
	if err != nil || r.ReleaseStatus != "RELEASED" || len(r.Result) == 0 {
		t.Fatalf("release: %+v %v", r, err)
	}
	fresh := workflowFor(t, c, p)
	if fresh.DomainID != w.DomainID || fresh.Exposure.Confidentiality != core.Restricted {
		t.Fatal("workflow reset erased exposure")
	}
	other := p
	other.User = "charlie"
	other.Workload = "another-host"
	otherWorkflow := workflowFor(t, c, other)
	if otherWorkflow.DomainID != w.DomainID || otherWorkflow.Exposure.Confidentiality != core.Restricted {
		t.Fatal("shared tool memory did not share domain")
	}
	send := operationFor(t, c, p, fresh, "send")
	r, err = c.Execute(ctx, p, send.ID)
	if err != nil || r.Decision.Outcome != core.Deny || e.calls.Load() != 1 {
		t.Fatalf("exfiltration dispatched: %+v %v", r, err)
	}
	if err = c.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestExactApprovalSingleUseAndHardDenial(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "write")
	r, err := c.Execute(ctx, p, o.ID)
	if err != nil || r.Decision.Outcome != core.RequireApproval || e.calls.Load() != 0 {
		t.Fatalf("pending dispatched: %+v %v", r, err)
	}
	self := p
	self.Roles = []string{"approver"}
	if _, err = c.Approve(ctx, self, o.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("self approval accepted")
	}
	review := approver(p)
	if _, err = c.GetOperation(ctx, review, o.ID); err != nil {
		t.Fatal("independent reviewer cannot inspect", err)
	}
	unentitled := review
	unentitled.Resources = nil
	if _, err = c.Approve(ctx, unentitled, o.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("unentitled approval accepted")
	}
	a, err := c.Approve(ctx, review, o.ID)
	if err != nil || a.RequestDigest != o.RequestDigest {
		t.Fatal("approval binding", err)
	}
	if _, err = c.Approve(ctx, review, o.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("duplicate approval accepted")
	}
	r, err = c.Execute(ctx, p, o.ID)
	if err != nil || r.ExecutionStatus != "SUCCEEDED" || e.calls.Load() != 1 {
		t.Fatalf("approved execution failed: %+v %v", r, err)
	}
	if _, err = c.Execute(ctx, p, o.ID); err != nil || e.calls.Load() != 1 {
		t.Fatal("consumed approval executed twice")
	}
	// A previously approved subject cannot be changed by the caller.
	wrong := p
	wrong.User = "eve"
	if _, err = c.Execute(ctx, wrong, o.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross principal operation access")
	}
	w = workflowFor(t, c, p)
	o = operationFor(t, c, p, w, "send")
	r, err = c.Execute(ctx, p, o.ID)
	if err != nil || r.Decision.Outcome != core.Deny {
		t.Fatal("hard flow denial missing")
	}
	if _, err = c.Approve(ctx, review, o.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("approval overrode hard denial")
	}
}
func TestUnknownRetainedAcrossRestartAndReconciledWithoutRetry(t *testing.T) {
	c, p, e, path := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	e.execute = func(context.Context, core.Dispatch) core.Execution { return core.Execution{Outcome: "UNKNOWN"} }
	r, err := c.Execute(ctx, p, o.ID)
	if err != nil || r.ExecutionStatus != "UNKNOWN" {
		t.Fatalf("unknown outcome lost: %+v %v", r, err)
	}
	second, err := Open(path, c.bundle, e, fakeGate{}, c.key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = second.CreateWorkflow(ctx, p, "report"); !errors.Is(err, ErrBusy) {
		t.Fatal("fresh workflow bypassed unresolved operation")
	}
	if _, err = second.Execute(ctx, p, o.ID); err != nil || e.calls.Load() != 1 {
		t.Fatal("unknown outcome automatically retried")
	}
	if _, err = second.Reconcile(ctx, approver(p), o.ID); err != nil {
		t.Fatal(err)
	}
	current, err := second.GetWorkflow(ctx, p, w.ID)
	if err != nil || current.Inflight != o.ID {
		t.Fatal("unknown status cleared execution slot")
	}
	e.reconcile = func(context.Context, core.Dispatch) core.Execution {
		return core.Execution{Outcome: "SUCCEEDED", Raw: json.RawMessage(`{"ok":true}`)}
	}
	r, err = second.Reconcile(ctx, approver(p), o.ID)
	if err != nil || r.ExecutionStatus != "SUCCEEDED" || len(r.Result) != 0 || e.calls.Load() != 1 {
		t.Fatalf("reconciliation repeated effect or disclosed result: %+v %v", r, err)
	}
	current, err = second.GetWorkflow(ctx, p, w.ID)
	if err != nil || current.Inflight != "" || current.Exposure.Confidentiality != core.Restricted {
		t.Fatal("reconciliation erased labels or held slot", err)
	}
}
func TestIndependentConnectionsCannotRaceDispatch(t *testing.T) {
	c, p, e, path := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	second, err := Open(path, c.bundle, e, fakeGate{}, c.key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	started := make(chan struct{})
	finish := make(chan struct{})
	e.execute = func(context.Context, core.Dispatch) core.Execution {
		close(started)
		<-finish
		return core.Execution{Outcome: "SUCCEEDED", Raw: json.RawMessage(`{"ok":true}`)}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	var firstErr error
	go func() { defer wg.Done(); _, firstErr = c.Execute(ctx, p, o.ID) }()
	<-started
	for i := 0; i < 5; i++ {
		r, err := second.Execute(ctx, p, o.ID)
		if err != nil || r.ExecutionStatus != "DISPATCHED" {
			t.Fatal("replayed call changed outcome", r, err)
		}
	}
	another := operationFor(t, second, p, w, "read")
	r, err := second.Execute(ctx, p, another.ID)
	if err != nil || r.Decision.Outcome != core.Deny || e.calls.Load() != 1 {
		t.Fatalf("domain race dispatched twice: %+v %v", r, err)
	}
	close(finish)
	wg.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
}
func TestResponseQuarantineDoesNotUndoKnownEffect(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx := context.Background()
	c.gate = fakeGate{fail: true}
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	r, err := c.Execute(ctx, p, o.ID)
	if err != nil || r.ExecutionStatus != "SUCCEEDED" || r.ReleaseStatus != "QUARANTINED" || len(r.Result) != 0 || e.calls.Load() != 1 {
		t.Fatalf("known effect misrepresented: %+v %v", r, err)
	}
	current, _ := c.GetWorkflow(ctx, p, w.ID)
	if current.Inflight != "" || current.Exposure.Confidentiality != core.Restricted {
		t.Fatal("quarantine erased exposure")
	}
}
func TestCancellationCannotLoseOutcome(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	e.execute = func(context.Context, core.Dispatch) core.Execution {
		cancel()
		return core.Execution{Outcome: "UNKNOWN"}
	}
	r, err := c.Execute(ctx, p, o.ID)
	if err != nil || r.ExecutionStatus != "UNKNOWN" {
		t.Fatalf("disconnect lost outcome: %+v %v", r, err)
	}
	saved, err := c.GetOperation(context.Background(), p, o.ID)
	if err != nil || saved.Status != "UNKNOWN" {
		t.Fatal("unknown was not durable", err)
	}
}
func TestReleaseFreshnessAndQuotaCannotReset(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx := context.Background()
	now := time.Now()
	c.now = func() time.Time { return now }
	c.bundle.Templates[0].MaxCalls = 1
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	e.execute = func(context.Context, core.Dispatch) core.Execution {
		now = now.Add(2 * time.Hour)
		return core.Execution{Outcome: "SUCCEEDED", Raw: json.RawMessage(`{"ok":true}`)}
	}
	r, err := c.Execute(ctx, p, o.ID)
	if err != nil || r.ReleaseStatus != "QUARANTINED" {
		t.Fatal("expired policy released result", r, err)
	}
	now = now.Add(-2 * time.Hour)
	fresh := workflowFor(t, c, p)
	if fresh.Calls != 1 {
		t.Fatal("new workflow reset tenant quota")
	}
	o = operationFor(t, c, p, fresh, "read")
	r, err = c.Execute(ctx, p, o.ID)
	if err != nil || r.Decision.Outcome != core.Deny || e.calls.Load() != 1 {
		t.Fatal("quota reset permitted dispatch", r, err)
	}
}
func TestAuditTamperAndWrongKeyFailClosed(t *testing.T) {
	c, p, _, path := fixture(t)
	ctx := context.Background()
	workflowFor(t, c, p)
	wrong, err := Open(path, c.bundle, c.executor, c.gate, bytes.Repeat([]byte{8}, 32))
	if err == nil {
		wrong.Close()
		t.Fatal("wrong audit key accepted")
	}
	if _, err = c.db.Exec(`UPDATE audit SET data=replace(CAST(data AS TEXT),'WORKFLOW_CREATED','WORKFLOW_ALTERED') WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	if err = c.VerifyAudit(ctx); err == nil {
		t.Fatal("tampered audit accepted")
	}
	reopened, err := Open(path, c.bundle, c.executor, c.gate, c.key)
	if err == nil {
		reopened.Close()
		t.Fatal("tampered audit accepted on startup")
	}
}
func TestRawPayloadsNeverEnterDatabaseAudit(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	secret := "synthetic-salary-928374"
	e.execute = func(context.Context, core.Dispatch) core.Execution {
		return core.Execution{Outcome: "SUCCEEDED", Raw: json.RawMessage(`{"secret":"` + secret + `"}`)}
	}
	if _, err := c.Execute(ctx, p, o.ID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"operations", "audit"} {
		rows, err := c.db.Query(`SELECT data FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var data []byte
			if err = rows.Scan(&data); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("raw result persisted to", table)
			}
		}
		rows.Close()
	}
}

func TestCrashAfterDispatchClaimNeverRetries(t *testing.T) {
	c, p, e, path := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	e.execute = func(context.Context, core.Dispatch) core.Execution { panic("simulated worker crash") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("fault was not injected")
			}
		}()
		_, _ = c.Execute(ctx, p, o.ID)
	}()
	restarted, err := Open(path, c.bundle, e, c.gate, c.key)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	r, err := restarted.Execute(ctx, p, o.ID)
	if err != nil || r.ExecutionStatus != "DISPATCHED" || e.calls.Load() != 1 {
		t.Fatal("crashed claim retried", r, err)
	}
	current, _ := restarted.GetWorkflow(ctx, p, w.ID)
	if current.Inflight != o.ID {
		t.Fatal("crash lost domain reservation")
	}
	e.reconcile = func(context.Context, core.Dispatch) core.Execution { return core.Execution{Outcome: "FAILED"} }
	r, err = restarted.Reconcile(ctx, approver(p), o.ID)
	if err != nil || r.ExecutionStatus != "FAILED" || e.calls.Load() != 1 {
		t.Fatal("authoritative failure reconciliation", r, err)
	}
}
func TestCrashAfterKnownOutcomeReconcilesRelease(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	c.gate = fakeGate{hook: func() { panic("crash after durable success before release") }}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("fault was not injected")
			}
		}()
		_, _ = c.Execute(ctx, p, o.ID)
	}()
	saved, err := c.GetOperation(ctx, p, o.ID)
	if err != nil || saved.Status != "SUCCEEDED" || saved.ReleaseStatus != "WITHHELD" {
		t.Fatal("known outcome was lost", saved, err)
	}
	c.gate = fakeGate{}
	e.reconcile = func(context.Context, core.Dispatch) core.Execution {
		return core.Execution{Outcome: "SUCCEEDED", Raw: json.RawMessage(`{"ok":true}`)}
	}
	r, err := c.Reconcile(ctx, approver(p), o.ID)
	if err != nil || r.ReleaseStatus != "RELEASED" || e.calls.Load() != 1 {
		t.Fatal("release recovery failed", r, err)
	}
	current, _ := c.GetWorkflow(ctx, p, w.ID)
	if current.Inflight != "" {
		t.Fatal("reconciled known outcome kept slot")
	}
}
func TestAuditReservationFailurePreventsDispatch(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	if _, err := c.db.Exec(`DROP TABLE audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Execute(ctx, p, o.ID); err == nil || e.calls.Load() != 0 {
		t.Fatal("audit failure dispatched an operation")
	}
	current, err := c.GetWorkflow(ctx, p, w.ID)
	if err != nil || current.Inflight != "" || current.Calls != 0 || current.Exposure.Confidentiality != core.Public {
		t.Fatal("failed reservation did not roll back state", current, err)
	}
}
func TestUninspectablePublicResultRaisesConservativeExposure(t *testing.T) {
	c, p, _, _ := fixture(t)
	ctx := context.Background()
	c.bundle.Tools[0].SourceExposure = core.Exposure{Confidentiality: core.Public}
	c.gate = fakeGate{fail: true}
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	if _, err := c.Execute(ctx, p, o.ID); err != nil {
		t.Fatal(err)
	}
	current, err := c.GetWorkflow(ctx, p, w.ID)
	if err != nil || current.Exposure.Confidentiality != core.Restricted || !current.Exposure.Untrusted {
		t.Fatal("failed classification did not raise conservative label", current, err)
	}
}

func TestIndentedManifestSchemaSurvivesDurableRoundTrip(t *testing.T) {
	c, p, e, path := fixture(t)
	ctx := context.Background()
	encoded, err := json.MarshalIndent(c.bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var indented core.Bundle
	if err = json.Unmarshal(encoded, &indented); err != nil {
		t.Fatal(err)
	}
	indented.Digest = c.bundle.Digest
	reopened, err := Open(path, indented, e, fakeGate{}, c.key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	w := workflowFor(t, reopened, p)
	o := operationFor(t, reopened, p, w, "read")
	r, err := reopened.Execute(ctx, p, o.ID)
	if err != nil || r.Decision.Outcome != core.Allow || e.calls.Load() != 1 {
		t.Fatal("schema whitespace changed approved manifest", r, err)
	}
}

func TestHistoricalOperationInspectionRechecksCurrentAuthority(t *testing.T) {
	c, p, _, _ := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "read")
	revoked := p
	revoked.Resources = nil
	if _, err := c.GetOperation(ctx, revoked, o.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked resource scope still disclosed historical arguments")
	}
	revoked = p
	revoked.Clearance = core.Public
	if _, err := c.GetOperation(ctx, revoked, o.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("lowered clearance still disclosed historical operation")
	}
}

func TestReservedCrashCanAbortWithoutResourceCallOrAuthorityRefund(t *testing.T) {
	c, p, e, _ := fixture(t)
	ctx := context.Background()
	w := workflowFor(t, c, p)
	o := operationFor(t, c, p, w, "write")
	if _, err := c.Execute(ctx, p, o.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Approve(ctx, approver(p), o.ID); err != nil {
		t.Fatal(err)
	}
	// Simulate the durable state left by a crash after the reservation transaction
	// commits but before dispatch has atomically claimed the server-held permit.
	tx, err := c.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	o, err = c.loadOperation(tx, p, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	var d domain
	if err = get(tx, "domains", w.DomainID, &d); err != nil {
		t.Fatal(err)
	}
	var a core.Approval
	if err = get(tx, "approvals", o.ApprovalID, &a); err != nil {
		t.Fatal(err)
	}
	a.Consumed = true
	if err = c.putApproval(tx, a); err != nil {
		t.Fatal(err)
	}
	o.Status = "RESERVED"
	o.PermitID = opaque("permit_")
	o.OwnerEpoch = opaque("epoch_")
	o.Decision.Outcome = core.Allow
	d.Inflight = o.ID
	d.Calls++
	d.Revision++
	d.Exposure = join(d.Exposure, o.Tool.SourceExposure)
	if err = put(tx, "operations", o.ID, o); err != nil {
		t.Fatal(err)
	}
	if err = put(tx, "domains", d.ID, d); err != nil {
		t.Fatal(err)
	}
	if err = c.event(tx, p.Tenant, w.ID, o.ID, "EXECUTION_RESERVED", o.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r, err := c.Reconcile(ctx, approver(p), o.ID)
	if err != nil || r.ExecutionStatus != "FAILED" || r.ReleaseStatus != "UNAVAILABLE" || len(r.Result) != 0 || !has(r.Decision.Reasons, "PRE_DISPATCH_ABORTED") {
		t.Fatal("reserved operation did not abort safely", r, err)
	}
	if e.calls.Load() != 0 || e.reconciles.Load() != 0 {
		t.Fatal("pre-dispatch abort contacted the resource")
	}
	current, err := c.GetWorkflow(ctx, p, w.ID)
	if err != nil || current.Inflight != "" || current.Calls != d.Calls || current.Revision != d.Revision+1 || current.Exposure.Confidentiality != core.Restricted || !current.Exposure.Untrusted {
		t.Fatal("abort refunded or erased reservation state", current, err)
	}
	tx, err = c.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = get(tx, "approvals", o.ApprovalID, &a); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	if !a.Consumed {
		t.Fatal("abort refunded approval")
	}
	if _, err = c.dispatch(ctx, p, o.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("delayed old worker claimed aborted permit", err)
	}
	if _, err = c.Execute(ctx, p, o.ID); err != nil || e.calls.Load() != 0 {
		t.Fatal("old operation executed after abort", err)
	}
	next := operationFor(t, c, p, w, "read")
	r, err = c.Execute(ctx, p, next.ID)
	if err != nil || r.ExecutionStatus != "SUCCEEDED" || e.calls.Load() != 1 {
		t.Fatal("abort did not free domain for a separate authorised operation", r, err)
	}
	if err = c.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}
