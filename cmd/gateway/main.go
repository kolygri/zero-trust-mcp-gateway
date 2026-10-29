// gateway serves the reference MCP enforcement boundary.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/config"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/executor"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/response"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/server"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/workflow"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return nil
	}
	if len(os.Args) > 1 && os.Args[1] == "init-demo" {
		f := flag.NewFlagSet("init-demo", flag.ContinueOnError)
		dir := f.String("dir", ".local", "new private demo directory")
		if err := f.Parse(os.Args[2:]); err != nil {
			return err
		}
		return initDemo(*dir)
	}
	f := flag.NewFlagSet("gateway", flag.ContinueOnError)
	path := f.String("config", ".local/gateway.json", "operator configuration")
	if err := f.Parse(os.Args[1:]); err != nil {
		return err
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	backend, err := executor.New(c.Bundle.Tools, 10*time.Second)
	if err != nil {
		return err
	}
	w, err := workflow.Open(c.Database, c.Bundle, backend, response.New(), c.AuditKey)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := w.VerifyAudit(context.Background()); err != nil {
		return fmt.Errorf("audit verification: %w", err)
	}
	srv := &http.Server{Addr: c.Listen, Handler: server.New(c, w), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("gateway %s listening on %s; protocol=%s policy=%s", version, c.Listen, core.ProtocolVersion, c.Bundle.Digest)
	if c.TLSCert != "" {
		err = srv.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func initDemo(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("create new demo directory: %w", err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	resources := []string{"payroll:2026-09"}
	destinations := []string{"internal-report-store"}
	toolNames := []string{"payroll.read", "payroll.report", "report.publish"}
	input := json.RawMessage(`{"type":"object","properties":{"resource":{"type":"string","enum":["payroll:2026-09"]}},"required":["resource"],"additionalProperties":false}`)
	output := json.RawMessage(`{"type":"object","properties":{"period":{"type":"string"},"department":{"type":"string"},"total":{"type":"number"},"variance":{"type":"number"}},"required":["period","department","total","variance"],"additionalProperties":false}`)
	deployment := sha256.Sum256([]byte("synthetic-mock-resource-v1-operator-assertion"))
	bundle := core.Bundle{Version: "demo-v1", Semantics: core.PolicySemanticsVersion, ExpiresAt: time.Now().UTC().Add(24 * time.Hour)}
	for _, name := range toolNames {
		t := core.Tool{Name: name, Description: "Approved synthetic payroll aggregate operation", ServerID: "synthetic-payroll-resource", DeploymentDigest: "sha256:" + hex.EncodeToString(deployment[:]), Endpoint: "http://127.0.0.1:8091/mcp", UpstreamName: name, TokenEnv: "MOCK_READ_TOKEN", StatusEndpoint: "http://127.0.0.1:8091/operations", InputSchema: input, OutputSchema: output, Effect: "read", Destination: "internal-report-store", ResourceArgument: "resource", Resources: resources, SourceExposure: core.Exposure{Confidentiality: core.Restricted, Untrusted: true}, MaxInputLabel: core.Restricted, ReleaseFields: []string{"period", "department", "total", "variance"}, MaxResultBytes: 65536}
		if name == "report.publish" {
			t.Effect = "write"
			t.RequireApproval = true
			t.TokenEnv = "MOCK_PUBLISH_TOKEN"
			t.InputSchema = json.RawMessage(`{"type":"object","properties":{"resource":{"type":"string","enum":["payroll:2026-09"]},"destination":{"type":"string","enum":["internal-report-store"]}},"required":["resource","destination"],"additionalProperties":false}`)
			t.OutputSchema = json.RawMessage(`{"type":"object","properties":{"period":{"type":"string"},"department":{"type":"string"},"total":{"type":"number"},"variance":{"type":"number"},"receipt":{"type":"string"}},"required":["period","department","total","variance","receipt"],"additionalProperties":false}`)
			t.ReleaseFields = append(t.ReleaseFields, "receipt")
		}
		bundle.Tools = append(bundle.Tools, t)
	}
	bundle.Templates = []core.Template{{ID: "payroll-report-v1", Tools: toolNames, Resources: resources, Destinations: destinations, InitialExposure: core.Exposure{Confidentiality: core.Restricted, Untrusted: true}, MaxCalls: 100, LifetimeSeconds: 3600}}
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	principal := core.Principal{Tenant: "finance-demo", User: "finance-user", Workload: "reporting-host", Tools: toolNames, Resources: resources, Destinations: destinations, Clearance: core.Restricted}
	host := principal
	host.Roles = []string{"host"}
	agent := principal
	agent.Roles = []string{"agent"}
	reviewer := principal
	reviewer.User = "finance-reviewer"
	reviewer.Workload = "review-console"
	reviewer.Roles = []string{"approver", "admin"}
	c := config.Config{Listen: "127.0.0.1:8080", Database: "gateway.db", BundlePath: "bundle.json", SignaturePath: "bundle.sig", PolicyPublicKey: base64.StdEncoding.EncodeToString(pub), AuditKeyEnv: "GATEWAY_AUDIT_KEY", AllowedOrigins: []string{}, Credentials: []config.Credential{{TokenEnv: "GATEWAY_HOST_TOKEN", Principal: host}, {TokenEnv: "GATEWAY_AGENT_TOKEN", Principal: agent}, {TokenEnv: "GATEWAY_REVIEWER_TOKEN", Principal: reviewer}}}
	cb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{"gateway.json": append(cb, '\n'), "bundle.json": b, "bundle.sig": []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, b)) + "\n"), "policy-private.key": []byte(base64.StdEncoding.EncodeToString(private) + "\n")}
	var env string
	for _, name := range []string{"GATEWAY_HOST_TOKEN", "GATEWAY_AGENT_TOKEN", "GATEWAY_REVIEWER_TOKEN", "GATEWAY_AUDIT_KEY", "MOCK_READ_TOKEN", "MOCK_PUBLISH_TOKEN"} {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		env += "export " + name + "='" + base64.StdEncoding.EncodeToString(secret) + "'\n"
	}
	files["demo.env"] = []byte(env)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return err
		}
	}
	fmt.Printf("Created signed synthetic demo in %s (policy expires in 24 hours).\n", dir)
	fmt.Println("Load demo.env in each terminal; keep this directory private. See README.md.")
	return nil
}
