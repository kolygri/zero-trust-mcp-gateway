package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
)

func signedFixture(t *testing.T, changeConfig func(*Config), changeBundle func(*core.Bundle)) (string, Config) {
	t.Helper()
	dir := t.TempDir()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	principal := core.Principal{Tenant: "finance", User: "user", Workload: "host", Roles: []string{"agent"}, Tools: []string{"report.read"}, Resources: []string{"dataset:one"}, Destinations: []string{"internal"}, Clearance: core.Restricted}
	tool := core.Tool{Name: "report.read", ServerID: "backend", DeploymentDigest: "sha256:" + strings.Repeat("a", 64), Endpoint: "http://127.0.0.1:9000/mcp", UpstreamName: "report.read", TokenEnv: "TEST_BACKEND_TOKEN", InputSchema: json.RawMessage(`{"type":"object","properties":{"resource":{"type":"string"}},"required":["resource"],"additionalProperties":false}`), OutputSchema: json.RawMessage(`{"type":"object"}`), Effect: "read", Destination: "internal", ResourceArgument: "resource", Resources: principal.Resources, SourceExposure: core.Exposure{Confidentiality: core.Public}, MaxInputLabel: core.Restricted, ReleaseFields: []string{"value"}, MaxResultBytes: 1024}
	bundle := core.Bundle{Version: "test-v1", Semantics: "v1", ExpiresAt: time.Now().Add(time.Hour), Tools: []core.Tool{tool}, Templates: []core.Template{{ID: "report-v1", Tools: principal.Tools, Resources: principal.Resources, Destinations: principal.Destinations, InitialExposure: core.Exposure{Confidentiality: core.Public}, MaxCalls: 10, LifetimeSeconds: 600}}}
	cfg := Config{Listen: "127.0.0.1:8080", Database: "test.db", BundlePath: "bundle.json", SignaturePath: "bundle.sig", PolicyPublicKey: base64.StdEncoding.EncodeToString(pub), AuditKeyEnv: "TEST_AUDIT_KEY", AllowedOrigins: []string{"https://console.example"}, Credentials: []Credential{{TokenEnv: "TEST_AGENT_TOKEN", Principal: principal}}}
	t.Setenv("TEST_AGENT_TOKEN", strings.Repeat("A", 40))
	t.Setenv("TEST_BACKEND_TOKEN", strings.Repeat("B", 40))
	t.Setenv("TEST_AUDIT_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("K", 32))))
	if changeConfig != nil {
		changeConfig(&cfg)
	}
	if changeBundle != nil {
		changeBundle(&bundle)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "bundle.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "bundle.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gateway.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

func TestLoadVerifiesBytesAndBindsIdentity(t *testing.T) {
	path, _ := signedFixture(t, nil, nil)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database != filepath.Join(filepath.Dir(path), "test.db") {
		t.Fatal("paths not resolved relative to config")
	}
	raw, err := os.ReadFile(cfg.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if cfg.SignedBundleDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("bundle not bound to signed bytes")
	}
	p, ok := cfg.Authenticate("Bearer " + strings.Repeat("A", 40))
	if !ok || p.User != "user" || p.Tenant != "finance" {
		t.Fatal("operator identity unavailable")
	}
	for _, header := range []string{"", "Bearer invalid", "Basic " + strings.Repeat("A", 40), "Bearer  " + strings.Repeat("A", 40)} {
		if _, ok = cfg.Authenticate(header); ok {
			t.Fatal("invalid credential accepted")
		}
	}
	if err = os.WriteFile(cfg.BundlePath, append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("unsigned byte change accepted")
	}
}

func TestLoadRejectsUnsupportedAuthorityAndSecrets(t *testing.T) {
	tests := []struct {
		name   string
		cfg    func(*Config)
		bundle func(*core.Bundle)
		env    func(*testing.T)
	}{
		{name: "short token", env: func(t *testing.T) { t.Setenv("TEST_AGENT_TOKEN", "short") }},
		{name: "whitespace token", env: func(t *testing.T) { t.Setenv("TEST_AGENT_TOKEN", strings.Repeat("A", 32)+" ") }},
		{name: "short audit key", env: func(t *testing.T) { t.Setenv("TEST_AUDIT_KEY", base64.StdEncoding.EncodeToString([]byte("short"))) }},
		{name: "reused backend credential", env: func(t *testing.T) { t.Setenv("TEST_BACKEND_TOKEN", strings.Repeat("A", 40)) }},
		{name: "reused audit credential", env: func(t *testing.T) { t.Setenv("TEST_AGENT_TOKEN", os.Getenv("TEST_AUDIT_KEY")) }},
		{name: "missing backend credential", env: func(t *testing.T) { t.Setenv("TEST_BACKEND_TOKEN", "") }},
		{name: "reused gateway token", cfg: func(c *Config) { c.Credentials = append(c.Credentials, c.Credentials[0]) }},
		{name: "multiple tenants", cfg: func(c *Config) {
			other := c.Credentials[0]
			other.Principal.Tenant = "other"
			other.TokenEnv = "OTHER_TOKEN"
			c.Credentials = append(c.Credentials, other)
		}, env: func(t *testing.T) { t.Setenv("OTHER_TOKEN", strings.Repeat("C", 40)) }},
		{name: "agent self approval", cfg: func(c *Config) { c.Credentials[0].Principal.Roles = []string{"agent", "approver"} }},
		{name: "agent creates workflows", cfg: func(c *Config) { c.Credentials[0].Principal.Roles = []string{"host", "agent"} }},
		{name: "no role", cfg: func(c *Config) { c.Credentials[0].Principal.Roles = nil }},
		{name: "unknown role", cfg: func(c *Config) { c.Credentials[0].Principal.Roles = []string{"owner"} }},
		{name: "remote cleartext listen", cfg: func(c *Config) { c.Listen = "0.0.0.0:8080" }},
		{name: "hostname cleartext listen", cfg: func(c *Config) { c.Listen = "localhost:8080" }},
		{name: "origin path", cfg: func(c *Config) { c.AllowedOrigins = []string{"https://console.example/app"} }},
		{name: "origin credentials", cfg: func(c *Config) { c.AllowedOrigins = []string{"https://user:password@console.example"} }},
		{name: "wildcard origin", cfg: func(c *Config) { c.AllowedOrigins = []string{"*"} }},
		{name: "expired policy", bundle: func(b *core.Bundle) { b.ExpiresAt = time.Now().Add(-time.Second) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := signedFixture(t, tc.cfg, tc.bundle)
			if tc.env != nil {
				tc.env(t)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestConfigRejectsDuplicateKeysAndOversizeFiles(t *testing.T) {
	path, _ := signedFixture(t, nil, nil)
	if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:8080","listen":"0.0.0.0:8080"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("duplicate config keys accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", (1<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("oversized config accepted")
	}
}

func TestEffectivePolicyDigestIncludesCredentialAuthorityAndRotation(t *testing.T) {
	path, original := signedFixture(t, nil, nil)
	baseline, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	reload := func(c Config) *Config {
		t.Helper()
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	unchanged := reload(original)
	if unchanged.Bundle.Digest != baseline.Bundle.Digest {
		t.Fatal("unchanged effective authority changed digest")
	}
	for _, change := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"entitlement revoked", func(c *Config) { c.Credentials[0].Principal.Resources = nil }},
		{"role changed", func(c *Config) { c.Credentials[0].Principal.Roles = []string{"host"} }},
		{"subject changed", func(c *Config) { c.Credentials[0].Principal.User = "another-user" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			// A JSON clone prevents a nested slice change from mutating the baseline.
			var c Config
			raw, _ := json.Marshal(original)
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			change.mutate(&c)
			changed := reload(c)
			if changed.Bundle.Digest == baseline.Bundle.Digest {
				t.Fatal("changed authority did not invalidate policy basis")
			}
			if changed.SignedBundleDigest != baseline.SignedBundleDigest {
				t.Fatal("signed bundle attribution changed with local authority")
			}
		})
	}
	reload(original)
	t.Setenv("TEST_AGENT_TOKEN", strings.Repeat("R", 40))
	rotated, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Bundle.Digest == baseline.Bundle.Digest || rotated.SignedBundleDigest != baseline.SignedBundleDigest {
		t.Fatal("credential rotation not bound independently of signed bytes")
	}
}
