// Package config loads operator-owned configuration and verifies policy bytes before parsing.
package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/policy"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
)

type Credential struct {
	TokenEnv  string         `json:"token_env"`
	Principal core.Principal `json:"principal"`
	token     []byte
}

type Config struct {
	Listen             string       `json:"listen"`
	Database           string       `json:"database"`
	BundlePath         string       `json:"bundle_path"`
	SignaturePath      string       `json:"signature_path"`
	PolicyPublicKey    string       `json:"policy_public_key"`
	AuditKeyEnv        string       `json:"audit_key_env"`
	AllowedOrigins     []string     `json:"allowed_origins"`
	TLSCert            string       `json:"tls_cert,omitempty"`
	TLSKey             string       `json:"tls_key,omitempty"`
	Credentials        []Credential `json:"credentials"`
	Bundle             core.Bundle  `json:"-"`
	AuditKey           []byte       `json:"-"`
	SignedBundleDigest string       `json:"-"`
}

func Load(path string) (*Config, error) {
	b, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := protocol.StrictJSON(b, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	base := filepath.Dir(path)
	resolve := func(p string) string {
		if p != "" && !filepath.IsAbs(p) {
			return filepath.Join(base, p)
		}
		return p
	}
	c.Database, c.BundlePath, c.SignaturePath = resolve(c.Database), resolve(c.BundlePath), resolve(c.SignaturePath)
	c.TLSCert, c.TLSKey = resolve(c.TLSCert), resolve(c.TLSKey)
	if c.Database == "" || c.BundlePath == "" || c.SignaturePath == "" {
		return nil, errors.New("database, signed bundle and signature paths required")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return nil, errors.New("listen must be host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		if c.TLSCert == "" || c.TLSKey == "" {
			return nil, errors.New("non-loopback listeners require TLS")
		}
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("both TLS certificate and key are required")
	}
	b, err = readBounded(c.BundlePath)
	if err != nil {
		return nil, err
	}
	sigBytes, err := readBounded(c.SignaturePath)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(c.PolicyPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid policy public key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBytes)))
	if err != nil || !ed25519.Verify(key, b, sig) {
		return nil, errors.New("policy signature verification failed")
	}
	if err := protocol.StrictJSON(b, &c.Bundle); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	digest := sha256.Sum256(b)
	c.SignedBundleDigest = "sha256:" + hex.EncodeToString(digest[:])
	c.Bundle.Digest = c.SignedBundleDigest
	if err := policy.ValidateBundle(c.Bundle); err != nil {
		return nil, err
	}
	if !time.Now().Before(c.Bundle.ExpiresAt) {
		return nil, errors.New("policy bundle has expired")
	}
	if err := validateOrigins(c.AllowedOrigins); err != nil {
		return nil, err
	}
	c.AuditKey, err = base64.StdEncoding.DecodeString(os.Getenv(c.AuditKeyEnv))
	if err != nil || len(c.AuditKey) < 32 {
		return nil, errors.New("audit key environment variable must contain at least 32 base64-encoded random bytes")
	}
	if len(c.Credentials) == 0 {
		return nil, errors.New("at least one credential required")
	}
	tenant := c.Credentials[0].Principal.Tenant
	for i := range c.Credentials {
		cred := &c.Credentials[i]
		cred.token = []byte(os.Getenv(cred.TokenEnv))
		p := cred.Principal
		if !validToken(cred.token) || p.Tenant == "" || p.User == "" || p.Workload == "" || policy.LabelRank(p.Clearance) < 0 {
			return nil, errors.New("invalid credential or principal")
		}
		if p.Tenant != tenant {
			return nil, errors.New("this reference deployment supports exactly one tenant")
		}
		if subtle.ConstantTimeCompare(cred.token, c.AuditKey) == 1 || subtle.ConstantTimeCompare(cred.token, []byte(os.Getenv(c.AuditKeyEnv))) == 1 {
			return nil, errors.New("audit and access secrets must be distinct")
		}
		if len(p.Roles) == 0 {
			return nil, errors.New("credential role required")
		}
		seenRoles := map[string]bool{}
		for _, r := range p.Roles {
			if seenRoles[r] {
				return nil, errors.New("duplicate credential role")
			}
			seenRoles[r] = true
		}
		if (seenRoles["agent"] || seenRoles["host"]) && len(p.Roles) != 1 {
			return nil, errors.New("host and agent credentials require separate roles")
		}
		for j := 0; j < i; j++ {
			if subtle.ConstantTimeCompare(cred.token, c.Credentials[j].token) == 1 {
				return nil, errors.New("credential tokens must be distinct")
			}
		}
		for _, role := range p.Roles {
			if role != "agent" && role != "host" && role != "approver" && role != "admin" {
				return nil, errors.New("unknown credential role")
			}
		}
	}
	for _, tool := range c.Bundle.Tools {
		backend := []byte(os.Getenv(tool.TokenEnv))
		if !validToken(backend) {
			return nil, errors.New("backend credential must contain 32..512 visible ASCII bytes")
		}
		if subtle.ConstantTimeCompare(backend, c.AuditKey) == 1 || subtle.ConstantTimeCompare(backend, []byte(os.Getenv(c.AuditKeyEnv))) == 1 {
			return nil, errors.New("backend and audit secrets must be distinct")
		}
		for _, cred := range c.Credentials {
			if subtle.ConstantTimeCompare(backend, cred.token) == 1 {
				return nil, errors.New("backend and gateway credentials must be distinct")
			}
		}
	}
	// Local identity configuration is part of the effective authorisation basis.
	// Revoking an approver, narrowing an entitlement, or rotating a credential
	// invalidates workflows and approvals even when signed tool policy is unchanged.
	type authority struct {
		TokenEnv  string         `json:"token_env"`
		Principal core.Principal `json:"principal"`
		TokenHash string         `json:"token_hash"`
	}
	authorities := make([]authority, 0, len(c.Credentials))
	for _, cred := range c.Credentials {
		hash := sha256.Sum256(cred.token)
		authorities = append(authorities, authority{TokenEnv: cred.TokenEnv, Principal: cred.Principal, TokenHash: hex.EncodeToString(hash[:])})
	}
	basis, err := json.Marshal(struct {
		Semantics          string      `json:"semantics"`
		SignedBundleDigest string      `json:"signed_bundle_digest"`
		Authorities        []authority `json:"authorities"`
	}{"enforcement-basis-v1", c.SignedBundleDigest, authorities})
	if err != nil {
		return nil, err
	}
	basis, err = protocol.CanonicalJSON(basis)
	if err != nil {
		return nil, err
	}
	effective := sha256.Sum256(basis)
	c.Bundle.Digest = "sha256:" + hex.EncodeToString(effective[:])
	return &c, nil
}

// Authenticate uses only operator-bound identity, never body fields or client metadata.
func (c *Config) Authenticate(header string) (core.Principal, bool) {
	if !strings.HasPrefix(header, "Bearer ") {
		return core.Principal{}, false
	}
	token := []byte(strings.TrimPrefix(header, "Bearer "))
	for _, cred := range c.Credentials {
		if subtle.ConstantTimeCompare(token, cred.token) == 1 {
			return cred.Principal, true
		}
	}
	return core.Principal{}, false
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("configuration must be a regular file of at most 1 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	return b, nil
}

func validToken(token []byte) bool {
	if len(token) < 32 || len(token) > 512 {
		return false
	}
	for _, b := range token {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func validateOrigins(origins []string) error {
	seen := map[string]bool{}
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") || seen[origin] {
			return errors.New("allowed origins must be unique exact HTTP(S) origins without paths")
		}
		seen[origin] = true
	}
	return nil
}
