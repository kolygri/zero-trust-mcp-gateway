package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/config"
)

func TestInitDemoCreatesPrivateSignedRunnableConfiguration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "demo")
	if err := initDemo(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("demo directory permissions %o", info.Mode().Perm())
	}
	env, err := os.ReadFile(filepath.Join(dir, "demo.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(env)), "\n") {
		parts := strings.SplitN(strings.TrimPrefix(line, "export "), "=", 2)
		if len(parts) != 2 {
			t.Fatal("invalid generated environment file")
		}
		t.Setenv(parts[0], strings.Trim(parts[1], "'"))
	}
	cfg, err := config.Load(filepath.Join(dir, "gateway.json"))
	if err != nil {
		t.Fatalf("generated config invalid: %v", err)
	}
	if len(cfg.Bundle.Tools) != 3 || len(cfg.Credentials) != 3 {
		t.Fatal("missing demo authority classes")
	}
	original, err := os.ReadFile(filepath.Join(dir, "bundle.sig"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s permissions %o", entry.Name(), info.Mode().Perm())
		}
	}
	if err = initDemo(dir); err == nil {
		t.Fatal("existing demo directory overwritten")
	}
	current, err := os.ReadFile(filepath.Join(dir, "bundle.sig"))
	if err != nil || string(current) != string(original) {
		t.Fatal("existing demo credentials changed")
	}
}
