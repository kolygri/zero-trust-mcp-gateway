// mock-resource is an independently authenticated synthetic test resource. Its
// state file atomically records the synthetic business effect and its receipt.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/core"
	"github.com/kolygri/zero-trust-mcp-gateway/internal/protocol"
)

type receipt struct {
	Digest string          `json:"digest"`
	Scope  string          `json:"scope"`
	Result json.RawMessage `json:"result"`
}
type resourceState struct {
	Publications int                `json:"publications"`
	Receipts     map[string]receipt `json:"receipts"`
}
type resource struct {
	mu           sync.Mutex
	token        string
	publishToken string
	path         string
	state        resourceState
}

func openResource(path, token, publishToken string) (*resource, error) {
	if len(token) < 16 || len(publishToken) < 16 || token == publishToken {
		return nil, errors.New("MOCK_READ_TOKEN and distinct MOCK_PUBLISH_TOKEN must contain at least 16 bytes")
	}
	r := &resource{token: token, publishToken: publishToken, path: path, state: resourceState{Receipts: map[string]receipt{}}}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err = protocol.StrictJSON(raw, &r.state); err != nil {
			return nil, err
		}
		if r.state.Receipts == nil {
			return nil, errors.New("invalid resource state")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return r, nil
}
func (r *resource) persist(next resourceState) error {
	directory := filepath.Dir(r.path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(directory, ".resource-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(next)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temp, r.path)
	}
	if err == nil {
		dir, e := os.Open(directory)
		if e != nil {
			return e
		}
		err = dir.Sync()
		dir.Close()
	}
	return err
}
func (r *resource) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	readAuthority := subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte("Bearer "+r.token)) == 1
	publishAuthority := subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte("Bearer "+r.publishToken)) == 1
	if !readAuthority && !publishAuthority {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	if req.URL.Path == "/operations" && req.Method == http.MethodGet {
		id := req.URL.Query().Get("operation_id")
		r.mu.Lock()
		stored, ok := r.state.Receipts[id]
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if ok && ((stored.Scope == "publish" && !publishAuthority) || (stored.Scope != "publish" && !readAuthority)) {
			http.Error(w, "operation authority forbidden", http.StatusForbidden)
			return
		}
		if !ok {
			json.NewEncoder(w).Encode(map[string]any{"outcome": "UNKNOWN"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"outcome": "SUCCEEDED", "result": stored.Result})
		return
	}
	if req.URL.Path != "/mcp" || req.Method != http.MethodPost {
		http.NotFound(w, req)
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, 64<<10)
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	call, err := protocol.Parse(raw, req.Header)
	if err != nil || call.Method != "tools/call" {
		http.Error(w, "invalid MCP request", http.StatusBadRequest)
		return
	}
	var id string
	if json.Unmarshal(call.ID, &id) != nil || id == "" || len(id) > 128 || req.Header.Get("X-Gateway-Operation-ID") != id || req.Header.Get("Idempotency-Key") != id {
		http.Error(w, "bound operation required", http.StatusBadRequest)
		return
	}
	var args struct {
		Resource    string `json:"resource"`
		Destination string `json:"destination,omitempty"`
	}
	if protocol.StrictJSON(call.Arguments, &args) != nil || args.Resource != "payroll:2026-09" {
		http.Error(w, "resource forbidden", http.StatusForbidden)
		return
	}
	// StrictJSON may accept unknown object fields for generic decoding; enforce the
	// resource's complete input contract independently of gateway policy.
	var fields map[string]any
	if protocol.StrictJSON(call.Arguments, &fields) != nil {
		http.Error(w, "invalid arguments", http.StatusBadRequest)
		return
	}
	for key := range fields {
		if key != "resource" && key != "destination" {
			http.Error(w, "argument forbidden", http.StatusForbidden)
			return
		}
	}
	switch call.Name {
	case "payroll.read", "payroll.report":
		if !readAuthority {
			http.Error(w, "read authority required", http.StatusForbidden)
			return
		}
		if args.Destination != "" {
			http.Error(w, "destination forbidden", http.StatusForbidden)
			return
		}
	case "report.publish":
		if !publishAuthority {
			http.Error(w, "publication authority required", http.StatusForbidden)
			return
		}
		if args.Destination != "internal-report-store" {
			http.Error(w, "destination forbidden", http.StatusForbidden)
			return
		}
	default:
		http.Error(w, "tool forbidden", http.StatusForbidden)
		return
	}
	canonical, err := protocol.CanonicalJSON(call.Arguments)
	if err != nil {
		http.Error(w, "invalid arguments", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(append([]byte(call.Name+"\x00"), canonical...))
	digest := hex.EncodeToString(sum[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if prior, exists := r.state.Receipts[id]; exists {
		if prior.Digest != digest {
			http.Error(w, "operation binding mismatch", http.StatusConflict)
			return
		}
		writeMCP(w, id, prior.Result)
		return
	}
	structured := map[string]any{"period": "2026-09", "department": "Engineering", "total": 125000, "variance": 2500}
	if call.Name == "report.publish" {
		structured["receipt"] = "published:" + id
	}
	result, _ := json.Marshal(map[string]any{"resultType": "complete", "structuredContent": structured, "content": []any{map[string]any{"type": "text", "text": "Synthetic payroll aggregate; not a real financial record."}}, "isError": false})
	next := resourceState{Publications: r.state.Publications, Receipts: map[string]receipt{}}
	for key, value := range r.state.Receipts {
		next.Receipts[key] = value
	}
	if call.Name == "report.publish" {
		next.Publications++
	}
	scope := "read"
	if call.Name == "report.publish" {
		scope = "publish"
	}
	next.Receipts[id] = receipt{Digest: digest, Scope: scope, Result: result}
	if err := r.persist(next); err != nil {
		http.Error(w, "state unavailable", http.StatusServiceUnavailable)
		return
	}
	r.state = next
	writeMCP(w, id, result)
}
func writeMCP(w http.ResponseWriter, id string, result json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:8091", "literal loopback listen address")
	statePath := flag.String("state", ".gateway/mock-resource.json", "private synthetic resource state")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("mock resource must bind a literal loopback address")
	}
	r, err := openResource(*statePath, os.Getenv("MOCK_READ_TOKEN"), os.Getenv("MOCK_PUBLISH_TOKEN"))
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(*statePath), 0700); err != nil {
		return err
	}
	lock, err := lockState(*statePath + ".lock")
	if err != nil {
		return fmt.Errorf("single-process mock lock unavailable: %w", err)
	}
	defer lock.Close()
	srv := &http.Server{Addr: *listen, Handler: r, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	log.Printf("synthetic resource listening on %s (protocol %s)", *listen, core.ProtocolVersion)
	if err = srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		log.Fatal(strings.ReplaceAll(err.Error(), "\n", " "))
	}
}
