package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRelayPreservesMessages(t *testing.T) {
	input := "{\"jsonrpc\":\"2.0\",\"id\":1}\r\n" + strings.Repeat("x", 128*1024) + "\npartial"
	var output, logs bytes.Buffer
	if err := relay(&output, strings.NewReader(input), "client_to_server", &messageLog{out: &logs}); err != nil {
		t.Fatal(err)
	}
	if output.String() != input {
		t.Fatal("forwarded bytes changed")
	}
	decoder := json.NewDecoder(&logs)
	var recovered strings.Builder
	count := 0
	for decoder.More() {
		var event struct{ Time, Direction, Message string }
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Direction != "client_to_server" || event.Time == "" {
			t.Fatalf("invalid log: %+v", event)
		}
		recovered.WriteString(event.Message)
		count++
	}
	if recovered.String() != input || count != 3 {
		t.Fatal("logs did not preserve every message")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRelayErrors(t *testing.T) {
	for _, failLog := range []bool{false, true} {
		var output, logs io.Writer = io.Discard, io.Discard
		if failLog {
			logs = failingWriter{}
		} else {
			output = failingWriter{}
		}
		if err := relay(output, strings.NewReader("{}\n"), "test", &messageLog{out: logs}); err == nil {
			t.Fatal("expected write failure")
		}
	}
}

func helperCommand(mode string) []string {
	return []string{os.Args[0], "-test.run=^TestServerHelper$", "--", "mcp-gateway-fixture", mode}
}

// TestServerHelper runs as an independent child process for integration tests.
func TestServerHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "mcp-gateway-fixture" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "exit":
		os.Exit(7)
	case "wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			os.Exit(3)
		}
		var result string
		switch request.Method {
		case "initialize":
			result = `{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}`
		case "notifications/initialized":
			continue
		case "tools/list":
			result = `{"tools":[{"name":"echo","description":"Echo","inputSchema":{"type":"object"}}]}`
		case "tools/call":
			result = `{"content":[{"type":"text","text":"hello"}]}`
		default:
			os.Exit(4)
		}
		fmt.Fprintf(os.Stdout, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n", request.ID, result)
	}
	os.Exit(0)
}

func TestMCPRoundTrip(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	}, "\n") + "\n"
	var output, logs bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Run(ctx, helperCommand("mcp"), strings.NewReader(input), &output, &logs); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(output.String()), "\n"); len(lines) != 3 {
		t.Fatalf("expected 3 responses: %s", output.String())
	}
	if !strings.Contains(output.String(), `"text":"hello"`) || !strings.Contains(output.String(), `"protocolVersion":"2025-03-26"`) {
		t.Fatalf("missing MCP results: %s", output.String())
	}
	var requests, responses strings.Builder
	decoder := json.NewDecoder(&logs)
	for decoder.More() {
		var event struct{ Direction, Message string }
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		switch event.Direction {
		case "client_to_server":
			requests.WriteString(event.Message)
		case "server_to_client":
			responses.WriteString(event.Message)
		default:
			t.Fatalf("unknown direction %q", event.Direction)
		}
	}
	if requests.String() != input || responses.String() != output.String() {
		t.Fatal("logs differ from actual MCP traffic")
	}
}

func TestServerFailure(t *testing.T) {
	err := Run(context.Background(), helperCommand("exit"), strings.NewReader(""), io.Discard, io.Discard)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("expected server exit 7, got %v", err)
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := Run(ctx, helperCommand("wait"), strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected cancellation error")
	}
}

type brokenPipeWriter struct{}

func (brokenPipeWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestInputLogFailureStopsServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, helperCommand("mcp"), strings.NewReader("{}\n"), io.Discard, brokenPipeWriter{})
	if !errors.Is(err, io.ErrClosedPipe) || !strings.Contains(err.Error(), "log client_to_server") {
		t.Fatalf("expected input logging failure, got %v", err)
	}
}
