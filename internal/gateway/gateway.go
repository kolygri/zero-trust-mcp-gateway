// Package gateway provides a transparent, logging MCP stdio relay.
package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type messageLog struct {
	mu  sync.Mutex
	out io.Writer
}

type forwardingError struct {
	direction string
	cause     error
}

func (e *forwardingError) Error() string {
	return fmt.Sprintf("forward %s: %v", e.direction, e.cause)
}

func (e *forwardingError) Unwrap() error { return e.cause }

func (l *messageLog) write(direction string, message []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return json.NewEncoder(l.out).Encode(struct {
		Time      string `json:"time"`
		Direction string `json:"direction"`
		Message   string `json:"message"`
	}{time.Now().UTC().Format(time.RFC3339Nano), direction, string(message)})
}

// relay preserves bytes, including newline delimiters and a final partial line.
// ReadBytes supports messages larger than bufio.Scanner's default token limit.
func relay(dst io.Writer, src io.Reader, direction string, log *messageLog) error {
	reader := bufio.NewReader(src)
	for {
		message, readErr := reader.ReadBytes('\n')
		if len(message) > 0 {
			if err := log.write(direction, message); err != nil {
				return fmt.Errorf("log %s: %w", direction, err)
			}
			if _, err := io.Copy(dst, bytes.NewReader(message)); err != nil {
				return &forwardingError{direction, err}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read %s: %w", direction, readErr)
		}
	}
}

// Run starts command without a shell and relays stdin/stdout in both directions.
// diagnostics receives JSON message logs and the server's own stderr. The caller
// must not reuse input after Run: a blocked input read may outlive the child.
func Run(ctx context.Context, command []string, input io.Reader, output, diagnostics io.Writer) error {
	if len(command) == 0 {
		return errors.New("server command is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	// Serialize server diagnostics with message logs, including for non-thread-safe writers.
	log := &messageLog{out: diagnostics}
	cmd.Stderr = lockedWriter{log}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return err
	}
	inputDone := make(chan error, 1)
	go func() {
		err := relay(stdin, input, "client_to_server", log)
		stdin.Close()
		// A server may exit without consuming all of its input.
		var forwardErr *forwardingError
		if errors.As(err, &forwardErr) && (errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe)) {
			err = nil
		}
		inputDone <- err
		if err != nil {
			cancel()
		}
	}()
	outputErr := relay(output, stdout, "server_to_client", log)
	if outputErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if outputErr != nil {
		return outputErr
	}
	select {
	case err := <-inputDone:
		if err != nil {
			return err
		}
	default:
	}
	return waitErr
}

type lockedWriter struct{ log *messageLog }

func (w lockedWriter) Write(p []byte) (int, error) {
	w.log.mu.Lock()
	defer w.log.mu.Unlock()
	return w.log.out.Write(p)
}
