// mcp-gateway logs and forwards the newline-delimited messages of an MCP stdio server.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/kolygri/zero-trust-mcp-gateway/internal/gateway"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: mcp-gateway -- <server-command> [args...]")
		fmt.Fprintln(os.Stderr, "Forwards MCP stdio messages unchanged; logs full message contents as JSON to stderr.")
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := gateway.Run(ctx, flag.Args(), os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-gateway:", err)
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() > 0 {
			os.Exit(exit.ExitCode())
		}
		os.Exit(1)
	}
}
