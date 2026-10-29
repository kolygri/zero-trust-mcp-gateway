# Logging MCP gateway

The gateway launches an MCP stdio server as a child process and relays its newline-delimited JSON-RPC messages. It logs requests, responses, and notifications in both directions. It forwards the original bytes without parsing, modifying, or enforcing policy on them. It supports stdio transport only; HTTP and SSE transports are not implemented.

## Build and test

The diagnostic relay package itself uses only the standard library. The repository now requires Go 1.27.3 or newer for the separate enforcing HTTP gateway. This relay performs no policy enforcement; see [README.md](README.md) for the security boundary.

From the repository root:

```sh
go test -race ./...
go vet ./...
go build -o bin/mcp-gateway ./cmd/mcp-gateway
```

In this cloud environment, initialize the installed toolchain before running these commands:

```sh
export PATH="/workspace/toolchains/go/bin:$PATH"
export GOCACHE=/workspace/.cache/go-build
```

## Run

Wrap the command you would normally use to start your MCP server:

```sh
./bin/mcp-gateway -- /absolute/path/to/mcp-server --server-option value
```

Arguments after `--` go to the server without shell interpretation. The child inherits the gateway's working directory and environment, so existing server configuration continues to apply. The gateway closes the child's stdin when the client closes its input, waits for the child to finish, and preserves a nonzero child exit code. Interrupting or terminating the gateway stops its immediate child process.

For MCP clients that use an `mcpServers` configuration object, replace the original server command with the gateway and place the original command first in `args`:

```json
{
  "mcpServers": {
    "logged-server": {
      "command": "/absolute/path/to/zero-trust-mcp-gateway/bin/mcp-gateway",
      "args": ["--", "/absolute/path/to/mcp-server", "--server-option", "value"]
    }
  }
}
```

Stdout contains only traffic from the server. Each message produces one JSON log record on stderr:

```json
{"time":"2026-10-28T12:00:00Z","direction":"client_to_server","message":"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"}
```

`direction` is `client_to_server` or `server_to_client`. `message` contains the complete original line, including its newline, encoded as a JSON string. Messages larger than 64 KiB are supported. A final line without a newline is also logged and forwarded. Blank or malformed lines are forwarded unchanged; protocol validation belongs to the client and server. Cross-direction log ordering reflects when the gateway reads each line.

Server stderr is also forwarded to gateway stderr, so server diagnostics may appear between JSON log records. MCP clients commonly capture stderr automatically. For a manual run, capture logs with:

```sh
./bin/mcp-gateway -- /absolute/path/to/mcp-server 2>gateway.log
```

Logs contain full payloads, including any credentials or private data present in MCP messages. There is no redaction or log rotation. A logging or forwarding error stops the gateway and its child. There is no network listener or separate service to start; each MCP client launches its own gateway.

The tests exercise an independent MCP fixture process through initialization, an initialized notification, tool listing, and a tool call, checking that logged messages match the actual traffic. They also cover large messages, exact byte preservation, write failures, child exit codes, and cancellation.

The static research library remains available through the workflow in [RESEARCH.md](RESEARCH.md).
