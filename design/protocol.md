# Supported protocol profile

Pinned revision: [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28). The implementation directly handles a small adapter rather than relying on an SDK that may use older initialization/session semantics. It does not claim full MCP conformance.

`POST /mcp` accepts one JSON-RPC 2.0 request object with a non-null string or safe integer ID. Requests must include:

```http
Authorization: Bearer <gateway-agent-token>
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: payroll.read
X-Gateway-Workflow-ID: <gateway-issued-workflow-id>
```

```json
{
  "jsonrpc":"2.0",
  "id":1,
  "method":"tools/call",
  "params":{
    "_meta":{
      "io.modelcontextprotocol/protocolVersion":"2026-07-28",
      "io.modelcontextprotocol/clientCapabilities":{}
    },
    "name":"payroll.read",
    "arguments":{"resource":"payroll:2026-09"}
  }
}
```

`tools/list`, `server/discover` and `ping` use matching `Mcp-Method`, omit `Mcp-Name` and include `_meta`. `tools/list` requires a bound workflow; `ping` and `server/discover` do not. Lists are built from approved operator metadata, never untrusted backend descriptions. Listed tools still require per-call checks, and exposure or quota can deny a subsequent call.

The server sends a single bounded JSON response, never an SSE prefix. Upstreams must also return bounded JSON. Per-request metadata is regenerated downstream. Client bearer tokens and self-reported client information are never used as backend authority.

| Feature | Behavior |
| --- | --- |
| `tools/list`, `tools/call`, `ping`, `server/discover` | Supported narrow shapes |
| `initialize`, legacy sessions or older revisions | Rejected |
| Unknown methods, extensions and client notifications | Rejected |
| Resources, prompts, subscriptions and change streams | Rejected |
| MRTR, input responses, request state, sampling or elicitation | Rejected; independent approval uses the control API |
| SSE upstreams, binary/image/audio/resource payloads and links | Quarantined or execution remains unknown, never forwarded |
| Batches, duplicate keys, ambiguous Unicode, excessive nesting | Rejected before evaluation |
| Header/body method, name or version mismatch | Rejected before dispatch |
| Unapproved Origin | HTTP 403 |

The application caps request bodies at 1 MiB, JSON depth at the parser's documented bound, header bytes at 16 KiB, simultaneous HTTP handlers at 32, backend calls at 10 seconds and manifest result bodies at no more than 16 MiB. Compressed bodies are rejected. Proxy/load-balancer settings must not introduce automatic effect retries.

Writes and external effects require `POST /v1/workflows/{id}/operations` with `{ "tool": "report.publish", "arguments": { ... } }` before the MCP call. Retain its returned `id` and supply it as `X-Gateway-Operation-ID` with identical arguments. This control operation creates no dispatch authority.

The implementation does not claim full protocol conformance or every optional capability. Unsupported features close the forwarding path rather than being proxied opaquely. Clients designed exclusively for MCP 2025 initialization are not compatible with this profile.
