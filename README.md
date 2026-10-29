# Zero Trust MCP Gateway

A Go reference implementation of a stateful security boundary between an untrusted AI agent and approved MCP tools. Each operation receives deterministic policy checks, a durable dispatch record and a response release decision. A rejected call, pending approval or uncertain write never becomes permission to execute.

**Status: experimental reference release.** Suitable for local evaluation and integration research. This is a single-tenant SQLite implementation, not a production isolation platform or a guarantee of general agent safety.

## Why Go

Go offers explicit concurrency, a mature HTTP and cryptography standard library, race detection, and small deployable binaries. The pure policy evaluator is independent of the network and database. Dependencies are limited to SQLite and JSON Schema validation plus their transitive modules. The data plane runs inside the customer's boundary; no model or vendor service is required.

## Run the synthetic demonstration

Requires **Go 1.27.3 or later**, Python 3 for the walkthrough, and macOS or Linux. The demo uses invented payroll aggregates, never personal data.

```sh
make build
./bin/gateway init-demo
```

`init-demo` creates a new private `.local/` directory containing an Ed25519-signed policy, configuration and random credentials. It refuses to overwrite an existing directory. The demo bundle expires after 24 hours. Keep `.local/` out of source control; its private signing key is for this demonstration only.

In one terminal:

```sh
source .local/demo.env
./bin/mock-resource -listen 127.0.0.1:8091 -state .local/resource.json
```

In another terminal:

```sh
source .local/demo.env
./bin/gateway -config .local/gateway.json
```

In a third terminal, exercise the trusted host, agent and independent reviewer:

```sh
source .local/demo.env
python3 scripts/demo.py
```

The walkthrough creates an authorised workflow, reads projected aggregates, verifies that extra arguments are denied, requests approval for a publish, approves through a separate identity, and resumes the **same operation**. It then verifies that replay does not perform another write and checks the audit chain. To run the complete scenario with temporary state and subprocess cleanup:

```sh
python3 scripts/smoke.py
```

The mock resource has distinct read and publish credentials and checks scope independently. It provides durable operation receipts and refuses read-token publication. It is a trusted test resource; it does not sandbox arbitrary tool code.

## What is implemented

- Operator-approved tool catalog and task templates in an Ed25519-signed, expiring policy bundle. No automatic discovery approval.
- Distinct trusted-host, agent and independent reviewer roles. Gateway bearer secrets map to configured tenant, user and workload identities; caller-supplied identity fields grant no authority.
- Strict bounded JSON, duplicate-key and Unicode ambiguity rejection, closed input schemas, canonical request bindings using HMAC, mirrored routing-header checks, and default denial of unsupported methods.
- Durable workflows, tenant-wide sticky confidentiality and integrity labels, an atomic execution slot, conservative shared call budget and single-use approvals. Opening a fresh workflow does not reset exposure or quota.
- Separate reservation, one-time dispatch claim, known/unknown execution outcome and response-release state. Network uncertainty blocks dependent work until authoritative reconciliation; it never triggers an automatic write retry.
- Bounded whole-result quarantine, structured output validation and field projection. Raw text, links, metadata and unsupported payload types are not forwarded; displayed text is regenerated from approved structured fields.
- Dedicated backend credentials, fixed endpoints, startup DNS pinning, redirect/proxy/decompression rejection, deadlines and response limits.
- Transactional metadata-only HMAC audit chain with an export and verification API. No raw arguments or response payloads in audit events; operation arguments remain sensitive database state.

## Protocol and API

The narrow adapter targets **MCP 2026-07-28 over Streamable HTTP**, with JSON responses only. It supports `server/discover`, `ping`, `tools/list` and `tools/call`. It requires per-request protocol metadata and matching `MCP-Protocol-Version`, `Mcp-Method` and (for a call) `Mcp-Name`. Clients must advertise both JSON and SSE acceptance; the gateway selects JSON. See [protocol support](design/protocol.md) for exact fields and exclusions.

| Endpoint | Actor | Purpose |
| --- | --- | --- |
| `POST /v1/workflows` | Trusted host | Instantiate a configured task template |
| `GET /v1/workflows/{id}` | Bound host or agent | Inspect current shared exposure and workflow scope |
| `POST /v1/workflows/{id}/operations` | Bound agent | Obtain an immutable operation reference before dispatch |
| `POST /mcp` | Bound agent | Discover approved tools and request exact operations |
| `GET /v1/operations/{id}` | Bound caller or entitled reviewer | Inspect status and trusted approval display fields |
| `POST /v1/operations/{id}/approve` | Independent entitled reviewer | Approve one exact pending request |
| `POST /v1/operations/{id}/reconcile` | Independent entitled reviewer | Query resource evidence; never redispatch |
| `GET /v1/audit` | Administrator | Verify and export metadata audit events |
| `GET /healthz` | Anyone | Process liveness only; not a policy-readiness guarantee |

The data plane requires `X-Gateway-Workflow-ID`. Writes and external effects require operation precreation through the control API, retaining the ID before dispatch. A call or resumed request supplies the gateway-issued `X-Gateway-Operation-ID` and **identical tool and arguments**. The gateway never uses a JSON-RPC transport ID as authority. Released payloads are not stored or replayed: a repeat returns status without new result bytes. A caller must inspect an interrupted operation before proposing another effect.

Approval and reconciliation take an empty JSON object. Review the operation's actor, arguments, destination, effect, deployment digest, release fields, request digest and expiry first. An approval cannot override a hard denial, expiry, reduced current entitlement or information-flow restriction.

## Configuration and deployment boundary

See [architecture and invariants](design/architecture.md), [configuration](design/configuration.md), [threat model](design/threat-model.md), [evaluation](design/evaluation.md), and [SECURITY.md](SECURITY.md).

The reference authentication profile uses locally configured, audience-specific opaque bearer credentials. It does **not** implement OAuth/OIDC, token exchange or delegation. Use an appropriate trusted identity adapter before integrating a real identity provider. Deploy TLS for any non-loopback listener; all requests with an unapproved Origin are rejected. Secrets are loaded from environment variables and never copied from client headers to a tool.

All workflows in one tenant intentionally share an exposure domain and execution slot, covering shared tool memory. Templates initialise exposure conservatively; the demo starts at `restricted` with untrusted integrity. The host, its model provider, database, policy administration and resource-status service are trusted components. Host and resource egress restrictions must be enforced by your deployment. HTTP endpoint pinning is not a tool sandbox.

## Development

```sh
make test       # unit, adversarial and concurrency tests with the race detector
make check      # vet and module checksum verification
make build      # gateway and synthetic resource binaries
```

Tests cover policy precedence, strict parsing, resource credential separation, quarantine, atomic approval consumption, concurrent store handles, sticky labels, lost replies and restart/reconciliation. [Evaluation notes](design/evaluation.md) distinguish these checks from a benchmark or proof. No claims of attack-success percentages or real-world payroll correctness are made.

## Limits and roadmap

The release implements the core local mediation, state, approval and recovery path from *Zero Trust Gateways for AI Agents*, version 1.0 (29 October 2026). It deliberately rejects stdio/legacy MCP, SSE upstreams, binary content, resource/prompt APIs, notifications, subscriptions, MRTR continuations, arbitrary execution and schema references requiring network access. Structured refusals support a fresh proposal, but no autonomous repair advisor or `PROPOSE_REVISION` execution path is enabled.

PostgreSQL/replicated coordination, protected value lineage, resource fencing for real services, independently anchored audit checkpoints, remote revocation distribution, sandbox lifecycle management, an identity-provider adapter and independent domain reconciliation are future work. Policy updates currently require a controlled restart; no hot reload or immediate remote revocation guarantee is claimed. See the design documents before adapting the reference to sensitive data.

## Diagnostic stdio relay

The existing `cmd/mcp-gateway` executable is preserved as a transparent logging relay; see [GATEWAY.md](GATEWAY.md). It forwards bytes unchanged and logs full payloads. Use `cmd/gateway` for the enforcing HTTP boundary described here. The diagnostic relay is outside that security boundary and must not provide a bypass to protected resources.

## Research library and licence

The original reading collection is preserved in [RESEARCH.md](RESEARCH.md) and [docs/](docs/). Its separate [Sites reading address](https://zero-trust-mcp-reading.k-l-grigorov.chatgpt.site/) is unchanged. Building or running the gateway does not deploy a website or enable GitHub Pages.

Original source: [Apache-2.0](LICENSE). Third-party papers, source snapshots and PDF.js retain the licences recorded in [NOTICE](NOTICE), [RESEARCH.md](RESEARCH.md) and their local notices. Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
