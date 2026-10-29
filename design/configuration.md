# Configuration

`gateway init-demo` is the executable configuration example. It creates `gateway.json`, `bundle.json`, `bundle.sig`, `policy-private.key` and `demo.env` under a new private directory. Paths in `gateway.json` resolve relative to that file. Protect the whole directory; never commit it. Rotate or replace the demo before real integration.

The bundle signature is base64 Ed25519 over the **exact bundle file bytes**, including whitespace and the final newline. The configured public key is a base64 32-byte Ed25519 key. The application computes a SHA-256 digest of exact signed bytes after verification. Its effective enforcement digest additionally binds the configured principal/entitlement map and credential token hashes. Authority changes or token rotation invalidate existing workflows and pending approvals even when the signed bundle is unchanged. Neither digest is accepted from clients. Raw token values are never emitted. A policy signature key must be administered separately from agents and backend servers. The startup configuration itself is operator-trusted and must be protected; replacing its public key replaces the trust root.

To sign a reviewed bundle using the generated raw 64-byte private key, use your offline signing workflow or an Ed25519 library. The runtime does not load the private signing key. Demo expiry is 24 hours and workflow lifetime is one hour. Editing a bundle without signing it fails closed. Production signing, review separation and emergency key distribution are deployment responsibilities.

Each credential names an environment variable and binds its bearer value to one configured principal. Host and agent tokens can bind to the same tenant/user/workload while having different roles. An independent reviewer must have a different user subject and explicit tool, resource, destination and clearance entitlements. Tokens are opaque gateway-specific secrets; none is sent downstream. Use random values of at least 32 characters. The persistent audit key must decode to at least 32 random bytes from base64 and remain stable across restarts.

The reference supports one tenant. Every principal, tool instance and workflow in that tenant shares a conservative exposure domain. No endpoint allows a caller to supply a user identity, arbitrary task contract, exposure label, domain ID or quota reset. Template selection is trusted-host activity. Template initial labels must cover user input, attachments, memory and all other host context; use `restricted` if provenance is unavailable.

Tool manifests pin an approved logical server, an operator-asserted deployment digest, endpoint, upstream tool name, effect, dedicated credential environment variable, resource argument and exact resource allowlist, destination, source exposure floor, maximum argument exposure, input/output schemas and released fields. Effects are `read`, `write` or `external`. Unknown effects are rejected. There is no general-purpose shell, SQL or arbitrary URL adapter.

Schemas are inline JSON Schema 2020-12. Input objects must deny additional properties; output release objects are closed and typed recursively. External references and schema identifiers are rejected to prevent validation-triggered network access. The response gate projects explicit top-level fields and validates the representation before release; it preserves conservative exposure and does not declassify data.

Use HTTPS endpoints, except explicit `127.0.0.1`/`::1` HTTP for local testing. The executor resolves and captures endpoint IPs at startup and dials only those addresses, retaining TLS hostname verification. Rotate a service address through a controlled restart. No redirect, environment proxy, upstream SSE or compression is followed. Configured private destinations are operator authority; these checks do not replace deployment egress rules.

A status endpoint returns a bounded authenticated JSON object of the form:

```json
{"outcome":"SUCCEEDED","result":{"resultType":"complete","content":[],"structuredContent":{"period":"2026-09","department":"Engineering","total":120000,"variance":5000},"isError":false}}
```

The allowed outcomes are `SUCCEEDED`, `FAILED` and `UNKNOWN`. Only an independently authoritative resource may assert a known result. `FAILED` must establish the operation did not happen and cannot later happen; an absent ID, timeout or server error cannot establish that. No status endpoint means uncertainty remains closed. `X-Gateway-Operation-ID` identifies the effect at the resource. This reference does not claim exactly-once effects for arbitrary remote services.
