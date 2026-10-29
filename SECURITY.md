# Security policy

This is an experimental security reference, not a production assurance claim. Supported source is the latest published implementation branch/release only; no long-term maintenance promise is made.

Report suspected vulnerabilities through this repository's **Security → Advisories → Report a vulnerability** interface when available. Do not post credentials, protected data or an exploit against someone else's deployment in a public issue. If private reporting is unavailable, open a minimal issue requesting a private reporting channel without exploit details or sensitive payloads.

Include the commit, Go version, policy semantics and bundle digest, supported transport, minimal synthetic reproduction, expected invariant and observed resource-side effect. Keep raw production databases and tokens out of the report.

## Required operational assumptions

- Protect operator configuration, policy public-key distribution, signing keys, audit HMAC key and database. The local state file contains tool arguments and authority metadata and is not encrypted by this application.
- Ensure the agent cannot bypass the gateway using another MCP route, browser, shell, API or credential. This application cannot configure an arbitrary host's network policy.
- Resource-side credentials must enforce the declared operation and resource scope. A manifest's description, deployment digest or read-only effect is an operator assertion about a remote service, not remote code attestation.
- Independently restrict untrusted tool egress, filesystem access and execution authority. The demo resource is trusted synthetic code, not a sandbox for third-party servers.
- Authorise host/model-provider disclosure for the workflow's maximum data class. Schemas and field projection do not prove the truth of data or remove prompt-injection meaning from approved strings.
- Persist and back up the audit key and SQLite state together. Store audit heads in an independent system if rollback or truncation detection is required. A local HMAC chain alone cannot detect a removed tail without a trusted external head.
- Keep proxy and client write retries disabled. A cancelled request may have executed. Reconcile the existing operation before any new side-effect attempt.
- Approvers are trusted independent actors. Authentication, entitlement and a structured display do not guarantee that a human makes the correct decision.

The application fails closed on missing/stale policy, storage errors, unsupported features, classifier/schema failure, and uncertain execution. Availability and correctness of policy are part of the deployment's trusted computing base.

The diagnostic `cmd/mcp-gateway` stdio relay is preserved for logging only. It does not perform these enforcement checks and logs complete payloads. Do not grant it a bypass route to a resource protected by `cmd/gateway`.
