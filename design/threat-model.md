# Threat model

## Protected effects

The gateway governs only supported requests and results crossing its authenticated interface. It aims to prevent an operation outside the accepted scope from being dispatched, prevent release before a durable decision, preserve conservative workflow exposure and withhold a duplicate effect after uncertainty. Resource-side effects and released bytes, rather than model explanations, are the test oracle.

The agent may choose arbitrary tool names, arguments, ordering, parallelism, retries, forged IDs and metadata. A backend may supply malicious descriptions, text, structured values, errors, oversized content, continuations or redirects. Endpoints may collude. The gateway does not treat authentication as general permission, hints as verified effects or a valid schema as factual truth.

## Trusted components

Operator configuration and signing-key distribution; principal issuance and entitlements; trusted host task intake and model-provider approval; gateway code and dependencies; SQLite integrity and durable storage; the audit key; TLS/DNS pin setup; the independently authoritative status service; resource-side credential enforcement; and any deployment-provided network/filesystem/sandbox restrictions.

A compromised remote server can misuse authority it already owns. Traffic inspection cannot reveal a hidden write whose observable response matches a legitimate read. A manifest digest is not attestation of remotely running bytes. The reference mock demonstrates separated credential scope at a trusted resource, not containment of arbitrary malicious local software.

The host may have unseen sensitive context or bypass routes. Templates default conservatively, but a gateway cannot infer complete provenance from a flat request. The operator must mediate all protected paths and classify all host context. Starting another network connection or workflow does not clear shared labels; using another uncontrolled application is outside the boundary.

## Remaining limitations

Approved strings can carry prompt injection or misleading information. Projection removes unapproved fields and protocol escape channels; it cannot establish semantic safety or truth. Independent aggregate reconciliation is required before high-impact use of real financial output. No model-based detector is used as an authorisation oracle.

Denial-of-service, incorrect operator policy, malicious independent reviewers, privileged database modification and unseen resource effects remain deployment risks. Integrity labels record untrusted provenance; they do not measure probability of correctness. A local HMAC chain requires an external trusted head to detect rollback/truncation. No autonomous repair, declassification, data export or cross-tenant sharing path is enabled.

A successful test suite is evidence about the included synthetic scenarios, not a certification or a measured guarantee against every adaptive attacker.
