# Evaluation and release checks

The automated suite tests enforcement invariants with synthetic data and instrumented executors/resources. It is not a reproduction of the white paper's proposed experimental programme. It does not report attack-success percentages, model utility, latency percentiles or production readiness.

Core checks include exact principal and manifest binding; default denial; approval after hard rules; duplicate/ambiguous JSON; schema and resource scope; input/output classification; mirrored routing headers; no direct credential pass-through; no redirect/retry forwarding; bounded whole-result quarantine and projection; durable approval consumption; concurrent database handles; unknown outcomes; restart without redispatch; and resource-side read/publish credential separation.

`python3 scripts/smoke.py` runs actual compiled processes, signed policy loading and HTTP requests. It checks useful authorised completion alongside denied arguments, independent approval and one dispatch per logical operation. Its resource state contains a receipt, so a refusal message alone cannot satisfy the duplicate-effect check.

Before a production claim, add independently instrumented hostile servers and deployment bypass tests, crashes at every persistence/dispatch/release boundary, resource fencing under worker death, PostgreSQL replica contention, held-out adversarial tasks, audited host provenance, and independent domain correctness checks. Compare a resource-only baseline and stateless gateway, then correction and isolation ablations. Record versions, policy digests, denominators, repetitions and uncertainty. Successful mock execution is not proof of a real resource's idempotency contract.

Build provenance, remote signing and independently anchored audit checkpoints are not implemented by the local demo. Release workflows build source and run deterministic tests. Operators must assess and establish their own deployment acceptance criteria.
