# Zero Trust MCP Gateway

Research and practical references for a zero-trust MCP gateway that enforces security policies at tool boundaries and coordinates corrective interventions throughout agent execution.

This repository currently contains the research library; the gateway implementation has not started.

## Reading on an iPhone

Read the published library in Safari or any browser: [Zero Trust MCP Gateway reading library](https://kolygri.github.io/zero-trust-mcp-gateway-reading/).

Open the [HTML reading library](docs/index.html) in a browser. It includes one page per resource, large adjustable text, a single-column layout, dark mode, and previous/next navigation. No build tools, account or JavaScript are required to read the pages.

The supplied research notes are preserved as written; the added Policies on Paths entry is a source-based summary. Where redistribution permission is established and source text is available, the reader also includes the original text with attribution. Each paper has an original-PDF viewer with page selection, zoom and panning, so diagrams, formulas and tables keep their published layout. MathML formulas in HTML copies retain mathematical structure and scroll independently when wider than the screen. GitHub's file view shows HTML source rather than rendering the reader.

The original PDFs for SAMOS, Task Shield, Governance by Construction, and Policies on Paths are included under CC BY 4.0 and work offline, including through `file://` pages. AgentTrust loads its PDF directly from arXiv. MDPI and IEEE may refuse in-page loading or require publisher access; their reader pages always provide links to the original paper and PDF. The viewer shows an explicit error if a remote source cannot load. JavaScript is required for the in-page PDF viewer; the original PDF links and reflowed text remain available without it.

To read on an iPhone over the same trusted Wi-Fi network, start a local server from the repository folder:

```sh
python3 -m http.server 8000 --bind 0.0.0.0 --directory docs
```

In iPhone Safari, open `http://<your-Mac-local-IP>:8000`. The files in `docs` are served to devices that can reach your Mac; stop the server with Ctrl-C when finished.

## Published website

The public [reading-site repository](https://github.com/kolygri/zero-trust-mcp-gateway-reading) contains a snapshot of `docs/`. GitHub Pages serves its `main` branch from the repository root. The gateway project repository remains private. The `.nojekyll` file publishes the HTML, PDF and JavaScript assets directly.

To update the website, rebuild the library here, copy the contents of `docs/` into the reading-site checkout, then commit and push that repository's `main` branch. Publishing the snapshot is a separate step from pushing this source repository.

## 1. The research most relevant to the gateway

Descriptions below preserve the supplied research notes, except the source-based summary of the newly added Policies on Paths paper. Relevance ratings are editorial judgements; reported results belong to each paper's evaluation, not this project.

### 1. [SAMOS — Securing MCP-based Agent Workflows](https://research.ibm.com/publications/securing-mcp-based-agent-workflows)

IBM Research · SOSP 2025 workshop

SAMOS enforces information-flow policies at the MCP gateway, tracks session-level context, and blocks tool interactions that violate security constraints. A particularly close match to your gateway-level control concept.

**Focus:** Cross-tool information flow and session-aware enforcement.

**Relevance:** Very close · [iPhone reading page](docs/resources/samos.html)

### 2. [Governance by Construction for Generalist Agents](https://doi.org/10.1145/3786335.3813192)

ACM · 2026

IBM's CUGA governance approach intervenes at five checkpoints: intent, planning guidance, tool calls, approval and output. Unlike a gateway that simply rejects unsafe operations, it also steers agents towards compliant behaviour.

**Focus:** Runtime intervention across the agent lifecycle.

**Relevance:** Very close · [iPhone reading page](docs/resources/governance-by-construction.html)

### 3. [AgentTrust — Runtime Safety Evaluation and Interception](https://arxiv.org/abs/2605.04785)

Research preprint · May 2026

Intercepts actions before execution, detects risky multistep sequences, and can suggest safer alternatives through its SafeFix mechanism.

**Focus:** Correcting dangerous tool calls, not merely blocking them.

**Relevance:** Very close · [iPhone reading page](docs/resources/agenttrust.html)

### 4. [Runtime Policy Enforcement for MCP-Based LLM Agents](https://www.mdpi.com/2079-9292/15/13/2829)

Electronics · June 2026

Implements deterministic enforcement at the tool-call boundary with cross-step sensitivity labels and tamper-evident audit records. The reported attack success rate fell from 40% to 5% in a controlled evaluation.

**Focus:** Deterministic enforcement independent of agent reasoning.

**Relevance:** Close · [iPhone reading page](docs/resources/runtime-policy-enforcement.html)

### 5. [The Task Shield — Enforcing Task Alignment](https://aclanthology.org/2025.acl-long.1435/)

ACL 2025

Tests whether instructions and tool calls genuinely contribute to the user's original objectives. This is particularly relevant to stopping an agent from drifting away from an authorized task.

**Focus:** Aligning execution with original user intent.

**Relevance:** Close · [iPhone reading page](docs/resources/task-shield.html)

### 6. [ZT-MCP — A Zero-Trust Security Architecture](https://ieeexplore.ieee.org/abstract/document/11715596)

IEEE COINS · September 2026

Combines tool identity verification, capability-based authorization, output filtering and audit logging. This is the most directly named Zero Trust MCP architecture I found.

**Focus:** Protocol-level trust boundaries and enforcement.

**Relevance:** Close · [iPhone reading page](docs/resources/zt-mcp-research.html)

### 7. [Runtime Governance for AI Agents: Policies on Paths](https://arxiv.org/abs/2603.16586)

arXiv preprint · March 2026

Formalizes runtime governance as a policy function over agent identity, the partial execution path, a proposed next action and organizational state. Explains why path-dependent rules require runtime checks, and discusses deployment designs and a reference implementation.

**Focus:** Path-dependent policies and per-action intervention across an execution history.

**Relevance:** Very close · [iPhone reading page](docs/resources/policies-on-paths.html)

### Working research hypothesis

These works collectively establish that your idea is technically credible. They also suggest that the novelty probably won't lie in introducing a gateway or adding policy checks. It will need to lie in how the gateway coordinates corrective interventions throughout execution.

## 2. Existing implementations worth studying

These are practical starting points for a prototype, rather than just theoretical references.

| Project | Existing capabilities | What to investigate | Reader |
| --- | --- | --- | --- |
| [Agentgateway](https://github.com/agentgateway/agentgateway) | MCP routing, identity and policy enforcement | Native MCP request/response mutation through ExtMCP | [Read](docs/resources/agentgateway.html) |
| [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | Agent identity, runtime governance, policy, execution validation and audit | Controlling agent actions as well as tool access | [Read](docs/resources/microsoft-agent-governance-toolkit.html) |
| [ZT-MCP](https://github.com/sarmishra/ZT-MCP-Project) | Identity verification, capability-based access controls, output filtering | Building a formal Zero Trust model | [Read](docs/resources/zt-mcp-implementation.html) |
| [ClawGuard](https://github.com/Claw-Guard/ClawGuard) | Task-specific constraints and pre-execution interception | Grounding permissions in the user's original request | [Read](docs/resources/clawguard.html) |
| [Uber MCP Gateway](https://www.uber.com/us/en/blog/designing-mcp-gateway/) | Centralized authorization, PII redaction, server registry, protocol translation | Enterprise architecture at scale | [Read](docs/resources/uber-mcp-gateway.html) |

## Source copies and attribution

Source links checked on 27 October 2026. The descriptions above preserve the supplied notes; link checking is not an independent reproduction of the research findings.

| Resource | Local reading content | Source / licence |
| --- | --- | --- |
| SAMOS — Securing MCP-based Agent Workflows | PDF text + original pages | [Source version](https://www.ntousakis.com/pacmi-25.pdf) · [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |
| Governance by Construction for Generalist Agents | Full preprint text | [Source version](https://arxiv.org/html/2605.20874v1) · [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |
| AgentTrust — Runtime Safety Evaluation and Interception | Supplied notes + live original-PDF viewer | The linked arXiv version uses arXiv's non-exclusive distribution licence, which does not grant this repository permission to redistribute the complete paper. Use the original HTML for the full text. |
| Runtime Policy Enforcement for MCP-Based LLM Agents | Supplied notes + live original-PDF viewer | The publisher blocked automated full-text retrieval during preparation, so no complete article is included locally. Read the original for the evaluation setup and limitations. |
| The Task Shield — Enforcing Task Alignment | PDF text + original pages | [Source version](https://aclanthology.org/2025.acl-long.1435.pdf) · [CC BY 4.0](https://aclanthology.org/faq/copyright/) |
| ZT-MCP — A Zero-Trust Security Architecture | Supplied notes + live original-PDF viewer | A redistribution licence for the complete IEEE paper has not been established. The reference implementation is listed separately. |
| Runtime Governance for AI Agents: Policies on Paths | Full preprint with MathML | [Source version](https://arxiv.org/html/2603.16586v1) · [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |
| Agentgateway | Full README | [Source version](https://github.com/agentgateway/agentgateway/blob/main/README.md) · [Apache-2.0](docs/licenses/agentgateway.txt) |
| Microsoft Agent Governance Toolkit | Full README | [Source version](https://github.com/microsoft/agent-governance-toolkit/blob/main/README.md) · [MIT](docs/licenses/microsoft-agent-governance-toolkit.txt) |
| ZT-MCP | Full README | [Source version](https://github.com/sarmishra/ZT-MCP-Project/blob/main/README.md) · [MIT](docs/licenses/zt-mcp-implementation.txt) |
| ClawGuard | Supplied notes + original link | The upstream README advertises MIT, but its linked LICENSE file returned 404 during preparation. The complete README is linked at its source pending clarification of the licence notice. |
| Uber MCP Gateway | Supplied notes + original link | A redistribution licence for the complete article has not been established. Read the original article for its architecture and diagrams. |

Third-party source copies retain their upstream licences; inclusion does not imply endorsement. Original project READMEs are reading material, and their commands are not automatically executed. The PDF viewer uses a bundled copy of Mozilla PDF.js; its version, build instructions, and licence are in `docs/assets/vendor/pdfjs/README.md`.

## Updating the library

Edit `docs/resources.json` for the supplied notes and metadata. Licensed reading snapshots live in `docs/sources/`, with applicable licence notices in `docs/licenses/`. Unmodified licensed PDFs live in `docs/assets/papers/`; the build also creates classic-script data copies so the viewer works through `file://` without cross-origin fetches or workers. Rebuild the README and reading pages using Python's standard library:

```sh
python3 scripts/build_reading.py
```

The build uses checked-in snapshots and does not fetch or execute anything from upstream sources.
