# Contributing

Start with the threat model and invariants in `design/`. Keep the evaluator pure, treat both endpoints as untrusted, and keep authentication independent of tool content. New protocol methods or payload types need explicit policy coverage and adversarial tests before they may forward anything.

Use Go 1.27.3 or later. Run `make test check build`. Add regression tests that observe resource invocation or released bytes, rather than only checking a denial string. Do not add real personal data, credentials, private documents, generated state or binaries.

Use conventional commit categories (`feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `build`). Describe the affected invariant, validation and limitations in a pull request. Security reports follow `SECURITY.md`.

Changes to the existing reading website, personal website, Pages, domains or DNS require the owner's specific permission; see `AGENTS.md`.
