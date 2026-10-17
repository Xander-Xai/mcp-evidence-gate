# Project evidence

This page records reproducible engineering evidence and explicit claim boundaries for `mcp-evidence-gate`. It is project documentation, not an application, endorsement dossier, or adoption claim.

## Scope

`mcp-evidence-gate` is an experimental downstream verifier and release admission controller for evidence-scoped MCP security scan receipts. It is not an official MCP project, an MCP Registry implementation, or a scanner. It separates scanner verdict, evidence validity, release policy, and server safety.

## Reproducible evidence

- The repository contains the `verify` and `verify-set` CLI paths and a self-contained Node 24 GitHub Action.
- The project includes pinned compatibility profiles, structural receipt validation, artifact/evidence digest binding, freshness and scope checks, and deterministic policy evaluation.
- The companion dogfood repository records cross-repository Action acceptance cases, including Trivy, OSV, multi-receipt composition, and OCI identity workflows. These are project-owned acceptance evidence, not third-party adoption.
- The companion Trivy producer repository supplies scanner-specific receipts while the consumer retains ownership of admission policy.
- Profile-drift checks keep compatibility behavior explicit and reviewable when upstream contracts change.

## External discussion record

Discussion signals are recorded here as dated, attributable events. None of them is a
maintainer review, an upstream merge, a schema acceptance, or a third-party adoption.
All timestamps are UTC and were read from the GitHub API during the audit.

| Date | Source | Participant | Association | Substance |
| --- | --- | --- | --- | --- |
| 2026-06-29 | registry#1404 (open) | `eeee2345` | PR author | Opened the optional `security-scan` receipt `_meta` extension (v1) that resolves registry#1273. |
| 2026-06-29 | registry#1404 | `JinNing6`, `HarperZ9` | none | Endorsed the digest-binding plus non-empty `scan_scope` invariant and the first-class `inconclusive` reason; `HarperZ9` closed their own competing #1405 to keep review in one place. |
| 2026-08-26 | mcp-use#2332 (closed) | `khandrew1` | none | Replied "it would be better for you to just test it in a fork of your own"; redirected the project to a self-run fork trial. |
| 2026-08-26 | chrome-devtools-mcp#2616 (closed) | `OrKoN` | none | Replied "we do not plan to include this right now"; explicit decline. |
| 2026-08-27 to 2026-09-03 | registry#1404 | `Nikolife2016` | `CONTRIBUTOR` | Raised name/provenance custody drift: a byte-identical artifact can change hands without invalidating a digest-bound `clean` receipt. Published per-type corrections and a frozen deposit. |
| 2026-09-15 to 2026-09-18 | registry#1404 | `ciceroyang` | none | Raised the scanner-crash failure mode (`AgentAuditKit` 0.6.5 reporting a crash as a clean scan, sattyamjjain/agent-audit-kit#743) and specified a completeness record that travels with the receipt. |

### Feedback that produced a code change

`ciceroyang` asked for four specific properties. Each is implemented in project-owned
code outside the Registry v1 receipt shape and covered by tests:

| Asked for | Implementation | Test |
| --- | --- | --- |
| The completion set must travel with the receipt, not as free-text `scan_scope`. | `src/core/scanner-execution.ts` derives `required`/`completed`/`failed` component roll-ups and recomputes them from the detached evidence snapshot instead of trusting the declared status. | `tests/scanner-completeness.test.ts`, `tests/sbom-schema-qualification.test.ts` |
| `incomplete` must not be able to coexist with `clean`. | `clean` is eligible only when every required component completed; a parseable report with `Results: []` is classified `trivy_result_sections_missing`. | dogfood `scripts/build_scanner_completeness_cases.py` cases `incomplete-zero-findings`, `producer-results-empty`, `failed-zero-findings` |
| Digest mismatch must become `inconclusive`, not `clean`. | Digest mismatch marks execution evidence unverified and the admission inconclusive; the scanner verdict is never rewritten. | `tests/scanner-completeness.test.ts` "keeps a tampered execution inconclusive rather than trusting its semantic status"; dogfood case `tampered-evidence` |
| An unknown `status`/`state`/`semantic_consistency` must be treated as unmeasured, never as pass. | Unknown enum values are rejected structurally; a self-declared `complete` that contradicts its own components is `scanner_execution_contradictory`. | dogfood cases `malformed-completeness`, `contradictory-complete`, `missing-completeness` |

### What the external implementations are, and are not

- `ciceroyang` published `ciceroyang/agentgate/docs/spec/scan-execution-v1.md` and states in
  that document that the field names were "borrowed from the shape discussed in
  `modelcontextprotocol/registry#1404`". A GitHub code search for `mcp-evidence-gate` across
  `ciceroyang/agentgate` and `ciceroyang/mcp-supply-audit` returns 0 matches. That makes the
  record a design reference to the proposed receipt shape and independent feedback, and it is
  **not** a reproduction of this project's code.
- The mcp-use fork trial reported in mcp-use#2332 was executed and reported by this project in
  its own fork. It is self-reported evidence, not third-party execution.
- Repository counters at the audit date were 0 stars and 0 forks on all three project
  repositories, and the only published releases are the pre-releases `v0.1.0-alpha.1` through
  `v0.1.0-alpha.3`. Stars, forks, and discussion activity were not treated as adoption evidence.

### Upstream state observed during the audit

- registry#1404 was `open` and unmerged, with `reviewDecision: REVIEW_REQUIRED`,
  `mergeStateStatus: BLOCKED`, 0 formal reviews, and 0 review comments. No comment on the
  thread carries a `MEMBER` or `OWNER` author association.
- The PR head advanced from `20747d32` to `9c9b76e1` during the audit. The live profile-drift
  sentinel reported `NON_CONTRACT_CHANGE` with an unchanged contract digest and
  `safe_to_continue_with_pinned_profile: true`.

### Limitations of the external signals

- `ciceroyang` and `Nikolife2016` publish their own measurements; this project did not
  re-derive their numbers and does not restate them as verified.
- The live profile-drift sentinel reads `GITHUB_TOKEN` or `GH_TOKEN`. Without a token it
  receives the shared unauthenticated GitHub rate limit and fails closed with
  `status: UNKNOWN` and `STOP_AND_INVESTIGATE_SENTINEL_FAILURE`. That is intended
  fail-closed behaviour, but it means the live check is not reproducible from an
  unauthenticated environment.
- The completeness contract is project-defined and deliberately not proposed into Registry
  v1. It carries no upstream standing while registry#1404 remains unmerged.

## Ecosystem boundaries

- Registry proposal #1404 is open and unmerged, with no formal maintainer review recorded on
  the thread. Discussion signals are not maintainer approval, schema acceptance, endorsement, or
  Registry adoption.
- The mcp-use fork-first validation, the self-reported fork trial, and the closed, unmerged
  pull request are interaction history, not upstream adoption or accepted contribution evidence.
- chrome-devtools-mcp#2616 was explicitly declined by the project that opened it.
- Dogfood, forks, issue discussions, and unmerged pull requests must not be counted as verified
  third-party usage.

## Claim boundary

`THIRD_PARTY_ADOPTION = NOT_VERIFIED` for the bounded public search represented here. No statement on this page implies official MCP status, Registry adoption, maintainer approval, broad usage, verified third-party adoption, or production-proven status.

For current test commands and exact repository state, use the repository's checked-in scripts and the commit history rather than treating this summary as a substitute for execution evidence.
