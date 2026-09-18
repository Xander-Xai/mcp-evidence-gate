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

## Ecosystem boundaries

- Registry proposal #1404 is open and unmerged. Discussion signals are not maintainer approval, schema acceptance, endorsement, or Registry adoption.
- The mcp-use fork-first validation and the closed, unmerged pull request are interaction history, not upstream adoption or accepted contribution evidence.
- Dogfood, forks, issue discussions, and unmerged pull requests must not be counted as verified third-party usage.

## Claim boundary

`THIRD_PARTY_ADOPTION = NOT_VERIFIED` for the bounded public search represented here. No statement on this page implies official MCP status, Registry adoption, maintainer approval, broad usage, verified third-party adoption, or production-proven status.

For current test commands and exact repository state, use the repository's checked-in scripts and the commit history rather than treating this summary as a substitute for execution evidence.
