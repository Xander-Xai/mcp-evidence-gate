# OpenAI Codex for Open Source application

Prepared: 2026-09-11

Governance reference: `yandexuanxuan/AI-Native-Work-Learning-OS@12a961249b8eb264a1595df20ec5ef37385dfc16`
Evidence rule: every claim below is tied to a repository fact or a public GitHub record. The audit baseline is frozen before this documentation commit; the final commit SHA is reported separately in the delivery audit.

## A. Application snapshot

| Field | Value |
| --- | --- |
| Repository | `yandexuanxuan/mcp-evidence-gate` |
| Role | Experimental downstream verifier and release-admission controller for evidence-scoped MCP security receipts |
| Primary maintainer | `@yandexuanxuan` (repository owner, sole listed contributor, and Action author) |
| Exact HEAD | `eb73c152b53e376d0bb7dd55b2948d0f62bfcc39` (audit baseline before this docs change) |
| Latest release | `v0.1.0-alpha.3` (prerelease), tag commit `d404b38f0ac0303438b561fe7358b0eec487c962` |
| Last meaningful maintenance | 2026-09-03T13:26:55+08:00 (`docs: refresh Registry #1404 custody evidence methodology`) |
| GitHub signals at audit | 0 stars, 0 forks, 0 open issues, 0 open PRs |
| Project status | Experimental downstream implementation; not an official MCP project; no Registry-adoption claim |
| Application readiness | `PASS` for truthful submission; third-party adoption is explicitly `NOT_VERIFIED` |

## B. Why this repository qualifies

I am the primary maintainer of `yandexuanxuan/mcp-evidence-gate`, an experimental verifier for MCP security receipts. It binds receipts to exact artifacts, checks freshness and scope, and applies deterministic release policy through a CLI and Node 24 GitHub Action. The repository has three alpha prereleases, 68 passing Vitest tests, an 11-case cross-repository dogfood matrix, and Trivy/OSV producer-consumer runs. I participate in Registry #1404 and mcp-use validation without claiming adoption.

## C. How API credits will be used

I would use Codex to review pull requests and security-sensitive changes, triage issues, generate regression tests, monitor schema drift in the pinned Registry profile, maintain compatibility profiles, audit release evidence, and automate routine maintenance. Codex would be assistive: security and release conclusions remain grounded in deterministic tests, exact-head checks, runtime receipts, and human-verifiable evidence. It will not replace maintainer judgment or scanner results.

## D. Anything else we should know?

This is an experimental downstream implementation, not an official MCP project, and I make no Registry-adoption or broad-usage claim. Registry #1404 is an open, unmerged proposal; a proposal-author gave a positive discussion signal about my consumer invariants, not approval. mcp-use #2332 led to a maintainer-recommended fork-first experiment against `mcp-use@2.3.3`. My #2375 contribution received automated review, and its reported findings were addressed, then the PR was closed unmerged by the maintainer because `WARNING` semantics remain unresolved in conformance #430. I continue maintaining the verifier, Action, CLI, profiles, tests, dogfood, and producer integrations.

## Evidence links used by the application

- [Primary repository](https://github.com/yandexuanxuan/mcp-evidence-gate), [releases](https://github.com/yandexuanxuan/mcp-evidence-gate/releases), and [CI](https://github.com/yandexuanxuan/mcp-evidence-gate/actions).
- [Dogfood repository](https://github.com/yandexuanxuan/mcp-evidence-gate-dogfood) and its [latest deterministic matrix run](https://github.com/yandexuanxuan/mcp-evidence-gate-dogfood/actions/runs/33461301620).
- [Registry proposal #1404](https://github.com/modelcontextprotocol/registry/pull/1404), [mcp-use #2332](https://github.com/mcp-use/mcp-use/issues/2332), [mcp-use #2375](https://github.com/mcp-use/mcp-use/pull/2375), and [conformance #430](https://github.com/modelcontextprotocol/conformance/issues/430).
