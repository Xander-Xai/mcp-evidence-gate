# Release Evidence and Claim Boundaries

Audit snapshot: 2026-10-10 (Asia/Shanghai).

## Repository and release state

- Canonical repository: [Xander-Xai/mcp-evidence-gate](https://github.com/Xander-Xai/mcp-evidence-gate).
- Default branch at audit: `main`, HEAD `7c6d7089d25a24ead7a42a3a96319fff2bbeac0a`.
- Published releases: three alpha prereleases; latest is `v0.1.0-alpha.3` (published 2026-08-31). The open SBOM PR #24 is not part of that release.
- Base SBOM admission v1 was merged to `main` by PR #23 on 2026-09-22, after the latest alpha release; it is present on `main` but has not thereby become part of a published release. PR #24 qualifies additional Syft JSON 16.1.10 behavior.
- Only open Core PR at audit: [#24](https://github.com/Xander-Xai/mcp-evidence-gate/pull/24), Syft JSON 16.1.10 qualification. It remains open and unmerged at `bddb49595b69b78eb46903b1f15bc09cf01eec23` after a bounded-read fix was pushed. Fresh CI was pending at report time; the previous head checks were green. No independent review decision was recorded.

## Compatibility source

The verifier pins the experimental `modelcontextprotocol/registry#1404` receipt proposal to `20747d3253ba8638161dd95f1cec70df02993c22`. On 2026-10-10 the proposal remained open and unmerged, with current head `9c9b76e102e43fe8f7bee1ba3e5f4f1c6a9a3ee6`. The live profile-drift check found the source contract hash unchanged from the pin. This establishes compatibility with a pinned proposal snapshot only; it does not establish Registry adoption, formal MCP approval, or official endorsement.

## Dogfood evidence

The companion [Dogfood repository](https://github.com/Xander-Xai/mcp-evidence-gate-dogfood) is a project-owned integration/acceptance suite. It covers Action outcomes and downstream acceptance workflows, including scanner and artifact identity scenarios. Its current main at audit was `4ecfe657209125092c0cf4964e783c648d707c8d`; the latest relevant public hosted acceptance records inspected were from 2026-09-24 and ran against an earlier Dogfood SHA. Treat the records as bounded historical engineering evidence, not as tests of every current Core or Dogfood commit and not as third-party adoption.

The mcp-use issue/fork experiment and closed-unmerged PR are interaction history. Discussion feedback, forks, Dogfood, and unmerged PRs are not official acceptance or verified third-party use.

## Required public wording

Describe the project as an **experimental downstream verifier and CI release policy gate**. It validates evidence and applies consumer-defined admission policy. It is not an MCP official scanner, not a Registry implementation, and not a verified third-party-adopted or production-proven project.

Keep separate: scanner verdict, evidence structure/integrity/freshness, project release policy, and the actual safety of the service. A pass means the selected policy accepted the supplied evidence; it does not prove that the service is safe or vulnerability-free.
