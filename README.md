# mcp-evidence-gate

Experimental downstream verifier and CI policy gate for evidence-scoped MCP security scan receipts.

This project is **not** an MCP Registry implementation, an official MCP project, or a scanner. It initially targets the experimental receipt proposal in [modelcontextprotocol/registry#1404](https://github.com/modelcontextprotocol/registry/pull/1404).

`mcp-evidence-gate` is a downstream release admission controller: it turns scanner-neutral MCP security receipts into deterministic, auditable release decisions without conflating evidence quality with server safety.

## Why this project matters

MCP security receipts can report a scanner verdict without proving that the evidence still covers the exact artifact, scope, or freshness window a release is about to ship. `mcp-evidence-gate` is an experimental downstream verifier and release admission controller that binds evidence-scoped receipts to exact artifact/evidence bytes and evaluates deterministic, project-defined policy through a CLI and a Node 24 GitHub Action. It keeps scanner verdict, evidence validity, release policy, and server safety as separate claims.

## Maintainer

Primary maintainer: [@yandexuanxuan](https://github.com/yandexuanxuan)

## Current evidence

- Public MIT repository; the audit baseline (`eb73c152b53e376d0bb7dd55b2948d0f62bfcc39`) is recorded in the application snapshot. Three alpha prereleases exist, latest `v0.1.0-alpha.3` at `d404b38f0ac0303438b561fe7358b0eec487c962`.
- `pnpm test`: 79 Vitest tests pass locally; the profile-drift sentinel adds 15 passing Node tests. The repository's CI and scheduled drift-sentinel runs are green for the audited baseline head.
- Companion [dogfood repository](https://github.com/yandexuanxuan/mcp-evidence-gate-dogfood) records an 11-case Action matrix and successful real Trivy, OSV, multi-receipt composition, and OCI identity workflows. These are project-owned cross-repository acceptance evidence, not third-party adoption.
- Both the `verify` / `verify-set` CLI and the self-contained Node 24 Action are checked in. The [Trivy producer](https://github.com/yandexuanxuan/mcp-evidence-producer-trivy) supplies scanner-specific receipts; the consumer still owns admission policy.
- The pinned `registry-pr-1404` compatibility profile is locally matched to the current open PR's contract; drift is reported as `NON_CONTRACT_CHANGE` and kept pinned until reviewed.

## Ecosystem engagement

- [modelcontextprotocol/registry#1404](https://github.com/modelcontextprotocol/registry/pull/1404) is an open, unmerged proposal with no formal review. A proposal-author wrote “+1 to @yandexuanxuan's consumer-side invariants upthread”; this is a positive discussion signal, not maintainer approval, endorsement, schema acceptance, or Registry adoption.
- [mcp-use#2332](https://github.com/mcp-use/mcp-use/issues/2332) resulted in the maintainer-recommended fork-first experiment against `mcp-use@2.3.3`; the fork run completed, with no upstream adoption claim.
- [mcp-use#2375](https://github.com/mcp-use/mcp-use/pull/2375) was reviewed by automated checks and its reported findings were addressed, then closed unmerged by the maintainer because `WARNING` semantics remain unresolved in [conformance#430](https://github.com/modelcontextprotocol/conformance/issues/430). It is not evidence of an accepted upstream contribution.

## Project status

Experimental downstream implementation. Not an official MCP project. No claim of Registry adoption. No verified third-party adoption was found in the bounded public search documented in [`docs/project-evidence.md`](docs/project-evidence.md).

The first compatibility profile is pinned to:

```text
registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22
```

The verifier answers whether a receipt is still eligible to support a release by checking artifact binding, freshness, non-empty scope, evidence metadata conformance, inconclusive reasons, and local attestation policy. It will not discover vulnerabilities or claim that a server is globally safe.

`evidence_digest` can optionally be bound to a local evidence report with the CLI `--evidence` option or Action `evidence` input; no network download is performed. Artifact and evidence digest binding are independent axes. The `attestation` value is declarative metadata, not a cryptographically authenticated issuer identity or signature.

The pinned profile follows the proposal's current schema boundary: `scanner`, `scanned_artifact_digest`, `scan_scope`, `verdict`, `scanned_at`, and `attestation` are required; `freshness_expires_at` is optional; `inconclusive_reason` is required only when `verdict` is `inconclusive`. Digest parsing currently supports lowercase `sha256:<64-hex>` values. Other well-formed algorithms are reported as unsupported by this verifier, not as malformed receipts. Scope values remain open strings so future upstream values are accepted.

The pinned structural schema is stored at `src/profiles/registry-pr-1404/security-scan-receipt.schema.json` with provenance in the adjacent `profile.json`. `verifyReceipt()` runs structural conformance first and then evidence-specific checks. `verifyReceiptEvidence()` remains the partial invariant layer for callers that already performed structural validation.

## Policy layer

`evaluatePolicy()` produces a project-defined release decision without changing the input receipt. It keeps the scanner's `verdict` separate from the gate decision and uses deterministic precedence: `fail > inconclusive > warn > pass`. The verifier carries one immutable `evaluatedAt` clock into policy evaluation, so historical replay does not drift with wall-clock time. Warning admission is explicit: `permissive` allows warnings as `WARN`, while strict policies block them as a policy `FAIL` (`receipt_warnings_blocked`).

Four built-in policies are included:

- `permissive`: freshness is optional, no scope is required, and all three attestation values are allowed.
- `strict-release-example`: a project-defined metadata policy that requires freshness, `package` plus `handler-validation`, `third-party-attested`, and a maximum scan age of seven days. It does not authenticate the attestation value.
- `strict-evidence-example`: the strict example plus a required local evidence report digest binding.
- `strict-scanner-completeness`: an explicit local `scanner-execution-completeness-policy-v2` extension. Producer evidence reports observed execution facts; Core policy owns supported Trivy FS, OSV lockfile, and Trivy OCI contracts, required components, and allowed successful exit codes. It requires a locally supplied, digest-bound evidence report and binds receipt scanner/version to evidence scanner identity/version. Unknown contracts and producer-shortened component lists cannot pass.

The strict policies are project-defined examples, not MCP Registry requirements or a trust hierarchy. Policy is local and deterministic; it does not contact the Registry, download evidence, run scanners, or modify receipts. Scanner completeness is checked only when the explicit strict policy is selected; `permissive` and the existing strict examples retain their legacy receipt behavior.

### Scanner execution completeness

`strict-scanner-completeness` keeps the decision layers separate:

```text
Registry receipt schema -> receipt_status
artifact/evidence digests -> integrity_status
project-defined policy -> policy_status
Core release gate -> admission_status
```

The policy consumes the abstract, versioned `scanner_execution` object in a local evidence report, while keeping acceptance rules consumer-owned. It verifies the `complete`/`incomplete`/`failed` status, exact required component coverage, output facts, scanner identity/version binding, and scanner-specific successful exit-code rules. A self-consistent `incomplete` or `failed` execution produces policy `FAIL` even when the receipt says `clean`; unknown contracts, narrowed producer component lists, missing versions, malformed objects, or unverified digests cannot produce `PASS`. A digest mismatch makes the scanner status `unverified` and admission `INCONCLUSIVE`. This is project-defined downstream policy, does not modify Registry SecurityScanReceipt v1, and is not an official MCP Registry standard. Legacy permissive behavior remains unchanged.

Machine-readable CLI output includes `integrity_status`, `receipt_status`, `policy_status`, `admission_status`, `scanner_execution_status`, and stable `reason_codes` (including `scanner_execution_missing`, `scanner_execution_malformed`, `scanner_execution_incomplete`, `scanner_execution_failed`, and `scanner_execution_contradictory`). The Action exposes the same layers through hyphenated outputs. See [`docs/design/scanner-execution-completeness.md`](docs/design/scanner-execution-completeness.md) for the contract and acceptance matrix.

## Multi-receipt composition

`evaluateReceiptSet()` and the CLI `verify-set` command compose **downstream admission decisions**, not scanner receipts. Each receipt is independently verified and evaluated against one shared artifact, one policy, and one evaluation time. The aggregate decision uses the same severity order as the single-receipt policy layer:

```text
pass < warn < inconclusive < fail
```

The set freezes the artifact SHA-256 before evaluating the first receipt and rechecks it after each receipt. Persistent artifact drift aborts the set as a runtime invariant violation instead of silently composing different artifact states. The frozen `artifactDigest` is exposed in text and JSON output. This is a drift guard, not a claim of transactional filesystem snapshot isolation.

No synthetic `SecurityScanReceipt` is created, scanner verdicts are not rewritten, and duplicate scanners do not create quorum or additional trust.

A receipt-set manifest is explicitly project-defined:

```json
{
  "schema_version": "project-defined-receipt-set-v1",
  "receipts": [
    {
      "id": "trivy",
      "receipt": "trivy/receipt.json",
      "evidence": "trivy/evidence.json"
    },
    {
      "id": "osv",
      "receipt": "osv/receipt.json",
      "evidence": "osv/evidence.json"
    }
  ]
}
```

Receipt and evidence paths are resolved relative to the manifest file. The artifact is supplied once to `verify-set`, forcing every receipt through independent binding against the same consumer-owned artifact. An empty set is rejected as input error rather than treated as PASS. See [`docs/design/multi-receipt-composition.md`](docs/design/multi-receipt-composition.md) for the frozen P2-003 semantics and boundaries.

## Status

Phase 1 / experimental. The profile is deliberately pinned to an open, unmerged proposal. If the proposal changes, a new profile will be added instead of silently changing existing behavior.

## Development

```bash
pnpm install
pnpm build
pnpm test
```

No external repository, scanner, or endpoint is contacted by the current CLI or core verifier.

## CLI

Build the executable package and verify one receipt:

```bash
pnpm build
node dist/cli.js verify \
  --receipt fixtures/valid/complete-clean.json \
  --artifact fixtures/artifacts/current-artifact.bin \
  --policy permissive \
  --now 2026-08-25T00:00:00Z
```

Or compose a project-defined receipt set:

```bash
node dist/cli.js verify-set \
  --set receipt-set.json \
  --artifact path/to/artifact \
  --policy permissive \
  --format json \
  --now 2026-08-25T00:00:00Z
```

Use `--format json` for machine-readable output. Exit codes are stable for both commands: `0` means PASS or WARN, `1` means FAIL, `2` means INCONCLUSIVE, and `3` means CLI/input/runtime error. The policy must be explicit; no MCP Registry policy is implied.

## GitHub Action

The experimental Action remains a thin **single-receipt** wrapper around the existing verifier and policy layer. It runs on the Node 24 GitHub Actions runtime, requires receipt, artifact, and policy inputs, and accepts an optional local `evidence` path. P2-003 does not change the Action input surface. It does not install dependencies or download `evidence_ref` in the consuming repository:

```yaml
- uses: yandexuanxuan/mcp-evidence-gate@<immutable-commit-sha>
  with:
    receipt: fixtures/valid/complete-clean.json
    artifact: fixtures/artifacts/current-artifact.bin
    policy: permissive
```

It emits `decision`, `receipt-verdict`, and `profile`. PASS and policy-allowed WARN succeed; FAIL and INCONCLUSIVE fail the step. INCONCLUSIVE means the evidence does not support the release, not that the server was proven unsafe. The checked-in `dist/action/index.cjs` is a self-contained Node 24 bundle matching the declared Action runtime.

## Tested downstream integration

The companion [mcp-evidence-gate-dogfood](https://github.com/yandexuanxuan/mcp-evidence-gate-dogfood) exercises the Action across its decision and step outcome matrix using immutable commit references and also hosts real producer-consumer promotion oracles. P2-003 requires a downstream real Trivy + OSV receipt-set composition run before the multi-receipt feature is considered fully closed.

Consumers should pin a full commit SHA rather than a moving branch.
