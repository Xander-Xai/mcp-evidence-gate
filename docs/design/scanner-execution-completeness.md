# Scanner execution completeness — local admission extension

Status: experimental `scanner-execution-completeness-policy-v2`.

This document describes a consumer-side policy extension. It does not change
the MCP Registry SecurityScanReceipt schema or claim that Registry PR #1404
adopts scanner-completeness semantics.

## Decision layers

The Core result intentionally keeps four claims separate:

| Layer | Meaning |
| --- | --- |
| `receipt_status` | The receipt conforms to the pinned Registry compatibility profile. |
| `integrity_status` | Artifact and, when required, evidence bytes are digest-bound. |
| `policy_status` | The selected local policy's deterministic result. |
| `admission_status` | The Core gate result currently returned to a caller. |

`policy_status` and `admission_status` currently have the same value because
Core has no additional outer release orchestrator. They are named separately
so a consumer can compose this result without conflating policy with receipt
validity or byte integrity.

## Explicit policy contract

Select `strict-scanner-completeness` through the existing CLI `--policy` flag,
the Action `policy` input, or the API `STRICT_SCANNER_COMPLETENESS_POLICY`
constant. The policy version is
`scanner-execution-completeness-policy-v2`.

Producer reports observed execution facts; Core owns the acceptance contract
and exact required component set. A producer cannot become complete by
shrinking its own `required_components`. Supported contracts are Trivy FS
(`trivy-fs-json-v1`, scanner `trivy`, exit `0`), OSV lockfile
(`osv-scanner-v2-lockfile-json-v1`, scanner `osv-scanner`, exits `0`/`1`), and
Trivy OCI (`trivy-oci-image-json-v1`, scanner `trivy`, exit `0`). Receipt
scanner/name and scanner version are bound to the evidence snapshot. Unknown
contracts cannot pass.

The policy requires `--evidence` (or an Action/API evidence path) and a receipt
`evidence_digest` that matches the exact local evidence bytes. It then reads
the abstract `scanner_execution` object and requires:

- `schema_version` = `project-defined-scanner-execution-v1`;
- non-empty `scanner_contract` and `completeness_reason` strings;
- boolean invocation, process, exit, output, required-work, and semantic flags;
- integer-or-null `exit_code` and non-negative integer-or-null `output_size`;
- non-empty string arrays for required, completed, and failed components;
- `completeness_status` = `complete`, `incomplete`, or `failed`.

For a `complete` claim, all completion flags must be true, the exit code must
be an integer, output must exist and be non-empty, every required component
must be completed, and no component may be failed. A complete claim that does
not satisfy those facts is `scanner_execution_contradictory`. A non-complete
claim that satisfies every completion fact is also contradictory. The Core
does not decide which exit codes Trivy, OSV, or another scanner should use;
that scanner-specific interpretation remains producer-owned.

## Admission matrix

| Evidence state | Integrity | Scanner status | Strict result |
| --- | --- | --- | --- |
| complete, digest valid | `pass` | `complete` | eligible for normal receipt policy evaluation |
| findings receipt, complete, digest valid | `pass` | `complete` | existing receipt `FAIL` |
| self-consistent incomplete | `pass` | `incomplete` | `FAIL`; a clean receipt cannot pass |
| self-consistent failed | `pass` | `failed` | `FAIL`; a clean receipt cannot pass |
| completeness object absent | `pass` | `missing` | `FAIL` when the evidence binding is valid |
| malformed object | `pass` | `malformed` | `FAIL` |
| contradictory complete claim | `pass` | `contradictory` | `FAIL` |
| evidence digest mismatch/tamper | `inconclusive` | `unverified` | `INCONCLUSIVE`; semantic status is not trusted |
| evidence path missing or not supplied | `inconclusive` | `missing` | `INCONCLUSIVE`; required evidence is unavailable |

The output's `reason_codes` keeps these cases machine-distinguishable with
`scanner_execution_missing`, `scanner_execution_malformed`,
`scanner_execution_incomplete`, `scanner_execution_failed`,
`scanner_execution_contradictory`, and `scanner_execution_unverified`.

## Legacy compatibility and boundaries

No scanner-completeness check is added to `permissive`,
`strict-release-example`, or `strict-evidence-example`. Existing receipts and
callers that do not opt into the new policy keep their prior behavior,
including the possibility that an evidence report is not supplied. The
extension is local, deterministic, and opt-in; it does not modify receipts,
Registry profile files, the profile drift sentinel, or Producer PR #4.

Completeness means only that the producer-observable scanner execution facts
are internally complete. It does not prove that an artifact or server is
globally safe, that a scanner detects every issue, that package ownership or
name custody is valid, that publisher identity or supply-chain provenance is
trusted, or that an attestation is cryptographically authentic.

## Verification surface

The same policy option is forwarded by `verifyReceipt()`,
`evaluateReceiptSet()`, the `verify`/`verify-set` CLI commands, and the Node 24
Action. The Registry profile remains pinned to
`registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22`.
