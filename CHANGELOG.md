# Changelog

All notable changes to this project are documented here.

## [Unreleased]

- Bounded every consumer-side file read (`src/core/bounded-reader.ts`,
  `src/core/input-budget.ts`): evidence snapshots are capped at 16 MiB,
  receipt JSON and receipt-set manifests at 4 MiB, receipt sets at 64 entries
  and 16 MiB of cumulative receipt bytes. Oversized evidence never yields a
  snapshot and stays fail-closed (`evidence_size_limit_exceeded`,
  `evidence_file_read_failed`); oversized receipts/sets abort as CLI input
  errors (exit 3). Previously all three paths used unbounded `readFile()`.
- Distinguish a missing evidence file (`evidence_file_missing`, ENOENT) from
  an unreadable evidence path (`evidence_file_read_failed`) instead of
  collapsing every read failure into "missing".
- Added `tests/resource-bounds.test.ts` covering the evidence snapshot bounds,
  the receipt/set input budget, duplicate-path sets, and the fail-closed policy
  mapping for oversized evidence.
- Marked the generated `dist/action/index.cjs` as `-text` and added a
  `windows-regression` CI job that re-materializes the working tree with
  `core.autocrlf=true` before running the test suite and the committed-bundle
  byte comparison, so the PR #28 line-ending class cannot regress silently on
  Windows.
- Added project-defined multi-receipt admission composition through
  `evaluateReceiptSet()` while preserving each receipt's independent verifier
  and policy evidence.
- Added CLI `verify-set` with one shared artifact/policy/evaluation clock and
  per-receipt optional local evidence binding.
- Froze the set-level artifact SHA-256 and rechecked it after each receipt
  evaluation so persistent cross-receipt artifact drift fails as a runtime
  invariant violation instead of being silently composed.
- Preserved aggregate decision precedence as
  `fail > inconclusive > warn > pass`; empty sets fail as input errors.
- Kept the existing single-receipt GitHub Action interface and checked-in
  Action bundle unchanged.
- Added Syft SBOM evidence admission v1 (#23): `sbom-evidence` / `sbom` Action
  inputs, a digest-bound CycloneDX/SPDX package inventory, and the
  `COMPLETE` / `INCONCLUSIVE` / `BLOCKED` SBOM decision layer that stays
  separate from receipt, integrity, and policy admission.
- Qualified Syft JSON 16.1.10 for SBOM admission (#24).
- Marked `tests/fixtures/**` as `-text` and added
  `tests/fixture-bytes-integrity.test.ts` (#28) so SHA-256-pinned SBOM fixtures
  keep their committed bytes under a CRLF-normalising checkout
  (`core.autocrlf=true`), which previously changed their digests and broke
  `validate_fixture_contract.py` on Windows while Linux CI stayed green.
- Pointed the pinned receipt schema `$id`, `SECURITY.md`, `LICENSE`, and the
  repository metadata at the canonical `Xander-Xai` owner namespace after the
  account rename, and recorded the proposal author's 2026-08-30 endorsement of
  the consumer-side invariants in `docs/project-evidence.md`.
- Added regression tests for the `receipt_set_artifact_drift` and
  `receipt_set_evaluation_time_drift` aborts, which were advertised in the
  README but had no coverage.

## [0.1.0-alpha.3] - 2026-08-31
- Preserved one deterministic verifier evaluation clock through policy replay
  to eliminate wall-clock drift.
- Made warning admission explicit with `warningDisposition: allow | block`;
  added `strict-evidence-example` policy with strict warning blocking.
- Added optional offline local evidence report digest binding via
  `--evidence` / Action `evidence` input.
- Enforced mandatory verification when evidence is explicitly supplied:
  read errors and digest mismatches are fail-closed/inconclusive across all
  policies including `permissive`.
- Rejected malformed known SHA-256 digests (`sha256:0`) even when no evidence
  path is supplied.
- Preserved unrequested, well-formed non-SHA-256 evidence algorithms under
  optional policy (do not block permissive solely on an unrequested
  algorithm).
- Loaded the CLI version from `package.json` using Node >=20-compatible
  `createRequire` instead of import attributes.
- Ensured packed `dist/core/*` modules are included in the npm tarball.
- Exercised an 11-case downstream dogfood oracle covering all admission
  decisions.

## [0.1.0-alpha.2] - 2026-08-31

- Closed the strict-policy max-age library-call bypass by making policy
  evaluation enforce its own `maxScanAgeMs`.
- Added regression coverage for direct two-step library usage without
  duplicated freshness forwarding.
- Hardened GitHub Action consumer verification so dogfood asserts both the
  decision output and Action step outcome.
- Updated the real `mcp-use` fork evidence trial to verify PASS,
  INCONCLUSIVE, and FAIL outcome behavior against a packed artifact.
- Preserved the Registry #1404 compatibility profile at
  `20747d3253ba8638161dd95f1cec70df02993c22`.

## [0.1.0-alpha.1] - 2026-08-26

- Added consumer-side freshness invariants and a seven-day strict-policy scan
  age limit.
- Switched artifact hashing to streaming reads.
- Documented declarative attestation and metadata-only evidence digest limits.
- Added executable dogfood coverage for PASS, INCONCLUSIVE, and FAIL decisions.
- Pinned the compatibility profile to MCP Registry PR #1404 head
  `20747d3253ba8638161dd95f1cec70df02993c22`.
