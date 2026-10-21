# Evidence semantics

This document records the stable semantics behind the gate. It is a product
design note, not an application or review log.

## Current semantics

- `scanned_at` is parsed with the same strict RFC3339 rules as expiry values.
- A scan more than five minutes in the future is invalid.
- `freshness_expires_at` earlier than `scanned_at` is invalid.
- Policies may set a consumer-side `maxScanAgeMs`; the strict example uses
  seven days. A publisher-selected far-future expiry cannot bypass that limit.
- Artifact hashing uses a read stream, so package and bundle size do not scale
  memory usage linearly.
- A matching `scanned_artifact_digest` establishes byte identity for the scanned
  artifact only. It does not establish package-name custody, repository
  provenance, or maintainer/ownership continuity. Those are separate evidence
  and policy concerns.
- `scan_scope` records what a receipt says was evaluated. Values remain open
  strings under the pinned proposal; this project does not claim that provenance
  must or must not become a future documented scope value upstream.
- README terminology says evidence metadata conformance. `evidence_digest` is
  bound to a local evidence report only when that report is supplied explicitly
  (CLI `--evidence`, Action `evidence`); no network download is performed, and
  the binding is byte identity of the supplied report, not issuer attestation.
- Attestation values are documented as declarative metadata. This verifier does
  not authenticate an issuer, signature, certificate, or OIDC identity.
- Dogfood permanently exercises PASS, expected INCONCLUSIVE, and expected FAIL
  decisions, including a malformed receipt.

## Deliberate non-goals for this profile

- Multiple-receipt aggregation: the GitHub Action remains a single-receipt
  consumer. The CLI adds a project-defined `verify-set` composition that
  verifies each receipt independently against one shared artifact and composes
  only the downstream admission decisions. It does not imply an upstream array
  contract or maintainer expectation.
- Cryptographic attestation verification: requires a trusted issuer and key
  distribution contract that this pinned profile does not define.
- Evidence-report digest binding beyond the explicit local input: the binding
  is limited to the exact bytes of a report the consumer supplies, so it
  establishes byte identity only and not provenance or custody.
- Package-custody or repository-provenance continuity: these can change while a
  scanned artifact remains byte-identical, so they are not inferred from the
  current artifact-bound receipt.

These boundaries preserve the distinction between scanner verdict, evidence
quality, provenance observations, and release policy decision.
