# Registry PR #1404 compatibility checkpoint

Status: project evidence checkpoint. This is a downstream compatibility
record, not an upstream adoption or review record.

## Snapshot

- Source PR: [`modelcontextprotocol/registry#1404`](https://github.com/modelcontextprotocol/registry/pull/1404)
- Observed through: `2026-09-03T05:09:25Z`
- Upstream state: `open`, unmerged; `mergeable=true`
- Current observed HEAD: `9c9b76e102e43fe8f7bee1ba3e5f4f1c6a9a3ee6`
- PR `updated_at`: `2026-09-03T05:09:25Z`
- PR author: `eeee2345`
- Formal reviews: none (`reviews=[]`)
- Requested reviewers: none
- Positive discussion signal retained: PR author `eeee2345` wrote
  “+1 to @yandexuanxuan's consumer-side invariants upthread.” This is a
  discussion signal only; it is not maintainer approval, a formal review, a
  merge, or an invitation to submit an upstream change.
- Latest external update: on 2026-09-03 `Nikolife2016` corrected the custody
  dataset methodology and published a v2 reading. GitHub reports
  `author_association=NONE` for that comment, so it is external evidence input,
  not a Registry maintainer acceptance signal.

## Delta from the pinned profile

Pinned compatibility identity:

```text
registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22
```

The GitHub compare API previously reported one commit and two changed files
between the pinned SHA and the current HEAD:

- `docs/reference/server-json/CHANGELOG.md`
- `docs/reference/server-json/generic-server-json.md`

The change documents a name-custody boundary for content/digest-scoped
receipts. It does not add a receipt field, required field, enum, or conditional
constraint. The SHA-256 of both consumed source files is identical at the
pinned SHA and current HEAD:

| File | Pinned SHA-256 | Current SHA-256 |
| --- | --- | --- |
| `docs/reference/api/openapi.yaml` | `4c6e550be16b154c9e3790eb9f9cb82a5ff78848f4a7a0cf66bcccd1d5b934ef` | same |
| `docs/reference/server-json/draft/server.schema.json` | `06ae66de74a6e72bcb4dd5bd623c676140d8b19f78f76ec409f5a9dc3d8dab66` | same |

Classification: **B — `DOC_SEMANTIC_CHANGE_ONLY`**.

The upstream HEAD remains
`9c9b76e102e43fe8f7bee1ba3e5f4f1c6a9a3ee6` at this refresh, so the
2026-09-03 comment changes evidence interpretation, not the consumed schema or
document bytes. The existing immutable profile therefore remains the
compatibility identity. The observation SHA must not replace the pinned profile
SHA, and no new profile is required for this evidence-only delta.

## Downstream boundary and provenance gate

`mcp-evidence-gate` continues to keep these axes separate:

```text
artifact digest / scan scope / freshness / scanner verdict
!= provenance or name-custody observation
!= downstream policy decision
```

The matching artifact digest proves byte identity only. It does not prove
package-name custody, ownership continuity, or repository continuity. No
`drift`/custody field, provenance input, new scan scope, or scanner-verdict
mutation is introduced by this checkpoint.

The custody series is now versioned on Zenodo. Dataset v2 is
`https://doi.org/10.5281/zenodo.22268322`; the concept DOI for all versions is
`https://doi.org/10.5281/zenodo.22251005`. On 2026-09-03 the producer explicitly
retracted the earlier characterization of same-day/same-observation shares as
“lower bounds”. Because custody changes and releases are inferred by diffing
consecutive daily snapshots, their true event times are interval-censored.

For the same 204-event series, the producer now reports two readings:

| Event type | Total | No release, same observation | No release, same or adjacent observation (±1 day) |
| --- | ---: | ---: | ---: |
| maintainer-set changes | 42 | 32 (76.2%) | 23 (54.8%) |
| repository URL changes | 77 | 1 (1.3%) | 1 (1.3%) |

The producer also clarifies that a maintainer-set change is not itself proof of
a transfer of control; package authority, registry-name authority, and
repository provenance must be reported separately.

These v2 figures are **producer-reported evidence**, not independently verified
project facts. The 2026-08-31 independent recount of the then-live JSON remains
a historical reproducibility observation only and must not be used as the
current custody prevalence estimate. Coverage and trust limitations remain:
the producer is an interested party, observation coverage is bounded by the
stated registry/npm surfaces, and timestamp proofs establish evidence existence
timing rather than semantic correctness.

Accordingly `PROVENANCE_IMPLEMENTATION_GATE=PROTOTYPE_READY`: a downstream
prototype/evaluator remains justified, while production trusted provenance is
still out of scope. The existing artifact-evidence dogfood remains the supported
consumer contract.

## Evidence references

- Upstream PR state, HEAD, comments, and review status were refreshed through the
  GitHub API through `2026-09-03T05:09:25Z`.
- Latest custody-method correction:
  `modelcontextprotocol/registry#1404` comment `5520801412`.
- Dataset v2: `https://doi.org/10.5281/zenodo.22268322`.
- Dataset concept DOI: `https://doi.org/10.5281/zenodo.22251005`.
- Compare range:
  `20747d3253ba8638161dd95f1cec70df02993c22...9c9b76e102e43fe8f7bee1ba3e5f4f1c6a9a3ee6`
- Local semantic boundary: [`evidence-semantics.md`](./evidence-semantics.md)
- Local provenance boundary: [`provenance-drift-follow-up.md`](./provenance-drift-follow-up.md)
- Downstream consumer: `Xander-Xai/mcp-evidence-gate-dogfood`, whose Action
  remains a project-owned cross-repository consumer fixture. Dogfood evidence is
  consumer-contract evidence, not proof of third-party adoption.
- A separate real-artifact external Action run
  ([`33036548697`](https://github.com/Xander-Xai/mcp-use/actions/runs/33036548697))
  completed matching-clean, digest-mismatch, and findings cases successfully;
  this is a fork experiment and not upstream `mcp-use` adoption.

## Unknowns and reopen conditions

## 2026-08-31 downstream implementation state

The historical dogfood observations above are retained as historical evidence.
The current development line at that checkpoint added explicit warning
disposition and optional offline local `evidence_digest` binding. Its Action
bundle was built from commit `f8a0b517a15896848530365f77d21482e34fdbca`;
the companion dogfood branch pinned that full SHA and added permissive/strict
warning cases. This subsection is retained for chronology and is not a statement
about the current default-branch head.

Known unknowns are whether a Registry maintainer will formally review or merge
#1404, whether the PR will receive additional schema changes, and whether the
versioned custody dataset will receive independent v2 reproduction. Re-open the
compatibility review if the PR schema changes substantively, the PR is merged
or closed, a maintainer explicitly asks for consumer fixtures/profile/dogfood
work, or an independently reproduced provenance dataset materially changes the
trust assessment. Until then this checkpoint requires no upstream comment or PR.
