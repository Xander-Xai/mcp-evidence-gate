# SBOM Evidence Admission Contract v1

**STATUS: IMPLEMENTED IN CORE PR #23**  
**IMPLEMENTED**

This document describes the implemented consumer-side contract. It changes
Core SBOM admission and the checked-in Action bundle, while preserving
Producer behavior and existing scanner contracts.

## 1. Ownership and scope

The Producer supplies evidence. Core decides whether evidence is admissible.
A Producer assertion such as `status: complete` is an observation only; it
cannot grant admission.

This contract covers SBOM byte identity, artifact identity, their exact
relationship, schema validation, inventory completeness, and fail-closed
admission. Vulnerability matching and security verdicts remain a separate
later layer.

## 2. Evidence axes

Core must evaluate independent axes rather than a single `sbom_valid` flag:

1. Artifact integrity
2. SBOM integrity
3. Artifact-to-SBOM binding
4. Schema validity
5. Inventory completeness
6. Evidence admission

The evaluation order is:

```text
Artifact identity
  -> SBOM identity
  -> exact artifact/SBOM binding
  -> schema validation
  -> inventory validation
  -> Core admission
```

## 3. Consumer-readable evidence envelope

The proposed envelope is deliberately independent of a Producer's private
status fields:

```json
{
  "schema_version": "project-defined-sbom-evidence-v1",
  "artifact": {
    "ref": "<immutable reference>",
    "sha256": "<64 lowercase hex digest>",
    "size": 29289629
  },
  "sbom": {
    "format": "syft-json",
    "schema_version": "16.1.3",
    "sha256": "<64 lowercase hex digest>",
    "size": 279264
  },
  "relationship": {
    "type": "generated-from",
    "artifact_sha256": "<artifact digest>",
    "sbom_sha256": "<SBOM bytes digest>",
    "binding": "exact-artifact"
  },
  "inventory": {
    "status": "present",
    "package_count": 275
  }
}
```

`artifact.sha256` and `sbom.sha256` identify different byte streams. Core must
hash the retained SBOM bytes itself and compare both relationship digests to
the envelope identities. Filename, URL, release tag, version, and package
count are not identity proofs.

## 4. Supported format registry (v1)

The first allowlist contains only the format exercised by the real pilot:

```ts
type ConsumerSbomContract = {
  format: "syft-json";
  supportedSchemaVersions: ["16.1.3", "16.1.10"];
  sourceTypes: ["file", "image"];
  binding: "exact-artifact";
  requiredEvidence: [
    "artifact_identity",
    "sbom_identity",
    "artifact_sbom_binding",
    "schema_validation",
    "inventory"
  ];
};
```

`16.x`, `>=16`, CycloneDX, and SPDX are not v1 allowlist entries. The two
Syft JSON versions above are explicit qualified entries; a later schema
version requires its own compatibility review and real artifact, SBOM,
binding, tamper, schema, and inventory evidence.

The Wave-3.2 fixture used CycloneDX-like fields. Wave-3.3 showed that real
Syft JSON uses schema `16.1.3` and Wave-3.7 qualified `16.1.10`; both use `artifacts` for the package collection,
`source.name`/`source.version` for source metadata, and `schema.version` for
the descriptor. Fixture assumptions are therefore subordinate to the real
Syft shape. CycloneDX and SPDX remain **NOT YET VERIFIED**.

## 5. Source-type binding

Source type is part of the consumer-owned admission contract. v1 admits only
the qualified Syft source types `file` and `image`; missing or unknown values
are not treated as legacy files. Image-shaped metadata (at minimum
`source.metadata.manifestDigest`) with a non-image type is contradictory and
fails closed. For `image`, both `source.id` and
`source.metadata.manifestDigest` must identify the exact resolved manifest
bytes when present; `source.version` is requested-reference provenance and is
not resolved-manifest proof. For `file`, `source.version` remains the primary
qualified identity and any supplied SHA-256 entry in `source.metadata.digests`
must agree with the artifact bytes.

For file-source digest metadata, every supplied SHA-256 identity entry must be
structurally valid and agree with the evaluated artifact. Malformed supplied
SHA-256 entries are not treated as absent and fail closed with
`artifact_sbom_binding_mismatch`; absence of SHA-256 metadata remains a
separate v1 state.

Binding selection also validates source metadata shape before selecting a rule.
Image signals are presence-based across Syft-native `userInput`, `imageID`,
`manifestDigest`, `layers`, and embedded `manifest` fields; file signals are
`path`, `digests`, and `mimeType`. A mixed shape is ambiguous and fails closed.
Deleting or corrupting one image field therefore cannot downgrade the
remaining image-shaped evidence into file binding. Missing source type remains
inconclusive, and unsupported source types are never inferred as files.

For security-sensitive source identity fields, field absence and field
malformation are distinct states. A present but malformed `source.id` or
`source.metadata.manifestDigest` fails closed with
`artifact_sbom_binding_mismatch` and cannot be treated as absent.

## 6. Identity and relationship rules

### Artifact identity

The consumer requires a supported digest representation with the existing
lowercase SHA-256 convention. Missing, malformed, unsupported, or mismatched
digests are rejected. The existing `artifact_digest_mismatch` reason code
should be reused where it has the same meaning.

### SBOM identity

The consumer requires the SHA-256 of the exact supplied SBOM bytes. A filename,
release version, URL, or tag cannot substitute for this identity. The bytes'
hash must equal `sbom.sha256`; otherwise the proposed result is
`sbom_digest_mismatch` and cannot be PASS.

### Exact binding

v1 supports only:

```text
relationship.type = generated-from
relationship.binding = exact-artifact
relationship.artifact_sha256 = artifact.sha256
relationship.sbom_sha256 = sbom.sha256
```

`same-release`, `same-version`, `same-source-tree`, and
`probably-generated-from` are not exact binding and cannot pass. Unsupported
or absent relationship semantics produce `INCONCLUSIVE`; a digest mismatch
produces `BLOCKED`/fail-closed according to the existing integrity policy.

Wave-3.3 proved exact binding for the Syft release pair because the retained
Syft SBOM reports source name `syft_1.52.0_linux_amd64.tar.gz` and source
version `sha256:caeedb81...d6133d`, matching the independently hashed release
asset. This is evidence for that pair, not a generic assumption for all SBOMs.

## 6. Syft-native schema and inventory

For qualified `syft-json` schemas `16.1.3` and `16.1.10`, Core must require parseable JSON, the expected
descriptor/schema information, source metadata, and an `artifacts` collection.
Each inventory item must expose the fields needed by the consumer contract:
stable identifier, name, version, and type/ecosystem information. The parser
must validate the collection it actually reads; `package_count` is a claim to
cross-check, not a substitute for parsing.

Inventory states are distinct:

| State | Meaning | v1 admission |
|---|---|---|
| `present` | schema parsed and one or more valid package records were parsed | eligible |
| `empty` | schema parsed but zero records | `INCONCLUSIVE` |
| `indeterminate` | bytes exist but inventory cannot be trusted or compared | `INCONCLUSIVE` |
| missing/malformed | required collection absent or invalid | `INCONCLUSIVE` |

An empty inventory is not evidence of a dependency-free artifact and must not
be treated as clean.

## 7. Admission matrix

`SBOM_ADMISSION_PASS` means only that this exact SBOM is admissible evidence
for this exact artifact with an accepted inventory. It does not mean zero
vulnerabilities, artifact safety, publisher trust, dependency freshness, or
benign content.

| Case | Required observation | Proposed result |
|---|---|---|
| A valid | artifact digest valid; SBOM digest valid; exact binding; supported schema; inventory present | `PASS` |
| B SBOM tampered | SBOM byte digest differs | `INCONCLUSIVE` or `BLOCKED`, never PASS |
| C artifact mismatch | artifact digest differs from relationship digest | `BLOCKED` |
| D malformed | invalid JSON, unsupported schema, or required field missing | `INCONCLUSIVE` |
| E missing | artifact exists but SBOM absent | `INCONCLUSIVE` |
| F no exact binding | valid SBOM but only release/version relationship | `INCONCLUSIVE` |
| G empty inventory | exact binding and parseable schema but zero packages | `INCONCLUSIVE` |

## 8. Implemented reason codes

The implementation reuses the existing artifact and policy taxonomy where
semantics match. The following SBOM-specific codes are emitted by v1:

```text
sbom_missing
sbom_digest_missing
sbom_digest_malformed
sbom_digest_mismatch
sbom_format_unsupported
sbom_schema_unsupported
sbom_malformed
sbom_inventory_missing
sbom_inventory_empty
artifact_sbom_binding_missing
artifact_sbom_binding_mismatch
```

The existing `artifact_digest_mismatch` and scanner-execution reason family
remain unchanged. SBOM admission reasons remain separate from vulnerability
findings.

## 9. Threat-model review

| Threat | Required defense |
|---|---|
| SBOM replaced while artifact is retained | hash exact bytes; `sbom_digest_mismatch` |
| Artifact replaced while SBOM is reused | compare artifact identity and relationship digest; binding mismatch |
| Package inventory edited while schema remains valid | hash retained SBOM bytes and reparse inventory; edited bytes no longer match digest |
| Correct SBOM digest but wrong relationship | independently compare both relationship digests; block mismatch |
| Same-version, different platform artifact | exact digest and platform/source metadata; version alone is insufficient |
| amd64 SBOM reused for arm64 artifact | exact artifact digest and, where present, platform metadata must agree |
| Same-release SBOM presented as exact | reject non-exact relationship binding |
| Schema version spoofing | explicit format/schema allowlist and descriptor validation |
| Untrusted package count | count parsed entries and cross-check claimed count |
| Claimed count differs from parsed entries | `INCONCLUSIVE`; never infer completeness |
| Empty inventory false-clean | explicit `empty` state; `INCONCLUSIVE` |
| Unknown fields hide required data | strict required-field validation; unknown fields do not satisfy requirements |
| Oversized/deeply nested SBOM | resource limits and parser failure become `INCONCLUSIVE` |
| Duplicate package identifiers | preserve all records, detect duplicates, and make duplicate policy explicit before PASS |
| Malformed source metadata | binding cannot be proven; `INCONCLUSIVE` |

## 10. Resource limits

The Wave-3.3 SBOM was 279,264 bytes with 275 packages. Limits should be
configurable policy values selected after corpus benchmarking, not hidden parser
constants. A conservative initial review range is:

| Resource | Review range | Rationale |
|---|---:|---|
| `MAX_SBOM_BYTES` | 16–256 MiB | substantially above the 0.27 MiB pilot while bounding memory |
| `MAX_PACKAGE_COUNT` | 10,000–1,000,000 | covers ordinary images through large aggregate SBOMs |
| `MAX_STRING_LENGTH` | 64 KiB–1 MiB | bounds hostile metadata without truncating normal identifiers |
| `MAX_NESTING_DEPTH` | 32–128 | bounds parser recursion while allowing real JSON structure |

The implementation uses explicit v1 bounds and performs path stat preflight
before SBOM byte allocation. Limit failures are structured `INCONCLUSIVE`
results.

## 11. Architecture decision

**Recommendation: B — independent evidence-admission axis.**

SBOM evidence is not scanner execution. A Syft SBOM may be generated without
Trivy/OSV execution, while scanner completeness can be valid without any SBOM.
Embedding SBOM admission inside `scanner_execution` would conflate generator
identity, package evidence, and vulnerability scanning. A future result may
compose both axes, but each must retain its own integrity, status, and reason
codes.

## 12. Backward compatibility

Existing Trivy filesystem, Trivy npm package-view, Trivy OCI, and OSV workflows
remain unchanged when no SBOM evidence is supplied. SBOM evidence is not a
new global prerequisite for existing Core admission. Existing scanner tests
and contracts must remain green.

## 13. Implementation surface

The implementation is limited to the following reviewed surface:

```text
src/core/sbom-admission.ts
src/core/types.ts (new result types only)
src/core/policy.ts (composition only)
src/profiles/.../sbom-contract.ts
schemas/project-defined-sbom-evidence-v1.json
tests/fixtures/sbom/*
tests/*sbom*contract*.test.ts
dist/action bundle (only after source and tests pass)
```

No Producer changes, scanner vulnerability matcher, registry profile rewrite,
or existing scanner contract migration belongs in that PR.

## 14. Regression test matrix

The implementation covers valid Syft 16.1.3 and 16.1.10 exact-bound, tampered SBOM,
artifact mismatch, missing SBOM, malformed JSON, unsupported schema, missing
inventory, empty inventory, missing binding, malformed SBOM digest, and
platform mismatch where platform metadata is present. Existing scanner tests
must remain unchanged and passing.

## 15. Readiness decision

The real contract is mapped, exact binding is explicit, the Syft-native schema
is supported by real evidence, fixture assumptions have been corrected,
inventory semantics are defined, the threat model is reviewed, backward
compatibility is bounded, and the implementation surface is constrained.

```text
CORE_SBOM_IMPLEMENTATION_READY = YES
CORE_CODE_CHANGED = YES
CORE_PR_CREATED = YES
```

Wave-3.7 qualification is cross-artifact / cross-project validation within
the Syft JSON producer ecosystem. It does not prove cross-producer
generalization; CycloneDX, SPDX, and other SBOM generators remain outside
this contract.

## 16. Qualified image source-shape and manifest fallback invariants

All image-native metadata fields in the qualified Syft image shape participate
in source classification, including `mediaType`, `imageSize`, `repoDigests`,
`tags`, and `labels`. Presence is sufficient for shape classification; malformed
values remain image-shaped evidence and cannot silently downgrade to file
binding. Manifest fallback is demand-driven: config, platform, or layer
validation independently requires loading the exact bound artifact manifest when
no verified embedded manifest is available. Layer equality remains fail-closed
and does not depend on an optional `imageID` claim.

Every supplied `metadata.config` payload is independently bound to the exact
image manifest `config.digest`. `imageID` is an additional config identity
claim, not a prerequisite for config-payload binding; verified embedded
manifests are preferred and the exact bounded artifact-manifest fallback is
used when needed.

When `source.metadata.mediaType` is supplied for image evidence, it must equal
the mediaType of the exact verified manifest. Malformed or contradictory
supplied mediaType values fail closed; absent mediaType remains compatible with
the existing v1 semantics.
