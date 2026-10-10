# Interview Guide

## 30-second explanation

`mcp-evidence-gate` is an experimental downstream verifier and CI release gate. A scanner receipt can say “clean” while being stale, malformed, or bound to different artifact bytes. The gate checks the receipt against a pinned experimental schema, binds evidence to exact bytes, applies a consumer-owned policy, and returns a deterministic release decision. It does not run the scanner or certify that a server is safe.

## Architecture to explain

1. **Receipt structure:** profile-pinned schema validation happens before semantic evidence checks.
2. **Integrity:** SHA-256 binding checks compare receipt/evidence digests to supplied local files; no network evidence download is implied.
3. **Freshness and scope:** policy checks determine whether evidence is usable for the requested release.
4. **Policy decision:** scanner verdict remains distinct from PASS/WARN/INCONCLUSIVE/FAIL admission status.
5. **Interfaces:** CLI and a bundled Node 24 GitHub Action use the same Core evaluator; multi-receipt composition verifies each receipt independently against one artifact.
6. **Optional SBOM admission:** project-defined envelope validates bounded Syft JSON formats/versions and exact artifact/SBOM relationships. It is inventory evidence, not a vulnerability verdict.

## Design questions

- Why separate receipt validity from policy? A structurally valid receipt can still be stale, digest-mismatched, incomplete, or unacceptable to a specific release policy.
- Why preserve `INCONCLUSIVE`? Missing or unsupported evidence should not be silently treated as clean or unsafe.
- Why no scanner verdict rewriting or quorum? Each scanner remains the source of its own result; composing policy decisions must not manufacture consensus.
- Why pin an upstream schema proposal? It makes compatibility reproducible while making the experimental and unadopted status explicit.
- Why bound SBOM input reads? A preflight file-size check followed by unbounded reading leaves a growth race; the PR review patch performs capped chunked reads.

## Evidence to state precisely

- Core main was tested in a clean worktree: 97 tests passed on three consecutive runs; build and TypeScript lint passed.
- PR #24 had 107 local tests passing after a bounded-read fix, plus build and lint. Until that fix is pushed and fresh CI completes, describe it as an unmerged PR with local validation, not a released feature.
- Dogfood is project-owned cross-repository acceptance. It is not independent customer adoption.
- Registry PR #1404 remains an open experimental compatibility source, not an official standard.

## Avoid claiming

- Official MCP security scanning, Registry implementation, or maintainer endorsement.
- Verified third-party adoption, user counts, production coverage, vulnerability discovery accuracy, or service safety certification.
- That all Syft versions or all scanner output formats are supported.
- That a green Dogfood run proves all current commits or external production deployments.
