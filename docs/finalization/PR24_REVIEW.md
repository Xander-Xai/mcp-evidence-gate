# PR #24 Technical Review

Reviewed PR: [Xander-Xai/mcp-evidence-gate#24](https://github.com/Xander-Xai/mcp-evidence-gate/pull/24), “qualify Syft JSON 16.1.10 for SBOM admission”.

Initial remote head at review: `20798b6166132b6eee72e97801368b23755f6b5d`; PR open, not merged; GitHub review decision was empty. Both GitHub CI `verify` checks passed on that exact head. Local worktree tests/build/lint also passed at that head.

## Findings

1. **Receipt compatibility remains separate.** The PR does not modify the pinned `SecurityScanReceipt` schema or existing receipt-policy evaluator. SBOM evidence uses a project-defined envelope and optional CLI/Action inputs. Existing receipt verification remains independently evaluated.
2. **Syft compatibility is explicit.** The consumer allowlist names exactly JSON schema versions `16.1.3` and `16.1.10`; unsupported versions do not silently pass. The PR includes real Syft-shaped and OCI identity fixtures for qualification. This is a bounded compatibility claim, not general support for all Syft output or future schema versions.
3. **Binding and inventory checks are fail-closed.** Declared SBOM digest is checked against supplied bytes; artifact digest and source metadata are bound to the supplied artifact; mismatches block admission. Empty, duplicate, malformed, unsupported, or count-mismatched inventory is inconclusive and cannot pass.
4. **Receipt freshness is not extended to inventory evidence.** The SBOM envelope has no scan timestamp. It proves exact-byte inventory association, not vulnerability-scan freshness or vulnerability absence. Freshness remains part of the receipt/policy path. This scope should remain explicit in public descriptions.
5. **Composition is conservative.** SBOM `blocked` maps to Core `fail`; `inconclusive` remains inconclusive; the existing decision is not downgraded. Multi-receipt `verify-set` semantics are unchanged and SBOM flags are only on single-receipt `verify`.
6. **Runtime packaging is consistent.** The Action declares Node 24 and uses a bundled `dist/action/index.cjs`; the PR build regenerated the bundle. The local build and typecheck pass. The existing Alpha release does not include this PR until merge and a new release.

## Blocking issue and local patch

The original input loader called `stat()` and then unbounded `readFile()`. A file that grows after the size preflight can exceed the documented 64 MiB resource cap during the read. I changed the PR worktree to read each envelope/SBOM through an open file handle in bounded chunks, allowing at most cap plus one byte before returning `sbom_size_limit_exceeded`. The regression test covers over-limit SBOM and envelope files. No fixture, schema, policy, supported scanner, or version scope was broadened.

Post-patch local results: `pnpm install --frozen-lockfile` PASS, `pnpm test` 107/107, `pnpm build` PASS, `pnpm lint` PASS. The fix was committed as `bddb49595b69b78eb46903b1f15bc09cf01eec23` and normally pushed to the existing PR branch. Fresh GitHub runs [38053411591](https://github.com/Xander-Xai/mcp-evidence-gate/actions/runs/38053411591) and [38053415832](https://github.com/Xander-Xai/mcp-evidence-gate/actions/runs/38053415832) both succeeded on that head. PR remains open and the review decision is empty.

## Recommendation

**The PR is technically suitable for merge after independent human review.** The bounded-read fix is small, local and remote CI pass on `bddb49595b69b78eb46903b1f15bc09cf01eec23`, and the PR is open/unmerged. Do not describe it as MCP Registry functionality, an official security scan, or a released capability before merge and release.
