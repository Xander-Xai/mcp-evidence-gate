# Final Test Report

Audit snapshot: 2026-10-10 to 2026-10-11 (Asia/Shanghai). The initial test record below is retained as original run evidence; the addendum records final PR and main results.

## Scope and checkouts

- Clean Core checkout: `origin/main` at `7c6d7089d25a24ead7a42a3a96319fff2bbeac0a`, in the isolated `codex/finalization-20261010` worktree.
- SBOM PR checkout: `feat/syft-json-16-1-10`, updated to remote head `bddb49595b69b78eb46903b1f15bc09cf01eec23` in the pre-existing PR worktree. The bounded-read review patch is described in [PR24_REVIEW.md](PR24_REVIEW.md).
- The original dirty checkout was left intact. Its nested `mcp-evidence-gate-wave37/` is a registered Git worktree, not disposable test data.

## Clean Core test results

Commands were run against clean Core `main` after `pnpm install --frozen-lockfile` (pnpm 10.33.4). Local Node was `v24.16.0`; Core CI Action runtime is Node 24.

| Command | Result |
|---|---|
| `pnpm install --frozen-lockfile` | PASS, exit 0 |
| `pnpm test` | PASS, 11 files / 97 tests; repeated three times after adding the explicit Vitest config |
| `pnpm build` | PASS |
| `pnpm lint` | PASS; this script is TypeScript `--noEmit`, not a formatter |
| `pnpm test:profile-drift` | PASS, 15 tests |
| `pnpm test:ci-hygiene` | PASS, 4 tests |
| `pnpm check:profile-drift` | PASS; pinned and current upstream contract hashes match |
| `pnpm check` | NOT AVAILABLE; `package.json` has no `check` script. The requested command was attempted and returned “Command `check` not found.” No substitute was represented as that command. |

The test collection fix adds `vitest.config.ts` with `include: ["tests/*.test.ts"]`; it intentionally collects direct Core tests only. `pnpm test:main` is an explicit alias. The Dogfood integration acceptance remains in its own repository and hosted workflows, rather than being represented as a local Core package script. Profile-drift and CI Hygiene retain separate commands.

## Previously contaminated checkout

Before the collection fix, `pnpm test` in the original checkout collected tests from the nested PR worktree using the Core checkout as `process.cwd()`. Result: 23 files, 204 tests, 202 passed and 2 failed with `ENOENT` for `tests/fixtures/sbom/github-mcp-server-16.1.10.min.json` and `github-mcp-server-b281-manifest.json`. Those fixtures exist in the nested PR worktree, but its tests resolved them relative to the outer checkout. No nested worktree or fixture was modified to obtain the clean-run result.

After adding the config on the isolated branch, I ran that exact config against the original dirty checkout (without changing its files): 11 Core files / 97 tests passed, and the nested PR worktree was not collected. This demonstrates the isolation fix against the reported environment while preserving its contents.

## SBOM PR local tests

At the PR head before the review patch, `pnpm test` passed 12 files / 107 tests, `pnpm build` passed, and `pnpm lint` passed. The bounded-read fix was committed and normally pushed as `bddb49595b69b78eb46903b1f15bc09cf01eec23`; its then-current GitHub checks passed. Final post-rebase local and hosted evidence is recorded in the closeout addendum below.

## Remote checks and evidence boundary

- On 2026-10-10, the Core Registry Profile Drift Sentinel succeeded on main SHA `7c6d7089d25a24ead7a42a3a96319fff2bbeac0a` (run [38052536717](https://github.com/Xander-Xai/mcp-evidence-gate/actions/runs/38052536717)). This is not a substitute for a full CI run on local changes.
- The isolated finalization branch was pushed as `ff9b13471bdc3e43d843cc8a675a061812b2beda`; full GitHub CI run [38054023018](https://github.com/Xander-Xai/mcp-evidence-gate/actions/runs/38054023018) passed, including typecheck, Core tests, CI Hygiene, profile-drift tests/check, build, bundle check, and CLI smoke test. Hosted annotations warn that pinned checkout/setup-node/upload-artifact actions currently target Node 20 and are being forced to Node 24; the job passed. Review those action runtime pins during routine maintenance.
- PR #24’s two GitHub `verify` checks were green at head `20798b6166132b6eee72e97801368b23755f6b5d` before the bounded-read patch.
- Dogfood main is `4ecfe657209125092c0cf4964e783c648d707c8d`. Relevant hosted acceptance runs at `0cf05513eebd2f4aa378c13516d6569812e6bdc3` completed successfully on 2026-09-24: [Core adversarial](https://github.com/Xander-Xai/mcp-evidence-gate-dogfood/actions/runs/36017054852), [Dogfood Action matrix](https://github.com/Xander-Xai/mcp-evidence-gate-dogfood/actions/runs/36017055385), [package proof](https://github.com/Xander-Xai/mcp-evidence-gate-dogfood/actions/runs/36017343180), and [external replay](https://github.com/Xander-Xai/mcp-evidence-gate-dogfood/actions/runs/36017352012). These runs predate Dogfood’s current main and are project-owned acceptance evidence.

No claim in this report treats local tests, Dogfood, an open PR, or discussion as official MCP adoption or third-party production use.

## Status matrix

| Area | Status | Evidence / limit |
|---|---|---|
| Clean Core local suite, build, TypeScript lint | **PASS** | 97 tests passed three times; build and lint pass on clean main worktree. |
| Test isolation in the reported dirty checkout | **PASS** | The new direct-file include run from that checkout passed 97 tests without changing its nested worktree. |
| Finalization branch hosted CI | **PASS** | Full CI run 38054023018 passed on `ff9b13471bdc3e43d843cc8a675a061812b2beda`. |
| Core latest full hosted CI on main | **PASS** | Main CI run 38072948125 passed on merge commit `69790b2056beff9a746f6bc409f01aad167cd38b`. |
| PR #24 code and CI at `61bc841…` | **PASS** | 107 local tests/build/typecheck/lint and both GitHub `verify` runs pass on updated head. |
| PR #24 merge | **PASS** | PR #24 merged on 2026-10-10; merge commit `69790b2056beff9a746f6bc409f01aad167cd38b`. No Release was created. |
| Dogfood runs against its audit-date main | **NOT_VERIFIED** | Available acceptance runs pass but predate Dogfood main SHA `4ecfe657…`. |
| Registry #1404 formal adoption | **NOT_VERIFIED** | Proposal remains open and unmerged; pin compatibility is not adoption. |
| Verified third-party adoption or production coverage | **NOT_VERIFIED** | No qualifying evidence is asserted by this audit. |

## Final closeout addendum (2026-10-11)

- Finalization PR [#25](https://github.com/Xander-Xai/mcp-evidence-gate/pull/25) merged by squash. Main CI run [38072948125](https://github.com/Xander-Xai/mcp-evidence-gate/actions/runs/38072948125) passed on the PR #24 merge commit.
- PR #24 was updated from new main using a normal merge commit (`61bc8419472979fdc10f2bae9574f80af734ddc7`), then pushed without force. Both exact-head `verify` runs [38072850645](https://github.com/Xander-Xai/mcp-evidence-gate/actions/runs/38072850645) and [38072854105](https://github.com/Xander-Xai/mcp-evidence-gate/actions/runs/38072854105) passed. The refreshed PR worktree passed `pnpm install --frozen-lockfile`, `pnpm test` (107/107), `pnpm build`, `pnpm typecheck`, `pnpm lint`, CI Hygiene (4/4), profile-drift tests (15/15), profile-drift check, and `node dist/cli.js --help`.
- `dist/action/index.cjs` had no generated diff after build; GitHub CI also passed its generated bundle check and CLI smoke test.
- Dogfood main remains `4ecfe657209125092c0cf4964e783c648d707c8d`. Its latest relevant hosted runs remain the historical 2026-09-24 runs listed above, so they are **not verification of PR #24**. Dogfood is project-owned integration evidence, not third-party adoption.
- After the merges, main is `69790b2056beff9a746f6bc409f01aad167cd38b`; the release list remains at `v0.1.0-alpha.3`. The merged SBOM qualification is on main but not in a published package/action release.
- Branch audit: `feat/npm-package-coverage-contract` at `27f66f977a94f7046403ef42ad38dd99f7fbc106` had its package coverage implementation merged by PR #22 (`da0b697…`); its remaining proposal document is superseded by the implemented PR #23 contract. It has no active worktree and was eligible for cleanup. `feat/sbom-admission-contract-v1` (`50f1138…`), `feat/syft-json-16-1-10` (`61bc841…`), and `codex/finalization-20261010` (`dd6d402…`) remain referenced by existing worktrees and were retained. The original checkout's untracked files and nested worktree were left untouched.
