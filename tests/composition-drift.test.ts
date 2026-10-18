import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import type { ReceiptInput } from "../src/core/types.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifact = resolve(root, "fixtures/artifacts/current-artifact.bin");
const validReceipt = (name: string) => resolve(root, "fixtures/valid", name);
const now = new Date("2026-08-25T00:00:00Z");

/**
 * `evaluateReceiptSet()` freezes the artifact digest on entry and re-hashes it
 * after every receipt so persistent artifact drift aborts the set instead of
 * being silently composed. That abort is advertised in the README but had no
 * coverage, so a future refactor could drop the re-hash and still pass CI.
 *
 * The set-level freeze/recheck is driven through the mocked `sha256Artifact`
 * rather than through a timing-based file mutation, so both cases below are
 * deterministic. Only the set-level calls are intercepted:
 * `verifyArtifactBinding()` calls the module-local `sha256Artifact` inside
 * `digest.ts`, so per-receipt artifact binding still performs the real hash.
 */
const drift = { enabled: false };

vi.mock("../src/core/digest.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/core/digest.js")>();
  let setLevelHashCalls = 0;
  return {
    ...actual,
    sha256Artifact: async () => {
      setLevelHashCalls += 1;
      if (!drift.enabled) {
        // Stable artifact: the freeze and every recheck agree.
        return `sha256:${"a".repeat(64)}`;
      }
      // Call 1 freezes the digest; every later call is the per-receipt recheck.
      return setLevelHashCalls === 1 ? `sha256:${"a".repeat(64)}` : `sha256:${"b".repeat(64)}`;
    }
  };
});

const { evaluateReceiptSet } = await import("../src/core/composition.js");
const { PERMISSIVE_POLICY } = await import("../src/core/policy.js");

async function cleanReceipt(): Promise<ReceiptInput> {
  return JSON.parse(await readFile(validReceipt("complete-clean.json"), "utf8")) as ReceiptInput;
}

describe("multi-receipt composition artifact drift guard", () => {
  it("aborts the set when the artifact stops matching the frozen digest", async () => {
    drift.enabled = true;
    const clean = await cleanReceipt();

    await expect(
      evaluateReceiptSet([{ receipt: clean }, { receipt: clean }], artifact, now, PERMISSIVE_POLICY)
    ).rejects.toThrow("receipt_set_artifact_drift");
  });

  it("completes normally when the artifact digest does not move", async () => {
    // The contrast case proves the guard is driven by an observed recheck
    // mismatch and is not simply throwing for any multi-receipt set.
    drift.enabled = false;
    const clean = await cleanReceipt();

    const result = await evaluateReceiptSet(
      [{ receipt: clean }, { receipt: clean }],
      artifact,
      now,
      PERMISSIVE_POLICY
    );

    expect(result.receiptCount).toBe(2);
    expect(result.artifactDigest).toBe(`sha256:${"a".repeat(64)}`);
  });
});

/**
 * `receipt_set_evaluation_time_drift` is deliberately left uncovered.
 *
 * `evaluateReceiptSet()` derives `evaluatedAt` from the same `Date` instance it
 * hands to every `verifyReceipt()` call, so the two ISO strings cannot differ
 * under the current implementation. It is a defensive invariant rather than a
 * reachable production behaviour, and exercising it would require mocking the
 * very verifier the assertion is meant to protect. A mock-backed test would
 * assert that the mock is wired up, not that the invariant holds.
 */
describe("multi-receipt composition evaluation-clock guard", () => {
  it("hands one identical evaluation clock to every receipt in the set", async () => {
    drift.enabled = false;
    const clean = await cleanReceipt();

    const result = await evaluateReceiptSet(
      [{ receipt: clean }, { receipt: clean }, { receipt: clean }],
      artifact,
      now,
      PERMISSIVE_POLICY
    );

    const clocks = new Set(result.receipts.map((entry) => entry.verification.evaluatedAt));
    expect(clocks).toEqual(new Set([now.toISOString()]));
    expect(result.evaluatedAt).toBe(now.toISOString());
  });
});
