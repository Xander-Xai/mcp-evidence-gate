import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import { EVIDENCE_RESOURCE_LIMITS, readEvidenceSnapshot } from "../src/core/digest.js";
import {
  RECEIPT_INPUT_BUDGET,
  ReceiptInputBudgetExceededError,
  readReceiptDocumentBounded
} from "../src/core/input-budget.js";
import {
  evaluatePolicy,
  PERMISSIVE_POLICY,
  STRICT_SCANNER_COMPLETENESS_POLICY
} from "../src/core/policy.js";
import { verifyReceipt } from "../src/core/verify.js";
import type { ReceiptInput } from "../src/core/types.js";

const root = resolve(import.meta.dirname, "..");
const artifactPath = resolve(root, "fixtures/artifacts/current-artifact.bin");
const validReceiptPath = resolve(root, "fixtures/valid/complete-clean.json");
const now = new Date("2026-08-25T00:00:00Z");
const limit = EVIDENCE_RESOURCE_LIMITS.maxEvidenceSnapshotBytes;

async function withTempDir(run: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(resolve(tmpdir(), "mcp-evidence-gate-bounds-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function invoke(args: string[]) {
  let stdout = "";
  let stderr = "";
  const code = await runCli(args, {
    stdout: (text) => { stdout += text; },
    stderr: (text) => { stderr += text; }
  });
  return { code, stdout, stderr };
}

async function writeOversizedEvidence(directory: string): Promise<string> {
  const path = resolve(directory, "oversized-evidence.json");
  await writeFile(path, Buffer.alloc(limit + 1, 0x61));
  return path;
}

/** Receipt with a well-formed, unbound evidence digest so evidence checks run. */
async function boundReceipt(): Promise<ReceiptInput> {
  const base = JSON.parse(await readFile(validReceiptPath, "utf8")) as ReceiptInput;
  return { ...base, evidence_digest: `sha256:${"0".repeat(64)}` };
}

async function writeBoundReceipt(directory: string): Promise<string> {
  const path = resolve(directory, "bound-receipt.json");
  await writeFile(path, `${JSON.stringify(await boundReceipt(), null, 2)}\n`, "utf8");
  return path;
}

describe("evidence snapshot resource bounds", () => {
  it("rejects an oversized evidence file without retaining its bytes", async () => {
    await withTempDir(async (directory) => {
      const evidencePath = await writeOversizedEvidence(directory);
      const result = await readEvidenceSnapshot(evidencePath);
      expect(result).toEqual({ provided: true, error: "evidence_size_limit_exceeded" });
      expect(result.snapshot).toBeUndefined();
    });
  });

  it("accepts the exact byte limit with a frozen snapshot handle over a detached copy", async () => {
    const source = new Uint8Array(limit).fill(0x62);
    let reads = 0;
    const result = await readEvidenceSnapshot("at-limit.json", async () => {
      reads += 1;
      return source;
    });
    expect(reads).toBe(1);
    expect(result.snapshot).toBeDefined();
    expect(result.snapshot?.bytes.byteLength).toBe(limit);
    expect(Object.is(result.snapshot?.bytes, source)).toBe(false);
    expect(Object.isFrozen(result.snapshot)).toBe(true);
    // The freeze protects the snapshot handle, not the array contents: the
    // copied Uint8Array is a plain view that is read-only by contract.
    expect(Object.isFrozen(result.snapshot?.bytes)).toBe(false);
    expect(() => {
      (result.snapshot as { bytes: Uint8Array }).bytes = new Uint8Array(0);
    }).toThrow(TypeError);
    source.fill(0);
    expect(result.snapshot?.bytes[0]).toBe(0x62);
  });

  it("enforces the size limit for injected readers one byte over the limit", async () => {
    const result = await readEvidenceSnapshot(
      "over-limit.json",
      async () => new Uint8Array(limit + 1).fill(0x63)
    );
    expect(result).toEqual({ provided: true, error: "evidence_size_limit_exceeded" });
    expect(result.snapshot).toBeUndefined();
  });

  it("distinguishes a missing evidence file from an unreadable evidence path", async () => {
    const missing = await readEvidenceSnapshot(resolve(tmpdir(), "definitely-absent-evidence.json"));
    expect(missing).toEqual({ provided: true, error: "evidence_file_missing" });

    await withTempDir(async (directory) => {
      const unreadable = await readEvidenceSnapshot(directory);
      expect(unreadable).toEqual({ provided: true, error: "evidence_file_read_failed" });
      expect(unreadable.snapshot).toBeUndefined();
    });
  });
});

describe("evidence resource limits stay fail-closed", () => {
  it("maps oversized evidence to INCONCLUSIVE, never PASS, under permissive policy", async () => {
    await withTempDir(async (directory) => {
      const evidencePath = await writeOversizedEvidence(directory);
      const receipt = await boundReceipt();
      const verification = await verifyReceipt(receipt, artifactPath, now, { evidencePath });
      const evaluation = evaluatePolicy(receipt, verification, PERMISSIVE_POLICY, now);
      expect(evaluation.decision).toBe("inconclusive");
      expect(evaluation.reasonCodes).toContain("evidence_size_limit_exceeded");
      expect(evaluation.integrityStatus).toBe("inconclusive");
    });
  });

  it("keeps scanner completeness fail-closed for oversized evidence", async () => {
    await withTempDir(async (directory) => {
      const evidencePath = await writeOversizedEvidence(directory);
      const receipt = await boundReceipt();
      const verification = await verifyReceipt(receipt, artifactPath, now, {
        evidencePath,
        requireScannerExecutionCompleteness: true
      });
      const evaluation = evaluatePolicy(receipt, verification, STRICT_SCANNER_COMPLETENESS_POLICY, now);
      expect(evaluation.decision).toBe("inconclusive");
      expect(evaluation.scannerExecutionStatus).toBe("missing");
      expect(evaluation.reasonCodes).toEqual(expect.arrayContaining([
        "evidence_size_limit_exceeded",
        "scanner_execution_missing"
      ]));
      expect(evaluation.reasonCodes).not.toContain("scanner_execution_unverified");
    });
  });

  it("CLI: oversized evidence exits 2 with an explicit reason code", async () => {
    await withTempDir(async (directory) => {
      const evidencePath = await writeOversizedEvidence(directory);
      const receiptPath = await writeBoundReceipt(directory);
      const result = await invoke([
        "verify", "--receipt", receiptPath, "--artifact", artifactPath,
        "--evidence", evidencePath, "--policy", "permissive", "--format", "json",
        "--now", "2026-08-25T00:00:00Z"
      ]);
      const model = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(result.code).toBe(2);
      expect(result.stderr).toBe("");
      expect(model.decision).toBe("inconclusive");
      expect(model.reason_codes).toContain("evidence_size_limit_exceeded");
    });
  });

  it("CLI: an unreadable evidence path reports evidence_file_read_failed", async () => {
    await withTempDir(async (directory) => {
      const receiptPath = await writeBoundReceipt(directory);
      const result = await invoke([
        "verify", "--receipt", receiptPath, "--artifact", artifactPath,
        "--evidence", directory, "--policy", "permissive", "--format", "json",
        "--now", "2026-08-25T00:00:00Z"
      ]);
      const model = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(result.code).toBe(2);
      expect(model.decision).toBe("inconclusive");
      expect(model.reason_codes).toContain("evidence_file_read_failed");
    });
  });
});

describe("receipt input resource budget", () => {
  it("bounded document reader throws a typed error over the receipt limit", async () => {
    await withTempDir(async (directory) => {
      const path = resolve(directory, "oversized-receipt.json");
      await writeFile(path, Buffer.alloc(RECEIPT_INPUT_BUDGET.maxReceiptJsonBytes + 1, 0x7b));
      await expect(readReceiptDocumentBounded(path)).rejects.toBeInstanceOf(ReceiptInputBudgetExceededError);
      await expect(readReceiptDocumentBounded(path)).rejects.toThrow("byte input limit");
    });
  });

  it("CLI: rejects an oversized receipt JSON document as input error", async () => {
    await withTempDir(async (directory) => {
      const receiptPath = resolve(directory, "oversized-receipt.json");
      await writeFile(receiptPath, Buffer.alloc(RECEIPT_INPUT_BUDGET.maxReceiptJsonBytes + 1, 0x7b));
      const result = await invoke([
        "verify", "--receipt", receiptPath, "--artifact", artifactPath,
        "--policy", "permissive", "--now", "2026-08-25T00:00:00Z"
      ]);
      expect(result.code).toBe(3);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("byte input limit");
    });
  });

  it("CLI: rejects an oversized receipt-set manifest as input error", async () => {
    await withTempDir(async (directory) => {
      const manifestPath = resolve(directory, "set.json");
      await writeFile(manifestPath, Buffer.alloc(RECEIPT_INPUT_BUDGET.maxReceiptSetManifestBytes + 1, 0x20));
      const result = await invoke([
        "verify-set", "--set", manifestPath, "--artifact", artifactPath,
        "--policy", "permissive", "--now", "2026-08-25T00:00:00Z"
      ]);
      expect(result.code).toBe(3);
      expect(result.stderr).toContain("byte input limit");
    });
  });

  it("CLI: rejects a receipt set over the entry limit before reading any receipt", async () => {
    await withTempDir(async (directory) => {
      const manifestPath = resolve(directory, "set.json");
      const receipts = Array.from({ length: RECEIPT_INPUT_BUDGET.maxReceiptSetEntries + 1 }, (_, index) => ({
        id: `entry-${index}`,
        receipt: "missing-receipt.json"
      }));
      await writeFile(manifestPath, JSON.stringify({ schema_version: "project-defined-receipt-set-v1", receipts }));
      const result = await invoke([
        "verify-set", "--set", manifestPath, "--artifact", artifactPath,
        "--policy", "permissive", "--now", "2026-08-25T00:00:00Z"
      ]);
      expect(result.code).toBe(3);
      expect(result.stderr).toContain("entry limit");
      expect(result.stderr).not.toContain("ENOENT");
    });
  });

  it("CLI: rejects a receipt set whose cumulative receipt bytes exceed the set budget", async () => {
    await withTempDir(async (directory) => {
      const padding = "a".repeat(RECEIPT_INPUT_BUDGET.maxReceiptJsonBytes - 10);
      const largeReceipt = `${JSON.stringify({ pad: padding })}`;
      expect(Buffer.byteLength(largeReceipt)).toBe(RECEIPT_INPUT_BUDGET.maxReceiptJsonBytes);
      const manifestPath = resolve(directory, "set.json");
      const receipts = Array.from({ length: 4 }, (_, index) => ({ id: `large-${index}`, receipt: "large.json" }));
      receipts.push({ id: "sentinel", receipt: "sentinel.json" });
      for (const name of ["large.json", "sentinel.json"]) {
        const body = name === "large.json" ? largeReceipt : "{}";
        await writeFile(resolve(directory, name), body);
      }
      await writeFile(manifestPath, JSON.stringify({ schema_version: "project-defined-receipt-set-v1", receipts }));
      const result = await invoke([
        "verify-set", "--set", manifestPath, "--artifact", artifactPath,
        "--policy", "permissive", "--now", "2026-08-25T00:00:00Z"
      ]);
      expect(result.code).toBe(3);
      expect(result.stderr).toContain("total input limit");
    });
  });

  it("CLI: keeps duplicate receipt paths within the same budget", async () => {
    await withTempDir(async (directory) => {
      const manifestPath = resolve(directory, "set.json");
      const receipts = Array.from({ length: RECEIPT_INPUT_BUDGET.maxReceiptSetEntries }, () => ({
        receipt: validReceiptPath
      }));
      await writeFile(manifestPath, JSON.stringify({ schema_version: "project-defined-receipt-set-v1", receipts }));
      const result = await invoke([
        "verify-set", "--set", manifestPath, "--artifact", artifactPath,
        "--policy", "permissive", "--now", "2026-08-25T00:00:00Z"
      ]);
      expect(result.code).toBe(0);
      expect(result.stdout).toContain("Decision: PASS");
    });
  });
});
