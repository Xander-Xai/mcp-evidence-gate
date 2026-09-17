import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import {
  evaluatePolicy,
  PERMISSIVE_POLICY,
  STRICT_SCANNER_COMPLETENESS_POLICY
} from "../src/core/policy.js";
import {
  readEvidenceSnapshot,
  sha256Bytes,
  verifyEvidenceBindingBytes
} from "../src/core/digest.js";
import { verifyScannerExecutionBytes } from "../src/core/scanner-execution.js";
import { verifyReceipt } from "../src/core/verify.js";
import type { ReceiptInput } from "../src/core/types.js";

const root = resolve(import.meta.dirname, "..");
const artifactPath = resolve(root, "fixtures/artifacts/current-artifact.bin");
const now = new Date("2026-08-25T00:00:00Z");

type ExecutionStatus = "complete" | "incomplete" | "failed";

function completeExecution(): Record<string, unknown> {
  return {
    schema_version: "project-defined-scanner-execution-v1",
    scanner_contract: "abstract-scanner-json-v1",
    invocation_started: true,
    process_completed: true,
    exit_code: 0,
    exit_state_valid: true,
    output_present: true,
    output_exists: true,
    output_size: 12,
    output_parseable: true,
    required_components: ["scanner_process", "scanner_output", "result_sections"],
    completed_components: ["scanner_process", "scanner_output", "result_sections"],
    failed_components: [],
    completeness_status: "complete",
    completeness_reason: "all_required_scanner_work_completed",
    required_work_completed: true,
    result_semantics_consistent: true
  };
}

function evidenceFor(execution: Record<string, unknown> | undefined): Record<string, unknown> {
  return {
    schema_version: "project-defined-evidence-manifest-v1",
    scanner_execution: execution,
    raw_report: { exists: true, present: true, size: 12 }
  };
}

async function materialize(
  execution: Record<string, unknown> | undefined,
  options: { tamperAfterBinding?: boolean } = {}
): Promise<{ receipt: ReceiptInput; receiptPath: string; evidencePath: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(resolve(tmpdir(), "mcp-evidence-gate-scanner-"));
  const evidencePath = resolve(directory, "evidence.json");
  const evidence = evidenceFor(execution);
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  await writeFile(evidencePath, bytes);
  const receipt: ReceiptInput = {
    scanner: "example-scanner",
    scanned_artifact_digest: "sha256:41f89c83905a2335098d6acf5a8fe9e490ee2b4747229e46349cfdf4e3973c78",
    scan_scope: ["package"],
    verdict: "clean",
    scanned_at: "2026-08-25T00:00:00Z",
    attestation: "publisher-asserted",
    evidence_digest: sha256Bytes(bytes)
  };
  const receiptPath = resolve(directory, "receipt.json");
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  if (options.tamperAfterBinding) {
    const tampered = { ...evidence, scanner_execution: { ...execution, completeness_status: "failed" } };
    await writeFile(evidencePath, `${JSON.stringify(tampered, null, 2)}\n`, "utf8");
  }
  return { receipt, receiptPath, evidencePath, cleanup: () => rm(directory, { recursive: true, force: true }) };
}

async function evaluateCase(
  status: ExecutionStatus | "missing" | "malformed" | "contradictory",
  options: { tamperAfterBinding?: boolean } = {}
) {
  const execution = status === "missing" ? undefined : completeExecution();
  if (status === "incomplete") {
    execution!.completeness_status = "incomplete";
    execution!.required_work_completed = false;
    execution!.result_semantics_consistent = false;
    execution!.completed_components = ["scanner_process", "scanner_output"];
    execution!.failed_components = ["result_sections"];
  }
  if (status === "failed") {
    execution!.completeness_status = "failed";
    execution!.required_work_completed = false;
    execution!.process_completed = false;
    execution!.exit_state_valid = false;
    execution!.exit_code = null;
    execution!.completed_components = ["scanner_output"];
    execution!.failed_components = ["scanner_process"];
  }
  if (status === "malformed") {
    execution!.completeness_status = "not-a-status";
  }
  if (status === "contradictory") {
    execution!.process_completed = false;
  }
  const materialized = await materialize(execution, options);
  const verification = await verifyReceipt(materialized.receipt, artifactPath, now, {
    evidencePath: materialized.evidencePath,
    requireScannerExecutionCompleteness: true
  });
  const evaluation = evaluatePolicy(
    materialized.receipt,
    verification,
    STRICT_SCANNER_COMPLETENESS_POLICY,
    now
  );
  return { ...materialized, verification, evaluation };
}

describe("strict scanner execution completeness policy", () => {
  it("uses consumer-owned contracts, identity binding, and exit-code policy", async () => {
    const execution: Record<string, unknown> = {
      ...completeExecution(),
      scanner_contract: "trivy-fs-json-v1",
      required_components: ["scanner_process", "scanner_output", "result_sections", "artifact_binding", "result_semantics"],
      completed_components: ["scanner_process", "scanner_output", "result_sections", "artifact_binding", "result_semantics"]
    };
    const bytes = Buffer.from(JSON.stringify({ scanner: { name: "trivy", version: "0.1.0" }, scanner_execution: execution }));
    const snapshot = await readEvidenceSnapshot("known.json", async () => bytes);
    expect(verifyScannerExecutionBytes(snapshot, { scanner: "trivy", scanner_version: "0.1.0" })).toMatchObject({ status: "pass" });
    expect(verifyScannerExecutionBytes(snapshot, { scanner: "osv-scanner", scanner_version: "0.1.0" })).toMatchObject({ reason: "scanner_execution_contract_mismatch" });
    execution.exit_code = 999;
    const illegal = await readEvidenceSnapshot("illegal.json", async () => Buffer.from(JSON.stringify({ scanner: { name: "trivy", version: "0.1.0" }, scanner_execution: execution })));
    expect(verifyScannerExecutionBytes(illegal, { scanner: "trivy", scanner_version: "0.1.0" })).toMatchObject({ reason: "scanner_execution_exit_code_invalid" });
  });

  it("records the legacy permissive false-clean gap while strict policy blocks it", async () => {
    const materialized = await materialize({
      ...completeExecution(),
      completeness_status: "failed",
      required_work_completed: false,
      process_completed: false,
      exit_state_valid: false,
      exit_code: null,
      completed_components: ["scanner_output"],
      failed_components: ["scanner_process"]
    });
    try {
      const legacyVerification = await verifyReceipt(materialized.receipt, artifactPath, now, {
        evidencePath: materialized.evidencePath
      });
      expect(evaluatePolicy(materialized.receipt, legacyVerification, PERMISSIVE_POLICY).decision).toBe("pass");

      const strictVerification = await verifyReceipt(materialized.receipt, artifactPath, now, {
        evidencePath: materialized.evidencePath,
        requireScannerExecutionCompleteness: true
      });
      const strict = evaluatePolicy(materialized.receipt, strictVerification, STRICT_SCANNER_COMPLETENESS_POLICY, now);
      expect(strict.decision).not.toBe("pass");
      expect(strict.reasons.map((reason) => reason.code)).toContain("scanner_execution_failed");
    } finally {
      await materialized.cleanup();
    }
  });

  it("keeps a complete clean execution eligible", async () => {
    const result = await evaluateCase("complete");
    try {
      expect(result.evaluation.decision).toBe("pass");
      expect(result.evaluation.integrityStatus).toBe("pass");
      expect(result.evaluation.receiptStatus).toBe("valid");
      expect(result.evaluation.scannerExecutionStatus).toBe("complete");
      expect(result.verification.checks).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: "scanner_execution", status: "pass" })
      ]));
    } finally {
      await result.cleanup();
    }
  });

  it.each([
    ["incomplete", "scanner_execution_incomplete"],
    ["failed", "scanner_execution_failed"],
    ["missing", "scanner_execution_missing"],
    ["malformed", "scanner_execution_malformed"],
    ["contradictory", "scanner_execution_contradictory"]
  ] as const)("blocks strict policy for %s execution", async (status, reasonCode) => {
    const result = await evaluateCase(status);
    try {
      expect(result.evaluation.decision).not.toBe("pass");
      expect(result.evaluation.reasonCodes).toContain(reasonCode);
      expect(result.evaluation.admissionStatus).not.toBe("pass");
      expect(result.evaluation.scannerExecutionStatus).toBe(status);
    } finally {
      await result.cleanup();
    }
  });

  it("keeps a tampered execution inconclusive rather than trusting its semantic status", async () => {
    const result = await evaluateCase("complete", { tamperAfterBinding: true });
    try {
      expect(result.evaluation.integrityStatus).toBe("inconclusive");
      expect(result.evaluation.decision).toBe("inconclusive");
      expect(result.evaluation.reasonCodes).toEqual(expect.arrayContaining([
        "evidence_digest_mismatch",
        "scanner_execution_unverified"
      ]));
      expect(result.evaluation.scannerExecutionStatus).toBe("unverified");
    } finally {
      await result.cleanup();
    }
  });

  it("does not enable scanner completeness checks in legacy mode", async () => {
    const result = await materialize({
      ...completeExecution(),
      completeness_status: "failed",
      required_work_completed: false,
      process_completed: false,
      exit_state_valid: false,
      exit_code: null,
      completed_components: ["scanner_output"],
      failed_components: ["scanner_process"]
    });
    try {
      const verification = await verifyReceipt(result.receipt, artifactPath, now, { evidencePath: result.evidencePath });
      expect(verification.checks.some((check) => check.id === "scanner_execution")).toBe(false);
      expect(evaluatePolicy(result.receipt, verification, PERMISSIVE_POLICY).decision).toBe("pass");
    } finally {
      await result.cleanup();
    }
  });

  it("requires a locally bound evidence report for the strict policy", async () => {
    const base = JSON.parse(await readFile(resolve(root, "fixtures/valid/complete-clean.json"), "utf8")) as ReceiptInput;
    const verification = await verifyReceipt(base, artifactPath, now);
    const evaluation = evaluatePolicy(base, verification, STRICT_SCANNER_COMPLETENESS_POLICY, now);
    expect(evaluation.decision).toBe("inconclusive");
    expect(evaluation.scannerExecutionStatus).toBe("missing");
    expect(evaluation.reasonCodes).toEqual(expect.arrayContaining([
      "evidence_binding_required",
      "scanner_execution_missing"
    ]));
  });

  it("keeps an explicitly missing evidence file as missing under strict policy", async () => {
    const base = JSON.parse(await readFile(resolve(root, "fixtures/valid/complete-clean.json"), "utf8")) as ReceiptInput;
    const receipt = { ...base, evidence_digest: `sha256:${"0".repeat(64)}` };
    const verification = await verifyReceipt(receipt, artifactPath, now, {
      evidencePath: resolve(root, "fixtures/does-not-exist-evidence.json"),
      requireScannerExecutionCompleteness: true
    });
    const evaluation = evaluatePolicy(receipt, verification, STRICT_SCANNER_COMPLETENESS_POLICY, now);
    expect(evaluation.scannerExecutionStatus).toBe("missing");
    expect(evaluation.reasonCodes).toEqual(expect.arrayContaining([
      "evidence_file_missing",
      "scanner_execution_missing"
    ]));
    expect(evaluation.reasonCodes).not.toContain("scanner_execution_unverified");
  });

  it("keeps present but digest-mismatched scanner bytes unverified", async () => {
    const result = await materialize(completeExecution());
    try {
      const receipt = { ...result.receipt, evidence_digest: `sha256:${"0".repeat(64)}` };
      const verification = await verifyReceipt(receipt, artifactPath, now, {
        evidencePath: result.evidencePath,
        requireScannerExecutionCompleteness: true
      });
      const evaluation = evaluatePolicy(receipt, verification, STRICT_SCANNER_COMPLETENESS_POLICY, now);
      expect(evaluation.scannerExecutionStatus).toBe("unverified");
      expect(evaluation.reasonCodes).toContain("scanner_execution_unverified");
      expect(evaluation.reasonCodes).toContain("evidence_digest_mismatch");
    } finally {
      await result.cleanup();
    }
  });

  it("binds digest and scanner semantics to one detached evidence snapshot", async () => {
    const incomplete = {
      ...completeExecution(),
      completeness_status: "incomplete",
      required_work_completed: false,
      result_semantics_consistent: false,
      completed_components: ["scanner_process", "scanner_output"],
      failed_components: ["result_sections"]
    };
    const bytesA = Buffer.from(`${JSON.stringify(evidenceFor(incomplete))}\n`, "utf8");
    const bytesB = Buffer.from(`${JSON.stringify(evidenceFor(completeExecution()))}\n`, "utf8");
    const sourceBytes = Uint8Array.from(bytesA);
    let reads = 0;
    const evidence = await readEvidenceSnapshot("virtual-evidence.json", async () => {
      reads += 1;
      return reads === 1 ? sourceBytes : bytesB;
    });
    sourceBytes.fill(0);

    const binding = verifyEvidenceBindingBytes(sha256Bytes(bytesA), evidence);
    const scanner = verifyScannerExecutionBytes(evidence);
    expect(reads).toBe(1);
    expect(binding).toMatchObject({ id: "evidence_binding", status: "pass" });
    expect(scanner).toMatchObject({
      id: "scanner_execution",
      status: "invalid",
      reason: "scanner_execution_incomplete"
    });
  });

  it("exposes integrity, receipt, policy, admission, and reason layers in CLI JSON", async () => {
    const result = await evaluateCase("incomplete");
    try {
      let stdout = "";
      let stderr = "";
      const code = await runCli([
        "verify",
        "--receipt",
        result.receiptPath,
        "--artifact",
        artifactPath,
        "--evidence",
        result.evidencePath,
        "--policy",
        "strict-scanner-completeness",
        "--format",
        "json",
        "--now",
        now.toISOString()
      ], {
        stdout: (text) => { stdout += text; },
        stderr: (text) => { stderr += text; }
      });
      const model = JSON.parse(stdout) as Record<string, unknown>;
      expect(code).toBe(1);
      expect(stderr).toBe("");
      expect(model).toMatchObject({
        policy: "strict-scanner-completeness",
        integrity_status: "pass",
        receipt_status: "valid",
        policy_status: "fail",
        admission_status: "fail",
        scanner_execution_status: "incomplete"
      });
      expect(model.reason_codes).toEqual(expect.arrayContaining(["scanner_execution_incomplete"]));
    } finally {
      await result.cleanup();
    }
  });
});
