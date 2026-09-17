import { REGISTRY_PR_1404_PROFILE } from "../profiles/registry-pr-1404.js";
import {
  readEvidenceSnapshot,
  verifyArtifactBinding,
  verifyEvidenceBindingBytes
} from "./digest.js";
import { evaluateFreshness } from "./freshness.js";
import { validateInconclusiveReason } from "./inconclusive.js";
import { verifyScannerExecutionBytes } from "./scanner-execution.js";
import { validateScanScope } from "./scope.js";
import { validateReceiptStructure } from "./structural.js";
import type { FreshnessOptions } from "./freshness.js";
import type { ReceiptInput, VerificationResult } from "./types.js";

export interface VerificationOptions extends Omit<FreshnessOptions, "now"> {
  evidencePath?: string;
  /** Opt into the project-defined scanner execution evidence contract. */
  requireScannerExecutionCompleteness?: boolean;
}

export async function verifyReceiptEvidence(
  receipt: ReceiptInput,
  artifactPath: string,
  now: Date,
  freshnessOptions: VerificationOptions = {}
): Promise<VerificationResult> {
  // Read an explicitly supplied evidence path exactly once. Both the digest
  // binding check and the opt-in scanner semantics check consume this same
  // detached snapshot, eliminating a path replacement TOCTOU window.
  const evidence = await readEvidenceSnapshot(freshnessOptions.evidencePath);
  return {
    profile: REGISTRY_PR_1404_PROFILE.id,
    evaluatedAt: now.toISOString(),
    checks: [
      await verifyArtifactBinding(receipt.scanned_artifact_digest, artifactPath),
      evaluateFreshness(receipt.freshness_expires_at, {
        now,
        scannedAt: receipt.scanned_at,
        ...freshnessOptions
      }),
      validateScanScope(receipt.scan_scope),
      validateInconclusiveReason(receipt.verdict, receipt.inconclusive_reason),
      ...(receipt.evidence_digest !== undefined || freshnessOptions.evidencePath
        ? [verifyEvidenceBindingBytes(receipt.evidence_digest, evidence)] : []),
      ...(freshnessOptions.requireScannerExecutionCompleteness
        ? [verifyScannerExecutionBytes(evidence, receipt)]
        : [])
    ]
  };
}

export async function verifyReceipt(
  receipt: ReceiptInput,
  artifactPath: string,
  now: Date,
  freshnessOptions: VerificationOptions = {}
): Promise<VerificationResult> {
  const structure = validateReceiptStructure(receipt);
  if (structure.status !== "pass") {
    return {
      profile: REGISTRY_PR_1404_PROFILE.id,
      evaluatedAt: now.toISOString(),
      checks: [structure]
    };
  }
  const evidence = await verifyReceiptEvidence(receipt, artifactPath, now, freshnessOptions);
  return {
    profile: evidence.profile,
    evaluatedAt: evidence.evaluatedAt,
    checks: [structure, ...evidence.checks]
  };
}
