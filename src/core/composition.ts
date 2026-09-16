import { sha256Artifact } from "./digest.js";
import {
  evaluatePolicy,
  type IntegrityStatus,
  type PolicyConfig,
  type PolicyDecision,
  type PolicyEvaluation,
  type ReceiptStatus
} from "./policy.js";
import { verifyReceipt } from "./verify.js";
import type { ReceiptInput, VerificationResult } from "./types.js";

export interface ReceiptSetEntryInput {
  receipt: ReceiptInput;
  evidencePath?: string;
  id?: string;
}

export interface ReceiptSetEntryEvaluation {
  index: number;
  id?: string;
  scanner: string;
  verification: VerificationResult;
  evaluation: PolicyEvaluation;
}

export interface ReceiptSetEvaluation {
  profile: VerificationResult["profile"];
  policy: string;
  evaluatedAt: string;
  artifactDigest: string;
  receiptCount: number;
  decision: PolicyDecision;
  integrityStatus: IntegrityStatus;
  receiptStatus: ReceiptStatus;
  policyStatus: PolicyDecision;
  admissionStatus: PolicyDecision;
  reasonCodes: string[];
  receipts: ReceiptSetEntryEvaluation[];
}

// This is the established downstream policy severity contract. It is repeated
// here intentionally so P2-003 does not perturb the existing single-receipt
// policy module and therefore does not rewrite the shipped Action bundle.
const COMPOSITION_RANK: Readonly<Record<PolicyDecision, number>> = {
  pass: 0,
  warn: 1,
  inconclusive: 2,
  fail: 3
};

function highestCompositionDecision(decisions: readonly PolicyDecision[]): PolicyDecision {
  return decisions.reduce<PolicyDecision>(
    (current, decision) =>
      COMPOSITION_RANK[decision] > COMPOSITION_RANK[current] ? decision : current,
    "pass"
  );
}

function highestIntegrityStatus(statuses: readonly IntegrityStatus[]): IntegrityStatus {
  if (statuses.includes("invalid")) return "invalid";
  if (statuses.includes("inconclusive")) return "inconclusive";
  return "pass";
}

/**
 * Verify and evaluate independent receipts against one shared artifact and one
 * policy, then compose only their downstream admission decisions.
 *
 * Composition never rewrites scanner verdicts and never creates a synthetic
 * SecurityScanReceipt. Each receipt keeps its complete verification and policy
 * evidence, while the aggregate decision uses the established severity order
 * pass < warn < inconclusive < fail.
 */
export async function evaluateReceiptSet(
  entries: readonly ReceiptSetEntryInput[],
  artifactPath: string,
  now: Date,
  policy: PolicyConfig
): Promise<ReceiptSetEvaluation> {
  if (entries.length === 0) {
    throw new Error("receipt_set_empty");
  }

  const evaluatedAt = now.toISOString();
  const artifactDigest = await sha256Artifact(artifactPath);
  const receipts: ReceiptSetEntryEvaluation[] = [];

  for (const [index, entry] of entries.entries()) {
    const verification = await verifyReceipt(entry.receipt, artifactPath, now, {
      maxScanAgeMs: policy.maxScanAgeMs,
      clockSkewMs: policy.clockSkewMs,
      evidencePath: entry.evidencePath,
      requireScannerExecutionCompleteness: policy.requireScannerExecutionCompleteness
    });
    if (verification.evaluatedAt !== evaluatedAt) {
      throw new Error("receipt_set_evaluation_time_drift");
    }

    // The set-level artifact identity is frozen at entry. Re-hash after every
    // receipt evaluation so a concurrent file rewrite cannot silently turn one
    // logical set into evaluations of different persistent artifact states.
    if (await sha256Artifact(artifactPath) !== artifactDigest) {
      throw new Error("receipt_set_artifact_drift");
    }

    receipts.push({
      index,
      ...(entry.id ? { id: entry.id } : {}),
      scanner: typeof entry.receipt.scanner === "string" ? entry.receipt.scanner : "unknown",
      verification,
      evaluation: evaluatePolicy(entry.receipt, verification, policy, now)
    });
  }

  const profiles = new Set(receipts.map((entry) => entry.verification.profile));
  if (profiles.size !== 1) {
    throw new Error("receipt_set_profile_mismatch");
  }

  const decision = highestCompositionDecision(receipts.map((entry) => entry.evaluation.decision));
  return {
    profile: receipts[0].verification.profile,
    policy: policy.name,
    evaluatedAt,
    artifactDigest,
    receiptCount: receipts.length,
    decision,
    integrityStatus: highestIntegrityStatus(receipts.map((entry) => entry.evaluation.integrityStatus)),
    receiptStatus: receipts.some((entry) => entry.evaluation.receiptStatus === "invalid") ? "invalid" : "valid",
    policyStatus: decision,
    admissionStatus: decision,
    reasonCodes: [...new Set(receipts.flatMap((entry) => entry.evaluation.reasonCodes))],
    receipts
  };
}
