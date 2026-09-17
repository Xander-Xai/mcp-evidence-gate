import { REGISTRY_PR_1404_PROFILE } from "../profiles/registry-pr-1404.js";
import {
  SCANNER_EXECUTION_POLICY_VERSION,
  type ScannerExecutionOutputStatus
} from "./scanner-execution.js";
import { evaluateFreshness } from "./freshness.js";
import type { Finding, ReceiptInput, VerificationResult } from "./types.js";

export type PolicyDecision = "pass" | "warn" | "inconclusive" | "fail";
export type Attestation = (typeof REGISTRY_PR_1404_PROFILE.attestations)[number];
export type IntegrityStatus = "pass" | "inconclusive" | "invalid";
export type ReceiptStatus = "valid" | "invalid";

export interface PolicyConfig {
  name: string;
  requireFreshness: boolean;
  requiredScopes: readonly string[];
  allowedAttestations: readonly Attestation[];
  maxScanAgeMs?: number;
  clockSkewMs?: number;
  warningDisposition: "allow" | "block";
  requireEvidenceBinding: boolean;
  /** Explicit opt-in to the producer-owned scanner execution contract. */
  requireScannerExecutionCompleteness?: boolean;
  /** Version for a project-defined local policy extension, when applicable. */
  policyVersion?: string;
}

export interface PolicyReason {
  code: string;
  decision: PolicyDecision;
  detail: string;
}

export interface PolicyEvaluation {
  policy: string;
  profile: typeof REGISTRY_PR_1404_PROFILE.id;
  decision: PolicyDecision;
  reasons: PolicyReason[];
  receiptVerdict: string;
  /** Integrity of the artifact/evidence bindings, separate from admission. */
  integrityStatus: IntegrityStatus;
  /** Structural validity of the Registry receipt, separate from policy. */
  receiptStatus: ReceiptStatus;
  /** Policy result before any future outer release orchestration. */
  policyStatus: PolicyDecision;
  /** Current Core admission result; kept explicit as a separate layer. */
  admissionStatus: PolicyDecision;
  scannerExecutionStatus: ScannerExecutionOutputStatus;
  reasonCodes: string[];
  policyVersion?: string;
}

export const PERMISSIVE_POLICY: PolicyConfig = {
  name: "permissive",
  requireFreshness: false,
  requiredScopes: [],
  allowedAttestations: REGISTRY_PR_1404_PROFILE.attestations,
  clockSkewMs: 5 * 60 * 1000,
  warningDisposition: "allow",
  requireEvidenceBinding: false,
  requireScannerExecutionCompleteness: false
};

export const STRICT_RELEASE_EXAMPLE_POLICY: PolicyConfig = {
  name: "strict-release-example",
  requireFreshness: true,
  requiredScopes: ["package", "handler-validation"],
  allowedAttestations: ["third-party-attested"],
  maxScanAgeMs: 7 * 24 * 60 * 60 * 1000,
  clockSkewMs: 5 * 60 * 1000,
  warningDisposition: "block",
  requireEvidenceBinding: false,
  requireScannerExecutionCompleteness: false
};

export const STRICT_EVIDENCE_EXAMPLE_POLICY: PolicyConfig = {
  ...STRICT_RELEASE_EXAMPLE_POLICY,
  name: "strict-evidence-example",
  requireEvidenceBinding: true
};

/**
 * Local admission policy for consumer-owned scanner execution contracts.
 * Registry PR #1404 remains unchanged; this policy only opts a consumer into
 * interpreting the versioned evidence extension.
 */
export const STRICT_SCANNER_COMPLETENESS_POLICY: PolicyConfig = {
  ...PERMISSIVE_POLICY,
  name: "strict-scanner-completeness",
  requireEvidenceBinding: true,
  requireScannerExecutionCompleteness: true,
  policyVersion: SCANNER_EXECUTION_POLICY_VERSION
};

export function policyByName(name: string): PolicyConfig {
  if (name === PERMISSIVE_POLICY.name) return PERMISSIVE_POLICY;
  if (name === STRICT_RELEASE_EXAMPLE_POLICY.name) return STRICT_RELEASE_EXAMPLE_POLICY;
  if (name === STRICT_EVIDENCE_EXAMPLE_POLICY.name) return STRICT_EVIDENCE_EXAMPLE_POLICY;
  if (name === STRICT_SCANNER_COMPLETENESS_POLICY.name) return STRICT_SCANNER_COMPLETENESS_POLICY;
  throw new Error(`unknown policy: ${name}`);
}

const RANK: Record<PolicyDecision, number> = {
  pass: 0,
  warn: 1,
  inconclusive: 2,
  fail: 3
};

function highestDecision(reasons: readonly PolicyReason[]): PolicyDecision {
  return reasons.reduce<PolicyDecision>(
    (current, reason) => (RANK[reason.decision] > RANK[current] ? reason.decision : current),
    "pass"
  );
}

function bindingIntegrity(
  verification: VerificationResult,
  policy: PolicyConfig,
  structure: Finding | undefined
): IntegrityStatus {
  if (structure?.status === "invalid") return "invalid";
  const artifact = verification.checks.find((check) => check.id === "artifact_binding");
  const evidence = verification.checks.find((check) => check.id === "evidence_binding");
  let status: IntegrityStatus = "pass";
  for (const [kind, check] of [["artifact", artifact], ["evidence", evidence]] as const) {
    if (!check) {
      if (kind === "artifact") status = "inconclusive";
      continue;
    }
    if (check.status === "invalid") status = "invalid";
    else if (
      check.status !== "pass" &&
      !(kind === "evidence" && check.status === "not_present" && check.reason === "evidence_file_not_provided" && !policy.requireEvidenceBinding) &&
      status !== "invalid"
    ) status = "inconclusive";
  }
  if (policy.requireEvidenceBinding && evidence?.status !== "pass" && status === "pass") {
    status = evidence?.status === "invalid" ? "invalid" : "inconclusive";
  }
  return status;
}

function scannerStatusFor(
  scanner: Finding | undefined,
  integrityTrusted: boolean
): ScannerExecutionOutputStatus {
  if (!scanner) return "missing";
  if (!integrityTrusted) {
    return scanner.reason === "scanner_execution_missing" ? "missing" : "unverified";
  }
  if (scanner.status === "pass") return "complete";
  if (scanner.reason === "scanner_execution_incomplete") return "incomplete";
  if (scanner.reason === "scanner_execution_failed") return "failed";
  if (scanner.reason === "scanner_execution_malformed") return "malformed";
  if (scanner.reason === "scanner_execution_contradictory") return "contradictory";
  if (scanner.reason === "scanner_execution_required_components_mismatch") return "contradictory";
  if (scanner.reason === "scanner_execution_contract_unsupported" || scanner.reason === "scanner_execution_contract_mismatch" || scanner.reason === "scanner_identity_mismatch" || scanner.reason === "scanner_version_mismatch" || scanner.reason === "scanner_execution_exit_code_invalid") return "malformed";
  if (scanner.reason === "scanner_execution_missing" || scanner.status === "not_present") return "missing";
  return "unverified";
}

function scannerDetail(status: ScannerExecutionOutputStatus): string {
  switch (status) {
    case "incomplete": return "The evidence report states that required scanner work was not completed.";
    case "failed": return "The evidence report states that the scanner execution failed.";
    case "missing": return "A bound evidence report with scanner execution completeness is required by this policy.";
    case "malformed": return "The scanner execution evidence violates the consumer-owned scanner contract.";
    case "contradictory": return "The scanner execution status contradicts its component and result fields.";
    case "unverified": return "Scanner execution semantics cannot be trusted until evidence binding is verified.";
    default: return "Scanner execution completeness is not proven.";
  }
}

function finish(
  receipt: ReceiptInput,
  verification: VerificationResult,
  policy: PolicyConfig,
  reasons: PolicyReason[],
  scannerExecutionStatus: ScannerExecutionOutputStatus,
  integrityStatus: IntegrityStatus,
  receiptStatus: ReceiptStatus
): PolicyEvaluation {
  reasons.sort((left, right) => RANK[right.decision] - RANK[left.decision]);
  const decision = highestDecision(reasons);
  return {
    policy: policy.name,
    profile: REGISTRY_PR_1404_PROFILE.id,
    decision,
    reasons,
    receiptVerdict: typeof receipt.verdict === "string" ? receipt.verdict : "unknown",
    integrityStatus,
    receiptStatus,
    policyStatus: decision,
    admissionStatus: decision,
    scannerExecutionStatus,
    reasonCodes: reasons.map((reason) => reason.code),
    ...(policy.policyVersion ? { policyVersion: policy.policyVersion } : {})
  };
}

export function evaluatePolicy(
  receipt: ReceiptInput,
  verification: VerificationResult,
  policy: PolicyConfig,
  _now?: Date
): PolicyEvaluation {
  const now = new Date(verification.evaluatedAt);
  if (Number.isNaN(now.getTime())) throw new Error("invalid_evaluated_at");
  const reasons: PolicyReason[] = [];
  const add = (code: string, decision: PolicyDecision, detail: string) =>
    reasons.push({ code, decision, detail });
  const structure = verification.checks.find((check) => check.id === "receipt_structure");
  const receiptStatus: ReceiptStatus = structure?.status === "pass" ? "valid" : "invalid";
  let integrityStatus = bindingIntegrity(verification, policy, structure);
  const scanner = verification.checks.find((check) => check.id === "scanner_execution");

  if (structure?.status === "invalid") {
    add("receipt_structure_invalid", "fail", "Receipt failed the pinned structural conformance profile.");
    return finish(receipt, verification, policy, reasons, "not_evaluated", integrityStatus, receiptStatus);
  }

  for (const check of verification.checks) {
    if (check.id === "artifact_binding" && check.status === "mismatch") {
      add("artifact_digest_mismatch", "inconclusive", "Receipt digest does not bind to the current artifact.");
    }
    if (check.id === "artifact_binding" && check.status === "unsupported") {
      add("unsupported_digest_algorithm", "inconclusive", "The receipt digest algorithm is not supported by this verifier.");
    }
    if (check.id === "freshness" && check.status === "inconclusive") {
      add(
        check.reason === "scan_too_old" ? "scan_too_old" : "stale_scan",
        "inconclusive",
        check.reason === "scan_too_old"
          ? "Receipt scanned_at exceeds the maximum age allowed by policy."
          : "Receipt freshness has expired and cannot support a clean claim."
      );
    }
    if (
      check.status === "invalid" &&
      check.id !== "receipt_structure" &&
      check.id !== "evidence_binding" &&
      check.id !== "scanner_execution"
    ) {
      add("evidence_check_invalid", "fail", `${check.id} evidence check is invalid.`);
    }
  }

  // A policy owns its max-age rule. This second evaluation closes the library
  // two-step API gap when callers do not forward policy freshness options to
  // verifyReceipt(). Avoid adding a duplicate reason when verification already
  // evaluated the same max-age constraint.
  if (
    policy.maxScanAgeMs !== undefined &&
    !reasons.some((reason) => reason.code === "scan_too_old")
  ) {
    const policyFreshness = evaluateFreshness(receipt.freshness_expires_at, {
      now,
      scannedAt: receipt.scanned_at,
      maxScanAgeMs: policy.maxScanAgeMs,
      clockSkewMs: policy.clockSkewMs
    });
    if (policyFreshness.reason === "scan_too_old") {
      add("scan_too_old", "inconclusive", "Receipt scanned_at exceeds the maximum age allowed by policy.");
    }
  }

  const evidence = verification.checks.find((check) => check.id === "evidence_binding");
  if (evidence) {
    if (evidence.status === "mismatch") {
      add("evidence_digest_mismatch", "inconclusive", "Evidence report digest does not bind to the receipt.");
    } else if (evidence.status === "unsupported") {
      add("unsupported_evidence_digest_algorithm", "inconclusive", "The evidence digest algorithm is not supported by this verifier.");
    } else if (evidence.status === "not_present" && evidence.reason === "evidence_file_missing") {
      add("evidence_file_missing", "inconclusive", "An explicitly supplied evidence report could not be read.");
    } else if (evidence.status === "invalid") {
      add("evidence_binding_invalid", "fail", "Evidence digest binding is invalid.");
    }
  }

  if (policy.requireEvidenceBinding && (!evidence || (evidence.status === "not_present" && evidence.reason !== "evidence_file_missing"))) {
    add("evidence_binding_required", "inconclusive", "This policy requires a locally provided evidence report bound by digest.");
    if (integrityStatus === "pass") integrityStatus = "inconclusive";
  }

  let scannerExecutionStatus: ScannerExecutionOutputStatus = "not_evaluated";
  if (policy.requireScannerExecutionCompleteness) {
    const artifact = verification.checks.find((check) => check.id === "artifact_binding");
    const evidenceTrusted = evidence?.status === "pass";
    const integrityTrusted = artifact?.status === "pass" && evidenceTrusted;
    scannerExecutionStatus = scannerStatusFor(scanner, integrityTrusted);
    // A missing scanner finding is a missing execution report, not an
    // unverified semantic claim. Keep this distinction even when the evidence
    // binding is absent or unreadable; "unverified" is reserved for a
    // present scanner finding whose bytes are not trusted by the bindings.
    if (!scanner || scanner.status === "not_present" || scanner.reason === "scanner_execution_missing") {
      scannerExecutionStatus = "missing";
      add(
        "scanner_execution_missing",
        integrityTrusted ? "fail" : "inconclusive",
        scannerDetail("missing")
      );
    } else if (scanner.status === "pass") {
      if (!integrityTrusted) {
        add("scanner_execution_unverified", "inconclusive", scannerDetail("unverified"));
      }
    } else if (!integrityTrusted) {
      scannerExecutionStatus = "unverified";
      add("scanner_execution_unverified", "inconclusive", scannerDetail("unverified"));
    } else {
      const reason = scanner.reason ?? "scanner_execution_malformed";
      const status = scannerStatusFor(scanner, true);
      add(reason, "fail", scannerDetail(status));
    }
  }

  const freshness = verification.checks.find((check) => check.id === "freshness");
  if (policy.requireFreshness && freshness?.status === "not_present") {
    add("freshness_required", "fail", "This policy requires freshness_expires_at to be declared.");
  }

  const scope = Array.isArray(receipt.scan_scope) ? receipt.scan_scope : [];
  for (const requiredScope of policy.requiredScopes) {
    if (!scope.includes(requiredScope)) {
      add("required_scope_missing", "inconclusive", `Required scan scope is missing: ${requiredScope}.`);
    }
  }

  if (typeof receipt.attestation === "string" && !policy.allowedAttestations.includes(receipt.attestation as Attestation)) {
    add("attestation_not_allowed", "fail", `Attestation is not allowed by policy: ${receipt.attestation}.`);
  }

  const verdict = typeof receipt.verdict === "string" ? receipt.verdict : "unknown";
  if (verdict === "findings") {
    add("receipt_findings", "fail", "Receipt verdict reports findings.");
  } else if (verdict === "warnings") {
    add(
      policy.warningDisposition === "block" ? "receipt_warnings_blocked" : "receipt_warnings",
      policy.warningDisposition === "block" ? "fail" : "warn",
      policy.warningDisposition === "block" ? "Policy blocks receipt warnings." : "Receipt verdict reports warnings."
    );
  } else if (verdict === "inconclusive") {
    add("receipt_inconclusive", "inconclusive", "Receipt verdict is inconclusive.");
  }

  return finish(receipt, verification, policy, reasons, scannerExecutionStatus, integrityStatus, receiptStatus);
}
