import type { RegistryPr1404Profile } from "../profiles/registry-pr-1404.js";

export type CheckStatus =
  | "pass"
  | "mismatch"
  | "inconclusive"
  | "invalid"
  | "not_present"
  | "unsupported";

export interface Finding {
  id:
    | "receipt_structure"
    | "artifact_binding"
    | "evidence_binding"
    | "scanner_execution"
    | "freshness"
    | "scan_scope"
    | "inconclusive_reason";
  status: CheckStatus;
  reason?: string;
  expected?: string;
  actual?: string;
  details?: string[];
}

export interface ReceiptInput {
  scanner?: unknown;
  scanner_version?: unknown;
  rule_set_ref?: unknown;
  policy_profile?: unknown;
  scanned_artifact_ref?: unknown;
  scanned_artifact_digest?: unknown;
  freshness_expires_at?: unknown;
  scanned_at?: unknown;
  evidence_ref?: unknown;
  evidence_digest?: unknown;
  attestation?: unknown;
  scan_scope?: unknown;
  verdict?: unknown;
  inconclusive_reason?: unknown;
}

export interface VerificationResult {
  profile: RegistryPr1404Profile["id"];
  evaluatedAt: string;
  checks: Finding[];
}
