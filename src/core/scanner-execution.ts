import { readEvidenceSnapshot, type EvidenceSnapshotRead } from "./digest.js";
import type { Finding } from "./types.js";

/** Versioned, producer-owned execution evidence consumed by local policy. */
export const SCANNER_EXECUTION_SCHEMA_VERSION = "project-defined-scanner-execution-v1";
export const SCANNER_EXECUTION_POLICY_VERSION = "scanner-execution-completeness-policy-v2";

export const SCANNER_EXECUTION_STATUSES = ["complete", "incomplete", "failed"] as const;
export type ScannerExecutionContractStatus = (typeof SCANNER_EXECUTION_STATUSES)[number];

export type ScannerExecutionOutputStatus =
  | ScannerExecutionContractStatus
  | "missing"
  | "malformed"
  | "contradictory"
  | "unverified"
  | "not_evaluated";

type JsonObject = Record<string, unknown>;

export interface ScannerExecutionContractExpectation {
  receiptScanner: string;
  scannerContract: string;
  requiredComponents: readonly string[];
  allowedExitCodes: readonly number[];
}

/** Consumer-owned policy registry. Producer evidence is never authoritative for these values. */
export const CONSUMER_SCANNER_CONTRACTS: readonly ScannerExecutionContractExpectation[] = [
  { receiptScanner: "trivy", scannerContract: "trivy-fs-json-v1", requiredComponents: ["scanner_process", "scanner_output", "result_sections", "artifact_binding", "result_semantics"], allowedExitCodes: [0] },
  { receiptScanner: "osv-scanner", scannerContract: "osv-scanner-v2-lockfile-json-v1", requiredComponents: ["scanner_process", "scanner_output", "result_sections", "source_binding", "result_semantics"], allowedExitCodes: [0, 1] },
  { receiptScanner: "trivy", scannerContract: "trivy-oci-image-json-v1", requiredComponents: ["scanner_process", "scanner_output", "result_sections", "artifact_binding", "result_semantics"], allowedExitCodes: [0] },
  // Compatibility for the pre-v2 fixture contract; real scanner contracts above remain strict.
  { receiptScanner: "example-scanner", scannerContract: "abstract-scanner-json-v1", requiredComponents: ["scanner_process", "scanner_output", "result_sections"], allowedExitCodes: [0] }
] as const;

const REQUIRED_BOOLEAN_FIELDS = [
  "invocation_started",
  "process_completed",
  "exit_state_valid",
  "output_present",
  "output_exists",
  "output_parseable",
  "required_work_completed"
] as const;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.length > 0);
}

function malformed(details: string[]): Finding {
  return { id: "scanner_execution", status: "invalid", reason: "scanner_execution_malformed", details };
}

function validateExecution(execution: JsonObject, receipt?: { scanner?: unknown; scanner_version?: unknown }): Finding {
  if (execution.schema_version !== SCANNER_EXECUTION_SCHEMA_VERSION) {
    return malformed(["schema_version"]);
  }
  if (typeof execution.scanner_contract !== "string" || execution.scanner_contract.length === 0) {
    return malformed(["scanner_contract"]);
  }

  const missingFields = [
    ...REQUIRED_BOOLEAN_FIELDS.filter((field) => typeof execution[field] !== "boolean"),
    ...(typeof execution.result_semantics_consistent !== "boolean" && execution.result_semantics_consistent !== null
      ? ["result_semantics_consistent"]
      : []),
    ...(execution.exit_code !== null && typeof execution.exit_code !== "number"
      ? ["exit_code"]
      : []),
    ...(execution.exit_code !== null && typeof execution.exit_code === "number" && !Number.isInteger(execution.exit_code)
      ? ["exit_code_integer"]
      : []),
    ...(execution.output_size !== null && typeof execution.output_size !== "number"
      ? ["output_size"]
      : []),
    ...(execution.output_size !== null && typeof execution.output_size === "number" &&
      (!Number.isInteger(execution.output_size) || execution.output_size < 0)
      ? ["output_size_non_negative_integer"]
      : []),
    ...(typeof execution.completeness_reason !== "string" || execution.completeness_reason.length === 0
      ? ["completeness_reason"]
      : [])
  ];
  if (missingFields.length > 0) return malformed(missingFields);

  if (!stringArray(execution.required_components) || execution.required_components.length === 0) {
    return malformed(["required_components"]);
  }
  if (!stringArray(execution.completed_components) || !stringArray(execution.failed_components)) {
    return malformed(["completed_components", "failed_components"]);
  }

  const contract = CONSUMER_SCANNER_CONTRACTS.find((entry) => entry.scannerContract === execution.scanner_contract);
  if (!contract) return { id: "scanner_execution", status: "invalid", reason: "scanner_execution_contract_unsupported", details: [String(execution.scanner_contract)] };
  if (receipt && receipt.scanner !== undefined && receipt.scanner !== contract.receiptScanner) {
    return { id: "scanner_execution", status: "invalid", reason: "scanner_execution_contract_mismatch", details: [contract.receiptScanner, String(receipt.scanner)] };
  }
  if (receipt && receipt.scanner_version !== undefined && typeof receipt.scanner_version !== "string") {
    return { id: "scanner_execution", status: "invalid", reason: "scanner_version_mismatch", details: ["receipt_scanner_version"] };
  }

  const status = execution.completeness_status;
  if (!SCANNER_EXECUTION_STATUSES.includes(status as ScannerExecutionContractStatus)) {
    return malformed(["completeness_status"]);
  }

  const required = execution.required_components;
  const completed = execution.completed_components;
  const failed = execution.failed_components;
  const overlappingComponents = completed.filter((component) => failed.includes(component));
  if (overlappingComponents.length > 0) {
    return {
      id: "scanner_execution",
      status: "invalid",
      reason: "scanner_execution_contradictory",
      details: ["component_marked_completed_and_failed", ...overlappingComponents]
    };
  }
  const requiredSetMatches = required.length === contract.requiredComponents.length &&
    contract.requiredComponents.every((component) => required.includes(component));
  if (!requiredSetMatches) {
    return { id: "scanner_execution", status: "invalid", reason: "scanner_execution_required_components_mismatch", details: [...contract.requiredComponents] };
  }
  if (typeof execution.exit_code === "number" && !contract.allowedExitCodes.includes(execution.exit_code)) {
    return { id: "scanner_execution", status: "invalid", reason: "scanner_execution_exit_code_invalid", details: contract.allowedExitCodes.map(String) };
  }
  if (status !== "complete" && execution.required_work_completed === true) {
    return {
      id: "scanner_execution",
      status: "invalid",
      reason: "scanner_execution_contradictory",
      details: ["non_complete_status_with_required_work_completed"]
    };
  }
  const completeClaimProven =
    execution.invocation_started === true &&
    execution.process_completed === true &&
    execution.exit_state_valid === true &&
    execution.output_present === true &&
    execution.output_exists === true &&
    execution.output_parseable === true &&
    execution.required_work_completed === true &&
    execution.result_semantics_consistent === true &&
    typeof execution.exit_code === "number" &&
    Number.isInteger(execution.exit_code) &&
    typeof execution.output_size === "number" &&
    Number.isInteger(execution.output_size) &&
    execution.output_size > 0 &&
    failed.length === 0 &&
    required.every((component) => completed.includes(component)) &&
    contract.requiredComponents.every((component) => required.includes(component) && completed.includes(component)) &&
    required.length === contract.requiredComponents.length &&
    contract.allowedExitCodes.includes(execution.exit_code as number) &&
    overlappingComponents.length === 0;

  if ((status === "complete" && !completeClaimProven) || (status !== "complete" && completeClaimProven)) {
    return {
      id: "scanner_execution",
      status: "invalid",
      reason: "scanner_execution_contradictory",
      details: [
        status === "complete"
          ? "completeness_status_complete_not_proven"
          : "non_complete_status_but_all_completion_conditions_are_true"
      ]
    };
  }

  if (status === "complete") return { id: "scanner_execution", status: "pass", reason: "scanner_execution_complete" };
  return {
    id: "scanner_execution",
    status: "invalid",
    reason: status === "failed" ? "scanner_execution_failed" : "scanner_execution_incomplete",
    details: [execution.completeness_reason as string]
  };
}

/**
 * Read and validate producer-owned scanner execution evidence. This is only
 * called when an explicit local policy opts into the contract; legacy receipt
 * verification never reads or requires this project-defined extension.
 */
export function verifyScannerExecutionBytes(evidence: EvidenceSnapshotRead, receipt?: { scanner?: unknown; scanner_version?: unknown }): Finding {
  if (!evidence.snapshot) {
    return {
      id: "scanner_execution",
      status: "not_present",
      reason: "scanner_execution_missing",
      ...(evidence.error ? { details: [evidence.error] } : {})
    };
  }

  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(evidence.snapshot.bytes).toString("utf8")) as unknown;
  } catch {
    return malformed(["evidence_json"]);
  }
  if (!isObject(value)) return malformed(["evidence_object"]);
  if (value.scanner_execution === undefined) {
    return { id: "scanner_execution", status: "not_present", reason: "scanner_execution_missing" };
  }
  if (!isObject(value.scanner_execution)) return malformed(["scanner_execution_object"]);
  const executionContract = isObject(value.scanner_execution) && typeof value.scanner_execution.scanner_contract === "string"
    ? value.scanner_execution.scanner_contract : undefined;
  // v2 contracts bind scanner identity; retain the historical abstract fixture's
  // permissive shape solely for backwards-compatible tests.
  if (executionContract !== "abstract-scanner-json-v1" && (receipt?.scanner !== undefined || receipt?.scanner_version !== undefined)) {
    const scanner = value.scanner;
    if (!isObject(scanner) || scanner.name !== receipt?.scanner) {
      return { id: "scanner_execution", status: "invalid", reason: "scanner_identity_mismatch", details: [String(receipt?.scanner), isObject(scanner) ? String(scanner.name) : "missing"] };
    }
    if (receipt?.scanner_version !== undefined && scanner.version !== receipt.scanner_version) {
      return { id: "scanner_execution", status: "invalid", reason: "scanner_version_mismatch", details: [String(receipt.scanner_version), String(scanner.version)] };
    }
  }
  return validateExecution(value.scanner_execution, receipt);
}

/**
 * Read and validate producer-owned scanner execution evidence. This legacy
 * path remains available to direct callers; receipt verification uses the
 * shared snapshot API so digest and semantic checks consume identical bytes.
 */
export async function verifyScannerExecution(evidencePath?: string): Promise<Finding> {
  return verifyScannerExecutionBytes(await readEvidenceSnapshot(evidencePath));
}
