import * as core from "@actions/core";
import { readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { evaluatePolicy, policyByName } from "./core/policy.js";
import { verifyReceipt } from "./core/verify.js";
import { composeSbomDecision, loadSbomEvidence, verifySbomEvidence, type SbomAdmissionResult } from "./core/sbom.js";
import type { ReceiptInput } from "./core/types.js";

function workspacePath(input: string): string {
  return isAbsolute(input) ? input : resolve(process.env.GITHUB_WORKSPACE ?? process.cwd(), input);
}

function formatReasons(reasons: readonly { code: string; detail: string }[]): string {
  return reasons.map((reason) => `${reason.code}: ${reason.detail}`).join("; ");
}

export async function runAction(): Promise<void> {
  const receiptInput = core.getInput("receipt", { required: true });
  const artifactInput = core.getInput("artifact", { required: true });
  const policyInput = core.getInput("policy", { required: true });
  const evidenceInput = core.getInput("evidence");
  const sbomEvidenceInput = core.getInput("sbom-evidence");
  const sbomInput = core.getInput("sbom");
  const receiptPath = workspacePath(receiptInput);
  const artifactPath = workspacePath(artifactInput);
  const policy = policyByName(policyInput);
  const evaluatedAt = new Date();
  const receipt = JSON.parse(await readFile(receiptPath, "utf8")) as ReceiptInput;
  const verification = await verifyReceipt(receipt, artifactPath, evaluatedAt, {
    maxScanAgeMs: policy.maxScanAgeMs,
    clockSkewMs: policy.clockSkewMs,
    evidencePath: evidenceInput ? workspacePath(evidenceInput) : undefined,
    requireScannerExecutionCompleteness: policy.requireScannerExecutionCompleteness
  });
  const evaluation = evaluatePolicy(receipt, verification, policy, evaluatedAt);
  let sbomAdmission: SbomAdmissionResult = { status: "not-provided", reasonCodes: [] };
  const sbomInputs = await loadSbomEvidence(
    sbomEvidenceInput ? workspacePath(sbomEvidenceInput) : undefined,
    sbomInput ? workspacePath(sbomInput) : undefined
  );
  if (sbomInputs.status === "result") sbomAdmission = sbomInputs.result;
  else if (sbomInputs.status === "inputs") {
    sbomAdmission = await verifySbomEvidence(artifactPath, sbomInputs.envelope, sbomInputs.sbomBytes);
  }
  const effectiveDecision = composeSbomDecision(evaluation.decision, sbomAdmission.status);

  core.setOutput("decision", effectiveDecision);
  core.setOutput("receipt-verdict", evaluation.receiptVerdict);
  core.setOutput("profile", evaluation.profile);
  core.setOutput("integrity-status", evaluation.integrityStatus);
  core.setOutput("receipt-status", evaluation.receiptStatus);
  core.setOutput("policy-status", evaluation.policyStatus);
  core.setOutput("admission-status", effectiveDecision);
  core.setOutput("scanner-execution-status", evaluation.scannerExecutionStatus);
  core.setOutput("reason-codes", [...evaluation.reasonCodes, ...sbomAdmission.reasonCodes].join(","));
  core.setOutput("policy-version", evaluation.policyVersion ?? "");
  core.setOutput("sbom-admission-status", sbomAdmission.status);
  core.setOutput("sbom-reason-codes", sbomAdmission.reasonCodes.join(","));
  core.setOutput("sbom-format", sbomAdmission.format ?? "");
  core.setOutput("sbom-schema-version", sbomAdmission.schemaVersion ?? "");
  core.setOutput("sbom-package-count", sbomAdmission.packageCount?.toString() ?? "");
  core.info(`MCP Evidence Gate decision: ${effectiveDecision.toUpperCase()}`);
  core.info(`SBOM evidence: ${sbomAdmission.status.toUpperCase()}`);
  core.info("Security verdict: NOT EVALUATED BY SBOM CONTRACT");

  const allReasons = [...evaluation.reasons.map((reason) => `${reason.code}: ${reason.detail}`), ...sbomAdmission.reasonCodes];
  if (effectiveDecision === "fail") {
    core.setFailed(`FAIL: ${allReasons.join("; ")}`);
    return;
  }
  if (sbomAdmission.status === "inconclusive") {
    core.setFailed(`SBOM INCONCLUSIVE: ${allReasons.join("; ")}`);
    return;
  }

  if (effectiveDecision === "warn") {
    core.warning(formatReasons(evaluation.reasons));
    return;
  }
  if (effectiveDecision === "inconclusive") {
    core.setFailed(`INCONCLUSIVE: evidence does not support this release. ${formatReasons(evaluation.reasons)}`);
  }
}

if (process.env.GITHUB_ACTIONS === "true") {
  void runAction().catch((error) => {
    core.setFailed(error instanceof Error ? error.message : String(error));
  });
}
