import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateReceiptSet } from "./core/composition.js";
import { evaluatePolicy, policyByName, type PolicyConfig } from "./core/policy.js";
import { verifyReceipt } from "./core/verify.js";
import { composeSbomDecision, loadSbomEvidence, type SbomAdmissionResult } from "./core/sbom.js";
import type { ReceiptInput, VerificationResult } from "./core/types.js";
const packageJson = createRequire(import.meta.url)("../package.json") as { version: string };
export const CLI_VERSION = packageJson.version;

export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

interface CommonArgs {
  artifact: string;
  policy: string;
  format: "text" | "json";
  now?: string;
}

interface VerifyArgs extends CommonArgs {
  command: "verify";
  receipt: string;
  evidence?: string;
  sbomEvidence?: string;
  sbom?: string;
}

interface VerifySetArgs extends CommonArgs {
  command: "verify-set";
  set: string;
}

interface ReceiptSetManifestEntry {
  receipt: string;
  evidence?: string;
  id?: string;
}

interface ReceiptSetManifest {
  schema_version: "project-defined-receipt-set-v1";
  receipts: ReceiptSetManifestEntry[];
}

class CliInputError extends Error {}

const HELP = `mcp-evidence-gate ${CLI_VERSION}

Usage:
  mcp-evidence-gate verify --receipt <path> --artifact <path> --policy <name> [options]
  mcp-evidence-gate verify-set --set <path> --artifact <path> --policy <name> [options]

Options:
  --receipt <path>   Receipt JSON path for verify
  --set <path>       Project-defined receipt-set JSON path for verify-set
  --artifact <path>  Artifact path shared by all receipts (required)
  --policy <name>    permissive, strict-release-example, strict-evidence-example, or strict-scanner-completeness (required)
  --evidence <path>  Optional local evidence report for single-receipt evidence_digest binding
  --sbom-evidence <path>  Optional SBOM evidence envelope JSON
  --sbom <path>      Optional exact SBOM bytes referenced by --sbom-evidence
  --format <mode>    text or json (default: text)
  --now <RFC3339>    Evaluation time; defaults to the current time
  --help             Show this help
  --version          Show the version

Receipt-set schema:
  {"schema_version":"project-defined-receipt-set-v1","receipts":[{"receipt":"receipt.json","evidence":"evidence.json","id":"optional"}]}
  Receipt and evidence paths are resolved relative to the receipt-set file.

Exit codes:
  0  PASS or WARN
  1  FAIL
  2  INCONCLUSIVE
  3  CLI, input, or runtime error
`;

function parseCommonOption(
  values: Partial<CommonArgs>,
  flag: string,
  value: string
): boolean {
  if (flag === "--artifact") values.artifact = value;
  else if (flag === "--policy") values.policy = value;
  else if (flag === "--format" && (value === "text" || value === "json")) values.format = value;
  else if (flag === "--now") values.now = value;
  else return false;
  return true;
}

function parseArgs(argv: string[]): VerifyArgs | VerifySetArgs | "help" | "version" {
  if (argv.includes("--help") || argv.length === 0) return "help";
  if (argv.includes("--version")) return "version";
  const command = argv[0];
  if (command !== "verify" && command !== "verify-set") {
    throw new CliInputError("command must be 'verify' or 'verify-set'");
  }

  const common: Partial<CommonArgs> = { format: "text" };
  let receipt: string | undefined;
  let evidence: string | undefined;
  let sbomEvidence: string | undefined;
  let sbom: string | undefined;
  let set: string | undefined;

  for (let index = 1; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!flag.startsWith("--")) throw new CliInputError(`unexpected argument: ${flag}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new CliInputError(`missing value for ${flag}`);
    index += 1;

    if (parseCommonOption(common, flag, value)) continue;
    if (command === "verify" && flag === "--receipt") receipt = value;
    else if (command === "verify" && flag === "--evidence") evidence = value;
    else if (command === "verify" && flag === "--sbom-evidence") sbomEvidence = value;
    else if (command === "verify" && flag === "--sbom") sbom = value;
    else if (command === "verify-set" && flag === "--set") set = value;
    else throw new CliInputError(`unknown option for ${command}: ${flag}`);
  }

  if (!common.artifact || !common.policy) {
    throw new CliInputError("--artifact and --policy are required");
  }
  if (command === "verify") {
    if (!receipt) throw new CliInputError("--receipt is required for verify");
    return { command, receipt, evidence, sbomEvidence, sbom, ...common } as VerifyArgs;
  }
  if (!set) throw new CliInputError("--set is required for verify-set");
  return { command, set, ...common } as VerifySetArgs;
}

function parseReceiptSetManifest(value: unknown): ReceiptSetManifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CliInputError("receipt set must be a JSON object");
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.schema_version !== "project-defined-receipt-set-v1") {
    throw new CliInputError("unsupported receipt-set schema_version");
  }
  if (!Array.isArray(candidate.receipts) || candidate.receipts.length === 0) {
    throw new CliInputError("receipt set must contain at least one receipt");
  }

  const receipts = candidate.receipts.map((entry, index): ReceiptSetManifestEntry => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new CliInputError(`receipt set entry ${index} must be an object`);
    }
    const item = entry as Record<string, unknown>;
    if (typeof item.receipt !== "string" || item.receipt.length === 0) {
      throw new CliInputError(`receipt set entry ${index} requires receipt`);
    }
    if (item.evidence !== undefined && (typeof item.evidence !== "string" || item.evidence.length === 0)) {
      throw new CliInputError(`receipt set entry ${index} evidence must be a non-empty string`);
    }
    if (item.id !== undefined && (typeof item.id !== "string" || item.id.length === 0)) {
      throw new CliInputError(`receipt set entry ${index} id must be a non-empty string`);
    }
    return {
      receipt: item.receipt,
      ...(typeof item.evidence === "string" ? { evidence: item.evidence } : {}),
      ...(typeof item.id === "string" ? { id: item.id } : {})
    };
  });

  return { schema_version: "project-defined-receipt-set-v1", receipts };
}

function evaluationTime(value: string | undefined): Date {
  const normalized = value?.replace("t", "T").replace(/z$/, "Z");
  const result = normalized ? new Date(normalized) : new Date();
  if (Number.isNaN(result.getTime())) throw new CliInputError("--now must be a valid RFC3339 date-time");
  return result;
}

function outputModel(
  policy: PolicyConfig,
  verification: VerificationResult,
  receipt: ReceiptInput,
  evaluatedAt: Date,
  sbomAdmission: SbomAdmissionResult
) {
  const decision = evaluatePolicy(receipt, verification, policy, evaluatedAt);
  const effectiveDecision = composeSbomDecision(decision.decision, sbomAdmission.status);
  const sbomReasons = sbomAdmission.reasonCodes.map((code) => ({ code, detail: `SBOM admission: ${code}` }));
  return {
    tool: "mcp-evidence-gate",
    version: CLI_VERSION,
    profile: decision.profile,
    policy: decision.policy,
    receiptVerdict: decision.receiptVerdict,
    decision: effectiveDecision,
    integrity_status: decision.integrityStatus,
    receipt_status: decision.receiptStatus,
    policy_status: decision.policyStatus,
    admission_status: effectiveDecision,
    scanner_execution_status: decision.scannerExecutionStatus,
    reason_codes: decision.reasonCodes,
    ...(decision.policyVersion ? { policy_version: decision.policyVersion } : {}),
    evaluatedAt: verification.evaluatedAt,
    checks: verification.checks,
    reasons: [...decision.reasons, ...sbomReasons],
    sbom_admission_status: sbomAdmission.status,
    sbom_reason_codes: sbomAdmission.reasonCodes,
    ...(sbomAdmission.format ? { sbom_format: sbomAdmission.format } : {}),
    ...(sbomAdmission.schemaVersion ? { sbom_schema_version: sbomAdmission.schemaVersion } : {}),
    ...(sbomAdmission.packageCount !== undefined ? { sbom_package_count: sbomAdmission.packageCount } : {})
  };
}

function exitCode(decision: string): number {
  if (decision === "pass" || decision === "warn") return 0;
  if (decision === "fail") return 1;
  if (decision === "inconclusive") return 2;
  return 3;
}

function checkLabel(id: string): string {
  return id.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function renderText(model: ReturnType<typeof outputModel>): string {
  const lines = [
    "MCP Evidence Gate",
    `Profile: ${model.profile}`,
    `Policy: ${model.policy}`,
    `Receipt verdict: ${model.receiptVerdict}`,
    `Integrity status: ${model.integrity_status}`,
    `Receipt status: ${model.receipt_status}`,
    `Policy status: ${model.policy_status}`,
    `Admission status: ${model.admission_status}`,
    `Scanner execution: ${model.scanner_execution_status}`,
    `SBOM evidence: ${model.sbom_admission_status.toUpperCase()}`,
    "Security verdict: NOT EVALUATED BY SBOM CONTRACT",
    `Evaluated at: ${model.evaluatedAt}`,
    "",
    ...model.checks.map((check) => {
      const status = check.status === "not_present" ? "N/A" : check.status.toUpperCase();
      return `${checkLabel(check.id).padEnd(26)} ${status}${check.reason ? ` (${check.reason})` : ""}`;
    }),
    "",
    `Decision: ${model.decision.toUpperCase()}`
  ];
  if (model.reasons.length > 0) {
    lines.push("Reasons:", ...model.reasons.map((reason) => `- ${reason.code}: ${reason.detail}`));
  }
  return `${lines.join("\n")}\n`;
}

function renderSetText(model: {
  profile: string;
  policy: string;
  evaluatedAt: string;
  artifactDigest: string;
  receiptCount: number;
  decision: string;
  integrity_status: string;
  receipt_status: string;
  policy_status: string;
  admission_status: string;
  receipts: Array<{
    index: number;
    id?: string;
    scanner: string;
    source: string;
    receiptVerdict: string;
    decision: string;
    integrityStatus: string;
    receiptStatus: string;
    scannerExecutionStatus: string;
  }>;
}): string {
  const lines = [
    "MCP Evidence Gate Receipt Set",
    `Profile: ${model.profile}`,
    `Policy: ${model.policy}`,
    `Artifact digest: ${model.artifactDigest}`,
    `Receipt count: ${model.receiptCount}`,
    `Integrity status: ${model.integrity_status}`,
    `Receipt status: ${model.receipt_status}`,
    `Policy status: ${model.policy_status}`,
    `Admission status: ${model.admission_status}`,
    `Evaluated at: ${model.evaluatedAt}`,
    "",
    ...model.receipts.map((entry) =>
      `#${entry.index + 1}${entry.id ? ` [${entry.id}]` : ""} ${entry.scanner} ${entry.receiptVerdict.toUpperCase()} -> ${entry.decision.toUpperCase()} (${entry.source}; integrity=${entry.integrityStatus}; receipt=${entry.receiptStatus}; scanner_execution=${entry.scannerExecutionStatus})`
    ),
    "",
    `Decision: ${model.decision.toUpperCase()}`
  ];
  return `${lines.join("\n")}\n`;
}

export async function runCli(argv: string[], io: CliIO): Promise<number> {
  try {
    const parsed = parseArgs(argv);
    if (parsed === "help") {
      io.stdout(HELP);
      return 0;
    }
    if (parsed === "version") {
      io.stdout(`${CLI_VERSION}\n`);
      return 0;
    }

    const policy = policyByName(parsed.policy);
    const evaluatedAt = evaluationTime(parsed.now);

    if (parsed.command === "verify") {
      const receipt = JSON.parse(await readFile(parsed.receipt, "utf8")) as ReceiptInput;
      const verification = await verifyReceipt(receipt, parsed.artifact, evaluatedAt, {
        maxScanAgeMs: policy.maxScanAgeMs,
        clockSkewMs: policy.clockSkewMs,
        evidencePath: parsed.evidence,
        requireScannerExecutionCompleteness: policy.requireScannerExecutionCompleteness
      });
      let sbomAdmission: SbomAdmissionResult = { status: "not-provided", reasonCodes: [] };
      const sbomInputs = await loadSbomEvidence(parsed.sbomEvidence, parsed.sbom);
      if (sbomInputs.status === "result") sbomAdmission = sbomInputs.result;
      else if (sbomInputs.status === "inputs") {
        const { verifySbomEvidence } = await import("./core/sbom.js");
        sbomAdmission = await verifySbomEvidence(parsed.artifact, sbomInputs.envelope, sbomInputs.sbomBytes);
      }
      const model = outputModel(policy, verification, receipt, evaluatedAt, sbomAdmission);
      if (parsed.format === "json") io.stdout(`${JSON.stringify(model, null, 2)}\n`);
      else io.stdout(renderText(model));
      return exitCode(model.decision);
    }

    const setPath = resolve(parsed.set);
    const manifest = parseReceiptSetManifest(JSON.parse(await readFile(setPath, "utf8")));
    const setDirectory = dirname(setPath);
    const entries = [];
    for (const item of manifest.receipts) {
      const receiptPath = resolve(setDirectory, item.receipt);
      entries.push({
        receipt: JSON.parse(await readFile(receiptPath, "utf8")) as ReceiptInput,
        ...(item.evidence ? { evidencePath: resolve(setDirectory, item.evidence) } : {}),
        ...(item.id ? { id: item.id } : {})
      });
    }

    const evaluation = await evaluateReceiptSet(entries, parsed.artifact, evaluatedAt, policy);
    const model = {
      tool: "mcp-evidence-gate",
      version: CLI_VERSION,
      mode: "receipt-set",
      profile: evaluation.profile,
      policy: evaluation.policy,
      evaluatedAt: evaluation.evaluatedAt,
      artifactDigest: evaluation.artifactDigest,
      receiptCount: evaluation.receiptCount,
      decision: evaluation.decision,
      integrity_status: evaluation.integrityStatus,
      receipt_status: evaluation.receiptStatus,
      policy_status: evaluation.policyStatus,
      admission_status: evaluation.admissionStatus,
      reason_codes: evaluation.reasonCodes,
      receipts: evaluation.receipts.map((entry) => ({
        index: entry.index,
        ...(entry.id ? { id: entry.id } : {}),
        scanner: entry.scanner,
        source: manifest.receipts[entry.index].receipt,
        receiptVerdict: entry.evaluation.receiptVerdict,
        decision: entry.evaluation.decision,
        integrityStatus: entry.evaluation.integrityStatus,
        receiptStatus: entry.evaluation.receiptStatus,
        scannerExecutionStatus: entry.evaluation.scannerExecutionStatus,
        integrity_status: entry.evaluation.integrityStatus,
        receipt_status: entry.evaluation.receiptStatus,
        policy_status: entry.evaluation.policyStatus,
        admission_status: entry.evaluation.admissionStatus,
        scanner_execution_status: entry.evaluation.scannerExecutionStatus,
        reason_codes: entry.evaluation.reasonCodes,
        ...(entry.evaluation.policyVersion ? { policy_version: entry.evaluation.policyVersion } : {}),
        checks: entry.verification.checks,
        reasons: entry.evaluation.reasons
      }))
    };
    if (parsed.format === "json") io.stdout(`${JSON.stringify(model, null, 2)}\n`);
    else io.stdout(renderSetText(model));
    return exitCode(model.decision);
  } catch (error) {
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n`);
    return 3;
  }
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath && invokedPath === fileURLToPath(import.meta.url)) {
  const code = await runCli(process.argv.slice(2), {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text)
  });
  process.exitCode = code;
}
