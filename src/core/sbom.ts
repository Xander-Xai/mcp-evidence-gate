import { parseDigest, sha256Bytes, sha256Artifact } from "./digest.js";
import { readFile, stat } from "node:fs/promises";

export type SbomAdmissionStatus = "pass" | "inconclusive" | "blocked" | "not-provided";

export interface SbomEvidenceEnvelope {
  schema_version?: unknown;
  artifact?: { ref?: unknown; sha256?: unknown; size?: unknown };
  sbom?: { format?: unknown; schema_version?: unknown; sha256?: unknown; size?: unknown };
  relationship?: { type?: unknown; artifact_sha256?: unknown; sbom_sha256?: unknown; binding?: unknown };
  inventory?: { status?: unknown; package_count?: unknown };
}

export interface SbomAdmissionResult {
  status: SbomAdmissionStatus;
  reasonCodes: string[];
  format?: string;
  schemaVersion?: string;
  inventoryStatus?: string;
  packageCount?: number;
}

export type CoreDecision = "pass" | "warn" | "inconclusive" | "fail";

export const SBOM_CONSUMER_CONTRACT = Object.freeze({
  envelopeSchema: "project-defined-sbom-evidence-v1",
  format: "syft-json",
  schemaVersion: "16.1.3",
  relationshipType: "generated-from",
  binding: "exact-artifact"
} as const);

// Explicit, exported policy values. They are intentionally conservative
// bounds pending a larger corpus benchmark; callers cannot silently change
// them through Producer claims.
export const SBOM_RESOURCE_LIMITS = Object.freeze({
  maxSbomBytes: 64 * 1024 * 1024,
  maxPackageCount: 1_000_000
} as const);

export type SbomInputLoad =
  | { status: "not-provided" }
  | { status: "result"; result: SbomAdmissionResult }
  | { status: "inputs"; envelope: unknown; sbomBytes: Uint8Array };

/** Read SBOM inputs with size preflight and one shared malformed-input path. */
export async function loadSbomEvidence(
  envelopePath?: string,
  sbomPath?: string
): Promise<SbomInputLoad> {
  if (!envelopePath && !sbomPath) return { status: "not-provided" };
  if (!envelopePath || !sbomPath) return { status: "result", result: inconclusive("sbom_missing") };
  try {
    const [envelopeStat, sbomStat] = await Promise.all([stat(envelopePath), stat(sbomPath)]);
    if (envelopeStat.size > SBOM_RESOURCE_LIMITS.maxSbomBytes || sbomStat.size > SBOM_RESOURCE_LIMITS.maxSbomBytes) {
      return { status: "result", result: inconclusive("sbom_size_limit_exceeded") };
    }
    const [envelopeBytes, sbomBytes] = await Promise.all([readFile(envelopePath), readFile(sbomPath)]);
    let envelope: unknown;
    try { envelope = JSON.parse(envelopeBytes.toString("utf8")) as unknown; }
    catch { return { status: "result", result: inconclusive("sbom_malformed") }; }
    return { status: "inputs", envelope, sbomBytes: new Uint8Array(sbomBytes) };
  } catch {
    return { status: "result", result: inconclusive("sbom_missing") };
  }
}

export function composeSbomDecision(existing: CoreDecision, status: SbomAdmissionStatus): CoreDecision {
  const sbomDecision: CoreDecision = status === "blocked" ? "fail" : status === "inconclusive" ? "inconclusive" : "pass";
  const rank: Record<CoreDecision, number> = { pass: 0, warn: 1, inconclusive: 2, fail: 3 };
  return rank[existing] >= rank[sbomDecision] ? existing : sbomDecision;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function blocked(...reasonCodes: string[]): SbomAdmissionResult {
  return { status: "blocked", reasonCodes };
}

function inconclusive(...reasonCodes: string[]): SbomAdmissionResult {
  return { status: "inconclusive", reasonCodes };
}

function digest(value: unknown, missingCode: string, malformedCode: string): string | undefined {
  if (value === undefined) return undefined;
  try {
    const parsed = parseDigest(value);
    return `sha256:${parsed.hex}`;
  } catch {
    throw new Error(malformedCode);
  }
}

function isPackageRecord(value: unknown): boolean {
  const item = object(value);
  return !!item && nonEmptyString(item.id) && nonEmptyString(item.name) &&
    nonEmptyString(item.version) && nonEmptyString(item.type);
}

/**
 * Verify a consumer-owned Syft SBOM evidence envelope against the exact
 * artifact bytes and exact SBOM bytes supplied by the caller.
 */
export async function verifySbomEvidence(
  artifactPath: string,
  envelope: unknown,
  sbomBytes: Uint8Array
): Promise<SbomAdmissionResult> {
  const root = object(envelope);
  if (!root) return inconclusive("sbom_malformed");
  if (sbomBytes.byteLength > SBOM_RESOURCE_LIMITS.maxSbomBytes) return inconclusive("sbom_size_limit_exceeded");

  const artifact = object(root.artifact);
  const sbom = object(root.sbom);
  const relationship = object(root.relationship);
  const inventory = object(root.inventory);
  if (!artifact || !sbom || !inventory) return inconclusive("sbom_malformed");
  if (root.schema_version !== SBOM_CONSUMER_CONTRACT.envelopeSchema) return inconclusive("sbom_schema_unsupported");

  let artifactDigest: string;
  let declaredArtifact: string;
  let declaredSbom: string;
  try {
    artifactDigest = await sha256Artifact(artifactPath);
    declaredArtifact = digest(artifact.sha256, "artifact_digest_missing", "artifact_digest_malformed") ?? "";
    declaredSbom = digest(sbom.sha256, "sbom_digest_missing", "sbom_digest_malformed") ?? "";
  } catch (error) {
    const code = error instanceof Error ? error.message : "sbom_malformed";
    if (code === "artifact_digest_malformed") return inconclusive(code);
    if (code === "sbom_digest_malformed") return inconclusive(code);
    return inconclusive("sbom_malformed");
  }
  if (!declaredArtifact) return inconclusive("artifact_digest_missing");
  if (!declaredSbom) return inconclusive("sbom_digest_missing");
  if (declaredArtifact !== artifactDigest) return blocked("artifact_digest_mismatch");
  const actualSbom = sha256Bytes(sbomBytes);
  if (declaredSbom !== actualSbom) return blocked("sbom_digest_mismatch");
  if (artifact.size !== undefined) {
    const artifactStat = await stat(artifactPath);
    if (typeof artifact.size !== "number" || artifact.size < 0 || artifact.size !== artifactStat.size) return inconclusive("artifact_size_mismatch");
  }
  if (sbom.size !== undefined && (typeof sbom.size !== "number" || sbom.size !== sbomBytes.byteLength)) return inconclusive("sbom_size_mismatch");

  if (sbom.format !== SBOM_CONSUMER_CONTRACT.format || sbom.schema_version !== SBOM_CONSUMER_CONTRACT.schemaVersion) {
    return inconclusive("sbom_format_unsupported");
  }
  if (!relationship) return inconclusive("artifact_sbom_binding_missing");
  if (relationship.artifact_sha256 !== declaredArtifact || relationship.sbom_sha256 !== declaredSbom) {
    return blocked("artifact_sbom_binding_mismatch");
  }
  if (relationship.type !== SBOM_CONSUMER_CONTRACT.relationshipType || relationship.binding !== SBOM_CONSUMER_CONTRACT.binding) {
    return inconclusive("artifact_sbom_binding_missing");
  }

  let parsed: Record<string, unknown>;
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(sbomBytes));
    const parsedObject = object(value);
    if (!parsedObject) return inconclusive("sbom_malformed");
    parsed = parsedObject;
  } catch {
    return inconclusive("sbom_malformed");
  }
  const schema = object(parsed.schema);
  const source = object(parsed.source);
  const artifacts = parsed.artifacts;
  if (schema?.version !== SBOM_CONSUMER_CONTRACT.schemaVersion || !source || !nonEmptyString(source.name) || !nonEmptyString(source.version)) {
    return inconclusive("sbom_schema_unsupported");
  }
  let sourceDigest: string;
  try { sourceDigest = digest(source.version, "artifact_sbom_binding_missing", "artifact_sbom_binding_mismatch") ?? ""; }
  catch { return blocked("artifact_sbom_binding_mismatch"); }
  if (sourceDigest !== artifactDigest) return blocked("artifact_sbom_binding_mismatch");
  if (!Array.isArray(artifacts)) return inconclusive("sbom_inventory_missing");
  if (artifacts.length === 0) return inconclusive("sbom_inventory_empty");
  if (artifacts.length > SBOM_RESOURCE_LIMITS.maxPackageCount) return inconclusive("sbom_package_limit_exceeded");
  if (!artifacts.every(isPackageRecord)) return inconclusive("sbom_inventory_malformed");
  const ids = artifacts.map((item) => (item as Record<string, unknown>).id as string);
  if (new Set(ids).size !== ids.length) return inconclusive("sbom_inventory_duplicate_id");
  if (inventory.status !== "present" || inventory.package_count !== artifacts.length) return inconclusive("sbom_inventory_count_mismatch");
  return { status: "pass", reasonCodes: [], format: SBOM_CONSUMER_CONTRACT.format, schemaVersion: SBOM_CONSUMER_CONTRACT.schemaVersion, inventoryStatus: "present", packageCount: artifacts.length };
}
