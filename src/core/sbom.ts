import { parseDigest, sha256Bytes, sha256Artifact } from "./digest.js";
import { open, readFile, stat } from "node:fs/promises";

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

export type SyftSourceShape = "FILE" | "IMAGE" | "AMBIGUOUS" | "UNKNOWN";

type OptionalIdentity =
  | { state: "absent" }
  | { state: "valid"; digest: string }
  | { state: "malformed" };

export const SBOM_CONSUMER_CONTRACT = Object.freeze({
  envelopeSchema: "project-defined-sbom-evidence-v1",
  format: "syft-json",
  schemaVersions: Object.freeze(["16.1.3", "16.1.10"] as const),
  sourceTypes: Object.freeze(["file", "image"] as const),
  relationshipType: "generated-from",
  binding: "exact-artifact"
} as const);

/** Qualified Syft image metadata keys are security-relevant source-shape signals. */
export const QUALIFIED_IMAGE_METADATA_SIGNALS = Object.freeze([
  "userInput", "imageID", "manifestDigest", "mediaType", "tags", "imageSize",
  "layers", "manifest", "config", "architecture", "os", "repoDigests", "labels"
] as const);

/** Explicitly qualified Syft JSON schema versions; never widen this to a range. */
const supportedSchemaVersions = new Set(SBOM_CONSUMER_CONTRACT.schemaVersions);
const supportedSourceTypes = new Set(SBOM_CONSUMER_CONTRACT.sourceTypes);
const maxEmbeddedManifestBytes = 4 * 1024 * 1024;

export function classifySyftSourceShape(sourceValue: unknown): SyftSourceShape {
  const source = object(sourceValue);
  const metadata = object(source?.metadata);
  if (!metadata) return "UNKNOWN";
  const imageSignals = QUALIFIED_IMAGE_METADATA_SIGNALS
    .some((key) => Object.prototype.hasOwnProperty.call(metadata, key));
  const fileSignals = ["path", "digests", "mimeType"]
    .some((key) => Object.prototype.hasOwnProperty.call(metadata, key));
  if (imageSignals && fileSignals) return "AMBIGUOUS";
  if (imageSignals) return "IMAGE";
  if (fileSignals) return "FILE";
  return "UNKNOWN";
}

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

  if (sbom.format !== SBOM_CONSUMER_CONTRACT.format) return inconclusive("sbom_format_unsupported");
  if (typeof sbom.schema_version !== "string" || !supportedSchemaVersions.has(sbom.schema_version as (typeof SBOM_CONSUMER_CONTRACT.schemaVersions)[number])) {
    return inconclusive("sbom_schema_unsupported");
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
  if (typeof schema?.version !== "string" || !supportedSchemaVersions.has(schema.version as (typeof SBOM_CONSUMER_CONTRACT.schemaVersions)[number]) ||
      schema.version !== sbom.schema_version || !source || !nonEmptyString(source.name) || !nonEmptyString(source.version)) {
    return inconclusive("sbom_schema_unsupported");
  }
  const sourceType = source.type;
  const metadata = object(source.metadata);
  const sourceShape = classifySyftSourceShape(source);
  if (sourceShape === "AMBIGUOUS") return blocked("artifact_sbom_binding_mismatch");
  if (typeof sourceType !== "string") return inconclusive("artifact_sbom_binding_missing");
  if (!supportedSourceTypes.has(sourceType as (typeof SBOM_CONSUMER_CONTRACT.sourceTypes)[number])) {
    if (sourceShape === "IMAGE") return blocked("artifact_sbom_binding_mismatch");
    return inconclusive("sbom_source_type_unsupported");
  }
  if (sourceType === "file" && sourceShape !== "FILE") return sourceShape === "IMAGE"
    ? blocked("artifact_sbom_binding_mismatch")
    : inconclusive("artifact_sbom_binding_missing");
  if (sourceType === "image" && sourceShape !== "IMAGE") return sourceShape === "FILE"
    ? inconclusive("artifact_sbom_binding_missing")
    : inconclusive("artifact_sbom_binding_missing");
  if (sourceType === "image") {
    const sourceId = parseOptionalIdentityField(source, "id", true);
    const manifest = parseOptionalIdentityField(metadata, "manifestDigest", false);
    if (sourceId.state === "malformed" || manifest.state === "malformed") {
      return blocked("artifact_sbom_binding_mismatch");
    }
    if (sourceId.state === "absent" && manifest.state === "absent") {
      return inconclusive("artifact_sbom_binding_missing");
    }
    const resolvedIdDigest = sourceId.state === "valid" ? sourceId.digest : undefined;
    const manifestDigestValue = manifest.state === "valid" ? manifest.digest : undefined;
    if (resolvedIdDigest && manifestDigestValue && resolvedIdDigest !== manifestDigestValue) {
      return blocked("artifact_sbom_binding_mismatch");
    }
    if ((resolvedIdDigest && resolvedIdDigest !== artifactDigest) ||
        (manifestDigestValue && manifestDigestValue !== artifactDigest)) {
      return blocked("artifact_sbom_binding_mismatch");
    }
    const imageId = parseOptionalIdentityField(metadata, "imageID", false);
    if (imageId.state === "malformed") return blocked("artifact_sbom_binding_mismatch");
    const mediaTypeClaim = metadata && Object.prototype.hasOwnProperty.call(metadata, "mediaType")
      ? metadata.mediaType
      : undefined;
    if (mediaTypeClaim !== undefined && (typeof mediaTypeClaim !== "string" || mediaTypeClaim.length === 0)) {
      return blocked("artifact_sbom_binding_mismatch");
    }
    let embeddedConfigDigest: string | undefined;
    let embeddedConfigDocument: Record<string, unknown> | undefined;
    let embeddedConfigPayloadDigest: string | undefined;
    let embeddedLayers: unknown;
    let verifiedManifestMediaType: string | undefined;
    if (metadata && Object.prototype.hasOwnProperty.call(metadata, "manifest")) {
      const embeddedManifest = metadata.manifest;
      if (typeof embeddedManifest !== "string" || !isCanonicalBase64(embeddedManifest)) {
        return blocked("artifact_sbom_binding_mismatch");
      }
      const embeddedBytes = Buffer.from(embeddedManifest, "base64");
      if (sha256Bytes(embeddedBytes) !== artifactDigest) {
        return blocked("artifact_sbom_binding_mismatch");
      }
      try {
        const parsedEmbedded = object(JSON.parse(new TextDecoder().decode(embeddedBytes)));
        const config = object(parsedEmbedded?.config);
        if (!parsedEmbedded || !config) return blocked("artifact_sbom_binding_mismatch");
        if (mediaTypeClaim !== undefined && (typeof parsedEmbedded.mediaType !== "string" || parsedEmbedded.mediaType.length === 0)) {
          return blocked("artifact_sbom_binding_mismatch");
        }
        verifiedManifestMediaType = typeof parsedEmbedded.mediaType === "string" ? parsedEmbedded.mediaType : undefined;
        const configDigest = parseOptionalIdentityField(config, "digest", false);
        if (configDigest.state !== "valid") return blocked("artifact_sbom_binding_mismatch");
        embeddedConfigDigest = configDigest.digest;
        embeddedConfigDocument = config;
        embeddedLayers = parsedEmbedded.layers;
      } catch {
        return blocked("artifact_sbom_binding_mismatch");
      }
    }
    if (metadata && Object.prototype.hasOwnProperty.call(metadata, "config")) {
      const encodedConfig = metadata.config;
      if (typeof encodedConfig !== "string" || !isCanonicalBase64(encodedConfig)) {
        return blocked("artifact_sbom_binding_mismatch");
      }
      const configBytes = Buffer.from(encodedConfig, "base64");
      embeddedConfigPayloadDigest = sha256Bytes(configBytes);
      if (imageId.state === "valid" && embeddedConfigPayloadDigest !== imageId.digest) {
        return blocked("artifact_sbom_binding_mismatch");
      }
      try {
        embeddedConfigDocument = object(JSON.parse(configBytes.toString("utf8")));
      } catch {
        return blocked("artifact_sbom_binding_mismatch");
      }
      if (!embeddedConfigDocument) return blocked("artifact_sbom_binding_mismatch");
    }
    if (embeddedConfigPayloadDigest && embeddedConfigDigest && embeddedConfigPayloadDigest !== embeddedConfigDigest) {
      return blocked("artifact_sbom_binding_mismatch");
    }
    const needsArtifactManifest = imageId.state === "valid" ||
      (embeddedConfigPayloadDigest !== undefined && !embeddedConfigDigest) ||
      (mediaTypeClaim !== undefined && !verifiedManifestMediaType) ||
      (metadata && (Object.prototype.hasOwnProperty.call(metadata, "architecture") || Object.prototype.hasOwnProperty.call(metadata, "os"))) ||
      (metadata && Object.prototype.hasOwnProperty.call(metadata, "layers") && !embeddedLayers);
    if (needsArtifactManifest) {
      let configDigest = embeddedConfigDigest;
      if (!configDigest || !embeddedConfigDocument || !embeddedLayers) {
        try {
          const artifactBytes = await readBoundedArtifact(artifactPath);
          if (sha256Bytes(artifactBytes) !== artifactDigest) return blocked("artifact_sbom_binding_mismatch");
          const artifactDocument = object(JSON.parse(artifactBytes.toString("utf8")));
          if (mediaTypeClaim !== undefined && (typeof artifactDocument?.mediaType !== "string" || artifactDocument.mediaType.length === 0)) {
            return blocked("artifact_sbom_binding_mismatch");
          }
          verifiedManifestMediaType = typeof artifactDocument?.mediaType === "string" ? artifactDocument.mediaType : undefined;
          const config = object(artifactDocument?.config);
          const parsedConfig = parseOptionalIdentityField(config, "digest", false);
          if (parsedConfig.state !== "valid") return blocked("artifact_sbom_binding_mismatch");
          configDigest = parsedConfig.digest;
          if (!embeddedConfigDocument) embeddedConfigDocument = config;
          embeddedLayers = artifactDocument?.layers;
        } catch {
          return blocked("artifact_sbom_binding_mismatch");
        }
      }
      if (imageId.state === "valid" && imageId.digest !== configDigest) return blocked("artifact_sbom_binding_mismatch");
      if (embeddedConfigPayloadDigest && embeddedConfigPayloadDigest !== configDigest) return blocked("artifact_sbom_binding_mismatch");
    }
    if (mediaTypeClaim !== undefined && mediaTypeClaim !== verifiedManifestMediaType) {
      return blocked("artifact_sbom_binding_mismatch");
    }
    if (embeddedConfigDocument && metadata) {
      for (const field of ["architecture", "os"] as const) {
        if (Object.prototype.hasOwnProperty.call(metadata, field) && metadata[field] !== embeddedConfigDocument[field]) {
          return blocked("artifact_sbom_binding_mismatch");
        }
      }
    }
    if (metadata && (Object.prototype.hasOwnProperty.call(metadata, "architecture") || Object.prototype.hasOwnProperty.call(metadata, "os")) && !embeddedConfigDocument) {
      return blocked("artifact_sbom_binding_mismatch");
    }
    if (metadata && Object.prototype.hasOwnProperty.call(metadata, "layers")) {
      if (!Array.isArray(metadata.layers) || !Array.isArray(embeddedLayers) || metadata.layers.length !== embeddedLayers.length) {
        return blocked("artifact_sbom_binding_mismatch");
      }
      for (let index = 0; index < metadata.layers.length; index += 1) {
        const sourceLayer = object(metadata.layers[index]);
        const manifestLayer = object(embeddedLayers[index]);
        const sourceDigest = parseOptionalIdentityField(sourceLayer, "digest", false);
        const manifestDigest = parseOptionalIdentityField(manifestLayer, "digest", false);
        if (sourceDigest.state !== "valid" || manifestDigest.state !== "valid" || sourceDigest.digest !== manifestDigest.digest) {
          return blocked("artifact_sbom_binding_mismatch");
        }
      }
    }
  } else if (sourceType === "file") {
    let sourceDigest: string;
    try { sourceDigest = digest(source.version, "artifact_sbom_binding_missing", "artifact_sbom_binding_mismatch") ?? ""; }
    catch { return blocked("artifact_sbom_binding_mismatch"); }
    if (sourceDigest !== artifactDigest) return blocked("artifact_sbom_binding_mismatch");
    const fileDigests = metadata?.digests;
    if (fileDigests !== undefined) {
      if (!Array.isArray(fileDigests)) return inconclusive("artifact_sbom_binding_missing");
      const sha256Values: string[] = [];
      for (const item of fileDigests) {
        const entry = object(item);
        if (!entry || typeof entry.algorithm !== "string") return inconclusive("artifact_sbom_binding_missing");
        if (entry.algorithm !== "sha256") continue;
        if (!Object.prototype.hasOwnProperty.call(entry, "value") ||
            typeof entry.value !== "string" || !/^[a-f0-9]{64}$/.test(entry.value)) {
          return blocked("artifact_sbom_binding_mismatch");
        }
        sha256Values.push(entry.value);
      }
      if (sha256Values.length > 0 && sha256Values.some((value) => `sha256:${value}` !== artifactDigest)) {
        return blocked("artifact_sbom_binding_mismatch");
      }
    }
  }
  if (!Array.isArray(artifacts)) return inconclusive("sbom_inventory_missing");
  if (artifacts.length === 0) return inconclusive("sbom_inventory_empty");
  if (artifacts.length > SBOM_RESOURCE_LIMITS.maxPackageCount) return inconclusive("sbom_package_limit_exceeded");
  if (!artifacts.every(isPackageRecord)) return inconclusive("sbom_inventory_malformed");
  const ids = artifacts.map((item) => (item as Record<string, unknown>).id as string);
  if (new Set(ids).size !== ids.length) return inconclusive("sbom_inventory_duplicate_id");
  if (inventory.status !== "present" || inventory.package_count !== artifacts.length) return inconclusive("sbom_inventory_count_mismatch");
  return { status: "pass", reasonCodes: [], format: SBOM_CONSUMER_CONTRACT.format, schemaVersion: schema.version, inventoryStatus: "present", packageCount: artifacts.length };
}

async function readBoundedArtifact(path: string): Promise<Buffer> {
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(maxEmbeddedManifestBytes + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > maxEmbeddedManifestBytes) throw new Error("artifact_too_large");
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

function parseOptionalIdentityField(container: Record<string, unknown> | undefined, key: string, allowBareHex: boolean): OptionalIdentity {
  if (!container || !Object.prototype.hasOwnProperty.call(container, key)) return { state: "absent" };
  const value = container[key];
  if (allowBareHex && typeof value === "string" && /^[a-f0-9]{64}$/.test(value)) {
    return { state: "valid", digest: `sha256:${value}` };
  }
  try {
    const parsed = parseDigest(value);
    return { state: "valid", digest: `sha256:${parsed.hex}` };
  } catch {
    return { state: "malformed" };
  }
}

function isCanonicalBase64(value: string): boolean {
  return value.length > 0 && value.length % 4 === 0 &&
    /^[A-Za-z0-9+/]*={0,2}$/.test(value) &&
    Buffer.from(value, "base64").toString("base64") === value;
}
