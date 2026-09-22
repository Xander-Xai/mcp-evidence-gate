import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, afterEach } from "vitest";
import { SBOM_CONSUMER_CONTRACT, classifySyftSourceShape, loadSbomEvidence, verifySbomEvidence } from "../src/core/sbom.js";
import { sha256Bytes } from "../src/core/digest.js";

const fixtureRoot = join(process.cwd(), "tests", "fixtures", "sbom");
const fixtureFiles = {
  "16.1.3": join(fixtureRoot, "syft-1.52.0-official-16.1.3.min.json"),
  "16.1.10": join(fixtureRoot, "github-mcp-server-16.1.10.min.json")
} as const;
const dirs: string[] = [];

type QualifiedSchema = keyof typeof fixtureFiles;
type CaseResult = { status: string; reasonCodes?: string[] };

async function makeFixture(schemaVersion: QualifiedSchema) {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sbom-schema-qualification-"));
  dirs.push(dir);
  const artifactPath = join(dir, "artifact.bin");
  const artifactBytes = new TextEncoder().encode("wave-3-7-qualification-artifact");
  await writeFile(artifactPath, artifactBytes);
  const artifactDigest = sha256Bytes(artifactBytes);
  const otherDigest = sha256Bytes(new TextEncoder().encode("other-artifact"));
  // Synthetic matrix fixture: keep this separate from the real OCI fixture so
  // the qualification matrix cannot hide a source-binding mutation.
  const document = {
    schema: { version: schemaVersion },
    source: { name: "synthetic-artifact", version: artifactDigest, type: "file", metadata: { path: "artifact.bin", mimeType: "application/octet-stream", digests: [{ algorithm: "sha256", value: artifactDigest.slice("sha256:".length) }] } },
    artifacts: [{ id: "pkg-1", name: "qualification-package", version: "1.0.0", type: "deb" }]
  } as Record<string, any>;
  const sbomBytes = new TextEncoder().encode(JSON.stringify(document));
  const envelope = (bytes = sbomBytes, options: { artifactSha?: string; source?: string; binding?: string; count?: number } = {}) => ({
    schema_version: "project-defined-sbom-evidence-v1",
    artifact: { ref: "artifact.bin", sha256: options.artifactSha ?? artifactDigest, size: artifactBytes.byteLength },
    sbom: { format: "syft-json", schema_version: schemaVersion, sha256: sha256Bytes(bytes), size: bytes.byteLength },
    relationship: {
      type: "generated-from",
      artifact_sha256: options.artifactSha ?? artifactDigest,
      sbom_sha256: sha256Bytes(bytes),
      binding: options.binding ?? "exact-artifact"
    },
    inventory: { status: "present", package_count: options.count ?? document.artifacts.length }
  });
  return { dir, artifactPath, artifactDigest, otherDigest, document, sbomBytes, envelope };
}

async function runCases(schemaVersion: QualifiedSchema): Promise<Record<string, CaseResult>> {
  const f = await makeFixture(schemaVersion);
  const exact = () => verifySbomEvidence(f.artifactPath, f.envelope(), f.sbomBytes);
  const tampered = () => verifySbomEvidence(f.artifactPath, f.envelope(), Uint8Array.from([...f.sbomBytes, 0x0a]));
  const artifactMismatch = () => verifySbomEvidence(f.artifactPath, f.envelope(f.sbomBytes, { artifactSha: f.otherDigest }), f.sbomBytes);
  const malformedBytes = new TextEncoder().encode("{");
  const malformed = () => verifySbomEvidence(f.artifactPath, f.envelope(malformedBytes, { count: 0 }), malformedBytes);
  const emptyDocument = { ...f.document, artifacts: [] };
  const emptyBytes = new TextEncoder().encode(JSON.stringify(emptyDocument));
  const empty = () => verifySbomEvidence(f.artifactPath, f.envelope(emptyBytes, { count: 0 }), emptyBytes);
  const duplicateDocument = { ...f.document, artifacts: [f.document.artifacts[0], f.document.artifacts[0]] };
  const duplicateBytes = new TextEncoder().encode(JSON.stringify(duplicateDocument));
  const duplicate = () => verifySbomEvidence(f.artifactPath, f.envelope(duplicateBytes, { count: 2 }), duplicateBytes);
  const countMismatch = () => verifySbomEvidence(f.artifactPath, f.envelope(f.sbomBytes, { count: f.document.artifacts.length - 1 }), f.sbomBytes);
  const unsupportedRelationship = () => verifySbomEvidence(f.artifactPath, f.envelope(f.sbomBytes, { binding: "same-release" }), f.sbomBytes);
  const sourceMismatchDocument = { ...f.document, source: { ...f.document.source, version: f.otherDigest } };
  const sourceMismatchBytes = new TextEncoder().encode(JSON.stringify(sourceMismatchDocument));
  const sourceMismatch = () => verifySbomEvidence(f.artifactPath, f.envelope(sourceMismatchBytes), sourceMismatchBytes);
  const oversized = () => verifySbomEvidence(f.artifactPath, f.envelope(), new Uint8Array(64 * 1024 * 1024 + 1));
  const missing = async () => {
    const result = await loadSbomEvidence(join(f.dir, "missing-envelope.json"), join(f.dir, "missing-sbom.json"));
    return result.status === "result" ? result.result : { status: result.status, reasonCodes: [] };
  };
  return {
    A_exact_valid: await exact(),
    B_sbom_tamper: await tampered(),
    C_artifact_mismatch: await artifactMismatch(),
    D_malformed_json: await malformed(),
    E_missing_sbom: await missing(),
    F_empty_inventory: await empty(),
    G_duplicate_package_id: await duplicate(),
    H_claimed_package_count_mismatch: await countMismatch(),
    I_unsupported_relationship: await unsupportedRelationship(),
    J_source_metadata_mismatch: await sourceMismatch(),
    K_oversized_sbom: await oversized()
  };
}

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("Syft JSON 16.1.3 and 16.1.10 qualification", () => {
  it("exports one complete schema allowlist used by the consumer", () => {
    expect(SBOM_CONSUMER_CONTRACT.schemaVersions).toEqual(["16.1.3", "16.1.10"]);
    expect(SBOM_CONSUMER_CONTRACT.sourceTypes).toEqual(["file", "image"]);
    expect(classifySyftSourceShape({ metadata: { path: "x", digests: [], mimeType: "" } })).toBe("FILE");
    expect(classifySyftSourceShape({ metadata: { imageID: "x", layers: [] } })).toBe("IMAGE");
    expect(classifySyftSourceShape({ metadata: { path: "x", manifest: "{}" } })).toBe("AMBIGUOUS");
    expect(classifySyftSourceShape({ metadata: {} })).toBe("UNKNOWN");
  });

  it("keeps the complete admission matrix semantically equivalent", async () => {
    const oldSchema = await runCases("16.1.3");
    const newSchema = await runCases("16.1.10");
    const withoutSchemaVersion = (results: Record<string, CaseResult>) => Object.fromEntries(
      Object.entries(results).map(([name, result]) => [name, { ...result, schemaVersion: undefined }])
    );
    expect(withoutSchemaVersion(newSchema)).toEqual(withoutSchemaVersion(oldSchema));
    expect(oldSchema.A_exact_valid).toMatchObject({ schemaVersion: "16.1.3" });
    expect(newSchema.A_exact_valid).toMatchObject({ schemaVersion: "16.1.10" });
    expect(oldSchema).toMatchObject({
      A_exact_valid: { status: "pass" },
      B_sbom_tamper: { status: "blocked", reasonCodes: ["sbom_digest_mismatch"] },
      C_artifact_mismatch: { status: "blocked", reasonCodes: ["artifact_digest_mismatch"] },
      D_malformed_json: { status: "inconclusive", reasonCodes: ["sbom_malformed"] },
      E_missing_sbom: { status: "inconclusive", reasonCodes: ["sbom_missing"] },
      F_empty_inventory: { status: "inconclusive", reasonCodes: ["sbom_inventory_empty"] },
      G_duplicate_package_id: { status: "inconclusive", reasonCodes: ["sbom_inventory_duplicate_id"] },
      H_claimed_package_count_mismatch: { status: "inconclusive", reasonCodes: ["sbom_inventory_count_mismatch"] },
      I_unsupported_relationship: { status: "inconclusive", reasonCodes: ["artifact_sbom_binding_missing"] },
      J_source_metadata_mismatch: { status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] },
      K_oversized_sbom: { status: "inconclusive", reasonCodes: ["sbom_size_limit_exceeded"] }
    });
  });

  it("fails closed on malformed file SHA-256 identity claims without tightening absence semantics", async () => {
    const f = await makeFixture("16.1.3");
    const verifySource = async (mutate: (source: Record<string, any>) => void) => {
      const document = JSON.parse(JSON.stringify(f.document)) as Record<string, any>;
      mutate(document.source);
      const bytes = new TextEncoder().encode(JSON.stringify(document));
      return verifySbomEvidence(f.artifactPath, f.envelope(bytes), bytes);
    };
    const malformed = [
      (source: Record<string, any>) => { source.metadata.digests = [{ algorithm: "sha256", value: null }]; },
      (source: Record<string, any>) => { source.metadata.digests = [{ algorithm: "sha256", value: "" }]; },
      (source: Record<string, any>) => { source.metadata.digests = [{ algorithm: "sha256" }]; },
      (source: Record<string, any>) => { source.metadata.digests = [{ algorithm: "sha256", value: 123 }]; },
      (source: Record<string, any>) => { source.metadata.digests = [{ algorithm: "sha256", value: "not-a-digest" }]; },
      (source: Record<string, any>) => { source.metadata.digests = [{ algorithm: "sha256", value: "0".repeat(64) }]; },
      (source: Record<string, any>) => { source.metadata.digests = [{ algorithm: "sha256", value: f.artifactDigest.slice("sha256:".length) }, { algorithm: "sha256", value: null }]; },
      (source: Record<string, any>) => { source.metadata.digests = [{ algorithm: "sha256", value: f.artifactDigest.slice("sha256:".length) }, { algorithm: "sha256", value: "0".repeat(64) }]; }
    ];
    for (const mutate of malformed) {
      expect(await verifySource(mutate)).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
    expect(await verifySource((source) => {
      source.metadata.digests = [
        { algorithm: "sha256", value: f.artifactDigest.slice("sha256:".length) },
        { algorithm: "sha256", value: f.artifactDigest.slice("sha256:".length) }
      ];
    })).toMatchObject({ status: "pass", schemaVersion: "16.1.3" });
    expect(await verifySource((source) => { source.metadata.digests = [{ algorithm: "sha1", value: "legacy" }]; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.3" });
    expect(await verifySource((source) => { delete source.metadata.digests; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.3" });
    expect(await verifySource((source) => { source.metadata.digests = [null]; }))
      .toMatchObject({ status: "inconclusive", reasonCodes: ["artifact_sbom_binding_missing"] });
    expect(await verifySource((source) => { source.metadata.digests = {}; }))
      .toMatchObject({ status: "inconclusive", reasonCodes: ["artifact_sbom_binding_missing"] });
  });

  it("keeps an exact-shaped future 16.1.11 document unsupported", async () => {
    const f = await makeFixture("16.1.10");
    const futureDocument = JSON.parse(JSON.stringify(f.document)) as Record<string, any>;
    futureDocument.schema.version = "16.1.11";
    const futureBytes = new TextEncoder().encode(JSON.stringify(futureDocument));
    const futureEnvelope = f.envelope(futureBytes, { count: futureDocument.artifacts.length });
    (futureEnvelope.sbom as Record<string, unknown>).schema_version = "16.1.11";
    const result = await verifySbomEvidence(f.artifactPath, futureEnvelope, futureBytes);
    expect(result).toMatchObject({ status: "inconclusive", reasonCodes: ["sbom_schema_unsupported"] });
  });

  it("qualifies the real 16.1.10 SBOM against the resolved OCI scan subject", async () => {
    const realArtifactPath = join(fixtureRoot, "github-mcp-server-b281-manifest.json");
    const requestedArtifactPath = join(fixtureRoot, "github-mcp-server-a44e77b-manifest.json");
    const mismatchArtifactPath = join(fixtureRoot, "ibm-mcp-context-forge-dd0998-manifest.json");
    const realSbomPath = fixtureFiles["16.1.10"];
    const artifactBytes = new Uint8Array(await readFile(realArtifactPath));
    const requestedBytes = new Uint8Array(await readFile(requestedArtifactPath));
    const sbomBytes = new Uint8Array(await readFile(realSbomPath));
    const mismatchBytes = new Uint8Array(await readFile(mismatchArtifactPath));
    const document = JSON.parse(new TextDecoder().decode(sbomBytes)) as Record<string, any>;
    const realDigest = sha256Bytes(artifactBytes);
    const requestedDigest = sha256Bytes(requestedBytes);
    const mismatchDigest = sha256Bytes(mismatchBytes);
    expect(realDigest).toBe("sha256:b2814a05586591dd361d361c26bbb1e1154cfbc1544fca32785fde5e11270d07");
    expect(requestedDigest).toBe("sha256:a44e77b9c9003ed0e228716d118aa4ce9f3418dce30fe2340c71553164bd96f0");
    expect(document.source.version).toBe(requestedDigest);
    expect(document.source.id).toBe("b2814a05586591dd361d361c26bbb1e1154cfbc1544fca32785fde5e11270d07");
    expect(document.source.metadata.manifestDigest).toBe(realDigest);
    const envelope = (artifactSha: string, relationshipArtifactSha = artifactSha, bytes = sbomBytes, artifactSize = artifactBytes.byteLength) => ({
      schema_version: SBOM_CONSUMER_CONTRACT.envelopeSchema,
      artifact: { ref: "ghcr.io/github/github-mcp-server@" + realDigest, sha256: artifactSha, size: artifactSize },
      sbom: { format: SBOM_CONSUMER_CONTRACT.format, schema_version: "16.1.10", sha256: sha256Bytes(bytes), size: bytes.byteLength },
      relationship: { type: SBOM_CONSUMER_CONTRACT.relationshipType, artifact_sha256: relationshipArtifactSha, sbom_sha256: sha256Bytes(bytes), binding: SBOM_CONSUMER_CONTRACT.binding },
      inventory: { status: "present", package_count: document.artifacts.length }
    });
    const exact = await verifySbomEvidence(realArtifactPath, envelope(realDigest), sbomBytes);
    expect(exact).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    const requestedAsArtifact = await verifySbomEvidence(requestedArtifactPath, envelope(requestedDigest, requestedDigest, sbomBytes, requestedBytes.byteLength), sbomBytes);
    expect(requestedAsArtifact).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    const tampered = await verifySbomEvidence(realArtifactPath, envelope(realDigest), Uint8Array.from([...sbomBytes, 0x0a]));
    expect(tampered).toMatchObject({ status: "blocked", reasonCodes: ["sbom_digest_mismatch"] });
    const mismatch = await verifySbomEvidence(mismatchArtifactPath, envelope(mismatchDigest, realDigest, sbomBytes, mismatchBytes.byteLength), sbomBytes);
    expect(mismatch).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });

    const withSource = async (mutate: (source: Record<string, any>) => void) => {
      const mutated = JSON.parse(JSON.stringify(document)) as Record<string, any>;
      mutate(mutated.source);
      const bytes = new TextEncoder().encode(JSON.stringify(mutated));
      return verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, bytes), bytes);
    };
    expect(await withSource((source) => {
      source.id = requestedDigest.slice("sha256:".length);
      source.metadata.manifestDigest = realDigest;
    }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.manifestDigest = requestedDigest; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.manifest = Buffer.from("{}").toString("base64"); }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.manifest = "not-base64"; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.id = requestedDigest.slice("sha256:".length); }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.manifestDigest = null; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.manifestDigest = ""; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.manifestDigest = 123; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.id = null; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.id = ""; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.id = "invalid"; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { delete source.id; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(await withSource((source) => { delete source.metadata.manifestDigest; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(await withSource((source) => { delete source.id; delete source.metadata.manifestDigest; }))
      .toMatchObject({ status: "inconclusive", reasonCodes: ["artifact_sbom_binding_missing"] });
    expect(await withSource((source) => { source.type = "file"; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.type = "file"; delete source.metadata.manifestDigest; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.type = "file"; source.metadata.manifestDigest = null; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.type = "file"; delete source.metadata.manifestDigest; delete source.metadata.manifest; delete source.metadata.userInput; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.type = "file"; delete source.metadata.manifestDigest; delete source.metadata.layers; delete source.metadata.manifest; delete source.metadata.userInput; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.type = "file"; delete source.metadata.manifestDigest; delete source.metadata.imageID; delete source.metadata.layers; delete source.metadata.userInput; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { delete source.type; }))
      .toMatchObject({ status: "inconclusive", reasonCodes: ["artifact_sbom_binding_missing"] });
    expect(await withSource((source) => { source.type = "unknown-test-type"; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => {
      source.type = "image";
      source.metadata = { path: "image-as-file", digests: [], mimeType: "" };
    })).toMatchObject({ status: "inconclusive", reasonCodes: ["artifact_sbom_binding_missing"] });
  });
});
