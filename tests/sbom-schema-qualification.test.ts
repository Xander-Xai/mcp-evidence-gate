import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { describe, expect, it, afterEach } from "vitest";
import { SBOM_CONSUMER_CONTRACT, classifySyftSourceShape, loadSbomEvidence, verifySbomEvidence } from "../src/core/sbom.js";
import { readBoundedArtifactFromHandle } from "../src/core/bounded-reader.js";
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
    expect(classifySyftSourceShape({ metadata: { config: "base64" } })).toBe("IMAGE");
    expect(classifySyftSourceShape({ metadata: { mediaType: null } })).toBe("IMAGE");
    expect(classifySyftSourceShape({ metadata: { imageSize: 0 } })).toBe("IMAGE");
    expect(classifySyftSourceShape({ metadata: { repoDigests: [] } })).toBe("IMAGE");
    expect(classifySyftSourceShape({ metadata: { tags: [] } })).toBe("IMAGE");
    expect(classifySyftSourceShape({ metadata: { labels: {} } })).toBe("IMAGE");
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

  it("rejects integrity-consistent but structurally invalid OCI image configs", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-sbom-invalid-image-config-"));
    dirs.push(dir);
    const artifactPath = join(dir, "manifest.json");
    const original = JSON.parse(await readFile(fixtureFiles["16.1.10"], "utf8")) as Record<string, any>;
    const configMediaType = "application/vnd.oci.image.config.v1+json";
    const manifestMediaType = "application/vnd.oci.image.manifest.v1+json";
    const baseConfig = { architecture: "amd64", os: "linux", rootfs: { type: "layers", diff_ids: [] } };
    const verifyConfig = async (configValue: unknown) => {
      const configBytes = Buffer.from(JSON.stringify(configValue));
      const configDigest = sha256Bytes(configBytes);
      const manifest = {
        schemaVersion: 2,
        mediaType: manifestMediaType,
        config: { mediaType: configMediaType, digest: configDigest, size: configBytes.byteLength },
        layers: []
      };
      const artifactBytes = Buffer.from(JSON.stringify(manifest));
      const artifactDigest = sha256Bytes(artifactBytes);
      await writeFile(artifactPath, artifactBytes);
      const document = JSON.parse(JSON.stringify(original)) as Record<string, any>;
      document.source.id = artifactDigest.slice("sha256:".length);
      document.source.version = artifactDigest;
      document.source.metadata = {
        manifestDigest: artifactDigest,
        imageID: configDigest,
        manifest: artifactBytes.toString("base64"),
        config: configBytes.toString("base64")
      };
      const sbomBytes = Buffer.from(JSON.stringify(document));
      const sbomDigest = sha256Bytes(sbomBytes);
      const envelope = {
        schema_version: SBOM_CONSUMER_CONTRACT.envelopeSchema,
        artifact: { ref: `example.test/image@${artifactDigest}`, sha256: artifactDigest, size: artifactBytes.byteLength },
        sbom: { format: SBOM_CONSUMER_CONTRACT.format, schema_version: "16.1.10", sha256: sbomDigest, size: sbomBytes.byteLength },
        relationship: { type: SBOM_CONSUMER_CONTRACT.relationshipType, artifact_sha256: artifactDigest, sbom_sha256: sbomDigest, binding: SBOM_CONSUMER_CONTRACT.binding },
        inventory: { status: "present", package_count: document.artifacts.length }
      };
      return verifySbomEvidence(artifactPath, envelope, sbomBytes);
    };

    expect(await verifyConfig(baseConfig)).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    const invalidConfigs: unknown[] = [
      {},
      { os: "linux", rootfs: baseConfig.rootfs },
      { ...baseConfig, architecture: "" },
      { ...baseConfig, architecture: 1 },
      { architecture: "amd64", rootfs: baseConfig.rootfs },
      { ...baseConfig, os: "" },
      { architecture: "amd64", os: "linux" },
      { ...baseConfig, rootfs: [] },
      { ...baseConfig, rootfs: { diff_ids: [] } },
      { ...baseConfig, rootfs: { type: "something-else", diff_ids: [] } },
      { ...baseConfig, rootfs: { type: "layers" } },
      { ...baseConfig, rootfs: { type: "layers", diff_ids: {} } },
      { ...baseConfig, rootfs: { type: "layers", diff_ids: ["not-a-digest"] } },
      { ...baseConfig, rootfs: { type: "layers", diff_ids: [`sha256:${"0".repeat(64)}`] } }
    ];
    for (const invalidConfig of invalidConfigs) {
      expect(await verifyConfig(invalidConfig)).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
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
    const fixtureConfig = JSON.parse(Buffer.from(document.source.metadata.config, "base64").toString("utf8"));
    const fixtureManifest = JSON.parse(Buffer.from(document.source.metadata.manifest, "base64").toString("utf8"));
    const envelope = (artifactSha: string, relationshipArtifactSha = artifactSha, bytes = sbomBytes, artifactSize = artifactBytes.byteLength) => ({
      schema_version: SBOM_CONSUMER_CONTRACT.envelopeSchema,
      artifact: { ref: "ghcr.io/github/github-mcp-server@" + realDigest, sha256: artifactSha, size: artifactSize },
      sbom: { format: SBOM_CONSUMER_CONTRACT.format, schema_version: "16.1.10", sha256: sha256Bytes(bytes), size: bytes.byteLength },
      relationship: { type: SBOM_CONSUMER_CONTRACT.relationshipType, artifact_sha256: relationshipArtifactSha, sbom_sha256: sha256Bytes(bytes), binding: SBOM_CONSUMER_CONTRACT.binding },
      inventory: { status: "present", package_count: document.artifacts.length }
    });
    const exact = await verifySbomEvidence(realArtifactPath, envelope(realDigest), sbomBytes);
    expect(exact).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    const withSource = async (mutate: (source: Record<string, any>) => void) => {
      const mutated = JSON.parse(JSON.stringify(document)) as Record<string, any>;
      mutate(mutated.source);
      const bytes = new TextEncoder().encode(JSON.stringify(mutated));
      return verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, bytes), bytes);
    };
    for (const mutate of [
      (source: Record<string, any>) => { source.metadata.repoDigests = null; },
      (source: Record<string, any>) => { source.metadata.repoDigests = {}; },
      (source: Record<string, any>) => { source.metadata.repoDigests = ["ghcr.io/other/image@sha256:" + "a".repeat(64)]; },
      (source: Record<string, any>) => { source.metadata.tags = null; },
      (source: Record<string, any>) => { source.metadata.tags = ["ghcr.io/other/image:latest"]; },
      (source: Record<string, any>) => { source.metadata.tags = [`ghcr.io/github/github-mcp-server:latest@sha256:${"0".repeat(64)}`]; },
      (source: Record<string, any>) => { source.metadata.userInput = null; },
      (source: Record<string, any>) => { source.metadata.userInput = {}; },
      (source: Record<string, any>) => { source.metadata.userInput = "ghcr.io/github/github-mcp-server@sha256:" + "a".repeat(64); },
      (source: Record<string, any>) => { source.version = "not-a-digest"; },
      (source: Record<string, any>) => { source.version = "sha256:" + "a".repeat(64); }
    ]) {
      expect(await withSource(mutate)).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
    expect(await withSource((source) => { source.metadata.repoDigests = []; source.metadata.tags = []; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(await withSource((source) => { source.name = "ghcr.io/other/github-mcp-server"; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => {
      source.metadata.userInput = `ghcr.io/other/github-mcp-server@${requestedDigest}`;
      source.metadata.repoDigests = [`ghcr.io/other/github-mcp-server@${requestedDigest}`];
    })).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });

    const verifyManifestMutation = async (mutate: (manifest: Record<string, any>) => void, sourceMediaType?: string) => {
      const changedManifest = JSON.parse(JSON.stringify(fixtureManifest)) as Record<string, any>;
      mutate(changedManifest);
      const changedArtifactBytes = Buffer.from(JSON.stringify(changedManifest));
      const changedArtifactDigest = sha256Bytes(changedArtifactBytes);
      const changedArtifactDir = await mkdtemp(join(tmpdir(), "mcp-sbom-image-media-type-"));
      dirs.push(changedArtifactDir);
      const changedArtifactPath = join(changedArtifactDir, "manifest.json");
      await writeFile(changedArtifactPath, changedArtifactBytes);
      const changedDocument = JSON.parse(JSON.stringify(document)) as Record<string, any>;
      changedDocument.source.id = changedArtifactDigest.slice("sha256:".length);
      changedDocument.source.metadata.manifestDigest = changedArtifactDigest;
      changedDocument.source.metadata.manifest = changedArtifactBytes.toString("base64");
      if (sourceMediaType === undefined) delete changedDocument.source.metadata.mediaType;
      else changedDocument.source.metadata.mediaType = sourceMediaType;
      const changedSbomBytes = new TextEncoder().encode(JSON.stringify(changedDocument));
      return verifySbomEvidence(
        changedArtifactPath,
        envelope(changedArtifactDigest, changedArtifactDigest, changedSbomBytes, changedArtifactBytes.byteLength),
        changedSbomBytes
      );
    };
    expect(await verifyManifestMutation((manifest) => { manifest.mediaType = "text/plain"; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await verifyManifestMutation((manifest) => { manifest.config.mediaType = "text/plain"; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await verifyManifestMutation((manifest) => {
      manifest.mediaType = "application/vnd.oci.image.manifest.v1+json";
      manifest.config.mediaType = "application/vnd.oci.image.config.v1+json";
    }, "application/vnd.oci.image.manifest.v1+json")).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(document.source.metadata.layers.map((layer: any) => layer.size).reduce((sum: number, size: number) => sum + size, 0)).toBe(46854914);
    expect(fixtureManifest.layers.reduce((sum: number, layer: any) => sum + layer.size, 0)).toBe(48188928);
    expect(document.source.metadata.layers.every((layer: any, index: number) => layer.digest === fixtureConfig.rootfs.diff_ids[index])).toBe(true);
    expect(document.source.metadata.layers.some((layer: any, index: number) => layer.size !== fixtureManifest.layers[index].size)).toBe(true);
    const requestedAsArtifact = await verifySbomEvidence(requestedArtifactPath, envelope(requestedDigest, requestedDigest, sbomBytes, requestedBytes.byteLength), sbomBytes);
    expect(requestedAsArtifact).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    const tampered = await verifySbomEvidence(realArtifactPath, envelope(realDigest), Uint8Array.from([...sbomBytes, 0x0a]));
    expect(tampered).toMatchObject({ status: "blocked", reasonCodes: ["sbom_digest_mismatch"] });
    const mismatch = await verifySbomEvidence(mismatchArtifactPath, envelope(mismatchDigest, realDigest, sbomBytes, mismatchBytes.byteLength), sbomBytes);
    expect(mismatch).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });

    const arbitraryImageArtifactDir = await mkdtemp(join(tmpdir(), "mcp-sbom-arbitrary-image-artifact-"));
    dirs.push(arbitraryImageArtifactDir);
    const arbitraryImageArtifactPath = join(arbitraryImageArtifactDir, "artifact.bin");
    const arbitraryImageArtifact = Buffer.from("these bytes are not an OCI image manifest");
    const arbitraryImageDigest = sha256Bytes(arbitraryImageArtifact);
    await writeFile(arbitraryImageArtifactPath, arbitraryImageArtifact);
    const identityOnlyImage = JSON.parse(JSON.stringify(document)) as Record<string, any>;
    identityOnlyImage.source.id = arbitraryImageDigest.slice("sha256:".length);
    identityOnlyImage.source.version = arbitraryImageDigest;
    identityOnlyImage.source.metadata = { userInput: "identity-only image source" };
    const identityOnlyImageBytes = new TextEncoder().encode(JSON.stringify(identityOnlyImage));
    expect(await verifySbomEvidence(
      arbitraryImageArtifactPath,
      envelope(arbitraryImageDigest, arbitraryImageDigest, identityOnlyImageBytes, arbitraryImageArtifact.byteLength),
      identityOnlyImageBytes
    )).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
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
    expect(await withSource((source) => { source.metadata.mediaType = "application/vnd.docker.distribution.manifest.v2+json"; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(await withSource((source) => { source.metadata.labels = { ...source.metadata.labels }; })).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(await withSource((source) => { source.metadata.imageSize = 46854914; })).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    for (const value of [null, "46854914", -1, 46854914.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(await withSource((source) => { source.metadata.imageSize = value; }))
        .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
    expect(await withSource((source) => { source.metadata.imageSize = 46854915; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { delete source.metadata.imageSize; source.metadata.layers[0].size += 1; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    const originalLayerSizes = document.source.metadata.layers.map((layer: any) => layer.size);
    const balancedTamper = await withSource((source) => {
      source.metadata.layers[0].size = originalLayerSizes[0] + 1;
      source.metadata.layers[1].size = originalLayerSizes[1] - 1;
      delete source.metadata.imageSize;
    });
    expect(originalLayerSizes[0] + originalLayerSizes[1]).toBe(
      (originalLayerSizes[0] + 1) + (originalLayerSizes[1] - 1)
    );
    expect(balancedTamper).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(await withSource((source) => { source.metadata.imageSize = 46854914; source.metadata.layers[0].size += 1; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    for (const value of [null, "123", -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(await withSource((source) => { source.metadata.imageSize = 46854914; source.metadata.layers[0].size = value; }))
        .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
    expect(await withSource((source) => { source.metadata.imageSize = 46854914; delete source.metadata.layers[0].size; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { delete source.metadata.imageSize; })).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(await withSource((source) => { source.metadata.layers[0].mediaType = fixtureManifest.layers[0].mediaType; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    for (const value of ["application/example.invalid", null, "", 123]) {
      expect(await withSource((source) => { source.metadata.layers[0].mediaType = value; }))
        .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
    expect(await withSource((source) => { delete source.metadata.layers[0].mediaType; }))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.10" });

    const oversizedManifestDir = await mkdtemp(join(tmpdir(), "mcp-sbom-oversized-manifest-"));
    dirs.push(oversizedManifestDir);
    const oversizedManifestPath = join(oversizedManifestDir, "manifest.json");
    const oversizedManifestDocument = JSON.parse(JSON.stringify(document)) as Record<string, any>;
    const oversizedManifestBytes = Buffer.concat([
      Buffer.from(oversizedManifestDocument.source.metadata.manifest, "base64"),
      Buffer.alloc(4 * 1024 * 1024, 0x20)
    ]);
    const oversizedManifestDigest = sha256Bytes(oversizedManifestBytes);
    await writeFile(oversizedManifestPath, oversizedManifestBytes);
    oversizedManifestDocument.source.id = oversizedManifestDigest.slice("sha256:".length);
    oversizedManifestDocument.source.version = oversizedManifestDigest;
    oversizedManifestDocument.source.metadata.manifestDigest = oversizedManifestDigest;
    oversizedManifestDocument.source.metadata.manifest = oversizedManifestBytes.toString("base64");
    const oversizedSbomBytes = new TextEncoder().encode(JSON.stringify(oversizedManifestDocument));
    expect(await verifySbomEvidence(
      oversizedManifestPath,
      envelope(oversizedManifestDigest, oversizedManifestDigest, oversizedSbomBytes, oversizedManifestBytes.byteLength),
      oversizedSbomBytes
    )).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });

    // A deterministic compressed blob gives a distinct descriptor digest and
    // uncompressed DiffID; Syft's layer digest must bind to the latter.
    const compressedControlDir = await mkdtemp(join(tmpdir(), "mcp-sbom-compressed-layer-"));
    dirs.push(compressedControlDir);
    const compressedControlArtifactPath = join(compressedControlDir, "manifest.json");
    const compressedControl = JSON.parse(JSON.stringify(document)) as Record<string, any>;
    const rawLayer = Buffer.from("synthetic uncompressed layer bytes for DiffID control");
    const compressedLayer = gzipSync(rawLayer);
    const expectedDiffId = sha256Bytes(rawLayer);
    const compressedBlobDigest = sha256Bytes(compressedLayer);
    expect(compressedBlobDigest).not.toBe(expectedDiffId);
    const compressedConfig = JSON.parse(Buffer.from(compressedControl.source.metadata.config, "base64").toString("utf8"));
    compressedConfig.rootfs.diff_ids[0] = expectedDiffId;
    const compressedConfigBytes = Buffer.from(JSON.stringify(compressedConfig));
    const compressedConfigDigest = sha256Bytes(compressedConfigBytes);
    const compressedManifest = JSON.parse(Buffer.from(compressedControl.source.metadata.manifest, "base64").toString("utf8"));
    compressedManifest.config.digest = compressedConfigDigest;
    compressedManifest.config.size = compressedConfigBytes.byteLength;
    compressedManifest.layers[0].digest = compressedBlobDigest;
    compressedManifest.layers[0].size = compressedLayer.byteLength;
    const compressedManifestBytes = Buffer.from(JSON.stringify(compressedManifest));
    const compressedManifestDigest = sha256Bytes(compressedManifestBytes);
    await writeFile(compressedControlArtifactPath, compressedManifestBytes);
    compressedControl.source.id = compressedManifestDigest.slice("sha256:".length);
    compressedControl.source.version = compressedManifestDigest;
    compressedControl.source.metadata.userInput = `ghcr.io/github/github-mcp-server@${compressedManifestDigest}`;
    compressedControl.source.metadata.repoDigests = [`ghcr.io/github/github-mcp-server@${compressedManifestDigest}`];
    compressedControl.source.metadata.manifestDigest = compressedManifestDigest;
    compressedControl.source.metadata.imageID = compressedConfigDigest;
    compressedControl.source.metadata.manifest = compressedManifestBytes.toString("base64");
    compressedControl.source.metadata.config = compressedConfigBytes.toString("base64");
    compressedControl.source.metadata.layers[0].digest = expectedDiffId;
    const verifyCompressedControl = async (sourceDocument: Record<string, any>) => {
      const bytes = new TextEncoder().encode(JSON.stringify(sourceDocument));
      return verifySbomEvidence(
        compressedControlArtifactPath,
        envelope(compressedManifestDigest, compressedManifestDigest, bytes, compressedManifestBytes.byteLength),
        bytes
      );
    };
    expect(await verifyCompressedControl(compressedControl)).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    const wrongCompressedDigest = JSON.parse(JSON.stringify(compressedControl)) as Record<string, any>;
    wrongCompressedDigest.source.metadata.layers[0].digest = compressedBlobDigest;
    expect(await verifyCompressedControl(wrongCompressedDigest)).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });

    const configSizeControlDir = await mkdtemp(join(tmpdir(), "mcp-sbom-config-size-control-"));
    dirs.push(configSizeControlDir);
    const configSizeControlPath = join(configSizeControlDir, "manifest.json");
    const configSizeControl = JSON.parse(JSON.stringify(document)) as Record<string, any>;
    const originalConfigBytes = Buffer.from(configSizeControl.source.metadata.config, "base64");
    const longerConfigBytes = Buffer.concat([originalConfigBytes, Buffer.from(" ")]);
    const longerConfigDigest = sha256Bytes(longerConfigBytes);
    const configSizeManifest = JSON.parse(Buffer.from(configSizeControl.source.metadata.manifest, "base64").toString("utf8"));
    configSizeManifest.config.digest = longerConfigDigest;
    const configSizeManifestBytes = Buffer.from(JSON.stringify(configSizeManifest));
    const configSizeManifestDigest = sha256Bytes(configSizeManifestBytes);
    await writeFile(configSizeControlPath, configSizeManifestBytes);
    configSizeControl.source.id = configSizeManifestDigest.slice("sha256:".length);
    configSizeControl.source.version = configSizeManifestDigest;
    configSizeControl.source.metadata.manifestDigest = configSizeManifestDigest;
    configSizeControl.source.metadata.imageID = longerConfigDigest;
    configSizeControl.source.metadata.manifest = configSizeManifestBytes.toString("base64");
    configSizeControl.source.metadata.config = longerConfigBytes.toString("base64");
    const configSizeControlBytes = new TextEncoder().encode(JSON.stringify(configSizeControl));
    expect(await verifySbomEvidence(
      configSizeControlPath,
      envelope(configSizeManifestDigest, configSizeManifestDigest, configSizeControlBytes, configSizeManifestBytes.byteLength),
      configSizeControlBytes
    )).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    const configSizeFallback = JSON.parse(JSON.stringify(configSizeControl)) as Record<string, any>;
    delete configSizeFallback.source.metadata.manifest;
    const configSizeFallbackBytes = new TextEncoder().encode(JSON.stringify(configSizeFallback));
    expect(await verifySbomEvidence(
      configSizeControlPath,
      envelope(configSizeManifestDigest, configSizeManifestDigest, configSizeFallbackBytes, configSizeManifestBytes.byteLength),
      configSizeFallbackBytes
    )).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });

    const invalidUtf8ManifestDir = await mkdtemp(join(tmpdir(), "mcp-sbom-invalid-utf8-manifest-"));
    dirs.push(invalidUtf8ManifestDir);
    const invalidUtf8ManifestPath = join(invalidUtf8ManifestDir, "manifest.json");
    const invalidUtf8Manifest = { ...fixtureManifest, invalidUtf8Field: "x" };
    const invalidUtf8ManifestBytes = Buffer.from(JSON.stringify(invalidUtf8Manifest));
    const invalidUtf8Marker = Buffer.from('"invalidUtf8Field":"x"');
    const invalidUtf8FieldOffset = invalidUtf8ManifestBytes.indexOf(invalidUtf8Marker);
    expect(invalidUtf8FieldOffset).toBeGreaterThanOrEqual(0);
    invalidUtf8ManifestBytes[invalidUtf8FieldOffset + invalidUtf8Marker.byteLength - 2] = 0xff;
    const invalidUtf8ManifestDigest = sha256Bytes(invalidUtf8ManifestBytes);
    await writeFile(invalidUtf8ManifestPath, invalidUtf8ManifestBytes);
    const invalidUtf8Embedded = JSON.parse(JSON.stringify(document)) as Record<string, any>;
    invalidUtf8Embedded.source.id = invalidUtf8ManifestDigest.slice("sha256:".length);
    invalidUtf8Embedded.source.version = invalidUtf8ManifestDigest;
    invalidUtf8Embedded.source.metadata.manifestDigest = invalidUtf8ManifestDigest;
    invalidUtf8Embedded.source.metadata.manifest = invalidUtf8ManifestBytes.toString("base64");
    const invalidUtf8EmbeddedBytes = new TextEncoder().encode(JSON.stringify(invalidUtf8Embedded));
    expect(await verifySbomEvidence(
      invalidUtf8ManifestPath,
      envelope(invalidUtf8ManifestDigest, invalidUtf8ManifestDigest, invalidUtf8EmbeddedBytes, invalidUtf8ManifestBytes.byteLength),
      invalidUtf8EmbeddedBytes
    )).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    const invalidUtf8Fallback = JSON.parse(JSON.stringify(invalidUtf8Embedded)) as Record<string, any>;
    delete invalidUtf8Fallback.source.metadata.manifest;
    const invalidUtf8FallbackBytes = new TextEncoder().encode(JSON.stringify(invalidUtf8Fallback));
    expect(await verifySbomEvidence(
      invalidUtf8ManifestPath,
      envelope(invalidUtf8ManifestDigest, invalidUtf8ManifestDigest, invalidUtf8FallbackBytes, invalidUtf8ManifestBytes.byteLength),
      invalidUtf8FallbackBytes
    )).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.labels = { ...source.metadata.labels, "org.opencontainers.image.version": "wrong" }; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { const { "org.opencontainers.image.version": _removed, ...labels } = source.metadata.labels; source.metadata.labels = labels; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.labels = { ...source.metadata.labels, "example.invalid": "value" }; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    for (const value of [null, [], "foo", 123]) {
      expect(await withSource((source) => { source.metadata.labels = value; }))
        .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
    for (const value of ["application/example.invalid", null, "", 123]) {
      expect(await withSource((source) => { source.metadata.mediaType = value; }))
        .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
    expect(await withSource((source) => { source.metadata.imageID = "sha256:" + "0".repeat(64); }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.imageID = "invalid"; }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { delete source.metadata.manifest; source.metadata.imageID = "sha256:" + "0".repeat(64); }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => { source.metadata.config = Buffer.from("tampered-config").toString("base64"); }))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    expect(await withSource((source) => {
      delete source.metadata.imageID;
      delete source.metadata.architecture;
      delete source.metadata.os;
      delete source.metadata.layers;
    })).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    expect(await withSource((source) => {
      delete source.metadata.imageID;
      delete source.metadata.architecture;
      delete source.metadata.os;
      delete source.metadata.layers;
      source.metadata.config = Buffer.from(JSON.stringify({ architecture: "amd64", os: "linux" })).toString("base64");
    })).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
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

    const qualifiedImageFields = ["mediaType", "imageSize", "repoDigests", "tags", "labels"] as const;
    for (const field of qualifiedImageFields) {
      const downgraded = JSON.parse(JSON.stringify(document)) as Record<string, any>;
      const retainedValue = downgraded.source.metadata[field];
      downgraded.source.type = "file";
      downgraded.source.metadata = { path: "synthetic-path", [field]: retainedValue };
      const downgradedBytes = new TextEncoder().encode(JSON.stringify(downgraded));
      const result = await verifySbomEvidence(requestedArtifactPath, envelope(requestedDigest, requestedDigest, downgradedBytes, requestedBytes.byteLength), downgradedBytes);
      expect(result, field).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }

    const layersWithoutManifest = JSON.parse(JSON.stringify(document)) as Record<string, any>;
    delete layersWithoutManifest.source.metadata.manifest;
    delete layersWithoutManifest.source.metadata.imageID;
    const layersWithoutManifestBytes = new TextEncoder().encode(JSON.stringify(layersWithoutManifest));
    const layersWithoutManifestResult = await verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, layersWithoutManifestBytes), layersWithoutManifestBytes);
    expect(layersWithoutManifestResult).toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    const fallbackSizeMismatch = JSON.parse(JSON.stringify(layersWithoutManifest)) as Record<string, any>;
    fallbackSizeMismatch.source.metadata.layers[0].size += 1;
    const fallbackSizeMismatchBytes = new TextEncoder().encode(JSON.stringify(fallbackSizeMismatch));
    expect(await verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, fallbackSizeMismatchBytes), fallbackSizeMismatchBytes))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    const fallbackConfigTamper = JSON.parse(JSON.stringify(layersWithoutManifest)) as Record<string, any>;
    fallbackConfigTamper.source.metadata.config = Buffer.from(JSON.stringify({ architecture: "amd64", os: "linux" })).toString("base64");
    const fallbackConfigTamperBytes = new TextEncoder().encode(JSON.stringify(fallbackConfigTamper));
    expect(await verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, fallbackConfigTamperBytes), fallbackConfigTamperBytes))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    const mediaFallback = JSON.parse(JSON.stringify(layersWithoutManifest)) as Record<string, any>;
    mediaFallback.source.metadata.mediaType = "application/vnd.docker.distribution.manifest.v2+json";
    const mediaFallbackBytes = new TextEncoder().encode(JSON.stringify(mediaFallback));
    expect(await verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, mediaFallbackBytes), mediaFallbackBytes))
      .toMatchObject({ status: "pass", schemaVersion: "16.1.10" });
    mediaFallback.source.metadata.mediaType = "application/example.invalid";
    const wrongMediaFallbackBytes = new TextEncoder().encode(JSON.stringify(mediaFallback));
    expect(await verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, wrongMediaFallbackBytes), wrongMediaFallbackBytes))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    const labelsWithoutConfig = JSON.parse(JSON.stringify(layersWithoutManifest)) as Record<string, any>;
    delete labelsWithoutConfig.source.metadata.config;
    const labelsWithoutConfigBytes = new TextEncoder().encode(JSON.stringify(labelsWithoutConfig));
    expect(await verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, labelsWithoutConfigBytes), labelsWithoutConfigBytes))
      .toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });

    for (const mutate of [
      (layers: any[]) => { layers[0].digest = "sha256:" + "0".repeat(64); },
      (layers: any[]) => { layers.pop(); },
      (layers: any[]) => { layers[0] = { digest: "invalid" }; },
      (layers: any[]) => { [layers[0], layers[1]] = [layers[1], layers[0]]; }
    ]) {
      const invalid = JSON.parse(JSON.stringify(layersWithoutManifest)) as Record<string, any>;
      mutate(invalid.source.metadata.layers);
      const invalidBytes = new TextEncoder().encode(JSON.stringify(invalid));
      const invalidResult = await verifySbomEvidence(realArtifactPath, envelope(realDigest, realDigest, invalidBytes), invalidBytes);
      expect(invalidResult).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    }
  });
});

describe("bounded artifact short-read handling", () => {
  const readWithChunks = async (bytes: Uint8Array, chunks: number[]) => {
    let position = 0;
    let index = 0;
    const handle = {
      read: async (buffer: Buffer, offset: number, length: number, filePosition: number) => {
        expect(filePosition).toBe(position);
        const requested = chunks[index++] ?? length;
        const count = Math.min(requested, length, bytes.length - position);
        if (count <= 0) return { bytesRead: 0 };
        Buffer.from(bytes).copy(buffer, offset, position, position + count);
        position += count;
        return { bytesRead: count };
      }
    };
    return readBoundedArtifactFromHandle(handle);
  };

  it("accumulates deterministic multi-chunk short reads exactly", async () => {
    const bytes = new TextEncoder().encode("bounded-short-read-fixture");
    await expect(readWithChunks(bytes, [7, 11, 3, 2])).resolves.toEqual(Buffer.from(bytes));
  });

  it("handles one-byte chunks and immediate EOF", async () => {
    const bytes = new TextEncoder().encode("one-byte");
    await expect(readWithChunks(bytes, Array(bytes.length).fill(1))).resolves.toEqual(Buffer.from(bytes));
    await expect(readWithChunks(new Uint8Array(), [0])).resolves.toEqual(Buffer.alloc(0));
  });

  it("accepts the exact bound and rejects the sentinel byte", async () => {
    const exact = new Uint8Array(4 * 1024 * 1024);
    await expect(readWithChunks(exact, [7, 11, 3])).resolves.toHaveLength(exact.length);
    const oversized = new Uint8Array(4 * 1024 * 1024 + 1);
    await expect(readWithChunks(oversized, [4 * 1024 * 1024 - 3, 2, 1])).rejects.toThrow("artifact_too_large");
  });

  it("propagates read errors", async () => {
    const handle = { read: async () => { throw new Error("read failure"); } };
    await expect(readBoundedArtifactFromHandle(handle)).rejects.toThrow("read failure");
  });
});
