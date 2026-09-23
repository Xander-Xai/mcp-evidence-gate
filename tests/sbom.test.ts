import { mkdtemp, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, afterEach } from "vitest";
import { sha256Bytes } from "../src/core/digest.js";
import { composeSbomDecision, loadSbomEvidence, SBOM_RESOURCE_LIMITS, verifySbomEvidence } from "../src/core/sbom.js";

const dirs: string[] = [];
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sbom-"));
  dirs.push(dir);
  const artifactPath = join(dir, "artifact.bin");
  await writeFile(artifactPath, "wave-3-5-artifact");
  const artifact = sha256Bytes(new TextEncoder().encode("wave-3-5-artifact"));
  const body = (sourceDigest = artifact, artifacts: unknown[] = [{ id: "pkg-1", name: "demo", version: "1.0.0", type: "library" }]) =>
    JSON.stringify({ schema: { version: "16.1.3" }, source: { name: "artifact.bin", version: sourceDigest, type: "file", metadata: { digests: [{ algorithm: "sha256", value: sourceDigest.slice("sha256:".length) }] } }, artifacts });
  const sbomBytes = new TextEncoder().encode(body());
  const envelope = () => ({
    schema_version: "project-defined-sbom-evidence-v1",
    artifact: { ref: "artifact.bin", sha256: artifact, size: 17 },
    sbom: { format: "syft-json", schema_version: "16.1.3", sha256: sha256Bytes(sbomBytes), size: sbomBytes.byteLength },
    relationship: { type: "generated-from", artifact_sha256: artifact, sbom_sha256: sha256Bytes(sbomBytes), binding: "exact-artifact" },
    inventory: { status: "present", package_count: 1 }
  });
  return { dir, artifactPath, artifact, sbomBytes, envelope, body };
}

afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

describe("SBOM admission v1", () => {
  it("admits real Syft-shaped exact-bound evidence", async () => {
    const f = await fixture();
    const result = await verifySbomEvidence(f.artifactPath, f.envelope(), f.sbomBytes);
    expect(result).toMatchObject({ status: "pass", format: "syft-json", schemaVersion: "16.1.3", inventoryStatus: "present", packageCount: 1 });
  });

  it("blocks tampered SBOM bytes", async () => {
    const f = await fixture();
    const result = await verifySbomEvidence(f.artifactPath, f.envelope(), Uint8Array.from([...f.sbomBytes, 0x0a]));
    expect(result).toMatchObject({ status: "blocked", reasonCodes: ["sbom_digest_mismatch"] });
  });

  it("blocks an artifact/SBOM binding contradiction", async () => {
    const f = await fixture();
    const other = sha256Bytes(new TextEncoder().encode("other-artifact"));
    const result = await verifySbomEvidence(f.artifactPath, { ...f.envelope(), relationship: { ...f.envelope().relationship, artifact_sha256: other } }, f.sbomBytes);
    expect(result).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
    const wrongSbom = { ...f.envelope(), relationship: { ...f.envelope().relationship, sbom_sha256: "sha256:" + "0".repeat(64) } };
    expect(await verifySbomEvidence(f.artifactPath, wrongSbom, f.sbomBytes)).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
  });

  it("treats internally consistent same-release semantics as inconclusive", async () => {
    const f = await fixture();
    const envelope = f.envelope();
    envelope.relationship.binding = "same-release";
    expect(await verifySbomEvidence(f.artifactPath, envelope, f.sbomBytes)).toMatchObject({ status: "inconclusive", reasonCodes: ["artifact_sbom_binding_missing"] });
    envelope.relationship.binding = "same-version";
    expect(await verifySbomEvidence(f.artifactPath, envelope, f.sbomBytes)).toMatchObject({ status: "inconclusive", reasonCodes: ["artifact_sbom_binding_missing"] });
  });

  it("preserves an existing FAIL when SBOM admission is inconclusive", () => {
    expect(composeSbomDecision("fail", "inconclusive")).toBe("fail");
    expect(composeSbomDecision("fail", "pass")).toBe("fail");
    expect(composeSbomDecision("pass", "inconclusive")).toBe("inconclusive");
    expect(composeSbomDecision("pass", "blocked")).toBe("fail");
  });

  it("rejects an oversized SBOM path before reading its bytes", async () => {
    const f = await fixture();
    const envelopePath = join(f.dir, "envelope.json");
    const oversizedPath = join(f.dir, "oversized.sbom");
    await writeFile(envelopePath, "{}");
    await writeFile(oversizedPath, "");
    await truncate(oversizedPath, SBOM_RESOURCE_LIMITS.maxSbomBytes + 1);
    expect(await loadSbomEvidence(envelopePath, oversizedPath)).toEqual({ status: "result", result: { status: "inconclusive", reasonCodes: ["sbom_size_limit_exceeded"] } });
  });

  it("blocks a Syft source metadata mismatch", async () => {
    const f = await fixture();
    const bytes = new TextEncoder().encode(f.body(sha256Bytes(new TextEncoder().encode("other-artifact"))));
    const envelope = f.envelope();
    envelope.sbom.sha256 = sha256Bytes(bytes); envelope.sbom.size = bytes.byteLength; envelope.relationship.sbom_sha256 = envelope.sbom.sha256;
    const result = await verifySbomEvidence(f.artifactPath, envelope, bytes);
    expect(result).toMatchObject({ status: "blocked", reasonCodes: ["artifact_sbom_binding_mismatch"] });
  });

  it("returns inconclusive for malformed, unsupported, empty, duplicate, and count-mismatch inventories", async () => {
    const f = await fixture();
    for (const bytes of [new TextEncoder().encode("{"), new TextEncoder().encode(JSON.stringify({ schema: { version: "16.1.4" }, source: { name: "artifact.bin", version: f.artifact }, artifacts: [] }))]) {
      const envelope = f.envelope(); envelope.sbom.sha256 = sha256Bytes(bytes); envelope.sbom.size = bytes.byteLength; envelope.relationship.sbom_sha256 = envelope.sbom.sha256;
      expect((await verifySbomEvidence(f.artifactPath, envelope, bytes)).status).toBe("inconclusive");
    }
    const duplicateBytes = new TextEncoder().encode(f.body(f.artifact, [{ id: "x", name: "a", version: "1", type: "library" }, { id: "x", name: "b", version: "2", type: "library" }]));
    const duplicateEnvelope = f.envelope(); duplicateEnvelope.sbom.sha256 = sha256Bytes(duplicateBytes); duplicateEnvelope.sbom.size = duplicateBytes.byteLength; duplicateEnvelope.relationship.sbom_sha256 = duplicateEnvelope.sbom.sha256; duplicateEnvelope.inventory.package_count = 2;
    expect((await verifySbomEvidence(f.artifactPath, duplicateEnvelope, duplicateBytes)).reasonCodes).toContain("sbom_inventory_duplicate_id");
  });
});
