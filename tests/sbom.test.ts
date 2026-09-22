import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, afterEach } from "vitest";
import { sha256Bytes } from "../src/core/digest.js";
import { verifySbomEvidence } from "../src/core/sbom.js";

const dirs: string[] = [];
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sbom-"));
  dirs.push(dir);
  const artifactPath = join(dir, "artifact.bin");
  await writeFile(artifactPath, "wave-3-5-artifact");
  const artifact = sha256Bytes(new TextEncoder().encode("wave-3-5-artifact"));
  const body = (sourceDigest = artifact, artifacts: unknown[] = [{ id: "pkg-1", name: "demo", version: "1.0.0", type: "library" }]) =>
    JSON.stringify({ schema: { version: "16.1.3" }, source: { name: "artifact.bin", version: sourceDigest }, artifacts });
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
