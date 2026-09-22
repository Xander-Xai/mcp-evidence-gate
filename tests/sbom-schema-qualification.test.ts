import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, afterEach } from "vitest";
import { loadSbomEvidence, verifySbomEvidence } from "../src/core/sbom.js";
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
  const document = JSON.parse(await readFile(fixtureFiles[schemaVersion], "utf8")) as Record<string, any>;
  document.source.version = artifactDigest;
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
});
