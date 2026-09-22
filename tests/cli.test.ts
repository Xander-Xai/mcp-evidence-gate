import { dirname, join, resolve } from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import packageJson from "../package.json" with { type: "json" };

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifact = resolve(root, "fixtures/artifacts/current-artifact.bin");
const receipt = (name: string) => resolve(root, "fixtures/valid", name);
const invalidReceipt = (name: string) => resolve(root, "fixtures/invalid", name);
const now = "2026-08-25T00:00:00Z";

async function invoke(args: string[]) {
  let stdout = "";
  let stderr = "";
  const code = await runCli(args, {
    stdout: (text) => { stdout += text; },
    stderr: (text) => { stderr += text; }
  });
  return { code, stdout, stderr };
}

describe("mcp-evidence-gate verify CLI", () => {
  it("returns PASS with exit 0", async () => {
    const result = await invoke([
      "verify", "--receipt", receipt("complete-clean.json"), "--artifact", artifact,
      "--policy", "permissive", "--now", now
    ]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("Decision: PASS");
    expect(result.stderr).toBe("");
  });

  it("returns WARN with exit 0", async () => {
    const result = await invoke([
      "verify", "--receipt", receipt("complete-warnings.json"), "--artifact", artifact,
      "--policy", "permissive", "--now", now
    ]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("Decision: WARN");
  });

  it("returns INCONCLUSIVE with exit 2 for a digest mismatch", async () => {
    const result = await invoke([
      "verify", "--receipt", receipt("complete-digest-mismatch.json"), "--artifact", artifact,
      "--policy", "permissive", "--now", now
    ]);
    expect(result.code).toBe(2);
    expect(result.stdout).toContain("Decision: INCONCLUSIVE");
  });

  it("returns FAIL with exit 1 for findings and structural invalidity", async () => {
    const findings = await invoke([
      "verify", "--receipt", receipt("complete-findings.json"), "--artifact", artifact,
      "--policy", "permissive", "--now", now
    ]);
    const structural = await invoke([
      "verify", "--receipt", invalidReceipt("structural-missing-scanner.json"), "--artifact", "/missing.tgz",
      "--policy", "permissive", "--now", now
    ]);
    expect(findings.code).toBe(1);
    expect(structural.code).toBe(1);
  });

  it("returns runtime error exit 3 for missing input or unknown policy", async () => {
    const missingReceipt = await invoke([
      "verify", "--receipt", "/missing.json", "--artifact", artifact,
      "--policy", "permissive", "--now", now
    ]);
    const missingArtifact = await invoke([
      "verify", "--receipt", receipt("complete-clean.json"), "--artifact", "/missing.tgz",
      "--policy", "permissive", "--now", now
    ]);
    const unknownPolicy = await invoke([
      "verify", "--receipt", receipt("complete-clean.json"), "--artifact", artifact,
      "--policy", "unknown", "--now", now
    ]);
    expect(missingReceipt.code).toBe(3);
    expect(missingArtifact.code).toBe(3);
    expect(unknownPolicy.code).toBe(3);
    expect(missingReceipt.stdout).toBe("");
  });

  it("emits parseable JSON only on stdout", async () => {
    const result = await invoke([
      "verify", "--receipt", receipt("complete-digest-mismatch.json"), "--artifact", artifact,
      "--policy", "permissive", "--format", "json", "--now", now
    ]);
    const model = JSON.parse(result.stdout);
    expect(result.code).toBe(2);
    expect(result.stderr).toBe("");
    expect(model).toMatchObject({
      tool: "mcp-evidence-gate",
      policy: "permissive",
      receiptVerdict: "clean",
      decision: "inconclusive"
    });
  });

  it("binds a local evidence report when requested by policy", async () => {
    const evidence = resolve(root, "fixtures/valid/complete-clean.json");
    const result = await invoke([
      "verify", "--receipt", receipt("complete-clean.json"), "--artifact", artifact,
      "--evidence", evidence, "--policy", "strict-evidence-example", "--now", now
    ]);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("Evidence Binding");
  });

  it("returns INCONCLUSIVE with exit 2 when explicit evidence mismatches under permissive policy", async () => {
    const evidence = resolve(root, "fixtures/valid/complete-clean.json");
    const result = await invoke([
      "verify", "--receipt", receipt("complete-evidence-mismatch.json"), "--artifact", artifact,
      "--evidence", evidence, "--policy", "permissive", "--now", now
    ]);
    expect(result.code).toBe(2);
    expect(result.stdout).toContain("Decision: INCONCLUSIVE");
  });

  it("returns FAIL with exit 1 for malformed evidence digest without --evidence", async () => {
    const result = await invoke([
      "verify", "--receipt", receipt("complete-malformed-evidence-digest.json"), "--artifact", artifact,
      "--policy", "permissive", "--now", now
    ]);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("Decision: FAIL");
    expect(result.stdout).toContain("evidence_binding_invalid");
  });

  it("maps malformed SBOM envelope JSON to structured inconclusive", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-cli-sbom-"));
    try {
      const envelope = join(dir, "malformed.json");
      const sbom = join(dir, "sbom.json");
      await writeFile(envelope, "{", "utf8");
      await writeFile(sbom, "{}", "utf8");
      const result = await invoke([
        "verify", "--receipt", receipt("complete-clean.json"), "--artifact", artifact,
        "--sbom-evidence", envelope, "--sbom", sbom, "--policy", "permissive", "--format", "json", "--now", now
      ]);
      const model = JSON.parse(result.stdout);
      expect(result.code).toBe(2);
      expect(model.decision).toBe("inconclusive");
      expect(model.sbom_admission_status).toBe("inconclusive");
      expect(model.sbom_reason_codes).toContain("sbom_malformed");
      expect(model.policy_status).toBe("pass");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not downgrade an existing FAIL when SBOM admission is inconclusive", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-cli-sbom-fail-"));
    try {
      const envelope = join(dir, "malformed.json");
      const sbom = join(dir, "sbom.json");
      await writeFile(envelope, "{", "utf8");
      await writeFile(sbom, "{}", "utf8");
      const result = await invoke([
        "verify", "--receipt", receipt("complete-findings.json"), "--artifact", artifact,
        "--sbom-evidence", envelope, "--sbom", sbom, "--policy", "permissive", "--format", "json", "--now", now
      ]);
      const model = JSON.parse(result.stdout);
      expect(result.code).toBe(1);
      expect(model.decision).toBe("fail");
      expect(model.sbom_admission_status).toBe("inconclusive");
      expect(model.policy_status).toBe("fail");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("returns PASS with exit 0 for unsupported well-formed evidence digest without --evidence", async () => {
    const result = await invoke([
      "verify", "--receipt", receipt("complete-unsupported-evidence-digest.json"), "--artifact", artifact,
      "--policy", "permissive", "--now", now
    ]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("Decision: PASS");
  });

  it("supports help and version without requiring verification inputs", async () => {
    const help = await invoke(["--help"]);
    const version = await invoke(["--version"]);
    expect(help.code).toBe(0);
    expect(help.stdout).toContain("Usage:");
    expect(version.code).toBe(0);
    expect(version.stdout.trim()).toBe(packageJson.version);
  });
});
