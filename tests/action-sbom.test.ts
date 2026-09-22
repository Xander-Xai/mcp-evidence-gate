import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  inputs: {} as Record<string, string>,
  outputs: new Map<string, string>(),
  failures: [] as string[]
}));

vi.mock("@actions/core", () => ({
  getInput: (name: string) => state.inputs[name] ?? "",
  setOutput: (name: string, value: string) => state.outputs.set(name, value),
  setFailed: (message: string) => state.failures.push(message),
  info: () => undefined,
  warning: () => undefined
}));

const root = resolve(import.meta.dirname, "..");
const artifact = resolve(root, "fixtures/artifacts/current-artifact.bin");
const receipt = resolve(root, "fixtures/valid/complete-clean.json");
const findingsReceipt = resolve(root, "fixtures/valid/complete-findings.json");

describe("Action SBOM input boundary", () => {
  it("emits structured inconclusive for malformed envelope JSON", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-action-sbom-"));
    try {
      const envelope = join(dir, "malformed.json");
      const sbom = join(dir, "sbom.json");
      await writeFile(envelope, "{", "utf8");
      await writeFile(sbom, "{}", "utf8");
      state.inputs = { receipt, artifact, policy: "permissive", "sbom-evidence": envelope, sbom };
      state.outputs.clear(); state.failures.length = 0;
      const { runAction } = await import("../src/action.js");
      await runAction();
      expect(state.outputs.get("sbom-admission-status")).toBe("inconclusive");
      expect(state.outputs.get("sbom-reason-codes")).toContain("sbom_malformed");
      expect(state.failures.join(" ")).toContain("SBOM INCONCLUSIVE");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reports the existing policy FAIL before SBOM inconclusive", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-action-sbom-fail-"));
    try {
      const envelope = join(dir, "malformed.json");
      const sbom = join(dir, "sbom.json");
      await writeFile(envelope, "{", "utf8");
      await writeFile(sbom, "{}", "utf8");
      state.inputs = { receipt: findingsReceipt, artifact, policy: "permissive", "sbom-evidence": envelope, sbom };
      state.outputs.clear(); state.failures.length = 0;
      const { runAction } = await import("../src/action.js");
      await runAction();
      expect(state.outputs.get("decision")).toBe("fail");
      expect(state.outputs.get("policy-status")).toBe("fail");
      expect(state.outputs.get("sbom-admission-status")).toBe("inconclusive");
      expect(state.failures.join(" ")).toContain("FAIL:");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
