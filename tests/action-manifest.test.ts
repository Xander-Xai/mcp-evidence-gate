import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const root = resolve(import.meta.dirname, "..");

describe("GitHub Action manifest", () => {
  it("parses as YAML and exposes the packaged action entrypoint", async () => {
    const manifest = parse(await readFile(resolve(root, "action.yml"), "utf8")) as {
      name?: unknown;
      description?: unknown;
      inputs?: Record<string, { description?: unknown }>;
      outputs?: Record<string, { description?: unknown }>;
      runs?: { using?: unknown; main?: unknown };
    };

    expect(manifest.name).toBe("MCP Evidence Gate");
    expect(typeof manifest.description).toBe("string");
    expect(manifest.runs).toEqual({ using: "node24", main: "dist/action/index.cjs" });
    expect(Object.keys(manifest.inputs ?? {})).toEqual(["receipt", "artifact", "policy", "evidence"]);
    expect(Object.keys(manifest.outputs ?? {})).toEqual([
      "decision",
      "receipt-verdict",
      "profile",
      "integrity-status",
      "receipt-status",
      "policy-status",
      "admission-status",
      "scanner-execution-status",
      "reason-codes",
      "policy-version"
    ]);
    for (const section of [manifest.inputs ?? {}, manifest.outputs ?? {}]) {
      for (const definition of Object.values(section)) {
        expect(typeof definition.description).toBe("string");
      }
    }
  });
});
