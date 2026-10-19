import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sha256Bytes } from "../src/core/digest.js";

const repoRoot = process.cwd();
const fixtureRoot = join(repoRoot, "tests", "fixtures", "sbom");

/**
 * Fixtures whose SHA-256 is pinned as a literal in the test suite and in
 * tests/fixtures/sbom/validate_fixture_contract.py. Their bytes must therefore
 * survive checkout unchanged on every platform, including CRLF-normalising
 * Windows checkouts (core.autocrlf=true).
 */
const DIGEST_PINNED_FIXTURES: Record<string, string> = {
  "github-mcp-server-b281-manifest.json":
    "sha256:b2814a05586591dd361d361c26bbb1e1154cfbc1544fca32785fde5e11270d07",
  "github-mcp-server-a44e77b-manifest.json":
    "sha256:a44e77b9c9003ed0e228716d118aa4ce9f3418dce30fe2340c71553164bd96f0",
  "ibm-mcp-context-forge-dd0998-manifest.json":
    "sha256:dd0998be722d180f429030cf2cd74357498b3e4daf887305ee9b8003526f83f0"
};

const readBytes = (relative: string) => new Uint8Array(readFileSync(join(repoRoot, relative)));

function attributeDirectives(): Array<{ pattern: string; directives: string[] }> {
  return readFileSync(join(repoRoot, ".gitattributes"), "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((line) => {
      const [pattern, ...directives] = line.split(/\s+/);
      return { pattern, directives };
    });
}

describe("digest-pinned fixture byte integrity", () => {
  it("marks the digest-pinned fixture subtree as -text in .gitattributes", () => {
    // A `-text` rule whose pattern covers everything under tests/fixtures.
    const coversFixtureSubtree = attributeDirectives().some(({ pattern, directives }) => {
      if (!directives.includes("-text")) return false;
      const normalized = pattern.replace(/^\/?/, "").replace(/\/+$/, "");
      return normalized === "tests/fixtures/**" || normalized === "tests/fixtures/*" || normalized === "tests/fixtures";
    });
    expect(
      coversFixtureSubtree,
      "tests/fixtures/** must be marked -text so CRLF checkout cannot change the bytes of digest-pinned fixtures",
    ).toBe(true);
  });

  it("marks the generated Action bundle as -text in .gitattributes", () => {
    const coversBundle = attributeDirectives().some(({ pattern, directives }) =>
      pattern.replace(/^\/?/, "") === "dist/action/index.cjs" && directives.includes("-text")
    );
    expect(
      coversBundle,
      "dist/action/index.cjs must be marked -text so a CRLF checkout cannot rewrite the byte-compared generated bundle",
    ).toBe(true);
  });

  it("keeps the on-disk bytes of every digest-pinned fixture equal to its committed digest", () => {
    for (const [name, expected] of Object.entries(DIGEST_PINNED_FIXTURES)) {
      const actual = sha256Bytes(readBytes(join("tests", "fixtures", "sbom", name)));
      expect(
        actual,
        `${name} resolves to ${actual} on disk but is pinned as ${expected}; a line-ending conversion or re-generated fixture will silently invalidate the pinned digest`,
      ).toBe(expected);
    }
  });
});
