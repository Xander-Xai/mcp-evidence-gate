export const SECURITY_SCAN_RECEIPT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://github.com/Xander-Xai/mcp-evidence-gate/schemas/registry-pr-1404/20747d3253ba8638161dd95f1cec70df02993c22/security-scan-receipt",
  title: "MCP Registry #1404 SecurityScanReceipt",
  description: "Pinned experimental subset of the open MCP Registry #1404 receipt proposal.",
  type: "object",
  additionalProperties: true,
  required: ["scanner", "scanned_artifact_digest", "scan_scope", "verdict", "scanned_at", "attestation"],
  properties: {
    scanner: { type: "string" },
    scanner_version: { type: "string" },
    rule_set_ref: { type: "string" },
    policy_profile: { type: "string" },
    scanned_artifact_ref: { type: "string" },
    scanned_artifact_digest: { type: "string", pattern: "^[a-z0-9]+:[a-f0-9]+$" },
    scan_scope: { type: "array", minItems: 1, items: { type: "string" } },
    verdict: { type: "string", enum: ["clean", "warnings", "findings", "inconclusive"] },
    inconclusive_reason: {
      type: "string",
      enum: [
        "artifact_digest_mismatch",
        "unsupported_package_type",
        "scope_excludes_handler_validation",
        "evidence_unavailable",
        "stale_scan"
      ]
    },
    scanned_at: { type: "string", format: "date-time" },
    freshness_expires_at: { type: "string", format: "date-time" },
    evidence_ref: { type: "string", format: "uri" },
    evidence_digest: { type: "string", pattern: "^[a-z0-9]+:[a-f0-9]+$" },
    attestation: { type: "string", enum: ["publisher-asserted", "registry-attested", "third-party-attested"] }
  },
  allOf: [
    {
      if: { properties: { verdict: { const: "inconclusive" } } },
      then: { required: ["inconclusive_reason"] }
    }
  ]
} as const;
