import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readBoundedFile } from "./bounded-reader.js";
import { REGISTRY_PR_1404_PROFILE } from "../profiles/registry-pr-1404.js";
import type { Finding } from "./types.js";

const DIGEST_PATTERN = /^([a-z0-9]+):([a-f0-9]+)$/;

export class DigestError extends Error {
  constructor(public readonly code: "malformed_digest" | "unsupported_digest_algorithm") {
    super(code);
  }
}

export interface ParsedDigest {
  algorithm: string;
  hex: string;
}

export function parseDigest(value: unknown): ParsedDigest {
  if (typeof value !== "string") {
    throw new DigestError("malformed_digest");
  }
  const match = DIGEST_PATTERN.exec(value);
  if (!match) {
    throw new DigestError("malformed_digest");
  }
  if (match[1] !== REGISTRY_PR_1404_PROFILE.digestAlgorithm) {
    throw new DigestError("unsupported_digest_algorithm");
  }
  if (match[2].length !== 64) {
    throw new DigestError("malformed_digest");
  }
  return { algorithm: match[1], hex: match[2] };
}

export function sha256Bytes(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

/**
 * Explicit consumer-owned resource budget for one evidence snapshot. Evidence
 * is parsed as a single in-memory JSON document, so the read must be bounded
 * before any parsing or hashing happens. Observed consumer evidence reports
 * are a few kilobytes; the limit keeps worst-case parse amplification well
 * below runner memory limits while leaving orders of magnitude of headroom.
 */
export const EVIDENCE_RESOURCE_LIMITS = Object.freeze({
  maxEvidenceSnapshotBytes: 16 * 1024 * 1024
} as const);

/**
 * The exact evidence bytes read for one verification attempt.  Callers must
 * pass this snapshot to every evidence consumer so a path replacement cannot
 * create a time-of-check/time-of-use gap between hashing and parsing.
 *
 * `readonly` is a TypeScript-level promise. At runtime, the snapshot object is
 * frozen and `bytes` is a detached copy, so neither the path binding nor the
 * reader's original buffer can change what the verifier consumes. The
 * `Uint8Array` contents themselves are not deep-frozen; they are read-only by
 * contract for the lifetime of one attempt.
 */
export interface EvidenceSnapshot {
  readonly path: string;
  readonly bytes: Uint8Array;
}

export type EvidenceSnapshotReadError =
  | "evidence_file_missing"
  | "evidence_file_read_failed"
  | "evidence_size_limit_exceeded";

export interface EvidenceSnapshotRead {
  readonly provided: boolean;
  readonly snapshot?: EvidenceSnapshot;
  readonly error?: EvidenceSnapshotReadError;
}

export type EvidenceBytesReader = (path: string) => Promise<Uint8Array>;

class EvidenceSizeLimitExceededError extends Error {
  constructor() {
    super("evidence_size_limit_exceeded");
  }
}

const readEvidenceBytes: EvidenceBytesReader = async (path) =>
  new Uint8Array(
    await readBoundedFile(path, EVIDENCE_RESOURCE_LIMITS.maxEvidenceSnapshotBytes, () => new EvidenceSizeLimitExceededError())
  );

function classifyEvidenceReadError(error: unknown): EvidenceSnapshotReadError {
  if (error instanceof EvidenceSizeLimitExceededError) return "evidence_size_limit_exceeded";
  if (typeof error === "object" && error !== null && (error as { code?: unknown }).code === "ENOENT") {
    return "evidence_file_missing";
  }
  return "evidence_file_read_failed";
}

/**
 * Read evidence bytes once, under the evidence resource budget, and retain a
 * detached snapshot for this attempt: the snapshot object is frozen and holds
 * a copy of the reader result. Path replacement and later mutation of the
 * reader's buffer therefore cannot change the bytes consumed by the verifier;
 * the copied array contents are read-only by contract, not by deep freeze.
 * A file that is missing, unreadable, or over the size limit never produces a
 * snapshot, so it can never be treated as complete, trustworthy evidence.
 */
export async function readEvidenceSnapshot(
  evidencePath?: string,
  reader: EvidenceBytesReader = readEvidenceBytes
): Promise<EvidenceSnapshotRead> {
  if (!evidencePath) return { provided: false };
  let source: Uint8Array;
  try {
    source = await reader(evidencePath);
  } catch (error) {
    return { provided: true, error: classifyEvidenceReadError(error) };
  }
  if (source.byteLength > EVIDENCE_RESOURCE_LIMITS.maxEvidenceSnapshotBytes) {
    return { provided: true, error: "evidence_size_limit_exceeded" };
  }
  // Copy the reader result so later mutation of a Buffer owned by the caller
  // cannot change the bytes consumed by the verifier.
  const bytes = Uint8Array.from(source);
  return {
    provided: true,
    snapshot: Object.freeze({ path: evidencePath, bytes })
  };
}

export async function sha256Artifact(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
  }
  return `sha256:${hash.digest("hex")}`;
}

export async function verifyArtifactBinding(
  receiptDigest: unknown,
  artifactPath: string
): Promise<Finding> {
  let expected: ParsedDigest;
  try {
    expected = parseDigest(receiptDigest);
  } catch (error) {
    const code = error instanceof DigestError ? error.code : "malformed_digest";
    return {
      id: "artifact_binding",
      status: code === "unsupported_digest_algorithm" ? "unsupported" : "invalid",
      reason: code
    };
  }

  const actual = await sha256Artifact(artifactPath);
  return actual === `sha256:${expected.hex}`
    ? { id: "artifact_binding", status: "pass", expected: actual, actual }
    : {
        id: "artifact_binding",
        status: "mismatch",
        reason: "artifact_digest_mismatch",
        expected: `sha256:${expected.hex}`,
        actual
      };
}

export async function verifyEvidenceBinding(receiptDigest: unknown, evidencePath?: string): Promise<Finding> {
  return verifyEvidenceBindingBytes(receiptDigest, await readEvidenceSnapshot(evidencePath));
}

/** Verify the receipt evidence digest against the bytes from one snapshot. */
export function verifyEvidenceBindingBytes(
  receiptDigest: unknown,
  evidence: EvidenceSnapshotRead
): Finding {
  let expected: ParsedDigest;
  try { expected = parseDigest(receiptDigest); }
  catch (error) {
    const code = error instanceof DigestError ? error.code : "malformed_digest";
    if (code === "unsupported_digest_algorithm") {
      if (!evidence.provided) {
        return { id: "evidence_binding", status: "not_present", reason: "evidence_file_not_provided" };
      }
      return { id: "evidence_binding", status: "unsupported", reason: code };
    }
    return { id: "evidence_binding", status: "invalid", reason: code };
  }
  if (!evidence.provided) {
    return { id: "evidence_binding", status: "not_present", reason: "evidence_file_not_provided" };
  }
  if (!evidence.snapshot) {
    return { id: "evidence_binding", status: "not_present", reason: evidence.error ?? "evidence_file_missing" };
  }
  const actual = sha256Bytes(evidence.snapshot.bytes);
  return actual === `sha256:${expected.hex}`
    ? { id: "evidence_binding", status: "pass", expected: actual, actual }
    : { id: "evidence_binding", status: "mismatch", reason: "evidence_digest_mismatch", expected: `sha256:${expected.hex}`, actual };
}
