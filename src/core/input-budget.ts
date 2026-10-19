import { readBoundedFile } from "./bounded-reader.js";

/**
 * Explicit consumer-owned resource budget for receipt documents. The CLI and
 * the Action read producer-supplied receipt JSON, so the same budget is
 * enforced at every entry point: a receipt document cannot force an unbounded
 * read, and a receipt set cannot retain unbounded bytes across many entries.
 *
 * Observed consumer receipts are a few kilobytes; the per-document limit
 * matches the repository's existing 4 MiB embedded-manifest bound, the entry
 * limit is far above any observed set (observed: 2), and the cumulative set
 * budget caps worst-case residency independently of the entry count.
 */
export const RECEIPT_INPUT_BUDGET = Object.freeze({
  maxReceiptJsonBytes: 4 * 1024 * 1024,
  maxReceiptSetManifestBytes: 4 * 1024 * 1024,
  maxReceiptSetEntries: 64,
  maxReceiptSetTotalReceiptBytes: 16 * 1024 * 1024
} as const);

export class ReceiptInputBudgetExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReceiptInputBudgetExceededError";
  }
}

export interface BoundedReceiptDocument {
  readonly text: string;
  readonly byteLength: number;
}

async function readDocumentBounded(
  path: string,
  maxBytes: number,
  description: string
): Promise<BoundedReceiptDocument> {
  const bytes = await readBoundedFile(
    path,
    maxBytes,
    () => new ReceiptInputBudgetExceededError(`${description} exceeds the ${maxBytes} byte input limit`)
  );
  return { text: bytes.toString("utf8"), byteLength: bytes.byteLength };
}

/** Read one receipt JSON document under the per-receipt byte limit. */
export async function readReceiptDocumentBounded(path: string): Promise<BoundedReceiptDocument> {
  return readDocumentBounded(path, RECEIPT_INPUT_BUDGET.maxReceiptJsonBytes, "receipt");
}

/** Read one receipt-set manifest under the manifest byte limit. */
export async function readReceiptSetManifestBounded(path: string): Promise<BoundedReceiptDocument> {
  return readDocumentBounded(path, RECEIPT_INPUT_BUDGET.maxReceiptSetManifestBytes, "receipt set manifest");
}
