import { open } from "node:fs/promises";

const maxEmbeddedManifestBytes = 4 * 1024 * 1024;
const readChunkBytes = 64 * 1024;

type BoundedArtifactHandle = {
  read(buffer: Buffer, offset: number, length: number, position: number): Promise<{ bytesRead: number }>;
};

/**
 * Read at most `maxBytes` plus one sentinel byte from an open handle. Reading
 * stops before the caller can retain oversized content; `tooLarge` is thrown
 * as soon as the sentinel byte is observed, independent of file stat or size.
 */
export async function readBoundedFromHandle(
  handle: BoundedArtifactHandle,
  maxBytes: number,
  tooLarge: () => Error
): Promise<Buffer> {
  const limit = maxBytes + 1;
  const chunks: Buffer[] = [];
  let totalRead = 0;
  while (totalRead < limit) {
    const buffer = Buffer.allocUnsafe(Math.min(readChunkBytes, limit - totalRead));
    const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, totalRead);
    if (bytesRead === 0) break;
    chunks.push(buffer.subarray(0, bytesRead));
    totalRead += bytesRead;
    if (totalRead > maxBytes) throw tooLarge();
  }
  return Buffer.concat(chunks, totalRead);
}

export async function readBoundedArtifactFromHandle(handle: BoundedArtifactHandle): Promise<Buffer> {
  return readBoundedFromHandle(handle, maxEmbeddedManifestBytes, () => new Error("artifact_too_large"));
}

/** Open and read a path through `readBoundedFromHandle`, always closing the handle. */
export async function readBoundedFile(
  path: string,
  maxBytes: number,
  tooLarge: () => Error
): Promise<Buffer> {
  const handle = await open(path, "r");
  try {
    return await readBoundedFromHandle(handle, maxBytes, tooLarge);
  } finally {
    await handle.close();
  }
}
