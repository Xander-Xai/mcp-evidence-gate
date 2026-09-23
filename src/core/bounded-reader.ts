const maxEmbeddedManifestBytes = 4 * 1024 * 1024;

type BoundedArtifactHandle = {
  read(buffer: Buffer, offset: number, length: number, position: number): Promise<{ bytesRead: number }>;
};

export async function readBoundedArtifactFromHandle(handle: BoundedArtifactHandle): Promise<Buffer> {
  const limit = maxEmbeddedManifestBytes + 1;
  const buffer = Buffer.alloc(limit);
  let totalRead = 0;
  while (totalRead < limit) {
    const { bytesRead } = await handle.read(buffer, totalRead, limit - totalRead, totalRead);
    if (bytesRead === 0) break;
    totalRead += bytesRead;
  }
  if (totalRead > maxEmbeddedManifestBytes) throw new Error("artifact_too_large");
  return buffer.subarray(0, totalRead);
}
