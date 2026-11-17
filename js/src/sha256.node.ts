/**
 * SHA-256 via `node:crypto`: works on every supported Node.js release (Node 18 has no global
 * `crypto`) and hashes Blobs as a stream, so large snapshots are not buffered twice.
 */

import { createHash } from "node:crypto";

import type { BinaryInput } from "./types.js";

/** Hex-encoded SHA-256 of the input bytes. */
export async function sha256Hex(data: BinaryInput): Promise<string> {
  const hash = createHash("sha256");
  if (data instanceof Blob) {
    const reader = data.stream().getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      hash.update(value);
    }
  } else if (data instanceof ArrayBuffer) {
    hash.update(new Uint8Array(data));
  } else if (ArrayBuffer.isView(data)) {
    hash.update(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
  } else {
    throw new TypeError("expected a Blob, ArrayBuffer or ArrayBufferView (Uint8Array, Buffer, ...)");
  }
  return hash.digest("hex");
}

/**
 * The `input_digest` for `ingestReport`: `sha256:<hex>` over the exact snapshot bytes, which binds
 * the attestation to that input.
 */
export async function inputDigest(data: BinaryInput): Promise<string> {
  return `sha256:${await sha256Hex(data)}`;
}
