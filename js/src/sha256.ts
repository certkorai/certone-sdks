/**
 * SHA-256 via the Web Crypto API (browsers, Deno, Bun, Node.js >= 19 global `crypto`).
 * The Node.js entry point replaces this with `node:crypto`, which also streams Blobs.
 */

import { toBytes, toHex } from "./binary.js";
import type { BinaryInput } from "./types.js";

/** Hex-encoded SHA-256 of the input bytes. */
export async function sha256Hex(data: BinaryInput): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new TypeError(
      "Web Crypto (crypto.subtle) is unavailable: use a secure context (https) or the Node.js build",
    );
  }
  return toHex(await subtle.digest("SHA-256", await toBytes(data)));
}

/**
 * The `input_digest` for `ingestReport`: `sha256:<hex>` over the exact snapshot bytes, which binds
 * the attestation to that input.
 */
export async function inputDigest(data: BinaryInput): Promise<string> {
  return `sha256:${await sha256Hex(data)}`;
}
