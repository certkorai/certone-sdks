import type { BinaryInput } from "./types.js";

function isBlob(value: unknown): value is Blob {
  return typeof Blob !== "undefined" && value instanceof Blob;
}

/** A view over the input's bytes backed by a plain `ArrayBuffer` (copies only shared memory). */
function bytesView(input: ArrayBuffer | ArrayBufferView): Uint8Array<ArrayBuffer> {
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    const view = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    return input.buffer instanceof ArrayBuffer ? (view as Uint8Array<ArrayBuffer>) : view.slice();
  }
  throw new TypeError("expected a Blob, ArrayBuffer or ArrayBufferView (Uint8Array, Buffer, ...)");
}

/** Wrap any supported binary input as a `Blob` for a multipart upload (no copy for Blobs). */
export function toBlob(input: BinaryInput, type = "application/gzip"): Blob {
  if (isBlob(input)) return input;
  return new Blob([bytesView(input)], { type });
}

/** The input's bytes, reading a `Blob` fully into memory. */
export async function toBytes(input: BinaryInput): Promise<Uint8Array<ArrayBuffer>> {
  if (isBlob(input)) return new Uint8Array(await input.arrayBuffer());
  return bytesView(input);
}

/** Lower-case hex encoding. */
export function toHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (const byte of view) out += byte.toString(16).padStart(2, "0");
  return out;
}
