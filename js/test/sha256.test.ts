import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import * as browser from "../src/index.js";
import * as node from "../src/index.node.js";
import { CONFORMANCE_DIR } from "./support/fake-fetch.js";

// FIPS 180-2 test vectors.
const ABC = new TextEncoder().encode("abc");
const ABC_HEX = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const EMPTY_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Node 18 has no global Web Crypto; browsers and Node >= 19 do. Provide it the way a browser would.
function ensureWebCrypto(): void {
  if (globalThis.crypto?.subtle === undefined) vi.stubGlobal("crypto", webcrypto);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe.each([
  ["browser entry (Web Crypto)", browser],
  ["node entry (node:crypto)", node],
] as const)("%s", (_label, impl) => {
  it("hashes the FIPS 180-2 vectors", async () => {
    ensureWebCrypto();
    expect(await impl.sha256Hex(ABC)).toBe(ABC_HEX);
    expect(await impl.sha256Hex(new Uint8Array())).toBe(EMPTY_HEX);
  });

  it("hashes every binary input form identically", async () => {
    ensureWebCrypto();
    const padded = new Uint8Array([0, 0, ...ABC, 0]);
    const shared = new Uint8Array(new SharedArrayBuffer(3));
    shared.set(ABC);
    const inputs = [
      ABC,
      ABC.slice().buffer,
      Buffer.from("abc"),
      padded.subarray(2, 5),
      new DataView(padded.buffer, 2, 3),
      shared,
      new Blob([ABC]),
    ];
    for (const input of inputs) expect(await impl.sha256Hex(input)).toBe(ABC_HEX);
  });

  it("builds the sha256:<hex> input digest of the conformance snapshot", async () => {
    ensureWebCrypto();
    const bytes = readFileSync(join(CONFORMANCE_DIR, "sample-project.tar.gz"));
    const expected = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    expect(await impl.inputDigest(bytes)).toBe(expected);
    expect(await impl.inputDigest(new Blob([bytes]))).toBe(expected);
  });

  it("rejects non-binary input", async () => {
    ensureWebCrypto();
    // @ts-expect-error -- runtime guard for JavaScript callers
    await expect(impl.sha256Hex("abc")).rejects.toThrow(TypeError);
  });
});

describe("browser entry without Web Crypto", () => {
  it("explains that a secure context is required", async () => {
    vi.stubGlobal("crypto", undefined);
    await expect(browser.sha256Hex(ABC)).rejects.toThrow(/secure context/);
  });
});

describe("entry points", () => {
  it("export the same API", () => {
    expect(Object.keys(browser).sort()).toEqual(Object.keys(node).sort());
    expect(browser.CertOneClient).toBe(node.CertOneClient);
    expect(node.VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("keeps VERSION in step with package.json", () => {
    const pkg = JSON.parse(readFileSync(join(CONFORMANCE_DIR, "..", "js", "package.json"), "utf8")) as { version: string };
    expect(node.VERSION).toBe(pkg.version);
  });
});
