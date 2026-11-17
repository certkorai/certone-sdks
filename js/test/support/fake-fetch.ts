import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { FetchLike } from "../../src/index.node.js";

/** Repo-relative locations of the shared conformance assets (`conformance`). */
export const CONFORMANCE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "conformance");

export function fixture(name: string): unknown {
  return JSON.parse(readFileSync(join(CONFORMANCE_DIR, "fixtures", `${name}.json`), "utf8")) as unknown;
}

export interface RecordedCall {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: RequestInit["body"];
  readonly signal: AbortSignal | undefined;
}

type Handler = (call: RecordedCall) => Response | Promise<Response>;

/**
 * A scripted `fetch`: each request consumes the next handler (the last one repeats), and every
 * request is recorded with its normalised headers and the exact body object passed to fetch.
 */
export function fakeFetch(...handlers: Handler[]): { fetch: FetchLike; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetch: FetchLike = async (input, init) => {
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, key) => {
      headers[key] = value;
    });
    const call: RecordedCall = {
      url: input,
      method: init.method ?? "GET",
      headers,
      body: init.body,
      signal: init.signal ?? undefined,
    };
    calls.push(call);
    const handler = handlers[Math.min(calls.length - 1, handlers.length - 1)];
    if (handler === undefined) throw new Error("fakeFetch: no handler configured");
    return handler(call);
  };
  return { fetch, calls };
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function text(body: string, status: number, contentType = "text/plain"): Response {
  return new Response(body, { status, headers: { "content-type": contentType } });
}

/** Behaves like a real fetch that never answers: it settles only when its signal aborts. */
export function hang(call: RecordedCall): Promise<Response> {
  return new Promise((_, reject) => {
    const signal = call.signal;
    if (signal === undefined) return;
    signal.addEventListener("abort", () => reject(new DOMException("The operation was aborted.", "AbortError")), {
      once: true,
    });
  });
}

/**
 * Headers arrive but the body stalls; like undici, aborting the request's signal errors the body
 * stream, so `response.text()` rejects.
 */
export function stalledBody(call: RecordedCall): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"partial":'));
      call.signal?.addEventListener(
        "abort",
        () => controller.error(new DOMException("The operation was aborted.", "AbortError")),
        { once: true },
      );
    },
  });
  return new Response(stream, { status: 200, headers: { "content-type": "application/json" } });
}
