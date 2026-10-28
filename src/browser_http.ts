// browser_http.js is generated from this TypeScript source. Do not edit its output.
// Same-origin fetch adapter, not an authenticated URL proxy. Domain/wire rules
// and request signatures remain in Rust. No request/response body is logged.
const requests = new Map<string, AbortController>();
const MAX_BYTES = 65536;
const profileMethods = new Map([
  ["/v3/sync", "GET"],
  ["/v3/sync/operations", "POST"],
  ["/v3/sync/history", "GET"],
  ["/v3/sync/base", "GET"],
  ["/v3/personal/devices", "GET"],
]);
export function currentOrigin() {
  return globalThis.location?.origin ?? "";
}
export function abortRequest(id: string): void {
  requests.get(id)?.abort();
}

export async function request(
  id: string,
  target: string,
  method: string,
  headerJson: string,
  input: Uint8Array,
  hasBody: boolean,
): Promise<[number, Uint8Array<ArrayBuffer>]> {
  const url = new URL(target);
  if (
    !globalThis.isSecureContext ||
    url.origin !== currentOrigin() ||
    url.username ||
    url.password ||
    url.hash ||
    !(
      url.pathname.startsWith("/v2/") ||
      url.pathname === "/v1/health" ||
      profileMethods.get(url.pathname) === method
    ) ||
    !["GET", "POST", "DELETE"].includes(method) ||
    !/^[A-Za-z0-9_-]{32,128}$/.test(id) ||
    requests.has(id) ||
    requests.size >= 4 ||
    headerJson.length > 8192 ||
    input.length > MAX_BYTES
  ) {
    throw new Error("invalid_request");
  }
  const supplied: unknown = JSON.parse(headerJson);
  const allowed = new Set([
    "accept-language",
    "content-type",
    "signature",
    "signature-input",
    "content-digest",
    "traceparent",
    "tracestate",
  ]);
  if (typeof supplied !== "object" || supplied === null || Array.isArray(supplied))
    throw new Error("invalid_request");
  const headers = new Headers();
  for (const [name, value] of Object.entries(supplied)) {
    if (!allowed.has(name) || typeof value !== "string") throw new Error("invalid_request");
    headers.set(name, value);
  }
  headers.set("x-nds-client", "browser");
  const body = new Uint8Array(input);
  const controller = new AbortController();
  requests.set(id, controller);
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, 15000);
  try {
    const response = await fetch(url.href, {
      method,
      headers,
      ...(hasBody ? { body } : {}),
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "same-origin",
      signal: controller.signal,
    });
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BYTES))
      throw new Error("invalid_response");
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (response.body) {
      const reader = response.body.getReader();
      try {
        while (true) {
          const item = await reader.read();
          if (item.done) break;
          if (size + item.value.byteLength > MAX_BYTES) {
            await reader.cancel();
            throw new Error("invalid_response");
          }
          size += item.value.byteLength;
          chunks.push(item.value);
        }
      } finally {
        reader.releaseLock();
      }
    }
    const output = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.length;
      chunk.fill(0);
    }
    return [response.status, output];
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "message" in error &&
      error.message === "invalid_response"
    )
      throw new Error("invalid_response");
    throw new Error(
      timedOut
        ? "request_timeout"
        : controller.signal.aborted
          ? "cancelled"
          : "transport_unavailable",
    );
  } finally {
    clearTimeout(timeout);
    requests.delete(id);
    body.fill(0);
  }
}
