// Unit tests for the same-origin fetch adapter guards. These exercise the
// public contract of request() without a browser or a real server.
import { beforeEach, describe, expect, test } from "bun:test";
import { abortRequest, currentOrigin, request } from "./browser_http";

const ORIGIN = "https://app.example";
const ID = "a".repeat(32);

beforeEach(() => {
  Object.defineProperty(globalThis, "location", {
    value: { origin: ORIGIN },
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, "isSecureContext", {
    value: true,
    configurable: true,
    writable: true,
  });
  globalThis.fetch = async () => new Response(new Uint8Array([1, 2, 3]), { status: 200 });
});

function call(
  target: string,
  overrides: Partial<{
    method: string;
    id: string;
    headerJson: string;
    input: Uint8Array;
    hasBody: boolean;
  }> = {},
) {
  return request(
    overrides.id ?? ID,
    target,
    overrides.method ?? "GET",
    overrides.headerJson ?? "{}",
    overrides.input ?? new Uint8Array(0),
    overrides.hasBody ?? false,
  );
}

async function rejected(promise: Promise<[number, Uint8Array<ArrayBuffer>]>, code: string) {
  await expect(promise).rejects.toThrow(code);
}

describe("same-origin guard", () => {
  test("rejects a foreign origin", () =>
    rejected(call("https://evil.example/v1/health"), "invalid_request"));

  test("rejects a URL carrying credentials or a fragment", async () => {
    await rejected(
      call(`${ORIGIN.replace("https://", "https://user:pw@")}/v1/health`),
      "invalid_request",
    );
    await rejected(call(`${ORIGIN}/v1/health#frag`), "invalid_request");
  });

  test("rejects paths outside the allowlist", () =>
    rejected(call(`${ORIGIN}/v9/unknown`), "invalid_request"));

  test("rejects a method that the path does not admit", () =>
    rejected(call(`${ORIGIN}/v3/sync`, { method: "POST" }), "invalid_request"));

  test("personal inventory admits only its fixed read route", async () => {
    expect((await call(`${ORIGIN}/v3/personal/devices?cursor=devices.0&limit=32`))[0]).toBe(200);
    await rejected(call(`${ORIGIN}/v3/personal/devices`, { method: "POST" }), "invalid_request");
    await rejected(call(`${ORIGIN}/v3/personal/devices/foreign`), "invalid_request");
  });

  test("closed organization routes reach I/O with their exact methods", async () => {
    // I/O admission only. Rust validates/signed-binds the body and captured
    // revision; the server still owns current membership authorization.
    const routes: [string, string][] = [
      ["/v3/organizations", "GET"],
      ["/v3/organizations", "POST"],
      ["/v3/organizations/org-1?membership_revision=7", "GET"],
      ["/v3/organizations/org-1/members?membership_revision=7&after=user_1", "GET"],
      ["/v3/organizations/org-1/invitations?membership_revision=7", "GET"],
      ["/v3/organizations/org-1/invitations", "POST"],
      ["/v3/organizations/org-1/invitations/invite-1/revoke", "POST"],
      ["/v3/organizations/org-1/members/user-1", "POST"],
    ];
    const seen: string[] = [];
    globalThis.fetch = async (target, init) => {
      seen.push(`${init?.method} ${target}`);
      return new Response(new Uint8Array([1]), { status: 200 });
    };
    for (const [path, method] of routes) {
      expect((await call(`${ORIGIN}${path}`, { method }))[0]).toBe(200);
    }
    expect(seen).toEqual(routes.map(([path, method]) => `${method} ${ORIGIN}${path}`));
  });

  test("organization admission is not a prefix or arbitrary-method proxy", async () => {
    const refused: [string, string][] = [
      ["/v3/organizations", "DELETE"],
      ["/v3/organizations-other", "GET"],
      ["/v3/organizations/org-1", "POST"],
      ["/v3/organizations/org-1", "DELETE"],
      ["/v3/organizations/org-1/members/user-1", "GET"],
      ["/v3/organizations/org-1/unknown", "POST"],
      ["/v3/organizations/org-1/invitations/invite-1", "POST"],
      ["/v3/organizations/org-1/invitations/invite-1/revoke/extra", "POST"],
      [`/v3/organizations/${"a".repeat(129)}`, "GET"],
      ["/v3/organizations/a%2Fb", "GET"],
    ];
    let sent = 0;
    globalThis.fetch = async () => {
      sent++;
      return new Response();
    };
    for (const [path, method] of refused)
      await rejected(call(`${ORIGIN}${path}`, { method }), "invalid_request");
    expect(sent).toBe(0);
  });

  test("rejects malformed identifiers", () =>
    rejected(call(`${ORIGIN}/v1/health`, { id: "short" }), "invalid_request"));

  test("rejects insecure contexts", () => {
    Object.defineProperty(globalThis, "isSecureContext", { value: false, configurable: true });
    return rejected(call(`${ORIGIN}/v1/health`), "invalid_request");
  });
});

describe("request bound guard", () => {
  test("rejects oversized header metadata", () =>
    rejected(
      call(`${ORIGIN}/v1/health`, { headerJson: `{${" ".repeat(8193)}}` }),
      "invalid_request",
    ));

  test("rejects oversized bodies", () =>
    rejected(
      call(`${ORIGIN}/v3/sync/operations`, {
        method: "POST",
        input: new Uint8Array(65537),
        hasBody: true,
      }),
      "invalid_request",
    ));

  test("rejects headers outside the allowlist and non-string values", async () => {
    await rejected(
      call(`${ORIGIN}/v1/health`, { headerJson: '{"cookie":"x"}' }),
      "invalid_request",
    );
    await rejected(
      call(`${ORIGIN}/v1/health`, { headerJson: '{"content-type":5}' }),
      "invalid_request",
    );
    await rejected(call(`${ORIGIN}/v1/health`, { headerJson: "[1]" }), "invalid_request");
  });
});

describe("transport", () => {
  test("returns status and bounded body for an admitted request", async () => {
    const [status, body] = await call(`${ORIGIN}/v1/health`);
    expect(status).toBe(200);
    expect([...body]).toEqual([1, 2, 3]);
  });

  test("rejects a response larger than the bound", () => {
    globalThis.fetch = async () => new Response(new Uint8Array(65537), { status: 200 });
    return rejected(call(`${ORIGIN}/v1/health`), "invalid_response");
  });

  test("aborting an in-flight request surfaces as cancelled", () => {
    globalThis.fetch = async (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const pending = call(`${ORIGIN}/v1/health`);
    abortRequest(ID);
    return rejected(pending, "cancelled");
  });
});

test("currentOrigin mirrors the active browsing context", () => {
  expect(currentOrigin()).toBe(ORIGIN);
});
