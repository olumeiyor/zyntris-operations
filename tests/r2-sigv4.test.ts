import test from "node:test";
import assert from "node:assert/strict";
import { signedR2Fetch } from "../src/r2-sigv4.ts";

test("R2 requests use S3 SigV4 credentials without sending the secret key", async () => {
  const originalFetch = globalThis.fetch;
  let captured: { url: URL; init: RequestInit } | undefined;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    captured = { url: new URL(input instanceof Request ? input.url : input.toString()), init: init || {} };
    return new Response("ok", { status: 200 });
  }) as typeof fetch;

  try {
    const url = new URL("https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/backups/tenant/file.txt?prefix=backup%2F2026&list-type=2");
    const response = await signedR2Fetch(url, { method: "PUT", headers: { "content-type": "text/plain" }, body: "sample" }, "ACCESS123", "private-secret", new Date("2026-10-14T12:00:00.000Z"));
    assert.equal(response.status, 200);
    assert.ok(captured);
    assert.equal(captured.init.method, "PUT");
    assert.equal(captured.url.pathname, "/backups/tenant/file.txt");
    assert.equal(captured.url.searchParams.get("prefix"), "backup/2026");
    const headers = new Headers(captured.init.headers);
    assert.match(headers.get("authorization") || "", /^AWS4-HMAC-SHA256 Credential=ACCESS123\/20261014\/auto\/s3\/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[a-f0-9]{64}$/);
    assert.equal(headers.get("x-amz-date"), "20261014T120000Z");
    assert.equal(headers.get("x-amz-content-sha256"), "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf");
    assert.equal(headers.get("authorization")?.includes("private-secret"), false);
    assert.equal(new TextDecoder().decode(captured.init.body as Uint8Array), "sample");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
