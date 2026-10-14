const encoder = new TextEncoder();

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function hex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encodeRfc3986(value: string) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

async function digest(value: string | Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(typeof value === "string" ? encoder.encode(value) : value)));
}

async function hmac(key: Uint8Array, value: string) {
  const cryptoKey = await crypto.subtle.importKey("raw", toArrayBuffer(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, toArrayBuffer(encoder.encode(value))));
}

function canonicalQuery(url: URL) {
  return [...url.searchParams.entries()]
    .map(([key, value]) => [encodeRfc3986(key), encodeRfc3986(value)] as const)
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => (leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0))
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
}

export async function signedR2Fetch(
  url: URL,
  init: RequestInit,
  accessKeyId: string,
  secretAccessKey: string,
  now = new Date(),
) {
  const method = (init.method || "GET").toUpperCase();
  const body = init.body;
  let payload: Uint8Array;
  if (body == null) payload = new Uint8Array();
  else if (typeof body === "string") payload = encoder.encode(body);
  else if (body instanceof ArrayBuffer) payload = new Uint8Array(body);
  else if (ArrayBuffer.isView(body)) payload = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  else if (body instanceof Blob) payload = new Uint8Array(await body.arrayBuffer());
  else throw new Error("Unsupported R2 request body type.");

  const dateTime = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const date = dateTime.slice(0, 8);
  const payloadHash = hex(await digest(payload));
  const headers = new Map<string, string>();
  const inputHeaders = new Headers(init.headers);
  inputHeaders.forEach((value, key) => headers.set(key.toLowerCase(), value.trim().replace(/\s+/g, " ")));
  headers.set("host", url.host);
  headers.set("x-amz-content-sha256", payloadHash);
  headers.set("x-amz-date", dateTime);

  const sortedHeaders = [...headers.entries()].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  const canonicalHeaders = sortedHeaders.map(([key, value]) => `${key}:${value}\n`).join("");
  const signedHeaders = sortedHeaders.map(([key]) => key).join(";");
  const canonicalRequest = [method, url.pathname || "/", canonicalQuery(url), canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${date}/auto/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${dateTime}\n${scope}\n${hex(await digest(canonicalRequest))}`;
  let signingKey = await hmac(encoder.encode(`AWS4${secretAccessKey}`), date);
  signingKey = await hmac(signingKey, "auto");
  signingKey = await hmac(signingKey, "s3");
  signingKey = await hmac(signingKey, "aws4_request");
  const signature = hex(await hmac(signingKey, stringToSign));
  const requestHeaders = new Headers(init.headers);
  requestHeaders.set("x-amz-content-sha256", payloadHash);
  requestHeaders.set("x-amz-date", dateTime);
  requestHeaders.set("authorization", `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`);
  return fetch(url, { ...init, method, headers: requestHeaders, body: body == null ? undefined : toArrayBuffer(payload) });
}
