import { argon2id, argon2Verify } from "hash-wasm";

const textEncoder = new TextEncoder();
const ARGON2_PREFIX = "$argon2id$v=19$m=19456,t=2,p=1$";
const LEGACY_PBKDF2_ROUNDS = 100000;

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function safeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

async function pepperedInput(password: string, pepper: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", textEncoder.encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, textEncoder.encode(password)));
  return `zyntris-password-v1:${toHex(digest)}`;
}

export async function passwordHash(password: string, pepper: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const encoded = await argon2id({
    password: await pepperedInput(password, pepper),
    salt,
    parallelism: 1,
    iterations: 2,
    memorySize: 19 * 1024,
    hashLength: 32,
    outputType: "encoded",
  });
  if (typeof encoded !== "string" || !encoded.startsWith(ARGON2_PREFIX)) throw new Error("Argon2id returned an unexpected hash format.");
  return encoded;
}

async function verifyLegacyPbkdf2(password: string, encoded: string, pepper?: string): Promise<boolean> {
  const [algorithm, rounds, salt, expected] = encoded.split("$");
  if ((algorithm !== "pbkdf2-sha256" && algorithm !== "pbkdf2-sha256-peppered")
    || rounds !== String(LEGACY_PBKDF2_ROUNDS)
    || !/^[a-f0-9]{32}$/i.test(salt || "")
    || !/^[a-f0-9]{64}$/i.test(expected || "")) return false;
  if (algorithm === "pbkdf2-sha256-peppered" && !pepper) return false;

  let input = textEncoder.encode(password);
  if (algorithm === "pbkdf2-sha256-peppered") input = new Uint8Array(await crypto.subtle.sign(
    "HMAC",
    await crypto.subtle.importKey("raw", textEncoder.encode(pepper!), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    input,
  ));
  const material = await crypto.subtle.importKey("raw", input, "PBKDF2", false, ["deriveBits"]);
  const result = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    hash: "SHA-256",
    salt: textEncoder.encode(salt),
    iterations: LEGACY_PBKDF2_ROUNDS,
  }, material, 256);
  return safeEqual(toHex(new Uint8Array(result)), expected.toLowerCase());
}

export async function verifyPassword(password: string, encoded: string, pepper?: string): Promise<boolean> {
  if (encoded.startsWith("$argon2id$")) {
    // Enforce our exact cost parameters before parsing attacker-modifiable database text.
    if (!pepper || !encoded.startsWith(ARGON2_PREFIX)
      || !/^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{20,24}\$[A-Za-z0-9+/]{40,44}$/.test(encoded)) return false;
    try {
      return await argon2Verify({ password: await pepperedInput(password, pepper), hash: encoded });
    } catch {
      return false;
    }
  }
  return verifyLegacyPbkdf2(password, encoded, pepper);
}
