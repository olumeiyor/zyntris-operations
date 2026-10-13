import test from "node:test";
import assert from "node:assert/strict";
import { passwordHash, verifyPassword } from "../src/password-hashing.ts";

test("Argon2id hashes verify with the correct password and pepper only", async () => {
  const hash = await passwordHash("correct horse battery staple", "test-only-pepper-value");
  assert.match(hash, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
  assert.equal(await verifyPassword("correct horse battery staple", hash, "test-only-pepper-value"), true);
  assert.equal(await verifyPassword("wrong password", hash, "test-only-pepper-value"), false);
  assert.equal(await verifyPassword("correct horse battery staple", hash, "different-test-pepper"), false);
  assert.equal(await verifyPassword("correct horse battery staple", hash), false);
});

test("Argon2id verifier rejects altered or excessive-cost stored parameters", async () => {
  const hash = await passwordHash("test-password", "test-only-pepper-value");
  assert.equal(await verifyPassword("test-password", hash.replace("m=19456", "m=131072"), "test-only-pepper-value"), false);
  assert.equal(await verifyPassword("test-password", `${hash}extra`, "test-only-pepper-value"), false);
});
