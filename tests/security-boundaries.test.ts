import test from "node:test";
import assert from "node:assert/strict";
import { allowedBrowserOrigin, isTenantObjectKey, tenantDocumentKey, tenantReceiptKey } from "../src/security-boundaries.ts";

test("browser mutations require the configured origin or same-origin referer", () => {
  const app = "https://app.zyntris.org";
  assert.equal(allowedBrowserOrigin(app, null, app), true);
  assert.equal(allowedBrowserOrigin(null, `${app}/workspace`, app), true);
  assert.equal(allowedBrowserOrigin("https://evil.example", `${app}/workspace`, app), false);
  assert.equal(allowedBrowserOrigin(null, null, app), false);
  assert.equal(allowedBrowserOrigin("null", null, app), false);
  assert.equal(allowedBrowserOrigin("https://app.zyntris.org.evil.example", null, app), false);
});

test("tenant storage keys cannot cross tenant prefixes", () => {
  const document = tenantDocumentKey("org-one", "report.pdf");
  const receipt = tenantReceiptKey("org-one", "expense-123", "file-456");
  assert.equal(isTenantObjectKey(document, "org-one"), true);
  assert.equal(isTenantObjectKey(receipt, "org-one"), true);
  assert.equal(isTenantObjectKey("org-one-extra/private.pdf", "org-one"), false);
  assert.equal(isTenantObjectKey("org-two/private.pdf", "org-one"), false);
  assert.equal(isTenantObjectKey("expense-receipts/org-two/expense-123/file-456", "org-one"), false);
  assert.equal(isTenantObjectKey("tenant-backups/org-two/backup/file.json", "org-one"), false);
  assert.throws(() => tenantDocumentKey("org/other", "report.pdf"));
  assert.throws(() => tenantReceiptKey("org-one", "../other", "file-456"));
});
