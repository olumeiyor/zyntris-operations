export function allowedBrowserOrigin(origin: string | null, referer: string | null, appOrigin: string): boolean {
  if (origin) return origin === appOrigin;
  if (!referer) return false;
  try {
    return new URL(referer).origin === appOrigin;
  } catch {
    return false;
  }
}

export function isTenantObjectKey(key: string, organizationId: string): boolean {
  if (!organizationId || organizationId.includes("/")) return false;
  return key.startsWith(`${organizationId}/`)
    || key.startsWith(`expense-receipts/${organizationId}/`)
    || key.startsWith(`tenant-backups/${organizationId}/`);
}

export function tenantDocumentKey(organizationId: string, objectName: string): string {
  if (!organizationId || organizationId.includes("/") || !objectName || objectName.includes("/")) {
    throw new Error("Invalid tenant storage key components.");
  }
  return `${organizationId}/${objectName}`;
}

export function tenantReceiptKey(organizationId: string, expenseId: string, objectId: string): string {
  if ([organizationId, expenseId, objectId].some((part) => !part || part.includes("/"))) {
    throw new Error("Invalid tenant receipt key components.");
  }
  return `expense-receipts/${organizationId}/${expenseId}/${objectId}`;
}
