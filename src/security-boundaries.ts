export function allowedBrowserOrigin(origin: string | null, referer: string | null, appOrigin: string): boolean {
  if (origin) return origin === appOrigin;
  if (!referer) return false;
  try {
    return new URL(referer).origin === appOrigin;
  } catch {
    return false;
  }
}

export function requestSessionToken(mobileRequest: boolean, authorization: string | null, sessionCookie: string | null | undefined): string | null {
  if (mobileRequest) return authorization?.match(/^Bearer\s+([a-f0-9]{64})$/i)?.[1] || null;
  return sessionCookie && /^[a-f0-9]{64}$/i.test(sessionCookie) ? sessionCookie : null;
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

export function tenantBackupKey(organizationId: string, backupId: string, objectPath: string): string {
  const safePart = (value: string) => value.length > 0 && value.split("/").every((part) => part.length > 0 && part !== "." && part !== "..");
  if (!organizationId || organizationId.includes("/") || !backupId || backupId.includes("/") || !safePart(objectPath)) {
    throw new Error("Invalid tenant backup key components.");
  }
  return `tenant-backups/${organizationId}/${backupId}/${objectPath}`;
}

export function isTenantBackupObjectKey(key: string, organizationId: string, backupId?: string): boolean {
  if (!organizationId || organizationId.includes("/")) return false;
  const parts = key.split("/");
  if (parts.some((part) => !part || part === "." || part === "..") || parts[0] !== "tenant-backups" || parts[1] !== organizationId) return false;
  return backupId === undefined || parts[2] === backupId;
}
