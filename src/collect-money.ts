const ZERO_DECIMAL_CURRENCIES = new Set(["BIF","CLP","DJF","GNF","ISK","JPY","KMF","KRW","PYG","RWF","UGX","VND","VUV","XAF","XOF","XPF"]);
const THREE_DECIMAL_CURRENCIES = new Set(["BHD","IQD","JOD","KWD","LYD","OMR","TND"]);

export function currencyExponent(currency: string) {
  return ZERO_DECIMAL_CURRENCIES.has(currency) ? 0 : THREE_DECIMAL_CURRENCIES.has(currency) ? 3 : 2;
}

export type BankStatementEntry = {
  bankReference: string;
  payerName?: string;
  invoiceReference?: string;
  amount: string;
  currency: string;
  transactionDate: string;
  description?: string;
};

function parseCsvRows(input: string): string[][] {
  const rows: string[][] = []; let row: string[] = []; let cell = ""; let quoted = false;
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (quoted) {
      if (char === '"' && input[index + 1] === '"') { cell += '"'; index += 1; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"' && cell.length === 0) quoted = true;
    else if (char === ",") { row.push(cell); cell = ""; }
    else if (char === "\n" || char === "\r") {
      if (char === "\r" && input[index + 1] === "\n") index += 1;
      row.push(cell); cell = "";
      if (row.some((value) => value.trim())) rows.push(row);
      row = [];
    } else cell += char;
  }
  if (quoted) throw new Error("The CSV has an unclosed quoted field.");
  row.push(cell); if (row.some((value) => value.trim())) rows.push(row);
  return rows;
}

export function parseBankStatementCsv(input: string): BankStatementEntry[] {
  if (input.length > 2_000_000) throw new Error("The statement CSV must be smaller than 2 MB.");
  const rows = parseCsvRows(input.replace(/^\uFEFF/, ""));
  if (rows.length < 2) throw new Error("The CSV must contain a header and at least one transaction row.");
  const normalize = (value: string) => value.trim().toLowerCase().replace(/[\s_-]+/g, " ");
  const headers = rows[0].map(normalize);
  const column = (...names: string[]) => headers.findIndex((header) => names.includes(header));
  const referenceIndex = column("bank reference", "reference", "transaction reference", "transaction id", "reference number");
  const dateIndex = column("transaction date", "date", "value date", "booking date");
  const currencyIndex = column("currency", "ccy");
  const amountIndex = column("credit", "credit amount", "amount", "transaction amount");
  const debitIndex = column("debit", "debit amount");
  if (referenceIndex < 0 || dateIndex < 0 || currencyIndex < 0 || amountIndex < 0) throw new Error("Required columns: bank reference, transaction date, currency, and credit or amount.");
  const payerIndex = column("payer name", "payer", "customer", "counterparty", "sender");
  const invoiceIndex = column("invoice reference", "invoice", "payment reference");
  const descriptionIndex = column("description", "narration", "details", "memo");
  const imported: BankStatementEntry[] = []; const seen = new Set<string>();
  for (const [offset, values] of rows.slice(1).entries()) {
    const get = (index: number) => index < 0 ? "" : (values[index] || "").trim();
    const reference = get(referenceIndex); const rawAmount = get(amountIndex).replace(/[₦$€£,\s]/g, "");
    if (!reference || reference.length > 120) throw new Error(`Row ${offset + 2}: transaction reference is missing or too long.`);
    if (seen.has(reference)) throw new Error(`Row ${offset + 2}: duplicate transaction reference in this file.`);
    seen.add(reference);
    const currency = get(currencyIndex).toUpperCase(); const transactionDate = get(dateIndex);
    if (!/^[A-Z]{3}$/.test(currency)) throw new Error(`Row ${offset + 2}: currency must be a three-letter code.`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(transactionDate) || !Number.isFinite(Date.parse(`${transactionDate}T00:00:00Z`)) || new Date(`${transactionDate}T00:00:00Z`).toISOString().slice(0, 10) !== transactionDate) throw new Error(`Row ${offset + 2}: date must use a real YYYY-MM-DD calendar date.`);
    const debit = debitIndex >= 0 ? get(debitIndex).replace(/[₦$€£,\s]/g, "") : "";
    if (debit && debit !== "0" && debit !== "0.00") continue;
    if (!/^\d{1,12}(?:\.\d{1,3})?$/.test(rawAmount) || Number(rawAmount) <= 0) throw new Error(`Row ${offset + 2}: credit/amount must be a positive number.`);
    imported.push({ bankReference: reference, payerName: get(payerIndex).slice(0, 200) || undefined, invoiceReference: get(invoiceIndex).slice(0, 120) || undefined, amount: rawAmount, currency, transactionDate, description: get(descriptionIndex).slice(0, 500) || undefined });
    if (imported.length > 100) throw new Error("Import up to 100 credit transactions per CSV. Split larger statements into separate files.");
  }
  if (!imported.length) throw new Error("No positive credit transactions were found in this CSV.");
  return imported;
}

function scaledDecimal(value: string, scale: number, maxWholeDigits = 14): bigint | null {
  const fractionPattern = scale > 0 ? `(?:\\.(\\d{1,${scale}}))?` : "";
  const match = value.trim().match(new RegExp(`^(\\d{1,${maxWholeDigits}})${fractionPattern}$`));
  if (!match) return null;
  return BigInt(match[1]) * (10n ** BigInt(scale)) + BigInt((match[2] || "").padEnd(scale, "0") || "0");
}

export function moneyToMinor(value: string, currency: string): number | null {
  const scaled = scaledDecimal(value, currencyExponent(currency), 12);
  return scaled === null || scaled > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(scaled);
}

export function quantityToMilli(value: string): number | null {
  const scaled = scaledDecimal(value, 3, 9);
  return scaled === null || scaled <= 0n || scaled > 1000000000000n ? null : Number(scaled);
}

function multiplyRounded(value: bigint, numerator: bigint, denominator: bigint) {
  return (value * numerator + denominator / 2n) / denominator;
}

export function calculateInvoiceLine(quantityMilli: number, unitPriceMinor: number, taxRateBps: number, discountMinor: number) {
  if (![quantityMilli, unitPriceMinor, taxRateBps, discountMinor].every(Number.isSafeInteger) || quantityMilli <= 0 || unitPriceMinor < 0 || taxRateBps < 0 || taxRateBps > 10000 || discountMinor < 0) return null;
  const subtotal = Number(multiplyRounded(BigInt(quantityMilli) * BigInt(unitPriceMinor), 1n, 1000n));
  if (!Number.isSafeInteger(subtotal) || discountMinor > subtotal) return null;
  const tax = Number(multiplyRounded(BigInt(subtotal - discountMinor), BigInt(taxRateBps), 10000n));
  const total = subtotal + tax - discountMinor;
  if (![tax, total].every(Number.isSafeInteger) || total < 0) return null;
  return { subtotalMinor: subtotal, taxMinor: tax, discountMinor, totalMinor: total };
}

export function convertMinor(amountMinor: number, transactionCurrency: string, baseCurrency: string, rate: string): number | null {
  const rateScaled = scaledDecimal(rate, 8, 8);
  if (!Number.isSafeInteger(amountMinor) || amountMinor < 0 || rateScaled === null || rateScaled <= 0n || rateScaled > 100000000000000n) return null;
  const numerator = rateScaled * (10n ** BigInt(currencyExponent(baseCurrency)));
  const denominator = 100000000n * (10n ** BigInt(currencyExponent(transactionCurrency)));
  const converted = multiplyRounded(BigInt(amountMinor), numerator, denominator);
  return converted > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(converted);
}
