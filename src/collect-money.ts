const ZERO_DECIMAL_CURRENCIES = new Set(["BIF","CLP","DJF","GNF","ISK","JPY","KMF","KRW","PYG","RWF","UGX","VND","VUV","XAF","XOF","XPF"]);
const THREE_DECIMAL_CURRENCIES = new Set(["BHD","IQD","JOD","KWD","LYD","OMR","TND"]);

export function currencyExponent(currency: string) {
  return ZERO_DECIMAL_CURRENCIES.has(currency) ? 0 : THREE_DECIMAL_CURRENCIES.has(currency) ? 3 : 2;
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
