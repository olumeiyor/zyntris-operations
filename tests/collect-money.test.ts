import test from "node:test";
import assert from "node:assert/strict";
import { calculateInvoiceLine, convertMinor, currencyExponent, moneyToMinor, parseBankStatementCsv, quantityToMilli } from "../src/collect-money.ts";

test("currency precision follows minor units for common zero, two and three decimal currencies", () => {
  assert.equal(currencyExponent("JPY"), 0);
  assert.equal(currencyExponent("NGN"), 2);
  assert.equal(currencyExponent("KWD"), 3);
  assert.equal(moneyToMinor("1200", "JPY"), 1200);
  assert.equal(moneyToMinor("12.34", "NGN"), 1234);
  assert.equal(moneyToMinor("1.234", "KWD"), 1234);
});

test("money parser rejects unsupported precision, signs, exponent notation and unsafe values", () => {
  assert.equal(moneyToMinor("1.001", "NGN"), null);
  assert.equal(moneyToMinor("-1.00", "NGN"), null);
  assert.equal(moneyToMinor("1e3", "NGN"), null);
  assert.equal(moneyToMinor("9999999999999.99", "NGN"), null);
});

test("quantity parsing allows three decimal places and rejects zero/negative quantity", () => {
  assert.equal(quantityToMilli("1.250"), 1250);
  assert.equal(quantityToMilli("0"), null);
  assert.equal(quantityToMilli("-1"), null);
  assert.equal(quantityToMilli("1.0001"), null);
});

test("line calculation rounds tax in integer arithmetic and checks discounts", () => {
  assert.deepEqual(calculateInvoiceLine(1500, 1000, 750, 100), {
    subtotalMinor: 1500,
    taxMinor: 105,
    discountMinor: 100,
    totalMinor: 1505,
  });
  assert.equal(calculateInvoiceLine(1000, 100, 0, 101), null);
  assert.equal(calculateInvoiceLine(1000, 100, 10001, 0), null);
});

test("FX conversion respects source and destination currency exponents", () => {
  assert.equal(convertMinor(10000, "USD", "NGN", "1500"), 15000000);
  assert.equal(convertMinor(100, "KWD", "NGN", "3000"), 30000);
  assert.equal(convertMinor(10000, "USD", "NGN", "0"), null);
  assert.equal(convertMinor(-1, "USD", "NGN", "1"), null);
});

test("bank statement CSV parser handles quoted cells and imports only credit rows", () => {
  const rows = parseBankStatementCsv([
    "Transaction ID,Transaction Date,Currency,Credit,Debit,Payer,Invoice Reference,Narration",
    'TX-1,2026-10-28,NGN,"125,000.00",0,"Acme, Ltd",INV-1,"October payment"',
    "TX-2,2026-10-28,NGN,0,8000,Vendor,,Outgoing transfer",
  ].join("\r\n"));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].bankReference, "TX-1");
  assert.equal(rows[0].payerName, "Acme, Ltd");
  assert.equal(rows[0].amount, "125000.00");
  assert.equal(rows[0].invoiceReference, "INV-1");
});

test("bank statement CSV parser rejects malformed headers, dates, duplicates and quoted fields", () => {
  assert.throws(() => parseBankStatementCsv("reference,amount\nTX-1,10"), /Required columns/);
  assert.throws(() => parseBankStatementCsv("reference,date,currency,amount\nTX-1,2026-02-30,NGN,10"), /YYYY-MM-DD/);
  assert.throws(() => parseBankStatementCsv("reference,date,currency,amount\nTX-1,2026-10-28,NGN,10\nTX-1,2026-10-29,NGN,20"), /duplicate transaction reference/);
  assert.throws(() => parseBankStatementCsv('reference,date,currency,amount\nTX-1,2026-10-28,NGN,"10'), /unclosed quoted/);
});
