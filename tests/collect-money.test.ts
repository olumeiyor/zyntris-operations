import test from "node:test";
import assert from "node:assert/strict";
import { calculateInvoiceLine, convertMinor, currencyExponent, moneyToMinor, quantityToMilli } from "../src/collect-money.ts";

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
