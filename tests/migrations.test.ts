import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");

test("all D1 migrations apply in order with valid foreign keys", (context) => {
  const available = spawnSync("sqlite3", ["--version"], { encoding: "utf8" });
  if (available.error?.code === "ENOENT") {
    context.skip("sqlite3 CLI is not installed in this environment");
    return;
  }
  assert.equal(available.status, 0, available.stderr);

  const migrations = readdirSync(resolve(root, "migrations"))
    .filter((name) => /^\d+.*\.sql$/.test(name))
    .sort((a, b) => a.localeCompare(b, "en", { numeric: true }));
  assert.ok(migrations.length > 0, "migration directory should not be empty");

  const sql = [
    "PRAGMA foreign_keys = ON;",
    ...migrations.map((name) => `-- ${name}\n${readFileSync(resolve(root, "migrations", name), "utf8")}`),
    "PRAGMA foreign_key_check;",
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'fleet_%' ORDER BY name;",
    "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_fleet_one_active_trip_per_vehicle';",
  ].join("\n");
  const applied = spawnSync("sqlite3", [":memory:"], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  assert.equal(applied.status, 0, applied.stderr || applied.stdout);
  const lines = applied.stdout.trim().split("\n");
  assert.deepEqual(lines.slice(0, 5), [
    "fleet_fuel_records",
    "fleet_incidents",
    "fleet_service_records",
    "fleet_trips",
    "fleet_vehicles",
  ], "fleet tables should exist after the complete migration chain");
  assert.equal(lines[5], "idx_fleet_one_active_trip_per_vehicle", "a vehicle must not have concurrent trips in progress");
});
