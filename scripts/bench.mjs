// Performance guard rail for the Library.
//
// Why this exists: the cost figures in README.md were measured once, by hand, with a script that lived
// outside this repository. Nothing kept them honest afterwards. This runs the same four operations against
// a throwaway library of a known size and compares the result with a committed baseline.
//
// It is a regression guard, not a benchmark report. The tolerance is deliberately generous (default 5x)
// because this machine is shared with other sessions and timings move; the thing worth catching is an
// order-of-magnitude change, not ten percent of noise. It is also deliberately NOT part of `npm run check`:
// a timed measurement in the invariant chain would make the invariants slow and flaky.
//
// Usage:
//   node scripts/bench.mjs                     measure and print
//   node scripts/bench.mjs --check             compare with bench/baseline.json (exit 1 on regression)
//   node scripts/bench.mjs --write-baseline    record the current numbers as the baseline
//   node scripts/bench.mjs --objects 10000     measure at another size
//
// The plugin is imported from this checkout, so @deepseek-ai/dsh-tools must be resolvable from lib/ (in this
// working copy that is the node_modules junction to the installed profile).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const BASELINE = path.join(ROOT, "bench", "baseline.json");
const DEFAULT_OBJECTS = 5000;
const DEFAULT_TOLERANCE = 5;
const OPS = ["queryMedianMs", "recordMedianMs", "rebuildMedianMs", "statusMedianMs"];

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return fallback;
  const raw = process.argv[i + 1];
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

const objects = Math.max(100, Math.trunc(arg("objects", DEFAULT_OBJECTS)));
const tolerance = Math.max(1, arg("tolerance", DEFAULT_TOLERANCE));
const check = process.argv.includes("--check");
const writeBaseline = process.argv.includes("--write-baseline");

// A throwaway library: the real one must never be measured, or touched, by a benchmark.
const home = fs.mkdtempSync(path.join(os.tmpdir(), "mega-bench-"));
process.env.DSH_HOME = home;
fs.mkdirSync(path.join(home, "library"), { recursive: true });

// Seed the index directly. Seeding through library_record would measure the writer N times over and take
// minutes; the four operations below are the ones being measured, and they run through the real code.
const seed = { version: 1, generatedAt: new Date().toISOString(), objects: [] };
const types = ["file", "tool", "env", "knowledge", "work_record"];
for (let i = 0; i < objects; i++) {
  const type = types[i % types.length];
  const name = `bench-object-${i}`;
  seed.objects.push({
    id: `${type}-${name}-bench`,
    type,
    name,
    source: `bench/${type}`,
    path: path.join(home, "fixtures", `${name}.bin`),
    description: `benchmark fixture ${i}`,
    tags: ["bench", type],
    summary: `fixture number ${i} for the performance guard rail`,
    createdAt: new Date(Date.now() - i * 1000).toISOString(),
  });
}
fs.writeFileSync(path.join(home, "library", "index.json"), JSON.stringify(seed, null, 2), "utf8");

const mod = await import(new URL("../lib/index.js", import.meta.url).href);
const tools = new Map();
await mod.apply({ tools: { register: (t) => tools.set(t.name, t) }, logger: { info: () => {}, warn: () => {} } }, { bootstrap: "off" });
const call = (name, args) => tools.get(name).execute(args || {});

const timed = async (fn) => {
  const t0 = process.hrtime.bigint();
  await fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
};
const median = (xs) => xs.slice().sort((a, b) => a - b)[Math.floor(xs.length / 2)];

const queryTimes = [];
for (let i = 0; i < 7; i++) queryTimes.push(await timed(() => call("library_query", { query: `bench-object-${i * 37}`, limit: 20 })));

const recordTimes = [];
for (let i = 0; i < 3; i++) {
  recordTimes.push(await timed(() => call("library_record", { type: "knowledge", name: `bench-record-${i}`, source: "bench", description: "recorded by the guard rail" })));
}
const rebuildTimes = [];
for (let i = 0; i < 3; i++) rebuildTimes.push(await timed(() => call("library_index", {})));
const statusTimes = [];
for (let i = 0; i < 3; i++) statusTimes.push(await timed(() => call("library_index", { op: "status" })));

const indexBytes = fs.statSync(path.join(home, "library", "index.json")).size;
const result = {
  objects: objects + 3,
  indexBytes,
  queryMedianMs: Math.round(median(queryTimes) * 10) / 10,
  recordMedianMs: Math.round(median(recordTimes) * 10) / 10,
  rebuildMedianMs: Math.round(median(rebuildTimes) * 10) / 10,
  statusMedianMs: Math.round(median(statusTimes) * 10) / 10,
  node: process.versions.node,
  measuredAt: new Date().toISOString(),
};
fs.rmSync(home, { recursive: true, force: true });

console.log(`library of ${result.objects} object(s), index ${(result.indexBytes / 1048576).toFixed(1)} MB, node ${result.node}`);
for (const op of OPS) console.log(`  ${op.padEnd(16)} ${result[op]} ms`);

if (writeBaseline) {
  const payload = {
    note: "Regression guard rail, not a benchmark report: these are medians from scripts/bench.mjs on one shared machine, and the check allows a wide multiple (5x by default) because the point is to catch an order-of-magnitude change rather than timing noise.",
    tolerance: DEFAULT_TOLERANCE,
    baseline: result,
  };
  fs.mkdirSync(path.dirname(BASELINE), { recursive: true });
  fs.writeFileSync(BASELINE, JSON.stringify(payload, null, 2) + "\n", "utf8");
  console.log(`baseline written to ${path.relative(ROOT, BASELINE)}`);
  process.exit(0);
}

if (check) {
  if (!fs.existsSync(BASELINE)) {
    console.log(`no baseline at ${path.relative(ROOT, BASELINE)} -- run with --write-baseline once`);
    process.exit(1);
  }
  const stored = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
  const base = stored.baseline || {};
  console.log(`comparing with the baseline from ${base.measuredAt || "?"} (tolerance ${tolerance}x)`);
  const regressed = [];
  for (const op of OPS) {
    const was = Number(base[op]);
    const now = Number(result[op]);
    if (!Number.isFinite(was) || !Number.isFinite(now)) continue;
    const ratio = now / (was || 1);
    const verdict = ratio > tolerance ? "REGRESSED" : "ok";
    if (ratio > tolerance) regressed.push(`${op}: ${was} ms -> ${now} ms (${ratio.toFixed(1)}x)`);
    console.log(`  ${op.padEnd(16)} ${String(was).padStart(8)} ms -> ${String(now).padStart(8)} ms  ${ratio.toFixed(2)}x  ${verdict}`);
  }
  if (result.objects !== base.objects) console.log(`note: measured at ${result.objects} objects against a baseline of ${base.objects} - sizes differ, so the comparison is loose`);
  if (regressed.length) {
    console.log("regressions:");
    for (const r of regressed) console.log(`  ${r}`);
    process.exit(1);
  }
  console.log("no regression beyond tolerance");
}
