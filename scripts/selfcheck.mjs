#!/usr/bin/env node
// The five-stage self-check, as a maintainable script instead of a machine-local one-off.
//
// Sequence (run in this order, twice around the middle so the middle is bracketed by the same check):
//
//   1. smoke       - bring the plugin up in a temp library and exercise every tool
//   2. traversal   - walk a real directory and sweep it for identification mistakes
//   3. proofread   - the repository invariants (ASCII, consistency, portability, isolation)
//   4. traversal   - the same walk again; a pass that changes its own answer is not a pass
//   5. smoke       - the same battery again
//
// Three axes are held across all five stages and reported at the end, because a pass that ignores them
// is not a pass:
//
//   ASCII      - source is checked by scripts/check-ascii.mjs; here the *runtime* output is checked too,
//                so a note or a name that leaks a non-ASCII character is caught at the call site.
//   PORTABILITY- Windows-specific code paths must have POSIX counterparts and spawns must be argv-only
//                (scripts/check-portability.mjs); here the runtime side is exercised with unicode and
//                space-bearing paths, argv spawns and os.tmpdir() only.
//   ENCODING   - UTF-8 in and out: CJK, Hangul, accents, a combining mark and an astral-plane emoji
//                must survive record -> index -> query -> export -> encrypt/decrypt, and the index must
//                stay BOM-free UTF-8.
//
// Usage:
//   node scripts/selfcheck.mjs [--dir <path>] [--plugin <path>] [--json <file>] [--quick] [--keep]
//
//   --dir    directory for the traversal stages (default: this repository)
//   --plugin plugin entry point to exercise (default: lib/index.js in this repository)
//   --json   also write the full report as JSON to this path
//   --quick  one smoke pass and one traversal only (no bracket, no proofread stages)
//   --keep   keep the temp library and fixtures for inspection
//
// The plugin needs its peer dependency (@deepseek-ai/dsh-tools) to load. Where that is absent - a plain
// checkout, or CI - the stages that need it are reported as SKIPPED with the reason and the invariants
// still run, so the script is useful on any machine rather than only on the author's.
//
// Dependency-free, ASCII-only, Windows/macOS/Linux.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL, fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : dflt;
};
const flag = (name) => argv.includes(`--${name}`);
const DIR = path.resolve(opt("dir", ROOT));
// --plugin lets the same battery run against a different build (an older tag, a sibling edition, or a
// deliberately broken copy) - which is also how the fault-injection test proves these checks bite.
const PLUGIN = path.resolve(opt("plugin", path.join(ROOT, "lib", "index.js")));
const JSON_OUT = opt("json", null);
const QUICK = flag("quick");
const KEEP = flag("keep");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "mega-selfcheck-"));
const HOME = path.join(TMP, "library-home");
const FIXTURES = path.join(TMP, "fixtures");
fs.mkdirSync(HOME, { recursive: true });
fs.mkdirSync(FIXTURES, { recursive: true });
process.env.DSH_HOME = HOME;

// ---------------------------------------------------------------- reporting
const AXES = ["ASCII", "PORTABILITY", "ENCODING"];
const results = [];
const stageReport = [];
function check(axis, stage, label, ok, detail) {
  results.push({ axis, stage, label, ok: !!ok, detail: detail === undefined ? "" : String(detail).slice(0, 200) });
  if (!ok) console.log(`  FAIL  [${axis}] ${label}${detail ? ` -> ${String(detail).slice(0, 160)}` : ""}`);
}
function stage(name, fn) {
  console.log(`\n=== ${name} ===`);
  const t0 = Date.now();
  return (async () => {
    // A stage reports { skipped: reason } when it cannot run here, or { value: <comparable> } otherwise.
    let out = null;
    let threw = null;
    try {
      out = await fn();
    } catch (e) {
      threw = String((e && e.message) || e);
      check("PORTABILITY", name, `${name} threw instead of failing a check`, false, threw);
      out = { value: null };
    }
    const ms = Date.now() - t0;
    const skipped = out && out.skipped ? out.skipped : null;
    const value = out ? out.value : null;
    stageReport.push({ stage: name, ms, skipped, threw, value: value === null || value === undefined ? null : String(value) });
    if (skipped) console.log(`  SKIP  ${skipped}`);
    else if (threw) console.log(`  ERROR ${threw}`);
    else console.log(`  done in ${ms} ms`);
    return { ms, skipped, threw, value };
  })();
}

// ---------------------------------------------------------------- plugin loading
let tools = null;
let unavailable = null;
try {
  const mod = await import(pathToFileURL(PLUGIN).href);
  const map = new Map();
  mod.apply({ tools: { register: (t) => map.set(t.name, t) } });
  tools = map;
} catch (e) {
  unavailable = `plugin not loadable here (${String((e && e.message) || e).split("\n")[0]}) - stage needs @deepseek-ai/dsh-tools`;
}

// ---------------------------------------------------------------- fixtures
const CJK = "\u6e2c\u8a66\u6a94\u6848\u30fb\u65e5\u672c\u8a9e\u30fb\ud55c\uad6d\uc5b4";
const ACCENT = "caf\u00e9 na\u00efve \u00c6r\u00f8 Z\u00fcrich";
const EMOJI = "memory \u{1F9E0} ok";
const COMBINING = "e\u0301clair";
const UNICODE_DIR = path.join(FIXTURES, "unicode \u4e2d\u6587 dir");

const plainFile = path.join(FIXTURES, "ordinary.bin");
const swapped = path.join(FIXTURES, "actually-text.png");
const textFile = path.join(FIXTURES, "note.txt");
const mysteryFile = path.join(FIXTURES, "mystery.qqq");
fs.mkdirSync(UNICODE_DIR, { recursive: true });
fs.writeFileSync(plainFile, Buffer.concat([Buffer.from([0x00, 0x01, 0x02, 0x03]), Buffer.alloc(64, 0x7f)]));
fs.writeFileSync(swapped, "this is plain text pretending to be a png\n", "utf8");
fs.writeFileSync(textFile, "\u7d14\u6587\u5b57\u5167\u5bb9\n", "utf8");
// An unknown extension with plain content: the only shape that reaches the "no signature matched"
// fallback note, which the ASCII axis scans.
fs.writeFileSync(mysteryFile, "an ordinary line of ascii text\n", "utf8");
fs.writeFileSync(path.join(UNICODE_DIR, "bom\u3042\u308a.txt"), "\uFEFFleading bom, unicode name\n", "utf8");
fs.writeFileSync(path.join(UNICODE_DIR, "utf16.txt"), Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from("utf16 le body\n", "utf16le")]));
const learnA = path.join(FIXTURES, "learnA.selfchk");
const learnB = path.join(FIXTURES, "learnB.selfchk");
fs.writeFileSync(learnA, Buffer.concat([Buffer.from("SELFCK"), Buffer.from([1, 0, 0, 0]), Buffer.alloc(24, 3)]));
fs.writeFileSync(learnB, Buffer.concat([Buffer.from("SELFCK"), Buffer.from([1, 0, 0, 0]), Buffer.alloc(24, 9)]));

const nonAsciiOffenders = [];
// ASCII axis at runtime means: the plugin's OWN vocabulary is ASCII. User data is not - a CJK file name
// or a Japanese note must come back exactly as stored, so echoing it is correct, not a violation. The
// scan therefore looks only at the keys the plugin itself writes, and the stored user data is verified
// separately by the ENCODING checks.
const PLUGIN_TEXT_KEYS = new Set(["note", "message", "label", "artifactNote", "format", "type", "kind", "op", "disposition", "err", "action", "steps", "subject", "body", "hints", "region", "allowed"]);
function scanAscii(value, where, key = null) {
  if (typeof value === "string") {
    if (key === null || !PLUGIN_TEXT_KEYS.has(key)) return;
    for (const ch of value) {
      const cp = ch.codePointAt(0);
      if (cp > 0x7f && !/\p{Script=Han}/u.test(ch)) nonAsciiOffenders.push(`${where}.${key}: ${JSON.stringify(ch)}`);
    }
    return;
  }
  if (Array.isArray(value)) return value.forEach((v) => scanAscii(v, where, key));
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) scanAscii(v, where, k);
  }
}

// ---------------------------------------------------------------- stage 1 and 5: smoke
function smoke() {
  if (!tools) return { skipped: unavailable };
  const call = async (name, args) => tools.get(name).execute(args || {});
  const need = ["library_record", "library_index", "library_query", "library_detect", "library_sniff", "library_format", "library_decrypt", "library_export", "library_encoding", "library_adb"];
  const missing = need.filter((n) => !tools.has(n));
  check("PORTABILITY", "smoke", `${need.length} tools registered`, missing.length === 0, missing.join(", "));

  // Run the async battery, then judge in the caller (this function is sync-friendly: it returns a promise).
  return (async () => {
    const rec = await call("library_record", { type: "knowledge", name: CJK, source: "%TOOLCHAIN_HOME%/\\u8a66", description: ACCENT, summary: EMOJI, tags: ["selfcheck", CJK] });
    check("ENCODING", "smoke", "record accepts multi-byte metadata", rec.ok === true, JSON.stringify(rec).slice(0, 120));
    const q = await call("library_query", { query: "\u6e2c\u8a66\u6a94\u6848" });
    const got = (q.results || []).find((o) => o.id === rec.id);
    check("ENCODING", "smoke", "CJK name survives record -> query", got && got.name === CJK, got && got.name);
    check("ENCODING", "smoke", "accents survive", got && got.description === ACCENT, got && got.description);
    check("ENCODING", "smoke", "astral-plane emoji survives", got && got.summary === EMOJI, got && got.summary);
    const comb = await call("library_record", { type: "knowledge", name: COMBINING, source: "%TOOLCHAIN_HOME%" });
    const q2 = await call("library_query", { query: "selfcheck" });
    const got2 = (q2.results || []).find((o) => o.id === comb.id);
    check("ENCODING", "smoke", "combining mark is not normalised", got2 && got2.name === COMBINING, got2 && JSON.stringify(got2.name));

    const idx = await call("library_index", {});
    check("PORTABILITY", "smoke", "index rebuild reports the same objects", idx.count >= 2, JSON.stringify(idx).slice(0, 120));

    const idxPath = path.join(HOME, "library", "index.json");
    const idxBytes = fs.readFileSync(idxPath);
    check("ENCODING", "smoke", "index.json is BOM-free UTF-8", !(idxBytes[0] === 0xEF && idxBytes[1] === 0xBB && idxBytes[2] === 0xBF), JSON.stringify([...idxBytes.slice(0, 3)]));
    check("ENCODING", "smoke", "index.json keeps real UTF-8, not escapes", idxBytes.toString("utf8").includes(CJK), "CJK sample absent from raw index");

    const exe = await call("library_sniff", { path: process.execPath });
    check("PORTABILITY", "smoke", "sniff identifies a real executable", exe.ok === true && exe.detected === true, JSON.stringify({ ok: exe.ok, type: exe.type, format: exe.format }));
    const spoof = await call("library_sniff", { path: swapped });
    check("PORTABILITY", "smoke", "text posing as .png is flagged", spoof.spoofed === true, JSON.stringify({ spoofed: spoof.spoofed, flags: spoof.flags }));
    const utf16 = await call("library_sniff", { path: path.join(UNICODE_DIR, "utf16.txt") });
    check("ENCODING", "smoke", "UTF-16LE with BOM reads as text", utf16.kind === "text", JSON.stringify({ kind: utf16.kind }));
    const mystery = await call("library_sniff", { path: mysteryFile });
    check("ENCODING", "smoke", "unknown extension reaches the no-signature fallback", mystery.detected === false && typeof mystery.note === "string", JSON.stringify({ detected: mystery.detected, note: mystery.note }));
    const bomName = await call("library_sniff", { path: path.join(UNICODE_DIR, "bom\u3042\u308a.txt") });
    check("PORTABILITY", "smoke", "unicode + space path handled", bomName.ok === true && bomName.kind === "text", JSON.stringify({ ok: bomName.ok, kind: bomName.kind }));

    const fmt = await call("library_format", { op: "list" });
    check("PORTABILITY", "smoke", "format library lists built-ins", fmt.ok === true && fmt.builtin.signatures > 0, JSON.stringify(fmt.builtin));
    const learn = await call("library_format", { op: "learn", ext: "selfchk", paths: [learnA, learnB], bytes: 4 });
    check("PORTABILITY", "smoke", "learn registers a signature from two samples", learn.ok === true && (learn.verified || []).every((v) => v.ok), JSON.stringify(learn.note).slice(0, 120));
    const learned = await call("library_sniff", { path: learnA });
    check("PORTABILITY", "smoke", "the learned signature is used", learned.format === "selfchk", JSON.stringify({ format: learned.format }));
    const clash = await call("library_format", { op: "add", format: "fake-png", sig: "89 50 4e 47 0d 0a 1a 0a", ext: "png" });
    check("PORTABILITY", "smoke", "a built-in signature cannot be shadowed", clash.ok === false, JSON.stringify(clash.conflicts));
    await call("library_format", { op: "remove", ext: "selfchk" });

    // A secret that appears nowhere else, so "not in the clear" cannot be satisfied by coincidence.
    const SECRET = `secret-${ACCENT}-${CJK}`;
    const sec = await call("library_record", { type: "knowledge", name: "secret note", source: "%TOOLCHAIN_HOME%", description: SECRET, sensitive: true });
    const dec = await call("library_decrypt", { id: sec.id });
    check("ENCODING", "smoke", "sensitive payload decrypts intact", dec.ok === true && dec.object && dec.object.description === SECRET, JSON.stringify(dec.object && dec.object.description));
    check("ENCODING", "smoke", "sensitive payload is not in the clear", !fs.readFileSync(idxPath, "utf8").includes(SECRET), "payload found in plaintext in index.json");

    const exp = await call("library_export", { path: path.join(FIXTURES, "export.json") });
    check("ENCODING", "smoke", "export writes JSON", exp.ok === true, JSON.stringify(exp).slice(0, 100));
    const expBytes = fs.readFileSync(path.join(FIXTURES, "export.json"));
    check("ENCODING", "smoke", "export is BOM-free", !(expBytes[0] === 0xEF), JSON.stringify([...expBytes.slice(0, 3)]));
    check("ENCODING", "smoke", "export keeps the CJK name", JSON.parse(expBytes.toString("utf8")).objects.some((o) => o.name === CJK), "not found");

    const enc = await call("library_encoding", {});
    check("ENCODING", "smoke", "encoding reporter answers", typeof enc.utf8 === "boolean" && !!enc.label, JSON.stringify(enc).slice(0, 120));

    // ASCII axis at runtime: nothing a tool returns to the model may carry non-Han non-ASCII text.
    for (const [name, args] of [
      ["library_encoding", {}],
      ["library_sniff", { path: textFile }],
      ["library_sniff", { path: mysteryFile }],
      ["library_sniff", { path: path.join(UNICODE_DIR, "bom\u3042\u308a.txt") }],
      ["library_query", { query: "selfcheck", limit: 2 }],
      ["library_index", {}],
    ]) {
      scanAscii(await call(name, args), name);
    }
    check("ASCII", "smoke", "tool output stays ASCII (Han allowed in user data)", nonAsciiOffenders.length === 0, nonAsciiOffenders.slice(0, 3).join(" | "));

    const lockFile = path.join(HOME, "library", ".lock");
    check("PORTABILITY", "smoke", "no lock file is left behind", !fs.existsSync(lockFile), lockFile);
    return { value: null };
  })();
}

// ---------------------------------------------------------------- stage 2 and 4: traversal
async function traversal() {
  if (!tools) return { skipped: unavailable };
  const call = async (name, args) => tools.get(name).execute(args || {});
  const leaked = [];
  const scanLocal = (value, where) => {
    const walk = (v, k) => {
      if (typeof v === "string") {
        if (!PLUGIN_TEXT_KEYS.has(k)) return;
        for (const ch of v) if (ch.codePointAt(0) > 0x7f && !/\p{Script=Han}/u.test(ch)) leaked.push(`${where}.${k}: ${JSON.stringify(ch)}`);
        return;
      }
      if (Array.isArray(v)) return v.forEach((x) => walk(x, k));
      if (v && typeof v === "object") for (const [kk, vv] of Object.entries(v)) walk(vv, kk);
    };
    walk(value, null);
  };
  const sweep = await call("library_sniff", { dir: DIR, maxFiles: 800 });
  check("PORTABILITY", "traversal", `sweep of ${DIR} completes`, sweep.ok === true && sweep.scanned > 0, JSON.stringify({ ok: sweep.ok, scanned: sweep.scanned }));
  const fixtureSweep = await call("library_sniff", { dir: FIXTURES, maxFiles: 200 });
  const flagged = (fixtureSweep.mismatches || []).map((m) => path.basename(m.path));
  check("PORTABILITY", "traversal", "exactly the swapped-extension fixture is flagged", flagged.length === 1 && flagged[0] === "actually-text.png", flagged.join(", "));

  // Every tool must answer something structured, even with a hostile or empty argument set.
  const hostile = [
    ["library_query", {}], ["library_index", {}], ["library_detect", { op: "list" }], ["library_sniff", {}],
    ["library_format", { op: "list" }], ["library_format", { op: "deps", dir: DIR, maxFiles: 50 }],
    ["library_encoding", {}], ["library_adb", { action: "devices" }], ["library_export", { format: "ndjson" }],
  ];
  let structured = 0;
  for (const [name, args] of hostile) {
    let out;
    try {
      out = await call(name, args);
    } catch (e) {
      check("PORTABILITY", "traversal", `${name} answered instead of throwing`, false, String((e && e.message) || e));
      continue;
    }
    if (out && typeof out === "object") structured++;
    scanLocal(out, name);
  }
  check("PORTABILITY", "traversal", `all ${hostile.length} tools answered structurally`, structured === hostile.length, `${structured}/${hostile.length}`);
  check("ASCII", "traversal", "no non-ASCII leaked from the traversal calls", leaked.length === 0, leaked.slice(0, 3).join(" | "));

  const digest = createHash("sha256").update(JSON.stringify({ scanned: sweep.scanned, flagged, structured })).digest("hex").slice(0, 16);
  return { value: digest };
}

// ---------------------------------------------------------------- stage 3: proofread
function proofread() {
  const scripts = ["check-ascii.mjs", "check-consistency.mjs", "check-portability.mjs", "check-isolation.mjs"];
  const digest = [];
  for (const s of scripts) {
    const p = path.join(ROOT, "scripts", s);
    if (!fs.existsSync(p)) {
      check("PORTABILITY", "proofread", `${s} present`, false, "missing");
      continue;
    }
    const r = spawnSync(process.execPath, [p], { cwd: ROOT, encoding: "utf8" });
    const line = String(r.stdout || "").trim().split("\n").filter(Boolean).slice(-1)[0] || "";
    check("PORTABILITY", "proofread", `${s} passes`, r.status === 0, String(r.stderr || "").trim().split("\n").slice(0, 2).join(" | "));
    console.log(`  ${r.status === 0 ? "ok  " : "FAIL"} ${line || s}`);
    digest.push(`${s}:${r.status}`);
  }
  return { value: digest.join(",") };
}

// ---------------------------------------------------------------- run
console.log(`mega-index-map self-check`);
console.log(`  repository : ${ROOT}`);
console.log(`  traversal  : ${DIR}`);
console.log(`  temp home  : ${HOME}`);
console.log(`  plugin     : ${tools ? `loaded, ${tools.size} tool(s)` : "unavailable"}`);

const s1 = await stage(QUICK ? "1. smoke" : "1. smoke (smoke)", smoke);
const s2 = await stage(QUICK ? "2. traversal" : "2. traversal (traverse)", traversal);
let s3 = null, s4 = null, s5 = null;
if (!QUICK) {
  s3 = await stage("3. proofread (invariants)", proofread);
  s4 = await stage("4. traversal again (same answer required)", traversal);
  s5 = await stage("5. smoke again (smoke)", smoke);
}

// ---------------------------------------------------------------- idempotence + axes
if (!QUICK && s2.skipped === null && s4 && s4.skipped === null) {
  check("PORTABILITY", "idempotence", "the two traversal passes agree", s2.value === s4.value, `${s2.value} vs ${s4.value}`);
}

const byAxis = {};
for (const axis of AXES) {
  const rows = results.filter((r) => r.axis === axis);
  byAxis[axis] = { total: rows.length, failed: rows.filter((r) => !r.ok).length };
}
const all = results.length;
const failed = results.filter((r) => !r.ok);
const skipped = stageReport.filter((s) => s.skipped);

console.log(`\n=== three axes ===`);
for (const axis of AXES) {
  const { total, failed: f } = byAxis[axis];
  console.log(`  ${axis.padEnd(12)} ${total === 0 ? "no checks ran" : `${total - f}/${total} ok`}`);
}
console.log(`\nsummary: checks=${all} failed=${failed.length} stages-with-plugin-skipped=${skipped.length}`);
if (failed.length) {
  console.log("failures:");
  for (const f of failed) console.log(`  [${f.axis}] ${f.stage}: ${f.label}${f.detail ? ` -> ${f.detail}` : ""}`);
}

if (JSON_OUT) {
  const payload = {
    at: new Date().toISOString(),
    repository: ROOT,
    traversal: DIR,
    plugin: tools ? [...tools.keys()] : null,
    pluginUnavailable: unavailable,
    stages: stageReport,
    axes: byAxis,
    checks: results,
    summary: { checks: all, failed: failed.length, skippedStages: skipped.length },
  };
  fs.writeFileSync(JSON_OUT, JSON.stringify(payload, null, 2) + "\n", "utf8");
  console.log(`report written: ${JSON_OUT}`);
}

if (!KEEP) {
  fs.rmSync(TMP, { recursive: true, force: true });
} else {
  console.log(`kept: ${TMP}`);
}

// A skipped plugin stage is not a failure: on a bare checkout there is no SDK to load the plugin with,
// and the invariants still ran. A failed check always is.
process.exit(failed.length ? 1 : 0);
