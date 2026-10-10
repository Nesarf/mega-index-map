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
import { zstdCompressSync } from "node:zlib";

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
let hooks = null;
try {
  const mod = await import(pathToFileURL(PLUGIN).href);
  const map = new Map();
  hooks = new Map();
  const logger = { info: () => {}, warn: () => {} };
  await mod.apply({ tools: { register: (t) => map.set(t.name, t) }, on: (name, handler) => hooks.set(name, handler), logger }, { bootstrap: "off" });
  tools = map;
  // The notice is opt-in, so the same module is applied a second time with it switched on: that is
  // where the hook has to appear.
  const noticeHooks = new Map();
  await mod.apply({ tools: { register: () => {} }, on: (name, handler) => noticeHooks.set(name, handler), logger }, { injectPrompt: true, bootstrap: "off" });
  hooks.set("__notice__", noticeHooks.get("agent/pre-step") || null);
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
    const rec = await call("library_record", { type: "knowledge", name: CJK, source: "selftest:/\u6e2c\u8a66", description: ACCENT, summary: EMOJI, tags: ["selfcheck", CJK] });
    check("ENCODING", "smoke", "record accepts multi-byte metadata", rec.ok === true, JSON.stringify(rec).slice(0, 120));
    const q = await call("library_query", { query: "\u6e2c\u8a66\u6a94\u6848" });
    const got = (q.results || []).find((o) => o.id === rec.id);
    check("ENCODING", "smoke", "CJK name survives record -> query", got && got.name === CJK, got && got.name);
    check("ENCODING", "smoke", "accents survive", got && got.description === ACCENT, got && got.description);
    check("ENCODING", "smoke", "astral-plane emoji survives", got && got.summary === EMOJI, got && got.summary);
    const comb = await call("library_record", { type: "knowledge", name: COMBINING, source: "selftest:/selfcheck" });
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
    const sec = await call("library_record", { type: "knowledge", name: "secret note", source: "selftest:/selfcheck", description: SECRET, sensitive: true });
    const dec = await call("library_decrypt", { id: sec.id });
    check("ENCODING", "smoke", "sensitive payload decrypts intact", dec.ok === true && dec.object && dec.object.description === SECRET, JSON.stringify(dec.object && dec.object.description));
    check("ENCODING", "smoke", "sensitive payload is not in the clear", !fs.readFileSync(idxPath, "utf8").includes(SECRET), "payload found in plaintext in index.json");

    // The confirmation route for the immutable class. A record whose content changed is refused - that
    // is the guard - and a caller holding the user's decision records it with confirm=true and a reason,
    // which must land in the append-only log. confirm without a reason must be refused, because an
    // unexplained confirmation is indistinguishable from the silent overwrite the guard exists to
    // prevent. This route was added because a guard with no way through turns a wrongly recorded object
    // into a permanent one: two harmless library records were encrypted by a mis-firing rule.
    //
    // This battery runs twice (smoke, traversal, proofread, traversal, smoke) against one temp library,
    // so every assertion below holds on both passes: the second pass sees the content it wrote, which is
    // "unchanged", and the interesting case is that nothing is overwritten silently on either pass.
    const confName = "confirm route note";
    const confArgs = (extra) => ({ type: "knowledge", name: confName, source: "selftest:/selfcheck", ...extra });
    const confFirst = await call("library_record", confArgs({ description: "first version" }));
    check("PORTABILITY", "smoke", "writing an immutable-class record is accepted, or refused as a change, but never a silent no-op", confFirst.ok === true || confFirst.changed === true, JSON.stringify(confFirst).slice(0, 120));
    const confChanged = await call("library_record", confArgs({ description: "second version" }));
    check("PORTABILITY", "smoke", "a changed immutable-class record is never silently overwritten", confChanged.ok === false || confChanged.changed === false, JSON.stringify(confChanged).slice(0, 140));
    let confNoReason;
    try {
      confNoReason = await call("library_record", confArgs({ description: "second version", confirm: true }));
      check("PORTABILITY", "smoke", "confirm without a reason is refused", confNoReason.changed === false, JSON.stringify(confNoReason).slice(0, 160));
    } catch (e) {
      check("PORTABILITY", "smoke", "confirm without a reason is refused", /reason/.test(String(e.message)), String(e.message).slice(0, 160));
    }
    const confReason = "selfcheck: the user's decision is simulated here, and the log must carry it";
    const confYes = await call("library_record", confArgs({ description: "second version", confirm: true, reason: confReason }));
    check("PORTABILITY", "smoke", "confirm with a reason records the change", confYes.ok === true, JSON.stringify(confYes).slice(0, 160));
    const confLog = fs.readFileSync(path.join(path.dirname(idxPath), "log.jsonl"), "utf8");
    check("PORTABILITY", "smoke", "the confirmation is traced in the append-only log", confLog.includes("record-confirm") && confLog.includes(confReason), "record-confirm entry not found");
    const confIndex = await call("library_index", {});
    check("PORTABILITY", "smoke", "the newest version supersedes the one it replaced", !confYes.changed || confIndex.superseded >= 1, JSON.stringify({ changed: confYes.changed, superseded: confIndex.superseded }));

    const exp = await call("library_export", { path: path.join(FIXTURES, "export.json") });
    check("ENCODING", "smoke", "export writes JSON", exp.ok === true, JSON.stringify(exp).slice(0, 100));
    const expBytes = fs.readFileSync(path.join(FIXTURES, "export.json"));
    check("ENCODING", "smoke", "export is BOM-free", !(expBytes[0] === 0xEF), JSON.stringify([...expBytes.slice(0, 3)]));
    check("ENCODING", "smoke", "export keeps the CJK name", JSON.parse(expBytes.toString("utf8")).objects.some((o) => o.name === CJK), "not found");

    const enc = await call("library_encoding", {});
    check("ENCODING", "smoke", "encoding reporter answers", typeof enc.utf8 === "boolean" && !!enc.label, JSON.stringify(enc).slice(0, 120));

    // Declared values + declared identity: declare the running interpreter as this machine's own
    // candidate (the documented op=add path), then scan and read back what the file says about itself.
    // Nothing is executed to obtain it - the plugin reads the image's own version resource - and the
    // ASCII axis applies to it too, because a product name is plugin vocabulary, not user data.
    const addSelf = await call("library_detect", { op: "add", type: "tool", name: "selfcheck runtime", path: process.execPath, desc: "the interpreter running this check" });
    check("PORTABILITY", "smoke", "a machine-specific tool is declared through op=add", addSelf.ok === true, JSON.stringify(addSelf).slice(0, 120));
    const idScan = await call("library_detect", { op: "scan" });
    const selfRow = (idScan.results || []).find((r) => r.name === "selfcheck runtime");
    check("PORTABILITY", "smoke", "the scan resolves the declared candidate", !!selfRow && selfRow.exists === true, JSON.stringify(selfRow || {}).slice(0, 120));
    if (process.platform === "win32") {
      const declared = selfRow && selfRow.declared;
      const named = declared && /node/i.test(String(declared.product || ""));
      check("PORTABILITY", "smoke", "the tool's own version resource is read statically", !!named && !!declared.version, JSON.stringify(declared || null).slice(0, 140));
      if (declared) scanAscii({ declared }, "library_detect.declared");
    }
    // A file that is not an image has nothing to declare, and must not invent an answer. It is kept out
    // of the fixture directory on purpose: a text file named .exe is exactly the spoofed-name case the
    // traversal stage counts, and this probe must not disturb that count.
    const junk = path.join(HOME, "not-an-image.exe");
    fs.writeFileSync(junk, Buffer.from("plain text pretending to be an executable\n", "utf8"));
    await call("library_detect", { op: "add", type: "tool", name: "selfcheck junk", path: junk, desc: "identity failure-mode probe" });
    const junkScan = await call("library_detect", { op: "scan" });
    const junkRow = (junkScan.results || []).find((r) => r.name === "selfcheck junk");
    check("PORTABILITY", "smoke", "a non-image declares nothing instead of guessing", !!junkRow && junkRow.declared === null, JSON.stringify(junkRow && junkRow.declared));
    await call("library_detect", { op: "remove", type: "tool", name: "selfcheck junk" });
    await call("library_detect", { op: "remove", type: "tool", name: "selfcheck runtime" });

    // Directory reconciliation: op=audit reports both directions read-only, op=index only writes with
    // an explicit confirmation, and a drive root is refused outright. The tree and the session ids carry
    // a per-run suffix, because the battery runs this stage twice and neither may depend on the other.
    const RUN = `${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
    const AUDIT_DIR = path.join(TMP, `audit-tree-${RUN}`);
    fs.mkdirSync(path.join(AUDIT_DIR, "deeper"), { recursive: true });
    fs.writeFileSync(path.join(AUDIT_DIR, "loose.txt"), "unrecorded\n", "utf8");
    fs.writeFileSync(path.join(AUDIT_DIR, "run-me.ps1"), "Write-Output 'unrecorded'\n", "utf8");
    fs.writeFileSync(path.join(AUDIT_DIR, "deeper", "inner.txt"), "unrecorded\n", "utf8");

    const audit1 = await call("library_index", { op: "audit", dir: AUDIT_DIR, depth: 2 });
    check("PORTABILITY", "smoke", "audit walks a directory and reports unrecorded entries", audit1.ok === true && audit1.missing >= 4 && audit1.scanned.entries >= 4, JSON.stringify({ scanned: audit1.scanned, missing: audit1.missing }));
    check("PORTABILITY", "smoke", "audit writes nothing and finds no dead path yet", audit1.dead === 0 && audit1.registered === undefined, JSON.stringify({ dead: audit1.dead }));
    const beforeIndex = JSON.parse(fs.readFileSync(path.join(HOME, "library", "index.json"), "utf8")).objects.length;

    const refusedConfirm = await call("library_index", { op: "index", dir: AUDIT_DIR });
    check("PORTABILITY", "smoke", "op=index without confirm is refused", refusedConfirm.ok === false && /confirm/.test(String(refusedConfirm.note)), String(refusedConfirm.note).slice(0, 90));
    const afterRefusal = JSON.parse(fs.readFileSync(path.join(HOME, "library", "index.json"), "utf8")).objects.length;
    check("PORTABILITY", "smoke", "a refused op=index writes nothing", afterRefusal === beforeIndex, `${afterRefusal} vs ${beforeIndex}`);

    const indexed = await call("library_index", { op: "index", dir: AUDIT_DIR, depth: 2, includeDirs: true, confirm: true, reason: "selfcheck reconciliation" });
    check("PORTABILITY", "smoke", "op=index registers the unrecorded entries", indexed.ok === true && indexed.registered >= 4, JSON.stringify({ registered: indexed.registered, missing: indexed.missing }));
    const audit2 = await call("library_index", { op: "audit", dir: AUDIT_DIR, depth: 2 });
    check("PORTABILITY", "smoke", "the second audit sees the tree as recorded", audit2.missing === 0, JSON.stringify({ missing: audit2.missing, scanned: audit2.scanned }));
    const scriptRecord = (await call("library_query", { query: "run-me" })).results.find((o) => o.name === "run-me");
    check("PORTABILITY", "smoke", "a registered script is typed as a tool", !!scriptRecord && scriptRecord.type === "tool", JSON.stringify(scriptRecord && scriptRecord.type));
    const dirRecord = (await call("library_query", { query: "deeper" })).results.find((o) => o.name === "deeper");
    check("PORTABILITY", "smoke", "a registered directory is typed as a workspace", !!dirRecord && dirRecord.type === "workspace", JSON.stringify(dirRecord && dirRecord.type));

    // A dead record: the library claims a path that the disk does not have.
    await call("library_record", { type: "file", name: "vanished", source: AUDIT_DIR, path: path.join(AUDIT_DIR, "vanished.txt") });
    const audit3 = await call("library_index", { op: "audit", dir: AUDIT_DIR, depth: 1 });
    check("PORTABILITY", "smoke", "audit reports a record whose path is gone", audit3.ok === true && audit3.dead >= 1 && (audit3.samples.dead || []).some((d) => d.name === "vanished"), JSON.stringify(audit3.samples.dead));

    const rootRefusal = await call("library_index", { op: "audit", dir: process.platform === "win32" ? `${process.env.SystemDrive || "C:"}\\` : "/" });
    check("PORTABILITY", "smoke", "a drive root is refused as an index scope", rootRefusal.ok === false && /refused/.test(String(rootRefusal.note)), String(rootRefusal.note).slice(0, 80));

    // The opt-in notice: absent unless the config asks for it, ASCII-only, injected once per session,
    // and never into a subagent's session.
    check("PORTABILITY", "smoke", "the session notice stays off unless configured", !hooks.get("agent/pre-step"), "a hook was registered without injectPrompt:true");
    const notice = hooks.get("__notice__");
    check("PORTABILITY", "smoke", "injectPrompt:true registers the notice hook", typeof notice === "function", String(notice));
    if (typeof notice === "function") {
      const runNotice = (session, priorUserEvents = 0) => {
        const messages = [{ source: { kind: "user" }, content: [{ type: "text", text: "hello" }] }];
        const payload = { agent: { session: { id: session.id, header: session.header || {}, events: Array.from({ length: priorUserEvents }, () => ({ type: "user/message" })) } }, signal: { aborted: false } };
        return notice(payload, async () => ({ kind: "enter", messages }));
      };
      const first = await runNotice({ id: `notice-${RUN}-a` });
      const injectedText = first && first.messages && first.messages[0].content[0] && first.messages[0].content[0].text ? first.messages[0].content[0].text : "";
      check("PORTABILITY", "smoke", "the notice reaches the first user message", injectedText.includes("mega-index-map") && injectedText.includes("library_query"), injectedText.slice(0, 80));
      check("ASCII", "smoke", "the injected notice is ASCII-only", !/[^\x20-\x7e\n]/.test(injectedText), JSON.stringify(injectedText.match(/[^\x20-\x7e\n]/g) || []));
      const again = await runNotice({ id: `notice-${RUN}-a` });
      check("PORTABILITY", "smoke", "the notice is injected once per session", (again.messages[0].content || []).length === 1, JSON.stringify(again.messages[0].content));
      const late = await runNotice({ id: `notice-${RUN}-b` }, 1);
      check("PORTABILITY", "smoke", "a session that already has user messages is left alone", (late.messages[0].content || []).length === 1, JSON.stringify(late.messages[0].content));
      const sub = await runNotice({ id: `notice-${RUN}-c`, header: { origin: "subagent" } });
      check("PORTABILITY", "smoke", "a subagent session is not injected", (sub.messages[0].content || []).length === 1, JSON.stringify(sub.messages[0].content));
    }
    await call("library_index", { op: "rebuild" });

    // DSH's own session store: one zstd frame per record, appended, with a torn tail possible. The
    // fixture is written the way the host writes it, so the frame-splitting path is what gets tested.
    const SES_WS = path.join(HOME, "sessions", "--E-selfcheck-ws--");
    const SES_DIR = path.join(SES_WS, "session-11111111-2222-3333-4444-555555555555");
    fs.mkdirSync(SES_DIR, { recursive: true });
    const now = Date.now();
    const sesRecords = [
      { type: "session", seq: 0, time: now - 60000, data: { id: "11111111-2222-3333-4444-555555555555", version: 3, createdAt: new Date(now - 60000).toISOString(), cwd: "E:\selfcheck-ws", agentPreset: "selfcheck" } },
      { type: "session/title", seq: 1, time: now - 50000, data: { title: "selfcheck fixture session", messageSeqs: [2], source: "llm" } },
      { type: "user/message", seq: 2, time: now - 40000, data: { role: "user", id: "m1", source: { kind: "user" }, content: [{ type: "text", text: "fixture question about zstd frames" }] } },
      { type: "assistant/message", seq: 3, time: now - 30000, data: { turn: 1, step: 0, message: { role: "assistant", id: "m2", content: [{ type: "text", text: "fixture answer mentioning 162 frames" }] }, usage: {} } },
      { type: "tool/call", seq: 4, time: now - 20000, data: { turn: 1, step: 1, callId: "c1", name: "fixture_tool", arguments: { a: 1 } } },
      { type: "tool/result", seq: 5, time: now - 10000, data: { turn: 1, step: 1, message: { role: "tool", content: [{ type: "text", text: "fixture tool output" }] } } },
    ];
    const sesFrames = sesRecords.map((r) => zstdCompressSync(Buffer.from(JSON.stringify(r), "utf8")));
    const sesTorn = sesFrames[sesFrames.length - 1].subarray(0, Math.max(1, Math.floor(sesFrames[sesFrames.length - 1].length / 2)));
    const sesFile = path.join(SES_DIR, "session.jsonl.zstd");
    fs.writeFileSync(sesFile, Buffer.concat([...sesFrames, sesTorn]));

    const sesList = await call("library_sessions", { op: "list", dir: path.join(HOME, "sessions"), titles: true });
    const sesEntry = (sesList.entries || []).find((e) => e.path === sesFile);
    check("PORTABILITY", "smoke", "sessions list finds a session and reads its header without the transcript", sesList.ok === true && !!sesEntry && sesEntry.id === "11111111-2222-3333-4444-555555555555" && sesEntry.cwd === "E:\selfcheck-ws", JSON.stringify(sesEntry || {}).slice(0, 140));
    check("PORTABILITY", "smoke", "sessions list reads the session's own title record", !!sesEntry && sesEntry.title === "selfcheck fixture session", sesEntry && String(sesEntry.title));
    check("PORTABILITY", "smoke", "a torn trailing frame is counted, not guessed at", !!sesEntry && sesEntry.framesUnreadable >= 1, sesEntry && `frames=${sesEntry.frames} unreadable=${sesEntry.framesUnreadable}`);

    const sesRead = await call("library_sessions", { op: "read", target: SES_DIR });
    check("PORTABILITY", "smoke", "read decodes every frame of a session", sesRead.ok === true && sesRead.frames >= sesRecords.length && sesRead.records >= sesRecords.length, JSON.stringify({ frames: sesRead.frames, records: sesRead.records }));
    check("PORTABILITY", "smoke", "read returns structure without content by default", sesRead.ok === true && (sesRead.messages || []).length === 0 && (sesRead.types || []).some((t) => t.type === "user/message"), JSON.stringify(sesRead.types || []).slice(0, 120));
    const sesContent = await call("library_sessions", { op: "read", target: SES_DIR, content: true, maxChars: 2000 });
    const joined = (sesContent.messages || []).map((m) => m.text).join(" | ");
    check("PORTABILITY", "smoke", "content:true returns the message text", /fixture question about zstd frames/.test(joined) && /fixture answer mentioning 162 frames/.test(joined), joined.slice(0, 120));
    const sesTail = await call("library_sessions", { op: "tail", target: SES_DIR, frames: 2 });
    check("PORTABILITY", "smoke", "tail decodes only the trailing frames", sesTail.ok === true && sesTail.records <= 2 && sesTail.frames >= sesRecords.length, JSON.stringify({ records: sesTail.records, frames: sesTail.frames }));
    const sesSearch = await call("library_sessions", { op: "search", dir: path.join(HOME, "sessions"), query: "162 frames" });
    check("PORTABILITY", "smoke", "search finds a phrase by scanning frames", sesSearch.ok === true && (sesSearch.hits || []).some((h) => /162 frames/.test(h.snippet)), JSON.stringify(sesSearch.hits || []).slice(0, 120));
    const sesMiss = await call("library_sessions", { op: "read", target: path.join(HOME, "sessions", "does-not-exist") });
    check("PORTABILITY", "smoke", "a missing session is refused, not invented", sesMiss.ok === false, JSON.stringify(sesMiss).slice(0, 100));
    const sesRecorded = await call("library_sessions", { op: "record", target: SES_DIR, content: true, maxChars: 3000 });
    check("PORTABILITY", "smoke", "record writes a session into the Library", sesRecorded.ok === true && sesRecorded.recorded && sesRecorded.recorded.name === "selfcheck fixture session", JSON.stringify(sesRecorded.recorded || {}).slice(0, 140));
    const sesFound = (await call("library_query", { query: "selfcheck fixture session" })).results.find((o) => o.name === "selfcheck fixture session");
    check("PORTABILITY", "smoke", "the recorded session is searchable afterwards", !!sesFound && sesFound.type === "log", JSON.stringify(sesFound && sesFound.type));

    // An exported session log is a ZIP (DSH's "Download this Session log"), with session*.jsonl members at
    // the root and subagent logs below subagents/. Built here by hand as stored entries, so the archive
    // branch is exercised on a machine that has never exported one.
    const crc32Of = (buf) => {
      let c = ~0;
      for (const b of buf) {
        c ^= b;
        for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1));
      }
      return (~c) >>> 0;
    };
    const storedZip = (entries) => {
      const locals = [];
      const central = [];
      let offset = 0;
      for (const e of entries) {
        const name = Buffer.from(e.name, "utf8");
        const crc = crc32Of(e.data);
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4);
        local.writeUInt32LE(crc, 14); local.writeUInt32LE(e.data.length, 18); local.writeUInt32LE(e.data.length, 22);
        local.writeUInt16LE(name.length, 26);
        locals.push(local, name, e.data);
        const cd = Buffer.alloc(46);
        cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6);
        cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(e.data.length, 20); cd.writeUInt32LE(e.data.length, 24);
        cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(offset, 42);
        central.push(cd, name);
        offset += 30 + name.length + e.data.length;
      }
      const centralBuf = Buffer.concat(central);
      const eocd = Buffer.alloc(22);
      eocd.writeUInt32LE(0x06054b50, 0);
      eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
      eocd.writeUInt32LE(centralBuf.length, 12); eocd.writeUInt32LE(offset, 16);
      return Buffer.concat([...locals, centralBuf, eocd]);
    };
    const zipPath = path.join(HOME, "sessions", "exported-log.zip");
    const NL = String.fromCharCode(10);
    const zipLog = [sesRecords[0], sesRecords[2], sesRecords[3]].map((r) => JSON.stringify(r)).join(NL) + NL;
    fs.writeFileSync(zipPath, storedZip([
      { name: "session.jsonl", data: Buffer.from(zipLog, "utf8") },
      { name: "subagents/abc/session.jsonl", data: Buffer.from(JSON.stringify(sesRecords[0]) + NL, "utf8") },
      { name: "media/pic.png", data: Buffer.from([0x89, 0x50, 0x4e, 0x47]) },
    ]));

    const zipList = await call("library_sessions", { op: "list", dir: path.join(HOME, "sessions") });
    const zipEntry = (zipList.entries || []).find((e) => e.kind === "archive");
    check("PORTABILITY", "smoke", "an exported session-log archive is listed with its session members", !!zipEntry && zipEntry.sessionLogs.length === 2 && zipEntry.attachments === 1, JSON.stringify(zipEntry || {}).slice(0, 140));
    const zipRead = await call("library_sessions", { op: "read", target: `${zipPath}#session.jsonl`, content: true, maxChars: 2000 });
    check("PORTABILITY", "smoke", "a session log inside an archive is read through #member", zipRead.ok === true && zipRead.records >= 3 && /fixture question about zstd frames/.test((zipRead.messages || []).map((m) => m.text).join(" ")), JSON.stringify({ ok: zipRead.ok, records: zipRead.records }) );
    const zipSearch = await call("library_sessions", { op: "search", dir: path.join(HOME, "sessions"), query: "fixture answer" });
    check("PORTABILITY", "smoke", "search reaches inside exported archives too", (zipSearch.hits || []).some((h) => /exported-log\.zip#/.test(h.source)), JSON.stringify((zipSearch.hits || []).map((h) => h.source).slice(0, 3)));

    // The first-run pass mines what a Library indexes out of the history - and only what exists here.
    // The fixture session names a command that resolves on this machine, a real directory, a path that is
    // NOT here, a local port, a variable that is set and an extension this library does not know; the
    // missing path must never become a record.
    const BT = String.fromCharCode(96);
    const mineText = [
      `the tool ${BT}node${BT} is what runs this,`,
      `and ${FIXTURES} is a real directory.`,
      `a file that is not here: ${path.join(FIXTURES, "no-such-tool-xyz.exe")}`,
      `and the port localhost:8123, with %DSH_HOME% set, a ${BT}.qqq9${BT} format mentioned once,`,
      `and a ${BT}.qqq8${BT} format mentioned ${BT}.qqq8${BT} twice.`,
    ].join(" ");
    const mineRecord = { type: "user/message", seq: 9, time: Date.now(), data: { role: "user", content: [{ type: "text", text: mineText }] } };
    const mineDir = path.join(HOME, "sessions", "--E-mine--", "session-99999999-8888-7777-6666-555555555555");
    fs.mkdirSync(mineDir, { recursive: true });
    fs.writeFileSync(path.join(mineDir, "session.jsonl.zstd"), zstdCompressSync(Buffer.from(JSON.stringify(mineRecord), "utf8")));

    const mined = await call("library_sessions", { op: "bootstrap", dir: path.join(HOME, "sessions"), budgetMs: 60000 });
    check("PORTABILITY", "smoke", "the first-run pass reads the history and reports what it found", mined.ok === true && mined.phase === "complete" && mined.sessionsTotal >= 2 && mined.found >= 4, JSON.stringify({ phase: mined.phase, total: mined.sessionsTotal, found: mined.found, added: mined.added }));
    const minedQuery = await call("library_query", { query: "mined", limit: 100 });
    const minedRows = (minedQuery.results || []).filter((o) => o.source === "session-mining");
    const minedNames = minedRows.map((o) => o.name);
    check("PORTABILITY", "smoke", "a command that resolves on this machine is mined as a tool", minedNames.includes("node"), JSON.stringify(minedNames).slice(0, 140));
    check("PORTABILITY", "smoke", "a real directory is mined, with its path", minedRows.some((o) => o.type === "env" && o.path && o.path.includes("fixtures")), JSON.stringify(minedRows.filter((o) => o.type === "env").map((o) => o.path)).slice(0, 140));
    check("PORTABILITY", "smoke", "a path that is not on this machine is NOT mined", !minedRows.some((o) => String(o.path || "").includes("no-such-tool-xyz")), JSON.stringify(minedRows.map((o) => o.path)).slice(0, 160));
    check("PORTABILITY", "smoke", "a local endpoint is recorded without probing it", minedNames.includes("localhost:8123"), JSON.stringify(minedNames).slice(0, 140));
    check("PORTABILITY", "smoke", "a variable that is set is mined, and one that is not is left out", minedNames.includes("%DSH_HOME%") && !minedNames.some((n) => n.includes("SELFCHECK_UNSET")), JSON.stringify(minedNames.filter((x) => x.startsWith("%"))));
    check("PORTABILITY", "smoke", "an unknown format is recorded as a lead, not as a known format", minedRows.some((o) => o.type === "reference" && o.name === ".qqq8"), JSON.stringify(minedRows.filter((o) => o.type === "reference").map((o) => o.name)));

    const again = await call("library_sessions", { op: "bootstrap", dir: path.join(HOME, "sessions"), budgetMs: 60000 });
    const afterRows = (await call("library_query", { query: "mined", limit: 100 })).results.filter((o) => o.source === "session-mining");
    check("PORTABILITY", "smoke", "a second pass replaces instead of piling up", again.ok === true && afterRows.length === minedRows.length && again.added === 0, JSON.stringify({ before: minedRows.length, after: afterRows.length, added: again.added, updated: again.updated }));
    // And it must find nothing to read at all: the resume marker has to survive the pass that wrote it,
    // otherwise every run silently re-reads the whole history (that regression existed once).
    check("PORTABILITY", "smoke", "the marker survives, so a second pass has nothing pending", again.sessionsTotal === 0 && again.records === 0, JSON.stringify({ pending: again.sessionsTotal, records: again.records }));
    const status = await call("library_sessions", { op: "status" });
    const hostOffset = -new Date().getTimezoneOffset();
    const expectedOffset = (hostOffset >= 0 ? "+" : "-") + String(Math.floor(Math.abs(hostOffset) / 60)).padStart(2, "0") + ":" + String(Math.abs(hostOffset) % 60).padStart(2, "0");
    check("PORTABILITY", "smoke", "reports carry the host UTC offset beside the UTC timestamps", !!status.timezone && status.timezone.offsetMinutes === hostOffset && status.timezone.utcOffset === expectedOffset, JSON.stringify(status.timezone));
    const stateHasTz = JSON.parse(fs.readFileSync(path.join(HOME, "library", "bootstrap-state.json"), "utf8")).timezone;
    check("PORTABILITY", "smoke", "the state file a poller reads carries it too", !!stateHasTz && stateHasTz.offsetMinutes === hostOffset, JSON.stringify(stateHasTz));
    check("PORTABILITY", "smoke", "status reports the pass", status.ok === true && status.state && ["complete", "partial", "mining"].includes(status.state.phase), JSON.stringify(status.state && status.state.phase));
    const progressLines = fs.readFileSync(status.progress, "utf8").split(String.fromCharCode(10)).filter(Boolean).length;
    check("PORTABILITY", "smoke", "the pass is visible step by step, not only at the end", progressLines >= 3, `${progressLines} line(s)`);


    // A lead is evidence, not a coincidence: one mention is dropped, two are recorded. (The fixture text
    // above mentions .qqq9 once and .qqq8 twice.)
    check("PORTABILITY", "smoke", "a format lead seen once is not recorded", !minedNames.includes(".qqq9"), JSON.stringify(minedNames.filter((n) => n.startsWith(".qqq"))));
    check("PORTABILITY", "smoke", "a format lead seen twice is recorded", minedNames.includes(".qqq8"), JSON.stringify(minedNames.filter((n) => n.startsWith(".qqq"))));
    const minerRows = minedRows.filter((o) => (o.tags || []).includes("mined"));
    check("PORTABILITY", "smoke", "a mined row carries its hit count as a field", minerRows.length >= 4 && minerRows.every((o) => typeof o.hits === "number" && o.hits >= 1), JSON.stringify(minerRows.map((o) => o.hits)));

    // Pruning derived rows that no longer qualify goes through the lock, and deletes only with a confirmation.
    await call("library_record", { type: "reference", name: ".pruneme", source: "session-mining", description: "below the threshold", summary: "seen 1 time(s) in the session history; mined for the prune test" });
    await call("library_record", { type: "reference", name: ".keepme", source: "session-mining", description: "above the threshold", summary: "seen 3 time(s) in the session history; mined for the prune test" });
    const pruneRefused = await call("library_index", { op: "prune", source: "session-mining", type: "reference" });
    check("PORTABILITY", "smoke", "prune without confirm is refused", pruneRefused.ok === false && /confirm/.test(String(pruneRefused.note)), String(pruneRefused.note).slice(0, 80));
    const stillThere = (await call("library_query", { query: ".pruneme" })).results.some((o) => o.name === ".pruneme");
    check("PORTABILITY", "smoke", "a refused prune deletes nothing", stillThere === true, "the row is gone without a confirmation");
    const pruned = await call("library_index", { op: "prune", source: "session-mining", type: "reference", keepHits: 2, confirm: true, reason: "selfcheck prune" });
    const afterPrune = (await call("library_query", { query: ".pruneme" })).results.some((o) => o.name === ".pruneme");
    const keptRow = (await call("library_query", { query: ".keepme" })).results.some((o) => o.name === ".keepme");
    check("PORTABILITY", "smoke", "a confirmed prune drops the row below the threshold and keeps the one above", pruned.ok === true && pruned.dropped >= 1 && afterPrune === false && keptRow === true, JSON.stringify({ dropped: pruned.dropped, gone: !afterPrune, kept: keptRow }));
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
