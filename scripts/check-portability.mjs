#!/usr/bin/env node
// Portability and encoding invariant: the standing three axes this package must always satisfy.
//
//   1. ASCII only            - enforced by scripts/check-ascii.mjs (English output, one documented CJK
//                              exception for the sensitive-content patterns).
//   2. Mainstream OS support - nothing here may assume Windows. The plugin runs on Linux and macOS too
//                              (the MCP/CLI editions of the same core do), so platform-specific code must
//                              sit behind a win32 guard with a real counterpart, spawns must pass argv
//                              arrays (never a shell string), temp files must use os.tmpdir(), and PATH
//                              must be split with path.delimiter.
//   3. Multi-language text   - UTF-8 in, UTF-8 out, explicit encodings for every text read/write, BOM
//                              policy stated (written for Windows viewers, stripped on read), and the
//                              locale detection anchored so a bare two-letter substring can never be
//                              mistaken for a language or country code.
//
// Every check below failed at least once in this repository's history, which is why they are here.
// Dependency-free so CI can always run it.
//
// Usage: node scripts/check-portability.mjs      (exit 1 on any finding)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// MEGA_INDEX_SRC lets the fault-injection test point this checker at a deliberately broken copy, so the
// checks themselves can be shown to fail when they should rather than only passing on clean code.
const SRC = process.env.MEGA_INDEX_SRC || path.join(ROOT, "lib", "index.js");
const problems = [];
const notes = [];

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (["node_modules", ".git"].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

// --- 1. line endings: a CRLF shell script cannot run on Linux/macOS --------------------------
const TEXT_EXT = /\.(mjs|cjs|js|json|md|ya?ml|yml|sh|ps1|cmd|txt|patch)$/i;
let crlf = 0;
for (const f of walk(ROOT)) {
  if (!TEXT_EXT.test(f)) continue;
  const bytes = fs.readFileSync(f);
  const cr = bytes.filter((b) => b === 13).length;
  if (cr > 0) {
    crlf += cr;
    problems.push(`${path.relative(ROOT, f)}: ${cr} CR byte(s) - shipped text must be LF (a CRLF script breaks on POSIX)`);
  }
}
notes.push(`line endings: ${crlf} CR byte(s) in shipped text`);

// --- 2. spawn safety: argv arrays or a variable, never a shell string ------------------------
const src = fs.readFileSync(SRC, "utf8");
if (/shell:\s*true/.test(src)) problems.push("lib/index.js: a spawn with shell:true - commands must be argv arrays, not shell strings");
// A spawn is unsafe when its second argument is a string literal (a command line to parse) rather than
// an array literal or a variable holding argv.
const spawnStringArg = [...src.matchAll(/\b(?:spawn|spawnSync)\s*\([^,()]+,\s*(["'`])/g)];
if (spawnStringArg.length) {
  problems.push(`lib/index.js: ${spawnStringArg.length} spawn call(s) pass a string as argv - pass an array instead`);
}
const spawnCalls = [...src.matchAll(/\b(?:spawn|spawnSync)\s*\(/g)].length;
const argvish = [...src.matchAll(/\b(?:spawn|spawnSync)\s*\([^,()]+,\s*(?:\[|\w+)/g)].length;
if (spawnCalls !== argvish) problems.push(`lib/index.js: ${spawnCalls} spawn call(s) but only ${argvish} pass an array or an argv variable`);
notes.push(`spawns: ${spawnCalls} call(s), string-argv: ${spawnStringArg.length}`);

// --- 3. platform branches must have a counterpart --------------------------------------------
const winGuards = [...src.matchAll(/process\.platform\s*===\s*"win32"/g)].length;
const posixGuards = [...src.matchAll(/process\.platform\s*!==\s*"win32"/g)].length +
  [...src.matchAll(/\?\s*"dialog\.ps1"\s*:\s*"dialog\.sh"/g)].length;
if (winGuards === 0) problems.push("lib/index.js: no win32 guard at all - Windows specifics must be guarded");
if (posixGuards === 0) problems.push("lib/index.js: no non-Windows counterpart found - the Windows branch needs a POSIX path");
for (const fn of ["windowsReportDialogScript", "posixReportDialogScript"]) {
  if (!new RegExp(`function ${fn}\\(`).test(src)) problems.push(`lib/index.js: ${fn} is missing - both dialog hosts must exist`);
}
// The Windows-only console code-page probe must never be reached on other platforms. Only CALL sites
// count: the function's own definition matches the same shape.
const syncCalls = [...src.matchAll(/(?<!function )detectSystemEncodingSync\s*\(\s*\)/g)];
for (const m of syncCalls) {
  const before = src.slice(Math.max(0, m.index - 400), m.index);
  if (!/process\.platform\s*===\s*"win32"[\s\S]{0,200}$/.test(before)) {
    problems.push("lib/index.js: detectSystemEncodingSync() (uses cmd/chcp) is not behind a win32 guard");
  }
}
notes.push(`platform guards: ${winGuards} win32, ${posixGuards} POSIX counterpart(s), ${syncCalls.length} guarded win32-only probe call(s)`);

// --- 4. temp files through os.tmpdir(), not a hardcoded path ---------------------------------
if (!/os\.tmpdir\(\)/.test(src)) problems.push("lib/index.js: temp files must be created under os.tmpdir()");
if (/["'`]\/tmp\//.test(src) || /["'`][A-Za-z]:\\\\Temp/i.test(src)) {
  problems.push("lib/index.js: a hardcoded temp path is used instead of os.tmpdir()");
}

// --- 5. explicit encodings for text I/O ------------------------------------------------------
// Judge each call by its whole LINE, so a binary read wrapped in zipReadEntry(...) is recognised as the
// binary operation it is instead of being read as an unencoded text write.
const ioLines = src.split("\n")
  .map((line, i) => ({ line, no: i + 1 }))
  .filter(({ line }) => /fs\.(readFileSync|writeFileSync)\(/.test(line));
const binaryOk = (line) => /utf8|hex|base64/.test(line) || /zipReadEntry|zipBuffer|Buffer\.|copyFileSync|buf\)|\.tar/.test(line);
const unencoded = ioLines.filter(({ line }) => !binaryOk(line));
if (unencoded.length) {
  for (const { line, no } of unencoded) {
    problems.push(`lib/index.js:${no}: text I/O without an explicit encoding and not recognisably binary (${line.trim().slice(0, 80)})`);
  }
}
const ioTotal = [...src.matchAll(/fs\.(readFileSync|writeFileSync)\(/g)].length;
notes.push(`text I/O: ${ioTotal} read/write call(s), ${unencoded.length} without an explicit encoding`);

// --- 6. BOM policy stated on both sides ------------------------------------------------------
if (!/\\uFEFF/.test(src)) problems.push("lib/index.js: the BOM policy for the manifest is missing (write with BOM, strip on read)");
if (!/replace\(\/\^\\uFEFF\//.test(src)) problems.push("lib/index.js: nothing strips a BOM when reading text back");

// --- 7. PATH must be split with the platform separator ---------------------------------------
// `\b` matters: PATHEXT is a semicolon-separated list by definition on Windows, so only PATH itself is
// the variable that must never be split on a bare ";". The gap tolerates a chained call split over
// lines (the resolver does exactly that), which a same-line rule would miss.
if (/process\.env\.PATH\b(?![A-Za-z0-9_])[\s\S]{0,80}?\.split\(\s*(?:["'`]\s*;|\/\s*;\s*\/)/.test(src)) {
  problems.push('lib/index.js: PATH is split on ";" - use path.delimiter');
}
if (!/split\(path\.delimiter\)/.test(src)) problems.push("lib/index.js: PATH is never split with path.delimiter");

// --- 8. locale detection stays anchored (regression: KOI8-R read as Korean, en_GB as Chinese) --
const detector = src.slice(src.indexOf("function detectSystemEncoding"), src.indexOf("function detectSystemEncodingSync"));
// The historical bug had two shapes, and both are checked here:
//   (a) a bare two-letter code tested against the raw locale string - "en_GB" matched /gb/i;
//   (b) a bare "ko" alternative that can also match a CODESET - "KOI8-R" matched /ko/i.
// The protection for (b) is ordering: the koi8 rule must come before any bare ko alternative.
const bareCodes = /(?:^|\|)\s*(ko|gb|ja|zh)\s*(?:\||$)/;
const isCodesetWord = (body) => /koi8|gb18030|gbk|gb2312|uhc|hz/.test(body);
const tested = [...detector.matchAll(/\/([^/\n]+)\/[a-z]*\.test\(\s*([A-Za-z_$][\w$]*)\s*\)/g)];
const badTargets = [];
for (const m of tested) {
  const body = m[1];
  const target = m[2];
  if (!bareCodes.test(body) || isCodesetWord(body)) continue;
  if (target !== "codeset") badTargets.push(`/${body}/i tested against ${target}`);
}
if (badTargets.length) {
  problems.push(`lib/index.js: a bare language/country code is tested against the raw locale (${badTargets.join("; ")}) - parse the locale and compare with code === "xx"`);
}
const koi8At = detector.search(/koi8/);
const bareKoAt = [...detector.matchAll(/\/([^/\n]+)\/[a-z]*\.test\(/g)]
  .filter((m) => bareCodes.test(m[1]) && !isCodesetWord(m[1]) && /(?:^|\|)\s*ko\s*(?:\||$)/.test(m[1]))
  .map((m) => m.index)
  .filter((i) => i !== undefined);
if (koi8At >= 0 && bareKoAt.some((i) => i < koi8At)) {
  problems.push("lib/index.js: a bare ko test runs before the koi8 rule, so KOI8-R would be read as Korean");
}
const anchored = [...detector.matchAll(/code === "[a-z]{2}"/g)].length;
if (anchored < 3) problems.push(`lib/index.js: locale detection has only ${anchored} anchored language checks - expected ja/ko/zh`);
notes.push(`locale detection: ${anchored} anchored language checks, ${badTargets.length} bare pattern(s), koi8 before ko: ${koi8At >= 0 && !bareKoAt.some((i) => i < koi8At)}`);

// --- 9. the generated POSIX dialog must be a real sh script -----------------------------------
const posixFn = src.slice(src.indexOf("function posixReportDialogScript"));
if (!/#!/.test(posixFn.slice(0, 400))) problems.push("lib/index.js: the POSIX dialog script has no shebang");

// --- 10. no maintainer's disk layout baked into the shipped source ----------------------------
// The built-in candidate seed has to work on a stranger's machine: a bare command name resolved from
// PATH, or a location a vendor's installer uses by default. A Windows path on any drive but the system
// drive is a leftover from the machine this plugin grew up on, and a named user profile is the same
// thing in another form. Machine-specific locations belong in the per-install local candidate pack
// (created with `library_detect op=add`), which is written under $DSH_HOME and never shipped.
const foreignDrive = [...src.matchAll(/(?<![A-Za-z0-9_$])[A-BD-Za-z]:[\\/]+[^\s"'`;,)]*/g)].map((m) => m[0]);
for (const p of foreignDrive) {
  problems.push(`lib/index.js: "${p}" is a non-system-drive path - a personal layout must live in the local candidate pack, not in shipped source`);
}
const namedProfile = [...src.matchAll(/(?<![A-Za-z0-9_$])[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9._-]+/g)].map((m) => m[0]);
for (const p of namedProfile) {
  problems.push(`lib/index.js: "${p}" names a specific user profile - use os.homedir() or a caller argument`);
}
const seed = src.slice(src.indexOf("const DETECT_CANDIDATES"), src.indexOf("function resolveOnPath"));
const bareNames = [...seed.matchAll(/path:\s*"([^"\\/]+)"/g)].length;
if (bareNames < 1) problems.push("lib/index.js: the candidate seed has no bare command name - tools must be found on PATH, not only at fixed paths");
notes.push(`machine neutrality: ${foreignDrive.length} foreign-drive path(s), ${namedProfile.length} named profile(s), ${bareNames} bare command name(s) in the seed`);

// --- report ---------------------------------------------------------------------------------
for (const n of notes) console.log(`  ${n}`);
if (problems.length) {
  console.error(`portability invariant FAILED: ${problems.length} finding(s)`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log("portability invariant OK - line endings LF, spawns argv-only, platform branches paired,");
console.log("temp via os.tmpdir(), text I/O explicitly encoded, BOM policy present, PATH via path.delimiter,");
console.log("the locale detector anchored, and no maintainer disk layout in the shipped source.");
