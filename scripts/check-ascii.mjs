#!/usr/bin/env node
// Repository invariant: this plugin is English-only and ASCII-only, with exactly two documented
// exceptions:
//   1. the SENSITIVE_PATTERNS regexes in lib/index.js, which must recognise Chinese sensitive content
//      (those CJK characters are functional, not prose);
//   2. README.zh-CN.md, the single localized document: prose in Chinese is the point of that file, so it
//      may carry Han characters and CJK punctuation. Nothing else may - no code, no tool output, no
//      other document.
//
// Usage: node scripts/check-ascii.mjs      (exit 1 on any other non-ASCII character)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const SKIP_DIRS = new Set(["node_modules", ".git"]);
// A local, machine-only declaration is not shipped content (see ISOLATION.md), so it is not scanned.
const SKIP_FILES = new Set([".isolation.local.json"]);
const ALLOWED_FILE = path.join(ROOT, "lib", "index.js");
const LOCALIZED_DOC = path.join(ROOT, "README.zh-CN.md");
const isHan = (c) => /\p{Script=Han}/u.test(c);
const isCjkPunct = (c) => /[\u3000-\u303F\uFF00-\uFFEF\u2014\u2018\u2019\u201C\u201D\u2026]/.test(c);
const isNonAscii = (c) => c.codePointAt(0) > 0x7f;
const describe = (c) => `"${c}" U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`;

// The one allowed region: the SENSITIVE_PATTERNS array in lib/index.js.
function allowedRange(file) {
  const lines = fs.readFileSync(file, "utf8").split("\n");
  const start = lines.findIndex((l) => /const SENSITIVE_PATTERNS = \[/.test(l));
  if (start < 0) return null;
  const end = lines.findIndex((l, i) => i > start && /^\];/.test(l));
  return end < 0 ? null : { start: start + 1, end: end + 1 };
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name) || SKIP_FILES.has(entry.name)) continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const range = allowedRange(ALLOWED_FILE);
const files = walk(ROOT).sort();
const violations = [];
let allowed = 0;
let localized = 0;
let scanned = 0;

for (const file of files) {
  const text = fs.readFileSync(file, "utf8");
  scanned++;
  const isAllowedFile = file === ALLOWED_FILE;
  const isLocalized = file === LOCALIZED_DOC;
  text.split("\n").forEach((line, i) => {
    const lineNo = i + 1;
    const inAllowedBlock = isAllowedFile && range !== null && lineNo >= range.start && lineNo <= range.end;
    for (const ch of line) {
      if (!isNonAscii(ch)) continue;
      if (inAllowedBlock && isHan(ch)) { allowed++; continue; }
      if (isLocalized && (isHan(ch) || isCjkPunct(ch))) { localized++; continue; }
      violations.push({ file: path.relative(ROOT, file), line: lineNo, char: ch, snippet: line.trim().slice(0, 80) });
    }
  });
}

if (violations.length) {
  console.error(`English/ASCII invariant FAILED: ${violations.length} unexpected non-ASCII character(s)`);
  for (const v of violations.slice(0, 40)) console.error(`  ${v.file}:${v.line}  ${describe(v.char)}  ${v.snippet}`);
  if (violations.length > 40) console.error(`  ... and ${violations.length - 40} more`);
  console.error("\nAllowed: CJK inside SENSITIVE_PATTERNS (lib/index.js, functional), and Han plus CJK punctuation in the one localized document README.zh-CN.md.");
  console.error("Everything else must be plain ASCII English.");
  process.exit(1);
}

if (range === null) {
  console.error("invariant check FAILED: could not locate the SENSITIVE_PATTERNS block in lib/index.js");
  process.exit(1);
}

console.log(`English/ASCII invariant OK - ${scanned} file(s) scanned, no unexpected non-ASCII.`);
console.log(`Allowed exception 1: ${allowed} CJK character(s) inside SENSITIVE_PATTERNS (lib/index.js lines ${range.start}-${range.end}).`);
console.log(`Allowed exception 2: ${localized} Han/CJK-punctuation character(s) in README.zh-CN.md (the one localized document).`);
