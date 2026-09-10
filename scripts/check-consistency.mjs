#!/usr/bin/env node
// Consistency proofread for this plugin: documentation vs code, dead declarations, tool parameter
// wiring, op-list agreement, and the safety invariants (no network capability, no leftover debug
// markers, English/ASCII only). Dependency-free on purpose so CI can always run it.
//
// Usage: node scripts/check-consistency.mjs        (exit 1 on any finding)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "lib", "index.js");
const src = fs.readFileSync(SRC, "utf8");
const problems = [];

function matchFrom(s, openIdx) {
  const open = s[openIdx];
  const close = open === "{" ? "}" : open === "[" ? "]" : ")";
  let depth = 0;
  for (let i = openIdx; i < s.length; i++) {
    const c = s[i];
    if (c === '"' || c === "'" || c === "`") {
      const q = c; i++;
      while (i < s.length) { if (s[i] === "\\") { i += 2; continue; } if (s[i] === q) break; i++; }
      continue;
    }
    if (c === "/" && s[i + 1] === "/") { while (i < s.length && s[i] !== "\n") i++; continue; }
    if (c === "/" && s[i + 1] === "*") { i += 2; while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++; i++; continue; }
    if (c === open) depth++;
    else if (c === close) { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (["node_modules", ".git", ".isolation.local.json"].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

// --- files: parseable, ASCII apart from the two documented exceptions -----------------------
// check-ascii.mjs owns the full statement of those exceptions; here the non-Han non-ASCII scan simply
// skips the one localized document, whose Chinese punctuation is prose.
const LOCALIZED_DOCS = new Set(["README.zh-CN.md"]);
const files = walk(ROOT);
for (const f of files) {
  const rel = path.relative(ROOT, f).replace(/\\/g, "/");
  const text = fs.readFileSync(f, "utf8");
  const nonHan = [...new Set([...text].filter((c) => c.codePointAt(0) > 0x7f))].filter((c) => !/\p{Script=Han}/u.test(c));
  if (nonHan.length && !LOCALIZED_DOCS.has(rel)) problems.push(`${rel}: non-Han non-ASCII ${nonHan.join(" ")}`);
  if (rel.endsWith(".json")) { try { JSON.parse(text); } catch (e) { problems.push(`${rel}: invalid JSON (${e.message})`); } }
  if (/\.ya?ml$/.test(rel) && text.split("\n").some((l) => l.startsWith("\t"))) problems.push(`${rel}: tab indentation in YAML`);
}

// --- declarations: dead or duplicated ------------------------------------------------------
const declared = new Map();
for (const m of src.matchAll(/^(?:async )?function ([A-Za-z_$][\w$]*)\s*\(/gm)) declared.set(m[1], "function");
for (const m of src.matchAll(/^const ([A-Za-z_$][\w$]*)\s*=/gm)) declared.set(m[1], "const");
const dead = [...declared.keys()].filter((n) => (src.match(new RegExp(`\\b${n}\\b`, "g")) || []).length <= 1);
if (dead.length) problems.push(`declared but never used: ${dead.join(", ")}`);
const seen = new Set();
for (const m of src.matchAll(/^(?:async )?function ([A-Za-z_$][\w$]*)\s*\(|^const ([A-Za-z_$][\w$]*)\s*=/gm)) {
  const n = m[1] || m[2];
  if (seen.has(n)) problems.push(`duplicate top-level declaration: ${n}`);
  seen.add(n);
}

// --- tools: parameters are really read, ops lists agree ------------------------------------
const tools = [];
for (const m of src.matchAll(/name: "(library_[a-z_]+)",/g)) {
  const open = src.lastIndexOf("{", m.index);
  tools.push({ name: m[1], text: src.slice(open, matchFrom(src, open) + 1) });
}
for (const t of tools) {
  const pm = t.text.indexOf("parameters: {");
  const pe = matchFrom(t.text, t.text.indexOf("{", pm));
  const names = [...t.text.slice(pm, pe + 1).matchAll(/^\s{6}([A-Za-z_][\w]*):\s*\{/gm)].map((x) => x[1]);
  const body = t.text.slice(t.text.indexOf("async execute"));
  const unread = names.filter((n) => !new RegExp(`args\\.${n}\\b`).test(body) && !new RegExp(`\\.\\s*${n}\\b`).test(src));
  if (unread.length) problems.push(`${t.name}: parameters never read: ${unread.join(", ")}`);
}
const lf = tools.find((t) => t.name === "library_format");
if (!lf) problems.push("library_format tool not found");
else {
  const listed = (lf.text.match(/op: \{ type: "string", required: true, description: "([^"]+)" \}/) || [, ""])[1].split("|").map((s) => s.trim()).filter(Boolean);
  const implemented = [...lf.text.matchAll(/if \(op === "([a-z]+)"\)/g)].map((m) => m[1]);
  const allowed = (lf.text.match(/allowed: ([a-z, ]+)/) || [, ""])[1].split(",").map((s) => s.trim()).filter(Boolean);
  const same = (a, b) => a.length === b.length && a.every((x) => b.includes(x));
  if (!same(listed, implemented)) problems.push(`library_format op list (${listed.join(",")}) != implemented (${implemented.join(",")})`);
  if (!same(implemented, allowed)) problems.push(`library_format error message lists ${allowed.join(",")} but implements ${implemented.join(",")}`);
}

// --- docs vs code --------------------------------------------------------------------------
const readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
const skill = fs.readFileSync(path.join(ROOT, "skills", "mega-index", "SKILL.md"), "utf8");
const sigCount = (src.match(/\{ sig: \[/g) || []).length;
for (const [label, doc] of [["README.md", readme], ["SKILL.md", skill]]) {
  const claimed = [...doc.matchAll(/\((\d+) signatures\)/g)].map((m) => Number(m[1]));
  if (claimed.length !== 1 || claimed[0] !== sigCount) problems.push(`${label}: claims ${claimed.join(",") || "no"} signatures, the table has ${sigCount}`);
  const missing = tools.map((t) => t.name).filter((n) => !doc.includes("`" + n + "`"));
  if (missing.length) problems.push(`${label}: tools not documented: ${missing.join(", ")}`);
}
for (const op of ["list", "scan", "learn", "add", "remove", "draft", "deps", "report", "deliver", "unseal"]) {
  if (!readme.includes(op) || !skill.includes(op)) problems.push(`op "${op}" is missing from README.md or SKILL.md`);
}
// The localized README is a translation, so it must not silently lose a tool or the signature count: a
// translation that drifts is worse than no translation, because it reads as authoritative.
const zhPath = path.join(ROOT, "README.zh-CN.md");
if (fs.existsSync(zhPath)) {
  const zh = fs.readFileSync(zhPath, "utf8");
  const missingZh = tools.map((t) => t.name).filter((n) => !zh.includes("`" + n + "`"));
  if (missingZh.length) problems.push(`README.zh-CN.md: tools not documented: ${missingZh.join(", ")}`);
  if (!new RegExp(`(?:^|[^0-9])${sigCount}(?:[^0-9]|$)`).test(zh)) problems.push(`README.zh-CN.md: does not state the signature count (${sigCount})`);
  for (const op of ["list", "scan", "learn", "add", "remove", "draft", "deps", "report", "deliver", "unseal"]) {
    if (!zh.includes(op)) problems.push(`README.zh-CN.md: op "${op}" is missing`);
  }
}

// --- safety invariants --------------------------------------------------------------------
const markers = [...new Set([...src.matchAll(/\b(TODO|FIXME|XXX|HACK|console\.log|debugger)\b/g)].map((m) => m[1]))];
if (markers.length) problems.push(`leftover debug markers: ${markers.join(", ")}`);
const net = [...new Set([...src.matchAll(/\b(fetch|XMLHttpRequest|https?\.request|net\.connect|nodemailer|smtp)\b/g)].map((m) => m[1]))];
if (net.length) problems.push(`network-capable code present: ${net.join(", ")}`);

if (problems.length) {
  console.error(`consistency check FAILED: ${problems.length} finding(s)`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`consistency check OK - ${files.length} file(s), ${tools.length} tool(s), ${sigCount} signature entries, ${declared.size} declarations.`);
console.log("documentation, op lists, parameter wiring and the no-network invariant all agree.");
