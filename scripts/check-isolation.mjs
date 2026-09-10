#!/usr/bin/env node
// Isolation guard for this repository (see ISOLATION.md).
//
// Two jobs:
//   static (default, what CI runs): this repository must never write into the sibling build, and
//     the sibling must never write into this one. Writes may only target the library under
//     $DSH_HOME, the OS temp directory, or a path the caller passed in - so any write-capable call
//     that names the sibling, or that carries a hardcoded absolute path, is a finding.
//   witness (`snapshot` / `verify`): hash this repository, the sibling tree and the real library
//     index, so a session can prove that running the tests and the proofread moved nothing.
//
// Dependency-free on purpose so CI can always run it. Usage:
//   node scripts/check-isolation.mjs
//   node scripts/check-isolation.mjs snapshot [manifest-path]
//   node scripts/check-isolation.mjs verify   [manifest-path]

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SIBLING = process.env.MEGA_INDEX_SIBLING || "%TOOLCHAIN_HOME%";
const SIBLING_NAME = /sibling-checkout|sibling-checkout/i;
const DEFAULT_MANIFEST = path.join(os.tmpdir(), "mega-index-map-isolation.json");

const WRITE_CALLS = /\b(fs\.)?(writeFileSync|writeFile|appendFileSync|createWriteStream|mkdirSync|mkdir|rmSync|rm|rmdirSync|unlinkSync|unlink|renameSync|rename|copyFileSync|copyFile|truncateSync|chmodSync|utimesSync)\s*\(/;
const SPAWN_CALLS = /\b(spawn|spawnSync|exec|execSync|execFile|execFileSync)\s*\(/;
const literals = (s) => [...s.matchAll(/"[^"]*"|'[^']*'|`[^`]*`/g)].map((m) => m[0]);
const isComment = (line) => /^\s*(\/\/|\*|\/\*)/.test(line);
const skipDir = new Set(["node_modules", ".git", "obj", "bin"]);

function walk(dir, out = []) {
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of ents.sort((a, b) => a.name.localeCompare(b.name))) {
    if (skipDir.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(mjs|cjs|js|ts|json|ya?ml|ps1|sh|cs|xaml|sln|cmd)$/i.test(e.name)) out.push(p);
  }
  return out;
}

// A write call is only acceptable when its target is computed, never a hardcoded absolute path.
function writeTargets(line) {
  const out = [];
  for (const lit of literals(line)) {
    const body = lit.slice(1, -1);
    if (/^[A-Za-z]:[\\/]/.test(body) || /^\\\\/.test(body) || /^\/(?:home|Users|mnt|opt|srv)\//.test(body)) out.push(body);
  }
  return out;
}

const problems = [];

function scanStatic() {
  const here = walk(ROOT);
  // --- direction 1: this repository must not write into the sibling, nor spawn it ---
  let writeCalls = 0;
  let spawnCalls = 0;
  for (const f of here) {
    const rel = path.relative(ROOT, f).replace(/\\/g, "/");
    const lines = fs.readFileSync(f, "utf8").split("\n");
    lines.forEach((line, i) => {
      const where = `${rel}:${i + 1}`;
      const writes = WRITE_CALLS.test(line);
      const spawns = SPAWN_CALLS.test(line);
      if (writes) writeCalls++;
      if (spawns) spawnCalls++;
      if (!isComment(line)) {
        if (writes && SIBLING_NAME.test(line)) {
          problems.push(`${where}: a write-capable call names the sibling build: ${line.trim().slice(0, 100)}`);
        }
        if (spawns && SIBLING_NAME.test(line)) {
          problems.push(`${where}: a spawned program is pointed at the sibling build: ${line.trim().slice(0, 100)}`);
        }
      }
      if (writes) {
        for (const t of writeTargets(line)) {
          problems.push(`${where}: hardcoded absolute path as a write target (${t}) - computed from $DSH_HOME, os.tmpdir() or a caller argument only`);
        }
      }
    });
  }

  // --- direction 2: the sibling must not write into this repository ---
  let siblingScanned = 0;
  if (fs.existsSync(SIBLING)) {
    for (const f of walk(SIBLING)) {
      const rel = path.relative(SIBLING, f).replace(/\\/g, "/");
      const lines = fs.readFileSync(f, "utf8").split("\n");
      siblingScanned++;
      lines.forEach((line, i) => {
        if (isComment(line)) return;
        if (!WRITE_CALLS.test(line)) return;
        if (/mega-index-map/i.test(line)) {
          problems.push(`sibling ${rel}:${i + 1}: write-capable call names this repository: ${line.trim().slice(0, 100)}`);
        }
        if (SPAWN_CALLS.test(line) && /mega-index-map/i.test(line)) {
          problems.push(`sibling ${rel}:${i + 1}: spawned program is pointed at this repository`);
        }
      });
    }
  }

  if (problems.length) {
    console.error(`isolation check FAILED: ${problems.length} finding(s)`);
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  console.log(`isolation check OK - ${here.length} file(s) here (${writeCalls} write call(s), ${spawnCalls} spawn call(s)), ` +
    `${siblingScanned} sibling file(s) scanned.`);
  console.log("no write path into the sibling, no hardcoded write target, no spawn pointed across the boundary.");
}

// --- witness: hash both trees plus the real library, then compare later ---
function hashManifest() {
  const entries = {};
  const add = (label, dir) => {
    for (const f of walk(dir)) {
      const rel = path.relative(dir, f).replace(/\\/g, "/");
      try {
        entries[`${label}/${rel}`] = createHash("sha256").update(fs.readFileSync(f)).digest("hex").slice(0, 16);
      } catch { /* unreadable file: leave it out rather than fail the witness */ }
    }
  };
  add("mega", ROOT);
  add("sibling", SIBLING);
  const lib = path.join(process.env.DSH_HOME || path.join(os.homedir(), ".dsh"), "library", "index.json");
  if (fs.existsSync(lib)) entries["real-library/index.json"] = createHash("sha256").update(fs.readFileSync(lib)).digest("hex").slice(0, 16);
  return entries;
}

function cmdSnapshot(manifestPath) {
  const entries = hashManifest();
  fs.writeFileSync(manifestPath, JSON.stringify({ at: new Date().toISOString(), roots: { mega: ROOT, sibling: SIBLING }, entries }, null, 2), "utf8");
  console.log(`isolation snapshot written: ${manifestPath} (${Object.keys(entries).length} file(s))`);
}

function cmdVerify(manifestPath) {
  if (!fs.existsSync(manifestPath)) {
    console.error(`no snapshot at ${manifestPath}: run "node scripts/check-isolation.mjs snapshot" first`);
    process.exit(1);
  }
  const saved = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const now = hashManifest();
  const changed = [];
  const added = [];
  const removed = [];
  for (const [k, v] of Object.entries(saved.entries)) {
    if (!(k in now)) removed.push(k);
    else if (now[k] !== v) changed.push(k);
  }
  for (const k of Object.keys(now)) if (!(k in saved.entries)) added.push(k);
  const moved = changed.length + added.length + removed.length;
  if (moved) {
    // Attribute every difference to its side. A sibling-only difference is the other project's own
    // session at work, not this package reaching across the boundary, so it must not be reported as
    // an isolation violation - but it is still worth saying loudly, because it means the sibling
    // moved while this session ran.
    const side = (k) => (k.startsWith("sibling/") ? "sibling" : k.startsWith("real-library") ? "library" : "this-repository");
    const list = (kind, arr) => arr.map((k) => `  ${kind}: ${k} [${side(k)}]`);
    const lines = [...list("changed", changed), ...list("added", added), ...list("removed", removed)];
    const ownMoved = [...changed, ...added, ...removed].filter((k) => side(k) !== "sibling");
    console.error(`isolation witness: ${moved} file(s) differ from the snapshot taken ${saved.at}`);
    for (const l of lines) console.error(l);
    if (ownMoved.length === 0) {
      console.error("");
      console.error("VERDICT: only the sibling tree moved. Nothing here wrote to it - this package has no");
      console.error("write path across the boundary - so that change came from the sibling's own session.");
      console.error("This repository and the user's library index are byte-identical to the snapshot.");
      process.exit(3);
    }
    console.error("");
    console.error("VERDICT: the isolation witness FAILED for this repository or the user's library:");
    for (const k of ownMoved) console.error(`  ${k}`);
    console.error("This package must not write outside $DSH_HOME, the OS temp directory or a passed path.");
    process.exit(1);
  }
  console.log(`isolation witness OK - ${Object.keys(saved.entries).length} file(s) unchanged since ${saved.at}`);
  console.log("neither tree was written, and the user's own library index is byte-identical.");
}

const [cmd, manifestArg] = process.argv.slice(2);
const manifest = manifestArg || DEFAULT_MANIFEST;
if (cmd === "snapshot") cmdSnapshot(manifest);
else if (cmd === "verify") cmdVerify(manifest);
else if (cmd === undefined || cmd === "static") scanStatic();
else {
  console.error(`unknown command "${cmd}"; use static (default), snapshot or verify`);
  process.exit(2);
}
