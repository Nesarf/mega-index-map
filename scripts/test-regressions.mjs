#!/usr/bin/env node
// Focused regression checks for public tool behavior. Run with:
//   MEGA_DSH_TOOLS=/path/to/@deepseek-ai/dsh-tools/lib/index.js node scripts/test-regressions.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { registerHooks } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { zstdCompressSync, deflateRawSync } from "node:zlib";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const peer = process.env.MEGA_DSH_TOOLS;
if (peer) {
const peerUrl = pathToFileURL(path.resolve(peer)).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "@deepseek-ai/dsh-tools") return { url: peerUrl, shortCircuit: true };
    return nextResolve(specifier, context);
  },
});
}

const home = fs.mkdtempSync(path.join(os.tmpdir(), "mega-regressions-"));
process.env.DSH_HOME = home;

const crcTable = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < table.length; n++) {
    let value = n;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[n] = value;
  }
  return table;
})();
function crc32(buf) {
  let value = -1;
  for (const byte of buf) value = crcTable[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ -1) >>> 0;
}
function zipStored(entries, streaming = false) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const data = Buffer.from(entry.data, "utf8");
    const compressed = streaming ? deflateRawSync(data) : data;
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(streaming ? 8 : 0, 6);
    header.writeUInt16LE(streaming ? 8 : 0, 8);
    header.writeUInt32LE(streaming ? 0 : crc32(data), 14);
    header.writeUInt32LE(streaming ? 0 : compressed.length, 18);
    header.writeUInt32LE(streaming ? 0 : data.length, 22);
    header.writeUInt16LE(name.length, 26);
    const directory = Buffer.alloc(46);
    directory.writeUInt32LE(0x02014b50, 0);
    directory.writeUInt16LE(20, 4);
    directory.writeUInt16LE(20, 6);
    directory.writeUInt32LE(crc32(data), 16);
    directory.writeUInt16LE(streaming ? 8 : 0, 8);
    directory.writeUInt16LE(streaming ? 8 : 0, 10);
    directory.writeUInt32LE(compressed.length, 20);
    directory.writeUInt32LE(data.length, 24);
    directory.writeUInt16LE(name.length, 28);
    directory.writeUInt32LE(offset, 42);
    const descriptor = Buffer.alloc(streaming ? 16 : 0);
    if (streaming) {
      descriptor.writeUInt32LE(0x08074b50, 0);
      descriptor.writeUInt32LE(crc32(data), 4);
      descriptor.writeUInt32LE(compressed.length, 8);
      descriptor.writeUInt32LE(data.length, 12);
    }
    local.push(header, name, compressed, descriptor);
    central.push(directory, name);
    offset += header.length + name.length + compressed.length + descriptor.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

async function loadTools() {
  const { validateJsonSchemaValue } = await import("@deepseek-ai/dsh-tools");
  const plugin = await import(pathToFileURL(path.join(ROOT, "lib", "index.js")).href);
  const registered = new Map();
  await plugin.apply({
    tools: { register: (tool) => registered.set(tool.name, tool) },
    logger: { info: () => {}, warn: () => {} },
  }, { bootstrap: "off" });
  const call = async (name, args) => {
    const tool = registered.get(name);
    assert.ok(tool && typeof tool.execute === "function", `${name} is publicly registered`);
    const result = await tool.execute(args);
    const violations = validateJsonSchemaValue(tool.output.schema, result);
    assert.deepEqual(violations, [], `${name} output matches its declared schema`);
    return result;
  };
  return { call };
}

try {
  const sessions = path.join(home, "sessions");
  fs.mkdirSync(sessions, { recursive: true });
  const record = JSON.stringify({ type: "user/message", data: { content: [{ type: "text", text: "localhost:8123" }] } }) + "\n";
  fs.writeFileSync(path.join(sessions, "session.jsonl"), record, "utf8");
  fs.writeFileSync(path.join(sessions, "session.v4.jsonl.zstd"), zstdCompressSync(Buffer.from(record, "utf8")));
  const archive = path.join(sessions, "export.zip");
  fs.writeFileSync(archive, zipStored([
    { name: "session.jsonl", data: record },
    { name: "subagents/worker/session.jsonl", data: record },
  ]));
  fs.writeFileSync(path.join(sessions, "streaming.zip"), zipStored([
    { name: "session.v4.jsonl", data: record },
    { name: "subagents/worker/session.v4.jsonl", data: record },
  ], true));
  const empty = path.join(sessions, "session.v5.jsonl");
  fs.writeFileSync(empty, "", "utf8");
  const broken = path.join(sessions, "session.v6.jsonl.zstd");
  fs.writeFileSync(broken, Buffer.from("incomplete compressed log", "utf8"));

  const { call } = await loadTools();
  const legacySeen = {};
  for (const file of [path.join(sessions, "session.jsonl"), archive]) {
    const stat = fs.statSync(file);
    legacySeen[file] = `${stat.size}:${Math.floor(stat.mtimeMs)}`;
  }
  fs.writeFileSync(path.join(home, "library", "bootstrap-state.json"), JSON.stringify({ seen: legacySeen }), "utf8");
  const first = await call("library_sessions", { op: "bootstrap", dir: sessions, budgetMs: 60000 });
  assert.equal(first.records, 6, "plain, zstd, stored and streaming ZIP members are read despite legacy markers");
  // 2026-11-17: these four assertions used to demand that a damaged session keep the whole pass at
  // partial and stay out of the marker. That turned out to be the bug rather than the requirement: a
  // torn last frame is how a real session ends when the host is killed mid-write, so re-reading the
  // same bytes at every boot bought nothing and held the pass at partial for ever. Damage inside a
  // file that OPENED is now a diagnostic; only a file that could not be opened at all is retried.
  // `broken` here is the first kind - a .zstd name over bytes that are not zstd.
  assert.equal(first.phase, "complete", "damage inside a file that opened does not hold the pass back");
  assert.ok(first.found >= 1, "decoded records reached mining");

  const statePath = path.join(home, "library", "bootstrap-state.json");
  const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
  assert.ok(state.seen[broken], "a file that opened but did not decode still gets its marker");
  assert.ok(state.seen[empty], "a valid empty session has a success marker");
  assert.ok(state.seen[archive].startsWith("jsonl-zip-v1:"), "ZIP marker uses the corrected reader format");

  // The other kind - listed, then unopenable - has no fixture here on purpose: making one on Windows
  // means ACL work, and that would turn this suite into a permissions suite. Its behaviour is the
  // catch around readFileSync in mineSessionFile, and the self-check covers the split from the other
  // side by asserting unreadable is zero while failed is not. Stated rather than quietly skipped.
  const second = await call("library_sessions", { op: "bootstrap", dir: sessions, budgetMs: 60000 });
  assert.equal(second.sessionsTotal, 0, "nothing is retried when every file could be opened");
  assert.equal(second.phase, "complete", "and the pass stays complete");

  fs.writeFileSync(broken, zstdCompressSync(Buffer.from(record, "utf8")));
  const repaired = await call("library_sessions", { op: "bootstrap", dir: sessions });
  assert.equal(repaired.phase, "complete", "a repaired session completes on the next pass");
  assert.equal(repaired.records, 1);

  const project = path.join(home, "project");
  fs.mkdirSync(path.join(project, "pkg"), { recursive: true });
  fs.mkdirSync(path.join(project, "tests"), { recursive: true });
  fs.writeFileSync(path.join(project, "pkg", "__init__.py"), "", "utf8");
  fs.writeFileSync(path.join(project, "pkg", "util.py"), "def f():\n    return 1\n", "utf8");
  fs.writeFileSync(path.join(project, "pkg", "consumer.py"), "from .util import f\n", "utf8");
  fs.writeFileSync(path.join(project, "tests", "test_absolute.py"), "from pkg.util import f\n", "utf8");
  fs.writeFileSync(path.join(project, "tests", "keep.mjs"), "import value from '../pkg/util.js';\n", "utf8");
  fs.writeFileSync(path.join(project, "pkg", "util.js"), "export default 1;\n", "utf8");
  const python = await call("library_project", { op: "affects", root: project, file: "pkg/util.py" });
  assert.equal(python.ok, true);
  assert.ok(python.files.includes("tests/test_absolute.py"), "Python absolute package import is internal");
  assert.ok(python.files.includes("pkg/consumer.py"), "Python explicit relative import is internal");
  const javascript = await call("library_project", { op: "affects", root: project, file: "pkg/util.js" });
  assert.equal(javascript.ok, true);
  assert.ok(javascript.files.includes("tests/keep.mjs"), "JavaScript relative import remains internal");

  // op=plan and op=map had no regression check at all until now, while three repositories on this
  // machine keep a design/PLAN.json that this reader is the only way in to. A reader nobody tests,
  // pointed at maps that decide what gets built next, is the wrong way round.
  //
  // The fixture rides on the tree the affects checks above already built, so it costs one file.
  fs.mkdirSync(path.join(project, "design"), { recursive: true });
  fs.writeFileSync(path.join(project, "design", "PLAN.json"), JSON.stringify({
    title: "fixture",
    goals: [
      { id: "root", title: "the root", scope: "project", status: "active", parent: null, after: [], touches: ["pkg"], verifiedBy: ["tests/keep.mjs"] },
      { id: "child", title: "a child", scope: "task", status: "open", parent: "root", after: ["root"], touches: ["pkg/util.py", "pkg/gone.py"], verifiedBy: ["tests/none.mjs", "tests/test_absolute.py"] },
      { id: "orphan", title: "a goal whose edges go nowhere", scope: "task", status: "open", parent: "ghost", after: ["ghost"], touches: [], verifiedBy: [] },
    ],
  }, null, 2), "utf8");

  const plan = await call("library_project", { op: "plan", root: project });
  assert.equal(plan.ok, true);
  assert.equal(plan.plan.source, "design/PLAN.json", "the file it read is named in the answer");
  assert.equal(plan.plan.total, 3, "three goals are read");
  assert.deepEqual(plan.plan.byStatus, { active: 1, open: 2 }, "statuses are counted");

  const rootGoal = plan.plan.goals.find((g) => g.id === "root");
  // A directory stands for the files the graph knows under it - not for the directory, and not for
  // everything on disk. This is the shape three repositories rely on: goals name src/, self/, boot/.
  assert.ok(rootGoal.files.includes("pkg/util.py"), "a directory in touches stands for files under it");
  assert.ok(rootGoal.files.includes("pkg/consumer.py"), "and for more than the first of them");
  assert.deepEqual(rootGoal.tests, ["tests/keep.mjs"], "a verifiedBy path that exists is kept");

  // One broken record per kind. A missing report that reported nothing would let a stale plan look
  // healthy, which is precisely the failure this reader exists to catch in somebody else's repository.
  const missing = plan.plan.missing.map((m) => m.kind + ":" + m.path).sort();
  assert.ok(missing.includes("touches:pkg/gone.py"), "a touched path that is not there is reported");
  assert.ok(missing.includes("verifiedBy:tests/none.mjs"), "a judge that is not there is reported");
  assert.ok(missing.includes("parent:ghost"), "a parent that is not there is reported");
  assert.ok(missing.includes("after:ghost"), "an ordering edge that is not there is reported");

  const cleanPlan = path.join(home, "clean-project");
  fs.mkdirSync(path.join(cleanPlan, "design"), { recursive: true });
  fs.writeFileSync(path.join(cleanPlan, "a.js"), "export default 1;\n", "utf8");
  fs.writeFileSync(path.join(cleanPlan, "tests.mjs"), "import a from './a.js';\n", "utf8");
  fs.writeFileSync(path.join(cleanPlan, "design", "PLAN.json"), JSON.stringify({
    goals: [{ id: "only", title: "a healthy plan", scope: "task", status: "done", parent: null, after: [], touches: ["a.js"], verifiedBy: ["tests.mjs"] }],
  }), "utf8");
  const healthy = await call("library_project", { op: "plan", root: cleanPlan });
  assert.deepEqual(healthy.plan.missing, [], "a plan whose every path exists reports nothing missing");

  const mapped = await call("library_project", { op: "map", root: project });
  assert.equal(mapped.ok, true);
  assert.ok(mapped.files > 0, "op=map counts files");
  assert.equal(mapped.plan && mapped.plan.total, 3, "op=map carries the plan network it found");
  assert.ok(Array.isArray(mapped.inventory.unmappedFiles), "op=map says what it could not reach");

  console.log("regressions OK");
} finally {
  fs.rmSync(home, { recursive: true, force: true });
}
