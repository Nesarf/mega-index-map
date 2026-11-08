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
  assert.equal(first.phase, "partial", "a damaged session is not reported complete");
  assert.ok(first.found >= 1, "decoded records reached mining");

  const statePath = path.join(home, "library", "bootstrap-state.json");
  const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
  assert.ok(!state.seen[broken], "damaged session has no success marker");
  assert.ok(state.seen[empty], "a valid empty session has a success marker");
  assert.ok(state.seen[archive].startsWith("jsonl-zip-v1:"), "ZIP marker uses the corrected reader format");

  const second = await call("library_sessions", { op: "bootstrap", dir: sessions, budgetMs: 60000 });
  assert.equal(second.sessionsTotal, 1, "only the damaged input is retried incrementally");
  assert.equal(second.phase, "partial", "retrying damaged input remains incomplete");

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

  console.log("regressions OK");
} finally {
  fs.rmSync(home, { recursive: true, force: true });
}
