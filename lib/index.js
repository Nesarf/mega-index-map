// mega-index-map — DSH cross-workspace interop Library (host plugin).
//
// This is the DeepSeek Harness (DSH) entry point. Since the cross-harness refactor, all
// core logic (storage/retrieval, file signatures, AES-256-GCM, ADB, encoding, media
// fingerprints) and the 9 tool `execute` bodies live in ./core.mjs as a pure-Node,
// DSH-independent shared core. This module only wires those tools into the DSH tool
// registry via defineTool + ctx.tools.register, and exports the DSH plugin contract
// { name, inject, apply }.
//
// Responsibilities:
//   1) Maintain a cross-workspace object index library under $DSH_HOME/library.
//   2) Register model-facing tools: library_record / library_index / library_query /
//      library_detect / library_sniff / library_decrypt / library_export /
//      library_encoding / library_adb.
//   3) Let Harness agents proactively record encountered objects into the library,
//      so any workspace (existing or new conversations) can index, use, research,
//      and learn from previously recorded objects.
//
// Follows:
//   - Disk discipline: the library lives at $DSH_HOME/library (default ~/.dsh/library);
//     large files / downloads / caches never touch the C: drive.
//   - Safety: only one target is written ($DSH_HOME/library/index.json); record fields
//     are length-capped to prevent pollution; sensitive content is encrypted at rest.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { defineTool } from "@deepseek-ai/dsh-tools";
import {
  TOOLS,
  registerDefaultMediaProvider,
  appendLog,
  MAX_LEN, clampField,
  dshHome, libraryDir, indexFile, payloadDir,
  OBJ_TYPES, DISPOSITION, dispositionFor, fingerprint,
  MEDIA_PROVIDERS, mediaFingerprint,
  runSilent, resolveTool,
  adbPath, runAdb, ADB_ACTIONS,
  INDICATIVE_ENCODING_HINTS, detectSystemEncoding, detectSystemEncodingSync,
  FILE_SIGNATURES, readHeader, sniffFileType, TEXT_EXTENSIONS,
  DETECT_CANDIDATES, resolveCandidatePath,
  SENSITIVE_PATTERNS, isSensitive, keyFile, masterFile,
  getMasterSecret, getOrCreateKey, encryptSensitive, decryptSensitive,
  storeObject, commitRecord, ensureLibrary, loadIndex, saveIndex, makeId,
} from "./core.mjs";

const name = "mega-index-map";
const inject = ["tools"];

// Register default media providers (ffprobe + MediaInfo).
registerDefaultMediaProvider();

function apply(ctx) {
  // ---- ④ Prevent waking outside DeepSeek Harness ----
  // Only register tools in a DSH host environment, identified by the DSH_HOME env var
  // (which the DSH host always sets). Outside DSH (bare node, other agent frameworks),
  // no library tools are registered, so the plugin cannot be woken externally.
  if (!process.env.DSH_HOME) {
    appendLog({ op: "gate", type: null, name: null, source: null, disposition: null, detail: "not a DSH host, refusing to register tools" });
    return;
  }

  // ---- library_record: record one encountered object into the library ----
  ctx.tools.register(defineTool({
    name: "library_record",
    description:
      "Record a valuable object (tool, file, environment, product, knowledge, work record, etc.) encountered during work into the cross-workspace Library. Examples: an executable tool found in a workspace, a path/port/service in use, a produced file, a research conclusion or work record. Record one object per call; source and type are required.",
    parameters: {
      type: {
        type: "string",
        required: true,
        description: "Object type: tool|plugin|env|file|product|knowledge|persona|image|document|table|audio|work_record|log|workspace|reference|other",
      },
      name: { type: "string", required: true, description: "Object name, e.g. 'game-drive.ps1' / 'llm_toolkit_api' / 'daily report'" },
      source: { type: "string", required: true, description: "Source workspace/directory, e.g. '%TOOLCHAIN_HOME%' or '%TOOLCHAIN_HOME%\\\\sibling-checkout'" },
      path: { type: "string", description: "Absolute path of the object (tool/file/directory); for env/port, an address" },
      description: { type: "string", description: "One-line purpose/description" },
      tags: {
        type: "array",
        items: { type: "string" },
        description: "Tags such as workspace/tool/python/sdk/game/vtuber/summary (used for retrieval filtering)",
      },
      summary: { type: "string", description: "Extra structured summary (may be multiline)" },
      links: {
        type: "array",
        items: { type: "string" },
        description: "Cross-object links: object ids or 'type:name:source' keys to associate; stored as the object's related list",
      },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          id: { type: "string" },
          ok: { type: "boolean" },
          count: { type: "number" },
          changed: { type: "boolean" },
          disposition: { type: "string" },
          message: { type: "string" },
        },
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value) }],
    },
    execute: TOOLS.find((t) => t.name === "library_record").execute,
  }));

  // ---- library_index: rebuild/dedupe index (+ conflict report) ----
  ctx.tools.register(defineTool({
    name: "library_index",
    description:
      "Rebuild/clean the Library index: dedupe (by type+name+source), sort by createdAt, rewrite index.json. When merging same-key objects with different content fingerprints, the dropped version is recorded in conflicts (no silent information loss). Returns total count, store path, and conflict list.",
    parameters: {},
    output: {
      schema: { type: "object", additionalProperties: false, properties: { count: { type: "number" }, store: { type: "string" }, conflicts: { type: "array", items: { type: "object", additionalProperties: true } } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    execute: TOOLS.find((t) => t.name === "library_index").execute,
  }));

  // ---- library_query: search the Library (index/use/research/learn) ----
  ctx.tools.register(defineTool({
    name: "library_query",
    description:
      "Search recorded objects in the cross-workspace Library. Filter by keyword (matches name/description/summary/source), type, and tags. Used to: let new conversations inherit past records, research/learn what tools a workspace used, and locate a path/service/record.",
    parameters: {
      query: { type: "string", description: "Free-text keyword, e.g. 'ffmpeg' / 'game automation' / 'vtuber daily'" },
      type: { type: "string", description: "Filter by type: tool|plugin|env|file|product|knowledge|persona|image|document|table|audio|work_record|log|workspace|reference|other" },
      tags: {
        type: "array",
        items: { type: "string" },
        description: "Filter by tags, e.g. ['game'] or ['python','sdk']",
      },
      limit: { type: "number", description: "Max results, default 20, max 100" },
      cursor: { type: "string", description: "Pagination cursor: pass the previous nextCursor to continue (stream/batch)" },
      pageSize: { type: "number", description: "Page size with cursor: return this many per page (defaults to limit)" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          count: { type: "number" },
          nextCursor: { type: "string" },
          results: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: true,
            },
          },
        },
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    execute: TOOLS.find((t) => t.name === "library_query").execute,
  }));

  // ---- ③ library_detect: scan known tools/environments/toolchains and register them ----
  // Registers only existing candidates; installing missing ones requires an instruction
  // plus a per-item report (this tool only registers by default).
  ctx.tools.register(defineTool({
    name: "library_detect",
    description:
      "Scan the machine's known handy tools/environments/toolchains (MediaInfo/ffmpeg/uv/llm_toolkit_api/DSH_HOME/SDK/VS, etc.), register the ones that actually exist into the Library, and report what was found. Used to bootstrap the index on install/init. Installing missing tools is NOT done here (requires instruction + report).",
    parameters: {
      force: { type: "boolean", description: "When true, re-scan and register even if already present; default skips already-registered items to avoid duplicates" },
      cross: { type: "boolean", description: "When true, cross-check scanned items against known objects and list items not yet in the Library" },
    },
    output: {
      schema: { type: "object", additionalProperties: false, properties: { found: { type: "number" }, registered: { type: "number" }, results: { type: "array", items: { type: "object", additionalProperties: true } }, cross: { type: "array", items: { type: "object", additionalProperties: true } } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    execute: TOOLS.find((t) => t.name === "library_detect").execute,
  }));

  // ---- library_sniff: identify true type by file header (7-Zip/Bandizip approach, extension-independent) ----
  ctx.tools.register(defineTool({
    name: "library_sniff",
    description:
      "Identify a file/object's true type (archive/image/audio/video/executable/document, etc.) from its magic header bytes, independent of a spoofable extension. Use to determine the real format of a file with no/suspicious extension, or to corroborate a type for library_record. Returns {type, format, note}.",
    parameters: {
      path: { type: "string", required: true, description: "Absolute path of the file to identify" },
    },
    output: {
      schema: { type: "object", additionalProperties: false, properties: { ok: { type: "boolean" }, detected: { type: "boolean" }, type: { type: "string" }, format: { type: "string" }, note: { type: "string" } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value) }],
    },
    execute: TOOLS.find((t) => t.name === "library_sniff").execute,
  }));

  // ---- library_decrypt: manually decrypt a sensitive object (never auto-decrypt) ----
  ctx.tools.register(defineTool({
    name: "library_decrypt",
    description:
      "Manually decrypt an encrypted-isolated sensitive object (sensitive:true). Call only when the user explicitly needs to read its content; never auto-decrypt in any query. Returns the decrypted full object; if the object is not sensitive it is returned as-is.",
    parameters: {
      id: { type: "string", required: true, description: "Object id to decrypt (the id of a sensitive item from library_query)" },
    },
    output: {
      schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean" }, object: { type: "object", additionalProperties: true }, message: { type: "string" } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    execute: TOOLS.find((t) => t.name === "library_decrypt").execute,
  }));

  // ---- library_export: export/migrate the Library to standard JSON/NDJSON ----
  ctx.tools.register(defineTool({
    name: "library_export",
    description:
      "Export the Library to standard JSON (or NDJSON). Sensitive objects stay encrypted (__content is not decrypted), so no plaintext is included. For cross-machine migration, backup, or sharing with other environments. path optional; defaults to a timestamped export-*.json in the library directory.",
    parameters: {
      format: { type: "string", description: "json | ndjson; default json" },
      path: { type: "string", description: "Absolute export target path; defaults to the library directory" },
    },
    output: {
      schema: { type: "object", additionalProperties: false, properties: { ok: { type: "boolean" }, file: { type: "string" }, count: { type: "number" } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value) }],
    },
    execute: TOOLS.find((t) => t.name === "library_export").execute,
  }));

  // ---- library_encoding: detect system default encoding and give indicative guidance ----
  // Reports the host's system default encoding, whether it is UTF-8 compatible, and (if not)
  // region-aware indicative commands to switch to UTF-8 so the plugin lands without mojibake.
  ctx.tools.register(defineTool({
    name: "library_encoding",
    description:
      "Detect the host's system default encoding and report compatibility plus region-aware indicative guidance (Japan/Korea/Southeast Asia/China-Taiwan/Europe/Latin America). The library always persists as UTF-8; if the system default is NOT UTF-8, external-tool output and file reads may mojibake. Use this to advise the user on how to set UTF-8 so the plugin works without mojibake.",
    parameters: {},
    output: {
      schema: { type: "object", additionalProperties: false, properties: { utf8: { type: "boolean" }, codepage: { type: "number" }, label: { type: "string" }, hints: { type: "array", items: { type: "object", additionalProperties: true } } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    execute: TOOLS.find((t) => t.name === "library_encoding").execute,
  }));

  // ---- library_adb: legitimate Android device management via adb ----
  // Wraps the developer-side ADB operations only (no Metasploit/DoS/SMS/bulk-privacy-copy).
  ctx.tools.register(defineTool({
    name: "library_adb",
    description:
      "Manage an Android device over ADB (Android Debug Bridge) with legitimate developer operations only. Actions: devices, restart-server, reboot, reboot-recovery, reboot-bootloader, shell, info-system, info-cpu, info-memory, device-details, bugreport, install, uninstall, list-packages, logcat, push, pull, launch, screenshot, screenrecord, root-check, remote-connect. Requires USB debugging enabled on the device. Use on your own test device only.",
    parameters: {
      action: {
        type: "string",
        required: true,
        description: "Operation: devices|restart-server|reboot|reboot-recovery|reboot-bootloader|shell|info-system|info-cpu|info-memory|device-details|bugreport|install|uninstall|list-packages|logcat|push|pull|launch|screenshot|screenrecord|root-check|remote-connect",
      },
      device: { type: "string", description: "Device serial (from 'devices'); omit for single device" },
      command: { type: "string", description: "Shell command to run on device (action=shell)" },
      package: { type: "string", description: "Package name (action=install/uninstall/launch)" },
      apk: { type: "string", description: "Local APK path (action=install)" },
      local: { type: "string", description: "Local file/folder path (action=push/pull; also screenshot/screenrecord output)" },
      remote: { type: "string", description: "Device path (action=push/pull)" },
      target: { type: "string", description: "ip:port to connect (action=remote-connect)" },
      lines: { type: "number", description: "Logcat line count (default 100)" },
      seconds: { type: "number", description: "Screenrecord duration seconds (default 10, max 180)" },
      record: { type: "boolean", description: "When true, record this operation into the Library as a work_record" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          ok: { type: "boolean" },
          action: { type: "string" },
          code: { type: "number" },
          out: { type: "string" },
          err: { type: "string" },
          local: { type: "string" },
          recorded: { type: "boolean" },
        },
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    execute: TOOLS.find((t) => t.name === "library_adb").execute,
  }));
}

export { name, inject, apply };
