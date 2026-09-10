// mega-index-map - cross-workspace interop Library (DSH host plugin).
//
// Maintains a cross-workspace object library under $DSH_HOME/library and registers
// library_record / library_index / library_query / library_detect / library_sniff /
// library_decrypt / library_export / library_encoding / library_adb.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { defineTool } from "@deepseek-ai/dsh-tools";

// Field length caps: guard against overlong/malformed input polluting the library
// (applies to name/description/summary/source/path).
const MAX_LEN = { name: 200, source: 300, path: 500, description: 1000, summary: 4000 };

function clampField(v, key) {
  if (typeof v !== "string") return "";
  const max = MAX_LEN[key] || 500;
  return v.length > max ? v.slice(0, max) : v;
}

// DSH home: library storage root. node_modules may be read-only or cleaned on update,
// so the library always lives under DSH_HOME.
function dshHome() {
  return process.env.DSH_HOME || path.join(os.homedir(), ".dsh");
}

function libraryDir() {
  return path.join(dshHome(), "library");
}

// Index file: a JSON manifest + objects array.
function indexFile() {
  return path.join(libraryDir(), "index.json");
}

// Directory for raw object payloads (optional; keeps index.json lean).
function payloadDir() {
  return path.join(libraryDir(), "objects");
}

// Allowed object types (enum-like set, prevents arbitrary strings polluting schema).
const OBJ_TYPES = new Set([
  "tool",          // executable tool / script / program
  "plugin",        // DSH plugin / extension
  "env",           // environment fact (path, variable, service, port)
  "file",          // file / folder (artifact, output dir)
  "product",       // product / deliverable (build, release)
  "knowledge",     // knowledge (doc, note, conclusion)
  "persona",       // persona / character card (immutable file)
  "image",         // image (immutable file)
  "document",      // document (immutable file)
  "table",         // table (immutable file)
  "audio",         // audio (immutable file)
  "work_record",   // work record (session, log, daily report, runtime state)
  "log",           // log (immutable file)
  "workspace",     // a workspace itself
  "reference",     // external reference / dependency (cross-directory external object)
  "other",         // fallback
]);

// Type -> change-disposition policy:
//   "verify"  : auto-verifiable (tool/plugin/env). On content change, record it and
//               notify DSH to check, outputting the result to the user.
//   "confirm" : immutable-file class (persona/image/document/table/audio/work_record/
//               log/file). On content change, do NOT auto-overwrite; force the user to
//               confirm the change or explain it.
const DISPOSITION = {
  tool: "verify",
  plugin: "verify",
  env: "verify",
  persona: "confirm",
  image: "confirm",
  document: "confirm",
  table: "confirm",
  audio: "confirm",
  work_record: "confirm",
  log: "confirm",
  file: "confirm",
  product: "confirm",
  knowledge: "confirm",
  workspace: "confirm",
  reference: "confirm",
  other: "confirm",
};

function dispositionFor(type) {
  return DISPOSITION[type] || "confirm";
}

// Change detection: fingerprint the substantive fields (everything except type/name/source).
function fingerprint(o) {
  return JSON.stringify([o.path || "", o.description || "", o.summary || "", (o.tags || []).slice().sort(), (o.related || []).slice().sort()]);
}

// ---------- Media evidence (pluggable providers) ----------
// Each media type can go through a dedicated analyzer (provider); adding a new format only
// requires registering a new provider without touching core logic.
// Provider shape: { match(ext) -> bool, async analyze(filePath) -> {ok, detail} }
const MEDIA_PROVIDERS = [];

// Register built-in media analysis engines: ffprobe (same ffmpeg family used by
// XSplit/PotPlayer; present on this machine) + MediaInfo.
// Both are generic fallback providers (match always true); mediaFingerprint tries each
// in order and returns on the first success.
function registerDefaultMediaProvider() {
  // 1) ffprobe engine (codecs/duration/streams) - resolve across platforms.
  const ffprobe = resolveTool(
    "FFPROBE_PATH",
    [
      "%TOOLCHAIN_HOME%\\\\bin\\ffprobe.exe",           // Windows (this machine)
      "/usr/bin/ffprobe", "/usr/local/bin/ffprobe", "/opt/homebrew/bin/ffprobe", // macOS/Linux
    ],
    "ffprobe"
  );
  MEDIA_PROVIDERS.push({
    name: "ffprobe",
    match: () => true,
    async analyze(filePath) {
      if (!ffprobe) return { ok: false, detail: "ffprobe not available" };
      const r = await runSilent(ffprobe, ["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", filePath], { timeoutMs: 20000 });
      if (!r.ok || !r.out) return { ok: false, detail: r.err.slice(0, 120) || "ffprobe produced no output" };
      try {
        const j = JSON.parse(r.out);
        const fmt = j.format || {};
        const streams = j.streams || [];
        const v = streams.filter((s) => s.codec_type === "video");
        const a = streams.filter((s) => s.codec_type === "audio");
        const format = fmt.format_name || "";
        const duration = fmt.duration ? ` ${Math.round(parseFloat(fmt.duration))}s` : "";
        return { ok: true, detail: `[ffprobe] ${format} ${v.length}V/${a.length}A${duration}` };
      } catch (e) {
        return { ok: false, detail: String(e && e.message || e).slice(0, 120) };
      }
    },
  });
  // 2) MediaInfo engine (detailed General metadata) - resolve across platforms.
  const exe = resolveTool(
    "MEDIAINFO_PATH",
    [
      "%TOOLCHAIN_HOME%\\\\downloads\\mediainfo-cli\\MediaInfo.exe",        // Windows (this machine)
      "/usr/bin/mediainfo", "/usr/local/bin/mediainfo", "/opt/homebrew/bin/mediainfo", // macOS/Linux
    ],
    "mediainfo"
  );
  MEDIA_PROVIDERS.push({
    name: "mediainfo",
    match: () => true,
    async analyze(filePath) {
      if (!exe) return { ok: false, detail: "MediaInfo CLI not available" };
      if (!fs.existsSync(filePath)) return { ok: false, detail: "path does not exist, skipping media evidence" };
      const r = await runSilent(exe, ["--Output=JSON", filePath], { timeoutMs: 20000 });
      if (!r.ok || !r.out) return { ok: false, detail: r.err.slice(0, 120) || "analysis produced no output" };
      try {
        const j = JSON.parse(r.out);
        const media = j && j.media;
        const tracks = (media && media.track) || [];
        const gen = tracks.find((t) => t["@type"] === "General") || {};
        const format = gen.Format || "?";
        const profile = gen.Format_Profile || "";
        const video = gen.VideoCount || "0";
        const audio = gen.AudioCount || "0";
        const ext = gen.FileExtension || "";
        return { ok: true, detail: `[MediaInfo] ${format}${profile ? `(${profile})` : ""} ${video}V/${audio}A ${ext ? `[${ext}]` : ""}${gen.Duration ? ` ${gen.Duration}` : ""}` };
      } catch (e) {
        return { ok: false, detail: String(e && e.message || e).slice(0, 120) };
      }
    },
  });
}

// Media analysis entry: try extension-specific provider, then all generic providers,
// then fall back to file-header signature sniffing. Returns { ok, detail }.
async function mediaFingerprint(filePath) {
  if (!filePath) return { ok: false, detail: "no path" };
  if (!fs.existsSync(filePath)) return { ok: false, detail: "path does not exist, skipping media evidence" };
  const ext = path.extname(filePath).toLowerCase().replace(".", "");
  // 1) extension-specific provider
  const specific = MEDIA_PROVIDERS.find((p) => p.match(ext));
  if (specific) {
    const r = await specific.analyze(filePath);
    if (r.ok) return r;
  }
  // 2) generic providers (ffprobe, mediainfo) in order
  for (const p of MEDIA_PROVIDERS.filter((x) => x.match(true))) {
    const r = await p.analyze(filePath);
    if (r.ok) return r;
  }
  // 3) file-header signature fallback (7-Zip/Bandizip approach)
  const sniff = (typeof sniffFileType === "function") ? sniffFileType(filePath) : null;
  if (sniff) return { ok: true, detail: `[signature] ${sniff.format} (${sniff.note})` };
  return { ok: false, detail: "unrecognized (no ffprobe/MediaInfo output and unknown signature)" };
}

// JSONL append log (generic, greppable, non-growing). Line shape: {ts, op, type, name, source, disposition, detail}
function appendLog(entry) {
  try {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
    fs.appendFileSync(path.join(libraryDir(), "log.jsonl"), line, "utf8");
  } catch {}
}

// ---------- Silent external tool invocation ----------
// Unified child_process.spawn wrapper with windowsHide:true to hide console windows
// (especially uv/CLI tools), preventing the plugin from popping unwanted windows.
// Has timeout protection; on failure returns {ok:false, err}.
import { spawn, spawnSync } from "node:child_process";

function runSilent(exe, args, { timeoutMs = 30000, maxOut = 2 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(exe, args, { windowsHide: true });
    } catch (e) {
      resolve({ ok: false, err: String(e && e.message || e), out: "" });
      return;
    }
    let out = "", err = "", done = false;
    const finish = (rc) => {
      if (done) return;
      done = true;
      resolve({ ok: rc === 0, code: rc, out, err });
    };
    child.stdout.on("data", (d) => { if (out.length < maxOut) out += d; });
    child.stderr.on("data", (d) => { if (err.length < maxOut) err += d; });
    child.on("close", finish);
    child.on("error", (e) => { err = String(e && e.message || e); finish(-1); });
    setTimeout(() => { if (!done) { try { child.kill(); } catch {} finish(-2); } }, timeoutMs);
  });
}

// ---------- Cross-platform tool resolution ----------
// Resolve an external tool's executable path across platforms. Priority:
//   1) explicit env var (e.g. FFPROBE_PATH / MEDIAINFO_PATH)
//   2) a per-platform list of common absolute paths (if file exists)
//   3) plain command name (relies on PATH via spawn; ffprobe/mediainfo are on PATH on most Unix systems)
// Returns the best candidate string, or null if nothing looks usable.
function resolveTool(envName, candidates, commandName) {
  if (process.env[envName]) return process.env[envName];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  // Last resort: bare command name - spawn will resolve it from PATH.
  return commandName || null;
}

// ---------- ADB device management (legitimate subset) ----------
// ADB-Toolkit (github.com/ASHWIN990/ADB-Toolkit) is a penetration-testing Bash script.
// This plugin integrates ONLY its legitimate Android-developer operations (device listing,
// install/uninstall, launch, shell, logcat, screenshot/screenrecord, root-check, reboot,
// pull/push, wireless connect). Its offensive sections (Metasploit payload, hang-the-phone
// DoS, send SMS, bulk-copy camera/downloads/WhatsApp/full storage) are deliberately NOT
// implemented here.
function adbPath() {
  return resolveTool(
    "ADB_PATH",
    ["%TOOLCHAIN_HOME%\\\\adb.exe", "/usr/bin/adb", "/usr/local/bin/adb", "/opt/homebrew/bin/adb"],
    "adb"
  );
}

// Run adb with an optional device serial (-s). Silent (windowsHide), timeout-capped.
async function runAdb(args, { timeoutMs = 30000, device = "" } = {}) {
  const adb = adbPath();
  if (!adb) return { ok: false, code: -1, out: "", err: "adb not found (set ADB_PATH or install Android platform-tools)" };
  const full = device ? ["-s", device, ...args] : args;
  return runSilent(adb, full, { timeoutMs, maxOut: 512 * 1024 });
}

// Legitimate ADB action catalogue (one tool, action-keyed). `need` = required tool args;
// `args(a)` maps tool args -> adb argv; special actions are handled inline in execute.
const ADB_ACTIONS = {
  devices: { args: () => ["devices", "-l"] },
  "restart-server": { restart: true },
  reboot: { args: () => ["reboot"] },
  "reboot-recovery": { args: () => ["reboot", "recovery"] },
  "reboot-bootloader": { args: () => ["reboot", "bootloader"] },
  shell: { args: (a) => ["shell", a.command], need: ["command"] },
  "info-system": { args: () => ["shell", "getprop"] },
  "info-cpu": { args: () => ["shell", "cat", "/proc/cpuinfo"] },
  "info-memory": { args: () => ["shell", "cat", "/proc/meminfo"] },
  "device-details": { details: true },
  bugreport: { args: () => ["bugreport"], timeoutMs: 60000 },
  install: { args: (a) => ["install", "-r", a.apk], need: ["apk"], timeoutMs: 120000 },
  uninstall: { args: (a) => ["uninstall", a.package], need: ["package"] },
  "list-packages": { args: () => ["shell", "pm", "list", "packages"] },
  logcat: { args: (a) => ["logcat", "-d", "-t", String(a.lines || 100)] },
  push: { args: (a) => ["push", a.local, a.remote], need: ["local", "remote"] },
  pull: { args: (a) => ["pull", a.remote, a.local], need: ["remote", "local"] },
  launch: { args: (a) => ["shell", "monkey", "-p", a.package, "-c", "android.intent.category.LAUNCHER", "1"], need: ["package"] },
  screenshot: { screenshot: true },
  screenrecord: { screenrecord: true },
  "root-check": { args: () => ["shell", "which", "su"] },
  "remote-connect": { args: (a) => ["connect", a.target], need: ["target"] },
};

// ---------- Encoding detection + indicative adaptation ----------
// The library always persists as UTF-8 (the most stable choice). But if the host's
// system default encoding is NOT UTF-8 (common across East Asia / some EU / LATAM
// locales), external-tool output and file reads can mojibake. This module detects the
// system default encoding and issues indicative guidance so the plugin lands without
// mojibake. It never rewrites the library; it only reports and advises.

// Region -> common legacy encodings -> indicative guidance (for future DSH regional builds
// or hosts whose system default encoding is not UTF-8).
const INDICATIVE_ENCODING_HINTS = [
  { region: "Japan (Japanese)", codepages: [932, 51932, 50220, 50221], labels: ["Shift-JIS", "EUC-JP", "ISO-2022-JP"], hint: "Set the terminal/system to UTF-8 (chcp 65001 on Windows; LANG=en_US.UTF-8 or ja_JP.UTF-8 on Unix)." },
  { region: "Korea (Korean)", codepages: [949, 51949], labels: ["EUC-KR", "CP949"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=ko_KR.UTF-8 on Unix)." },
  { region: "Southeast Asia (Thai/Vietnamese/Indonesian)", codepages: [874], labels: ["Windows-874 (Thai)"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=th_TH.UTF-8 / vi_VN.UTF-8 / id_ID.UTF-8 on Unix)." },
  { region: "China / Taiwan / Hong Kong (Chinese)", codepages: [936, 950], labels: ["GBK/GB2312", "Big5"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=zh_CN.UTF-8 / zh_TW.UTF-8 on Unix)." },
  { region: "Europe (Western/Central/Eastern)", codepages: [1250, 1251, 1252, 1253, 1254, 1257], labels: ["Windows-1250/1251/1252/1253/1254/1257", "ISO-8859-x"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=en_US.UTF-8 / de_DE.UTF-8 / fr_FR.UTF-8 / ru_RU.UTF-8 on Unix)." },
  { region: "Latin America (Spanish/Portuguese)", codepages: [1252, 28591], labels: ["Windows-1252", "ISO-8859-1 (Latin-1)"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=es_ES.UTF-8 / pt_BR.UTF-8 on Unix)." },
];

// Detect the current system default encoding (best effort).
// Returns { codepage, label, utf8 } - codepage/label may be null if unknown.
function detectSystemEncoding() {
  if (process.platform === "win32") {
    // Windows: chcp reports the active console code page (65001 = UTF-8).
    return detectSystemEncodingSync();
  }
  // Unix: derive from LANG/LC_ALL locale.
  const lang = process.env.LANG || process.env.LC_ALL || process.env.LC_CTYPE || "";
  if (/utf-?8/i.test(lang)) return { codepage: null, label: "UTF-8", utf8: true };
  if (/shift.?jis|ja/i.test(lang)) return { codepage: 932, label: "Shift-JIS", utf8: false };
  if (/euc.?kr|ko/i.test(lang)) return { codepage: 949, label: "EUC-KR/CP949", utf8: false };
  if (/gb|zh/i.test(lang)) return { codepage: 936, label: "GBK/GB2312", utf8: false };
  if (/big5/i.test(lang)) return { codepage: 950, label: "Big5", utf8: false };
  if (/8859-1|latin-?1|es|pt|fr|de|it/i.test(lang)) return { codepage: 28591, label: "ISO-8859-1 (Latin-1)", utf8: false };
  if (/1252|cp1252/i.test(lang)) return { codepage: 1252, label: "Windows-1252", utf8: false };
  return { codepage: null, label: lang || "unknown", utf8: false };
}

// Sync fallback for Windows code page detection (avoids making detectSystemEncoding async).
function detectSystemEncodingSync() {
  try {
    const r = spawnSync("cmd", ["/c", "chcp"], { encoding: "utf8", windowsHide: true, timeout: 5000 });
    const out = (r.stdout || "") + (r.stderr || "");
    const m = out.match(/(\d+)/);
    const cp = m ? parseInt(m[1], 10) : null;
    if (cp === 65001) return { codepage: 65001, label: "UTF-8", utf8: true };
    if (cp === 936) return { codepage: 936, label: "GBK/GB2312", utf8: false };
    if (cp === 932) return { codepage: 932, label: "Shift-JIS", utf8: false };
    if (cp === 949) return { codepage: 949, label: "EUC-KR/CP949", utf8: false };
    if (cp === 950) return { codepage: 950, label: "Big5", utf8: false };
    if (cp === 874) return { codepage: 874, label: "Windows-874 (Thai)", utf8: false };
    if (cp === 1252) return { codepage: 1252, label: "Windows-1252", utf8: false };
    return { codepage: cp, label: `CP${cp}`, utf8: false };
  } catch {
    return { codepage: null, label: "unknown", utf8: false };
  }
}

// ---------- File signature recognition (magic bytes) ----------
// Identify a file's true type from its header bytes rather than a spoofable/changeable
// extension. Coverage: archives / common images / audio / video / executables / documents.
// Extend by appending entries to FILE_SIGNATURES.
// Note: signature table is compiled from public format specs and open-source recognition
// approaches (e.g. 7-Zip's 7zHeader.h); licenses are independent (see README).
const FILE_SIGNATURES = [
  // Archives / containers
  { sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], type: "archive", format: "7z", note: "7-Zip archive (37 7A BC AF 27 1C)" },
  { sig: [0x50, 0x4B, 0x03, 0x04], type: "archive", format: "zip", note: "ZIP / ZIP-based format (incl. docx/xlsx - disambiguate by extension)" },
  { sig: [0x50, 0x4B, 0x07, 0x08], type: "archive", format: "zip-spanned", note: "ZIP spanned/empty header" },
  { sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], type: "archive", format: "rar", note: "RAR archive" },
  { sig: [0x1F, 0x8B], type: "archive", format: "gzip", note: "GZIP" },
  { sig: [0x42, 0x5A, 0x68], type: "archive", format: "bzip2", note: "BZip2" },
  { sig: [0x28, 0xB5, 0x2F, 0xFD], type: "archive", format: "zstd", note: "Zstandard" },
  { sig: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], type: "archive", format: "xz", note: "XZ compressed stream (FD 37 7A 58 5A 00)" },
  { sig: [0x5D, 0x00, 0x00], type: "archive", format: "lzma", note: "LZMA-Alone stream (5D 00 00 prefix)" },
  { sig: [0x75, 0x73, 0x74, 0x61, 0x72], type: "archive", format: "tar", note: "TAR (ustar header)" },
  { sig: [0x4D, 0x50, 0x51, 0x1A], type: "archive", format: "mpq", note: "Blizzard MPQ archive (StarCraft/Warcraft, MPQ header)" },
  { sig: [0x43, 0x50, 0x4B, 0x20], type: "archive", format: "cri-cpk", note: "CRIWARE CPK container (CPK header)" },
  // Images (incl. game/engine resource formats)
  { sig: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], type: "image", format: "png", note: "PNG (8-byte header)" },
  { sig: [0xFF, 0xD8, 0xFF], type: "image", format: "jpeg", note: "JPEG (FF D8 FF)" },
  { sig: [0x42, 0x4D], type: "image", format: "bmp", note: "BMP (BM)" },
  { sig: [0x47, 0x49, 0x46, 0x38], type: "image", format: "gif", note: "GIF (GIF8)" },
  { sig: [0x49, 0x49, 0x2A, 0x00], type: "image", format: "tiff-le", note: "TIFF (II little-endian)" },
  { sig: [0x4D, 0x4D, 0x00, 0x2A], type: "image", format: "tiff-be", note: "TIFF (MM big-endian)" },
  { sig: [0x54, 0x4C, 0x47, 0x35, 0x2E, 0x30, 0x00, 0x00], type: "image", format: "tlg5", note: "KiriKiri/Emote TLG5 image (TLG5.0)" },
  { sig: [0x54, 0x4C, 0x47, 0x36, 0x2E, 0x30, 0x00, 0x00], type: "image", format: "tlg6", note: "KiriKiri/Emote TLG6 image (TLG6.0)" },
  { sig: [0x32, 0x2E, 0x30, 0x4E], type: "image", format: "aoe-slp", note: "Age of Empires graphics (SLP, 2.0N + ArtDesk header)" },
  { sig: [0x00, 0x00, 0x01, 0x00], type: "image", format: "ico", note: "Windows icon (ICO)" },
  // Audio
  { sig: [0x49, 0x44, 0x33], type: "audio", format: "mp3", note: "MP3 (ID3 tag)" },
  { sig: [0x4F, 0x67, 0x67, 0x53], type: "audio", format: "ogg", note: "OGG (OggS)" },
  { sig: [0x66, 0x4C, 0x61, 0x43], type: "audio", format: "flac", note: "FLAC (fLaC)" },
  { sig: [0x4D, 0x41, 0x43, 0x20], type: "audio", format: "ape", note: "Monkey's Audio APE (MAC )" },
  { sig: [0x44, 0x53, 0x44, 0x20], type: "audio", format: "dsf", note: "Sony DSF (DSD Stream File, 'DSD ' header)" },
  // VST presets
  { sig: [0x43, 0x63, 0x6E, 0x4B], type: "audio", format: "vst-preset", note: "VST preset (.fxp/.fxb, magic CcnK)" },
  { sig: [0x4D, 0x54, 0x68, 0x64], type: "audio", format: "midi", note: "MIDI (MThd header)" },
  { sig: [0x46, 0x4C, 0x68, 0x64], type: "audio", format: "fl-studio", note: "FL Studio project (FLhd header)" },
  { sig: [0x43, 0x41, 0x54, 0x20], type: "audio", format: "rex2", note: "Propellerhead REX2 sample (CAT  + REX2)" },
  { sig: [0x4E, 0x45, 0x58, 0x55, 0x53], type: "audio", format: "nexus-preset", note: "Nexus preset/arp (NEXUS2 header)" },
  { sig: [0x5A, 0x54, 0x44, 0x53], type: "audio", format: "ztdw-sample", note: "ZTDW compressed sample (ZTDS header)" },
  { sig: [0x46, 0x4D, 0x69, 0x63], type: "audio", format: "fabfilter-preset", note: "FabFilter preset (FMic header)" },
  { sig: [0x32, 0x50, 0x4D, 0x44, 0x43], type: "audio", format: "fl-drum-patch", note: "FL Studio drum patch (2PMDCrash header)" },
  { sig: [0x32, 0x69, 0x42, 0x54], type: "audio", format: "fl-tbio", note: "FL Studio binary (2iBT header)" },
  { sig: [0x42, 0x4B, 0x48, 0x44], type: "audio", format: "wwise-bnk", note: "Wwise sound bank (BKHD header)" },
  { sig: [0x46, 0x52, 0x4D, 0x32], type: "audio", format: "vocaloid-db", note: "Vocaloid voice DB (FRM2 header)" },
  // Game resources
  { sig: [0x55, 0x6E, 0x69, 0x74, 0x79, 0x46, 0x53], type: "game", format: "unity-asset", note: "Unity asset bundle (UnityFS header)" },
  // Video / containers
  { sig: [0x4D, 0x4F, 0x4F, 0x56], type: "video", format: "mov/mp4-qt", note: "QuickTime/MOV (moov)" },
  { sig: [0x1A, 0x45, 0xDF, 0xA3], type: "video", format: "mkv/webm", note: "Matroska/WebM (EBML)" },
  { sig: [0x47, 0x40], type: "video", format: "mpeg-ts", note: "MPEG-2 transport stream (TS/live)" },
  { sig: [0x46, 0x4C, 0x56], type: "video", format: "flv", note: "Flash Video (FLV)" },
  // Executables / system
  { sig: [0x4D, 0x5A], type: "executable", format: "pe", note: "Windows executable (MZ, PE/EXE/DLL)" },
  { sig: [0x7F, 0x45, 0x4C, 0x46], type: "executable", format: "elf", note: "ELF (Linux executable/object/shared lib)" },
  // Documents
  { sig: [0x25, 0x50, 0x44, 0x46], type: "document", format: "pdf", note: "PDF (%PDF)" },
  { sig: [0x7B, 0x5C, 0x72, 0x74, 0x66], type: "document", format: "rtf", note: "Rich Text Format (RTF, 7B 5C 72 74 66)" },
  { sig: [0x49, 0x6E, 0x6E, 0x6F, 0x20, 0x53, 0x65, 0x74, 0x75, 0x70], type: "document", format: "inno-setup", note: "Inno Setup installer/uninstaller data" },
  // Databases
  { sig: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00], type: "database", format: "sqlite", note: "SQLite 3 database (SQLite format 3)" },
  { sig: [0x37, 0x7F, 0x06, 0x82], type: "database", format: "sqlite-wal", note: "SQLite write-ahead log (-wal sidecar)" },
  { sig: [0x37, 0x7F, 0x06, 0x83], type: "database", format: "sqlite-wal", note: "SQLite write-ahead log (-wal sidecar, big-endian checksum)" },
  // Images (additional)
  { sig: [0x38, 0x42, 0x50, 0x53], type: "image", format: "psd", note: "Photoshop PSD (8BPS)" },
  { sig: [0x76, 0x2F, 0x31, 0x01], type: "image", format: "exr", note: "OpenEXR image (magic 0x01312F76)" },
  { sig: [0x50, 0x53, 0x42, 0x00], type: "image", format: "psb", note: "KiriKiri/FreeMote PSB resource (PSB)" },
  // Databases (additional) - placed before TTF because ACE/Jet share the 00 01 00 00 prefix.
  { sig: [0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x41, 0x43, 0x45, 0x20, 0x44, 0x42], type: "database", format: "accdb", note: "Microsoft Access database (Standard ACE DB, ACE 2007+; .accdb/.accde/.accdu/.accda/.acc)" },
  { sig: [0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4A, 0x65, 0x74, 0x20, 0x44, 0x42], type: "database", format: "mdb", note: "Microsoft Access database (Standard Jet DB, Access 97-2003; .mdb/.mde)" },
  // Fonts
  { sig: [0x00, 0x01, 0x00, 0x00], type: "font", format: "ttf", note: "TrueType font (sfnt 0x00010000)" },
  { sig: [0x4F, 0x54, 0x54, 0x4F], type: "font", format: "otf", note: "OpenType CFF font (OTTO)" },
  { sig: [0x77, 0x4F, 0x46, 0x46], type: "font", format: "woff", note: "Web Open Font Format (wOFF)" },
  { sig: [0x77, 0x4F, 0x46, 0x32], type: "font", format: "woff2", note: "Web Open Font Format 2 (wOF2)" },
  // Archives (additional)
  { sig: [0x58, 0x50, 0x33, 0x0D, 0x0A], type: "archive", format: "xp3", note: "KiriKiri XP3 archive (XP3)" },
  { sig: [0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E, 0x0A], type: "archive", format: "ar", note: "ar/COFF static library (!<arch>; .a and MSVC .lib)" },
  // Video / media
  { sig: [0x43, 0x57, 0x53], type: "video", format: "swf", note: "Flash SWF (CWS, zlib-compressed)" },
  { sig: [0x46, 0x57, 0x53], type: "video", format: "swf", note: "Flash SWF (FWS, uncompressed)" },
  // Models / serialization
  { sig: [0x08, 0x06, 0x12, 0x07], type: "model", format: "onnx", note: "ONNX model (protobuf 08 06 12 07)" },
  { sig: [0x80, 0x05], type: "document", format: "pickle", note: "Python pickle (protocol 5, 80 05)" },
  // Documents / other
  { sig: [0x51, 0x43, 0x34, 0x44, 0x43, 0x34, 0x44], type: "document", format: "c4d", note: "Cinema 4D document (QC4DC4D)" },
  { sig: [0x3C, 0x3C, 0x3C, 0x20, 0x4F, 0x72, 0x61, 0x63, 0x6C, 0x65], type: "document", format: "vdi", note: "Oracle VirtualBox disk image (<<< Oracle VM)" },
  // Images (additional)
  { sig: [0x67, 0x69, 0x6D, 0x70, 0x20, 0x78, 0x63, 0x66, 0x20], type: "image", format: "xcf", note: "GIMP XCF image (gimp xcf)" },
  { sig: [0x41, 0x54, 0x26, 0x54, 0x46, 0x4F, 0x52, 0x4D], type: "image", format: "djvu", note: "DjVu document (AT&TFORM)" },
  // Fonts (additional)
  { sig: [0x74, 0x74, 0x63, 0x66], type: "font", format: "ttc", note: "TrueType Collection font (ttcf)" },
  // Archives (additional)
  { sig: [0x4D, 0x53, 0x43, 0x46], type: "archive", format: "cab", note: "Microsoft Cabinet (MSCF)" },
  { sig: [0xED, 0xAB, 0xEE, 0xDB], type: "archive", format: "rpm", note: "RPM package (ED AB EE DB)" },
  // Audio (additional)
  { sig: [0x2E, 0x73, 0x6E, 0x64], type: "audio", format: "au", note: "Sun/NeXT AU audio (.snd)" },
  // Video (additional)
  { sig: [0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C], type: "video", format: "asf", note: "ASF container (WMA/WMV)" },
  { sig: [0x2E, 0x52, 0x4D, 0x46], type: "video", format: "realmedia", note: "RealMedia (RM/RMVB, .RMF)" },
  // Models (additional)
  { sig: [0x47, 0x47, 0x55, 0x46], type: "model", format: "gguf", note: "GGUF model (llama.cpp)" },
  { sig: [0x67, 0x67, 0x6D, 0x6C], type: "model", format: "ggml", note: "GGML model (llama.cpp legacy)" },
  // Web archive
  { sig: [0x57, 0x41, 0x52, 0x43, 0x2F], type: "document", format: "warc", note: "WARC web archive (WARC/)" },
  // Audio (professional - Dolby/DTS)
  { sig: [0x0B, 0x77], type: "audio", format: "ac3", note: "Dolby Digital AC3/E-AC3 (sync 0B 77)" },
  { sig: [0x7F, 0xFE, 0x80, 0x01], type: "audio", format: "dts", note: "DTS audio (sync 7F FE 80 01)" },
  { sig: [0xF8, 0x72, 0x6F, 0xBA], type: "audio", format: "truehd", note: "Dolby TrueHD / MLP (F8 72 6F BA)" },
  // CAD / 3D engineering
  { sig: [0x41, 0x43, 0x31, 0x30], type: "document", format: "dwg", note: "AutoCAD DWG (AC10xx)" },
  { sig: [0x28, 0x44, 0x57, 0x46], type: "document", format: "dwf", note: "Autodesk DWF ((DWF)" },
  { sig: [0x42, 0x4C, 0x45, 0x4E, 0x44, 0x45, 0x52], type: "document", format: "blend", note: "Blender 3D project (BLENDER)" },
  { sig: [0x67, 0x6C, 0x54, 0x46], type: "model", format: "glb", note: "glTF binary (glTF)" },
  // Documents (OLE2 compound)
  { sig: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], type: "document", format: "ole2", note: "OLE2 compound document (DOC/XLS/PPT/INDD/PUB/MSI)" },
  // Disk images
  { sig: [0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78], type: "document", format: "vhd", note: "Virtual Hard Disk (conectix)" },
  { sig: [0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65], type: "document", format: "vhdx", note: "Virtual Hard Disk v2 (vhdxfile)" },
  { sig: [0x51, 0x46, 0x49, 0xFB], type: "document", format: "qcow2", note: "QEMU QCOW2 disk image (QFI FB)" },
  { sig: [0x4D, 0x53, 0x57, 0x49, 0x4D], type: "archive", format: "wim", note: "Windows Imaging Format (MSWIM)" },
  // Scientific / ML data
  { sig: [0x89, 0x48, 0x44, 0x46, 0x0D, 0x0A, 0x1A, 0x0A], type: "model", format: "hdf5", note: "HDF5 scientific data (89 48 44 46)" },
  { sig: [0x93, 0x4E, 0x55, 0x4D, 0x50, 0x59], type: "document", format: "npy", note: "NumPy array (93 NUMPY)" },
  // Professional video exchange
  { sig: [0x06, 0x0E, 0x2B, 0x34, 0x02, 0x05, 0x01, 0x01, 0x0D, 0x01, 0x02, 0x01, 0x01, 0x02], type: "video", format: "mxf", note: "MXF professional media container (KLV key)" },
  // MikuMikuDance / Vocaloid / 3D model formats
  { sig: [0x50, 0x6D, 0x64, 0x00], type: "model", format: "pmd", note: "MikuMikuDance model (PMD, Pmd)" },
  { sig: [0x50, 0x4D, 0x58, 0x20], type: "model", format: "pmx", note: "MikuMikuDance model (PMX)" },
  { sig: [0x50, 0x6F, 0x6C, 0x79, 0x67, 0x6F, 0x6E], type: "document", format: "pmm", note: "MikuMikuDance project (PMM, Polygon Movie maker)" },
  { sig: [0x78, 0x6F, 0x66, 0x20], type: "model", format: "directx", note: "DirectX .x model (xof)" },
  { sig: [0x56, 0x6F, 0x63, 0x61, 0x6C, 0x6F, 0x69, 0x64], type: "document", format: "vpd", note: "Vocaloid/MMD pose data (Vocaloid Pose Data file)" },
  // Developer toolchains (Visual Studio / MSBuild / SQL Server) - headers verified against
  // files shipped with Visual Studio 2022 & 2026 and SSMS 22.
  { sig: [0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20], type: "executable", format: "pdb", note: "Microsoft program database (debug symbols, 'Microsoft C/C++ ')" },
  { sig: [0x4D, 0x53, 0x46, 0x54, 0x02, 0x00], type: "executable", format: "tlb", note: "COM type library (MSFT 2.0 header; .tlb/.olb)" },
  { sig: [0x56, 0x53, 0x57, 0x49, 0x5A, 0x41, 0x52, 0x44, 0x20], type: "document", format: "vsz", note: "Visual Studio wizard (VSWIZARD)" },
  { sig: [0x64, 0x65, 0x78, 0x0A], type: "executable", format: "dex", note: "Android Dalvik executable (dex\\n)" },
  // Help / graphics resources shipped with developer tools (CUR is handled as a special
  // case: its 00 00 02 00 header collides with TGA image-type 2).
  { sig: [0x49, 0x54, 0x53, 0x46], type: "document", format: "chm", note: "Compiled HTML Help (ITSF)" },
  { sig: [0x3F, 0x5F, 0x03, 0x00], type: "document", format: "hlp", note: "Windows Help (HLP 3.x header)" },
  { sig: [0x44, 0x44, 0x53, 0x20], type: "image", format: "dds", note: "DirectDraw Surface texture (DDS )" },
  // OneNote (Office) revision store - file-type GUID at offset 0.
  { sig: [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3], type: "document", format: "one", note: "OneNote section/page (.one; .onepkg is CAB)" },
  { sig: [0xA1, 0x2F, 0xFF, 0x43, 0xD9, 0xEF, 0x76, 0x4C, 0x9E, 0xE2, 0x10, 0xEA, 0x57, 0x22, 0x76, 0x5F], type: "document", format: "onetoc2", note: "OneNote 2007+ index (.onetoc2)" },
];

// ZIP-based (OPC/OOXML) packages share the PK header, so the extension is the only
// discriminator. Verified against Office 2016 / Visual Studio 2022-2026 / SSMS 22 files.
const ZIP_PACKAGE_FORMATS = {
  docx: ["document", "Word document"], docm: ["document", "Word macro-enabled document"],
  dotx: ["document", "Word template"], dotm: ["document", "Word macro-enabled template"],
  xlsx: ["document", "Excel workbook"], xlsm: ["document", "Excel macro-enabled workbook"],
  xlsb: ["document", "Excel binary workbook"], xltx: ["document", "Excel template"],
  xltm: ["document", "Excel macro-enabled template"], xlam: ["document", "Excel add-in"],
  pptx: ["document", "PowerPoint presentation"], pptm: ["document", "PowerPoint macro-enabled presentation"],
  potx: ["document", "PowerPoint template"], potm: ["document", "PowerPoint macro-enabled template"],
  ppsx: ["document", "PowerPoint slide show"], ppsm: ["document", "PowerPoint macro-enabled slide show"],
  thmx: ["document", "Office theme package"],
  accdt: ["document", "Access database template"], accft: ["document", "Access field template"],
  odt: ["document", "ODF text"], ods: ["document", "ODF sheet"], odp: ["document", "ODF presentation"],
  odg: ["document", "ODF graphics"], epub: ["document", "EPUB ebook"],
  dacpac: ["archive", "SQL data-tier application"], vsix: ["archive", "Visual Studio extension"],
  nupkg: ["archive", "NuGet package"], jar: ["archive", "Java archive"],
  appx: ["archive", "Windows app package"], msix: ["archive", "MSIX app package"],
};

// Extension whitelist for text-ish formats that carry no magic header. Used by the
// plain-text heuristic and by the declared-vs-actual forgery check below.
const TEXT_EXTENSIONS = [
  // plain text / scripts / config / dotfiles
  "txt", "md", "log", "csv", "json", "jsonl", "ndjson", "ps1", "sh", "py", "js", "mjs", "cjs", "ts", "bat", "cmd", "yaml", "yml", "ini", "xml", "html", "htm", "css", "toml", "cfg", "conf", "config", "reg", "properties", "plist", "manifest", "nfo", "srt", "vdf", "qml", "mm", "env", "gitignore", "gitattributes", "editorconfig",
  // scratch / temp artifacts (content is whatever the writer put there)
  "tmp", "temp", "part", "partial", "crdownload", "bak", "orig", "swp", "swo", "pid",
  // C family / build systems
  "c", "h", "cpp", "hpp", "cc", "hh", "cs", "cxx", "hxx", "ixx", "inl", "def", "asm", "s", "inc", "cmake", "make", "ninja", "gypi", "m4", "lua", "pl", "awk", "rst", "adoc", "jsx", "tsx", "scss", "less", "vue", "pug", "jade", "coffee", "map", "in",
  // shaders / DCC interchange
  "glsl", "hlsl", "hlsli", "osl", "sl", "cginc", "glslinc", "ocio", "cube", "lut", "look", "itx", "spi1d", "spi3d", "epr", "mtlx", "usda", "svg", "dxf", "step", "stp", "iges", "igs", "obj", "stl", "ply", "gltf", "dae", "x3d", "mtl", "wrl",
  // audio / score / font metadata / app-specific text
  "sfz", "mscx", "afm", "pfm", "inf", "cf", "cfu", "tab", "tsv", "pem", "pth", "mht", "mhtml", "fb2", "vac", "aupreset", "kps", "kpsstats", "effect", "mcfunction", "osu", "osr", "vsclip", "vsstyle", "kys", "ksvlayout",
  // Visual Studio / MSBuild / .NET toolchain (verified against VS 2022-2026 + SSMS 22 files)
  "sln", "vcxproj", "vcxitems", "csproj", "vbproj", "fsproj", "njsproj", "pyproj", "sqlproj", "shproj", "sfproj", "wapproj", "projitems", "props", "targets", "filters", "resx", "resw", "resjson", "xaml", "xamlx", "xsd", "xsl", "xslt", "xlf", "snippet", "vstemplate", "vstemplatex", "vstman", "vsdir", "vstdir", "vsixmanifest", "vsixlangpack", "vsct", "pkgdef", "pkgundef", "ruleset", "natvis", "natjmc", "natstepfilter", "imagemanifest", "tmlanguage", "tmsnippet", "tmtheme", "vssettings", "settings", "myapp", "testsettings", "appinstaller", "appxmanifest", "pubxml", "cscfg", "csdef", "wprp", "webinfo", "package", "spdata", "dgsl", "webpart",
  // SQL Server / data tooling
  "sql", "usql", "dmx", "mdx", "xmla", "mof", "rsp", "tt", "t4", "ttinclude", "rdlc",
  // .NET & web app text
  "vb", "fs", "fsx", "fsi", "aspx", "ascx", "asmx", "ashx", "asax", "cshtml", "vbhtml", "master", "skin", "svc", "sitemap", "psm1", "psd1", "ps1xml", "idl", "odl", "acf", "rc", "rgs",
  // Office text resources
  "xrm-ms", "hxc", "hxt", "hxk",
  // documents / man pages / misc
  "man", "1", "5", "7", "dic", "pyx", "pyi", "f", "f90", "cu", "m",
  // other toolchains
  "go", "lock",
];

// Read the first N bytes (default 8) of a file; returns a Buffer or null on failure.
function readHeader(filePath, len = 8) {
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(len);
    const read = fs.readSync(fd, buf, 0, len, 0);
    fs.closeSync(fd);
    return read > 0 ? buf.subarray(0, read) : null;
  } catch {
    return null;
  }
}

// Match header bytes against the signature table; returns { type, format, note } or null.
function sniffFileType(filePath) {
  const head = readHeader(filePath, 128);
  if (!head) return null;
  const ext = path.extname(filePath).toLowerCase().replace(".", "");
  for (const entry of FILE_SIGNATURES) {
    const sigLen = entry.sig.length;
    if (sigLen > head.length) continue;
    let match = true;
    for (let i = 0; i < sigLen; i++) {
      if (head[i] !== entry.sig[i]) { match = false; break; }
    }
    if (!match) continue;
    // ZIP-based (OPC/OOXML) packages: disambiguate by extension (they all start with PK).
    if (entry.format === "zip") {
      const pkg = ZIP_PACKAGE_FORMATS[ext];
      if (pkg) return { type: pkg[0], format: ext, note: `ZIP-based package (${pkg[1]})` };
    }
    // GZIP-based project: Ableton Live Set (.als) is gzip-compressed XML.
    if (entry.format === "gzip" && ext === "als") {
      return { type: "audio", format: "ableton", note: "Ableton Live Set (gzip-compressed XML)" };
    }
    return { type: entry.type, format: entry.format, note: entry.note };
  }
  // RIFF special-case: bytes 8-11 WAVE->audio/wav, AVI->video/avi, NIKS->NKS sample.
  if (head.length >= 12 && head[0] === 0x52 && head[1] === 0x49 && head[2] === 0x46 && head[3] === 0x46) {
    const kind = head.slice(8, 12).toString("latin1");
    if (kind === "WAVE") return { type: "audio", format: "wav", note: "RIFF-WAVE audio" };
    if (kind === "AVI ") return { type: "video", format: "avi", note: "RIFF-AVI video" };
    if (kind === "NIKS") return { type: "audio", format: "nks", note: "Native Instruments NKS sample (RIFF NIKS)" };
    if (kind === "WEBP") return { type: "image", format: "webp", note: "WebP (RIFF WEBP)" };
    if (kind === "sfbk") return { type: "audio", format: "sf2", note: "SoundFont 2 (RIFF sfbk)" };
    if (kind.startsWith("CDR")) return { type: "image", format: "cdr", note: `CorelDRAW (RIFF ${kind.trim()})` };
    return { type: "audio", format: "riff", note: "RIFF container (unrecognized sub-type)" };
  }
  // AIFF special-case: FORM + AIFF/AIFC at bytes 8-11.
  if (head.length >= 12 && head[0] === 0x46 && head[1] === 0x4F && head[2] === 0x52 && head[3] === 0x4D) {
    const kind = head.slice(8, 12).toString("latin1");
    if (kind === "AIFF" || kind === "AIFC") return { type: "audio", format: "aiff", note: "AIFF audio (FORM + AIFF/AIFC)" };
  }
  // MP4/QuickTime ftyp special-case: 'ftyp' at offset 4. AVIF (AV1 still image) shares
  // the ftyp box but is an image, not video - disambiguate by the major brand.
  if (head.length >= 8 && head[4] === 0x66 && head[5] === 0x74 && head[6] === 0x79 && head[7] === 0x70) {
    const brand = head.slice(8, 12).toString("latin1");
    if (brand === "avif" || brand === "avis") {
      return { type: "image", format: "avif", note: `AVIF (AV1 image, ftyp ${brand})` };
    }
    if (["heic", "heix", "hevc", "hevx", "mif1", "msf1", "hevm", "heim", "heis"].includes(brand)) {
      return { type: "image", format: "heic", note: `HEIC/HEIF image (ftyp ${brand})` };
    }
    return { type: "video", format: "mp4", note: `MP4 (ftyp${brand ? ` ${brand}` : ""})` };
  }
  // Vocaloid DB index special-case: 'DBSe' at offset 8.
  if (head.length >= 12 && head[8] === 0x44 && head[9] === 0x42 && head[10] === 0x53 && head[11] === 0x65) {
    return { type: "audio", format: "vocaloid-db-index", note: "Vocaloid DB index (DBSe at offset 8)" };
  }
  // MOBI/AZW ebook: "BOOKMOBI" or "TEXtREAd" at offset 60.
  if (head.length >= 68) {
    const mtag = head.slice(60, 68).toString("latin1");
    if (mtag === "BOOKMOBI" || mtag === "TEXtREAd") {
      return { type: "document", format: "mobi", note: "Mobipocket/Kindle ebook (MOBI/AZW)" };
    }
  }
  // zlib deflate stream: CMF=0x78 with valid (CMF<<8 | FLG) checksum.
  if (head.length >= 2 && head[0] === 0x78 && (((head[0] << 8) | head[1]) % 31 === 0)) {
    return { type: "archive", format: "zlib", note: "zlib deflate stream" };
  }
  // Mach-O (macOS/iOS executable/library): four magic variants (32/64-bit x endian).
  if (head.length >= 4) {
    const mh = head.slice(0, 4).toString("hex");
    if (mh === "cffaedfe" || mh === "cefaedfe" || mh === "feedfacf" || mh === "feedface") {
      return { type: "executable", format: "macho", note: "Mach-O (macOS/iOS executable/library)" };
    }
  }
  // 3DS (3D Studio): 'MM' (0x4D4D main chunk) at offset 0 + '==' (0x3D3D version chunk)
  // at offset 6 - avoids matching text files that merely start with "MM".
  if (head.length >= 8 && head[0] === 0x4D && head[1] === 0x4D && head[6] === 0x3D && head[7] === 0x3D) {
    return { type: "document", format: "3ds", note: "3D Studio 3DS (MM + 3D 3D version)" };
  }
  // Cursor (CUR): 00 00 02 00 + a plausible image count (bytes 4-5). Kept out of the
  // signature table because TGA image-type 2 files also begin with 00 00 02 00.
  if (head.length >= 6 && head[0] === 0 && head[1] === 0 && head[2] === 2 && head[3] === 0 && ext !== "tga") {
    const count = head[4] | (head[5] << 8);
    if (count >= 1 && count <= 32) return { type: "image", format: "cur", note: "Windows cursor (CUR)" };
  }
  // TGA (Truevision) image: no leading magic - identify by header fields (image-type
  // at byte 2, pixel-depth at byte 16, color-map-type at byte 1).
  if (head.length >= 18 && [0, 1].includes(head[1]) && [0, 1, 2, 3, 9, 10, 11].includes(head[2]) && [8, 15, 16, 24, 32].includes(head[16])) {
    return { type: "image", format: "tga", note: "Truevision TGA image" };
  }
  // Visual Studio solution (.sln): plain text that may be preceded by a BOM or a blank
  // line, so locate the format marker instead of matching a fixed offset.
  if (ext === "sln" && head.indexOf("Microsoft Visual Studio Solution File") !== -1) {
    return { type: "document", format: "sln", note: "Visual Studio solution (text)" };
  }
  // Local (per-install) signatures are matched last: a locally learned format may only
  // fill a gap, it can never shadow a built-in format.
  const local = loadLocalFormats();
  for (const lf of local.formats) {
    if (lf.sig.length > head.length) continue;
    if (lf.sig.every((b, i) => head[i] === b)) {
      return { type: lf.type, format: lf.format, note: `${lf.note || "locally learned format"} (local pack)` };
    }
  }
  // Plain-text heuristic. A BOM is a strong text signal independent of extension (it
  // covers JSON stored as .db, UTF-16 Windows/Office/VS resources, extensionless text,
  // etc.) and never misclassifies binary files, so it is checked before the whitelist.
  // Go module metadata: .mod/.sum are ambiguous extensions (ProTracker modules also use
  // .mod), so match the well-known file names instead of the extension.
  const base = path.basename(filePath).toLowerCase();
  if (base === "go.mod" || base === "go.sum") {
    return { type: "document", format: base.replace(".", "-"), note: `Go module metadata (${base}, text)` };
  }
  if (head[0] === 0xEF && head[1] === 0xBB && head[2] === 0xBF) {
    return { type: "document", format: ext || "text", note: `UTF-8 text (BOM${ext ? `, .${ext}` : ", no extension"})` };
  }
  // UTF-16 BOM (FF FE little-endian / FE FF big-endian): common for Windows toolchain
  // resources (.rc/.tt/.psd1/.pkgdef) where every ASCII byte is NUL-padded.
  if (head.length >= 2 && ((head[0] === 0xFF && head[1] === 0xFE) || (head[0] === 0xFE && head[1] === 0xFF))) {
    return { type: "document", format: ext || "text", note: `UTF-16 text (BOM${ext ? `, .${ext}` : ", no extension"})` };
  }
  // Extensionless plain-ASCII metadata (e.g. VRChat __info cache entries, version
  // stamps): every byte is printable ASCII/whitespace - a strong text signal that
  // never matches binary blobs (which contain control bytes).
  if (!ext && head.length > 0 && head.every((b) => b === 0x09 || b === 0x0A || b === 0x0D || (b >= 0x20 && b <= 0x7E))) {
    return { type: "document", format: "text", note: "extensionless plain text" };
  }
  if (TEXT_EXTENSIONS.includes(ext) || local.textExtensions.includes(ext)) {
    const looksText = head.every((b, i) => i === 0 ? true : (b === 0x09 || b === 0x0A || b === 0x0D || (b >= 0x20 && b <= 0x7E) || b >= 0x80));
    if (looksText) return { type: "document", format: ext, note: `plain text / script (${ext})` };
  }
  return null;
}

// ---------- DSH-produced artifacts + declared-vs-actual (forgery) check ----------
// DSH writes the files below while working: session transcripts, storage state,
// content-addressed attachment blobs, config, temp scratch. Knowing their expected shape
// means a planted file that merely *claims* to be DSH output gets caught - the identity
// implied by its name/extension is compared against the magic-byte truth.
const DSH_ARTIFACTS = [
  { re: /^session\..+\.(zstd|jsonl)$/i, role: "dsh-session", note: "DSH session transcript (JSONL, zstd-compressed)", expect: "archive" },
  { re: /^settings\.ya?ml$/i, role: "dsh-settings", note: "DSH settings", expect: "document" },
  { re: /^cordis\.patch\.ya?ml$/i, role: "dsh-plugin-patch", note: "DSH plugin patch manifest", expect: "document" },
  { re: /^disk-guard\.ya?ml$/i, role: "dsh-disk-guard", note: "DSH disk guard config", expect: "document" },
  { re: /^\.credentials\.ya?ml$/i, role: "dsh-credentials", note: "DSH credentials (sensitive)", expect: "document", sensitive: true },
  { re: /^\.anonymous-user-id$/i, role: "dsh-anonymous-id", note: "DSH anonymous user id", expect: "document" },
  { re: /^\.dshw-(size|usage)\.json$/i, role: "dsh-usage", note: "DSH web usage/size counters", expect: "document" },
  { re: /[\\/]attachments[\\/]v1[\\/]objects[\\/]/i, role: "dsh-attachment", note: "DSH attachment blob (content-addressed sha256 name; type comes from content only)" },
  { re: /[\\/]storages[\\/][^\\/]+\.json$/i, role: "dsh-storage", note: "DSH storage state", expect: "document" },
  { re: /[\\/]library[\\/]index\.json$/i, role: "library-index", note: "Library index", expect: "document" },
  { re: /[\\/]library[\\/][^\\/]+\.ndjson$/i, role: "library-log", note: "Library operation log (NDJSON)", expect: "document" },
];

// Scratch/temp names promise nothing about content, so they are recognised but never
// used as an expectation (a temp file legitimately holds anything).
const TEMP_NAME_RE = /\.(tmp|temp|part|partial|crdownload|download|bak|orig|swp|swo|pid)$/i;
const NO_EXPECT = new Set(["tmp", "temp", "part", "partial", "crdownload", "download", "bak", "orig", "swp", "swo", "pid"]);

// Family the *name* claims, per extension: from the text whitelist and the ZIP package
// table, plus the binary families. Used to decide "does the content contradict the name".
const EXT_FAMILY = (() => {
  const m = {};
  for (const e of TEXT_EXTENSIONS) if (!NO_EXPECT.has(e)) m[e] = "document";
  for (const [e, meta] of Object.entries(ZIP_PACKAGE_FORMATS)) m[e] = meta[0];
  Object.assign(m, {
    png: "image", jpg: "image", jpeg: "image", gif: "image", bmp: "image", webp: "image", tga: "image", tif: "image", tiff: "image", psd: "image", dds: "image", ico: "image", cur: "image", exr: "image", heic: "image", avif: "image", xcf: "image", djvu: "image", wmf: "image", emf: "image",
    mp3: "audio", wav: "audio", flac: "audio", ogg: "audio", m4a: "audio", aac: "audio", ac3: "audio", dts: "audio", dsf: "audio", mid: "audio", midi: "audio", sf2: "audio", ape: "audio", rex2: "audio",
    mp4: "video", mkv: "video", webm: "video", avi: "video", mov: "video", wmv: "video", flv: "video", mxf: "video", asf: "video", rmvb: "video",
    zip: "archive", "7z": "archive", rar: "archive", gz: "archive", tar: "archive", xz: "archive", bz2: "archive", zst: "archive", zstd: "archive", cab: "archive", iso: "archive", rpm: "archive", wim: "archive",
    exe: "executable", dll: "executable", sys: "executable", so: "executable", dylib: "executable", pyd: "executable", ocx: "executable", cpl: "executable", scr: "executable", com: "executable", tlb: "executable", olb: "executable", pdb: "executable", winmd: "executable",
    db: "database", sqlite: "database", sqlite3: "database", accdb: "database", accde: "database", mdb: "database", "db-wal": "database", "db-shm": "database", wal: "database", shm: "database",
    ttf: "font", otf: "font", woff: "font", woff2: "font", ttc: "font",
    doc: "document", xls: "document", ppt: "document", pub: "document", msi: "document", msg: "document", one: "document", onetoc2: "document", chm: "document", pdf: "document", rtf: "document", ole2: "document",
    pmx: "model", pmd: "model", glb: "model", onnx: "model", gguf: "model", ggml: "model", hdf5: "model",
  });
  return m;
})();

function dshArtifactOf(filePath) {
  const base = path.basename(filePath);
  for (const a of DSH_ARTIFACTS) if (a.re.test(base) || a.re.test(filePath)) return a;
  // Locally taught name rules (the user's own artifact roles) come after the built-ins.
  for (const a of loadLocalFormats().nameRules) if (a.re.test(base) || a.re.test(filePath)) return { ...a, local: true };
  return null;
}

// Declared family for an extension: local pack first for locally known formats, then the
// built-in table (built-ins still win inside sniffFileType itself).
function declaredFamily(ext) {
  if (!ext) return null;
  const local = loadLocalFormats();
  for (const lf of local.formats) if (lf.ext.includes(ext)) return lf.type;
  if (local.textExtensions.includes(ext)) return "document";
  return EXT_FAMILY[ext] || null;
}

// Assess one file: what it claims to be (name/extension, DSH artifact role) versus what
// its bytes actually are. Any contradiction becomes a flag -> spoofed: true.
// Byte-level text/binary verdict, independent of the extension. Needed because the
// strongest forgery signal is often "no signature matched at all": a .png whose bytes are
// plain ASCII, or a .json holding raw binary, must still be catchable.
function contentKind(filePath) {
  const h = readHeader(filePath, 128);
  if (!h || h.length === 0) return "empty";
  if (h[0] === 0xEF && h[1] === 0xBB && h[2] === 0xBF) return "text";
  if ((h[0] === 0xFF && h[1] === 0xFE) || (h[0] === 0xFE && h[1] === 0xFF)) return "text";
  const printable = h.every((b, i) => i === 0 ? true : (b === 0x09 || b === 0x0A || b === 0x0D || (b >= 0x20 && b <= 0x7E) || b >= 0x80));
  return printable ? "text" : "binary";
}

// Families whose members are never plain text, and formats that are (in practice) always
// text - used to flag contradictions that carry no magic signature at all. `.log` is
// deliberately NOT in the text set: Office diagnostic logs are binary on this machine.
const BINARY_FAMILIES = new Set(["image", "audio", "video", "archive", "executable", "database", "font", "model"]);
const ALWAYS_TEXT_EXTS = new Set(["json", "jsonl", "ndjson", "yaml", "yml", "txt", "md", "csv", "ini", "env", "sln", "xml", "html", "htm"]);

function assessFile(filePath) {
  const base = path.basename(filePath);
  const ext = path.extname(base).toLowerCase().replace(".", "");
  const sniff = sniffFileType(filePath);
  const declared = declaredFamily(ext);
  const artifact = dshArtifactOf(filePath);
  const kind = contentKind(filePath);
  const flags = [];
  if (sniff && declared && sniff.type !== declared) flags.push(`name claims ${declared} (.${ext}) but content is ${sniff.type}/${sniff.format}`);
  if (sniff && artifact && artifact.expect && sniff.type !== artifact.expect) flags.push(`DSH role "${artifact.role}" expects ${artifact.expect} but content is ${sniff.type}/${sniff.format}`);
  if (sniff && artifact && !artifact.expect && sniff.type === "executable") flags.push(`executable content inside DSH artifact role "${artifact.role}"`);
  // No signature matched: fall back to the raw text/binary verdict.
  if (!sniff && kind === "text" && declared && BINARY_FAMILIES.has(declared)) flags.push(`name claims ${declared} (.${ext}) but content is plain text`);
  if (!sniff && kind === "binary" && ALWAYS_TEXT_EXTS.has(ext)) flags.push(`name claims text (.${ext}) but content is binary and matches no known signature`);
  return {
    path: filePath,
    declared,
    artifact: artifact ? artifact.role : null,
    artifactNote: artifact ? artifact.note : null,
    sensitive: !!(artifact && artifact.sensitive),
    temp: TEMP_NAME_RE.test(base),
    kind,
    detected: !!sniff,
    type: sniff ? sniff.type : null,
    format: sniff ? sniff.format : null,
    note: sniff ? sniff.note : "no known signature matched",
    spoofed: flags.length > 0,
    flags,
  };
}

// (3) Known handy tools/environments/toolchains (registered on scan; installing missing
// ones requires an instruction + report). Each tool may carry `alts` - alternative
// paths across platforms - so the same scan works on Windows / macOS / Linux.
const DETECT_CANDIDATES = [
  { type: "tool", name: "MediaInfo", path: "%TOOLCHAIN_HOME%\\\\downloads\\mediainfo-cli\\MediaInfo.exe", alts: ["/usr/bin/mediainfo", "/usr/local/bin/mediainfo", "/opt/homebrew/bin/mediainfo"], desc: "media metadata analysis" },
  { type: "tool", name: "ffmpeg", path: "%TOOLCHAIN_HOME%\\\\bin\\ffmpeg.exe", alts: ["/usr/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/opt/homebrew/bin/ffmpeg"], desc: "transcoding / media processing" },
  { type: "tool", name: "ffprobe", path: "%TOOLCHAIN_HOME%\\\\bin\\ffprobe.exe", alts: ["/usr/bin/ffprobe", "/usr/local/bin/ffprobe", "/opt/homebrew/bin/ffprobe"], desc: "media probing (alternative fingerprint source)" },
  { type: "tool", name: "uv", path: "%TOOLCHAIN_HOME%\\\\uv\\uv.exe", alts: ["/usr/local/bin/uv", "/opt/homebrew/bin/uv", "~/.local/bin/uv"], desc: "Python package/interpreter manager" },
  { type: "env", name: "llm_toolkit_api", path: "http://127.0.0.1:8100", desc: "local multimodal/retrieval toolkit (needs startup)" },
  { type: "env", name: "DSH_HOME", path: process.env.DSH_HOME || path.join(os.homedir(), ".dsh"), desc: "DSH home directory (host navigation)" },
  { type: "env", name: "Windows SDK", path: "C:\\Program Files (x86)\\Windows Kits\\10", desc: "Windows development SDK" },
  { type: "env", name: "Visual Studio 2026 Community", path: "%TOOLCHAIN_HOME%\\\\Microsoft Visual Studio\\18\\Community", desc: "Visual Studio Community 2026 (18.10) + MSVC 14.51.36231 (v145) + MSBuild; no vcpkg in this instance (vcpkg lives in the VS 2022 instance)" },
  { type: "env", name: "Visual Studio 2022 Community", path: "%TOOLCHAIN_HOME%\\\\Microsoft Visual Studio\\2022\\Community", alts: ["C:\\Program Files\\Microsoft Visual Studio\\2022\\Community"], desc: "Visual Studio Community 2022 17.14; 16 workloads, MSVC 14.44.35207 (v143), vcpkg, Clang/LLVM, MFC/ATL, WDK driver toolset (~17 GB)" },
  { type: "env", name: "SSMS 22", path: "%TOOLCHAIN_HOME%\\\\Microsoft SQL Server Management Studio 22\\Release", desc: "SQL Server Management Studio 22" },
  { type: "env", name: "Microsoft Office 2016 ProPlus", path: "C:\\Program Files\\Microsoft Office\\root\\Office16", desc: "Office 2016 ProPlus 16.0 ClickToRun: Word/Excel/PowerPoint/Access/Outlook/Publisher/OneNote (COM automation; ACE DB engine for accdb/mdb)" },
  { type: "env", name: "WDK (Windows Driver Kit)", path: "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\km", desc: "WDK 10.0.26100 fully installed (km/wdf headers, wdf libs, Inf2Cat/stampinf); VS integration installed into the VS 2022 instance" },
  { type: "tool", name: "Go", path: "%TOOLCHAIN_HOME%\\\\go\\bin\\go.exe", alts: ["/usr/local/go/bin/go", "/opt/homebrew/bin/go"], desc: "Go 1.27.1 toolchain (GOPATH/GOCACHE/GOMODCACHE on a second drive)" },
  { type: "tool", name: "Git", path: "C:\\Program Files\\Git\\cmd\\git.exe", alts: ["/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git"], desc: "Git 2.55.0 for Windows" },
  { type: "env", name: "DSH temp dir", path: process.env.TEMP || process.env.TMP || os.tmpdir(), desc: "DSH/Windows scratch area: per-run .tmpXXXXXX dirs, payload/log/err files (library_sniff dir mode can sweep it)" },
];

// Resolve a DETECT candidate's actual existing path across path + alts.
function resolveCandidatePath(c) {
  const candidates = [c.path, ...(c.alts || [])].filter(Boolean);
  for (const p of candidates) {
    if (p.startsWith("~")) {
      const expanded = path.join(os.homedir(), p.slice(1));
      if (fs.existsSync(expanded)) return expanded;
      continue;
    }
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// ---------- Local tool/env candidate pack: per-install personalisation ----------
// DETECT_CANDIDATES above is a fixed list; every machine has its own toolchains, SDKs,
// runtimes and services (in-house CLIs, private engines, local daemons). The local pack
// records them so library_detect adapts to THIS installation, with the same invariants as the
// format pack: built-ins always win, conflicts are refused unless explicitly confirmed,
// proposing never records anything, and no candidate is ever executed - a path is only
// recorded and checked for existence.
function candidatesFile() {
  return path.join(libraryDir(), "candidates.local.json");
}

function emptyCandidatePack() {
  return { version: 1, updatedAt: null, candidates: [] };
}

function normalizeCandidatePack(raw) {
  const d = emptyCandidatePack();
  if (!raw || typeof raw !== "object") return d;
  d.updatedAt = raw.updatedAt || null;
  for (const c of Array.isArray(raw.candidates) ? raw.candidates : []) {
    const type = c && c.type === "env" ? "env" : c && c.type === "tool" ? "tool" : null;
    const name = String((c && c.name) || "").trim();
    const p = String((c && c.path) || "").trim();
    if (!type || !name || !p) continue;
    d.candidates.push({
      type,
      name: name.slice(0, 120),
      path: p.slice(0, 400),
      alts: (Array.isArray(c.alts) ? c.alts : []).map((a) => String(a).slice(0, 400)).slice(0, 20),
      desc: String((c && c.desc) || "").slice(0, 300),
      createdAt: (c && c.createdAt) || null,
    });
  }
  return d;
}

let _candPack = { key: null, data: null };

function loadLocalCandidates() {
  let key = "absent";
  try {
    const st = fs.statSync(candidatesFile());
    key = `${st.mtimeMs}:${st.size}`;
  } catch {
    key = "absent";
  }
  if (_candPack.data && _candPack.key === key) return _candPack.data;
  let data = emptyCandidatePack();
  if (key !== "absent") {
    try {
      data = normalizeCandidatePack(JSON.parse(fs.readFileSync(candidatesFile(), "utf8")));
    } catch {
      data = emptyCandidatePack();
    }
  }
  _candPack = { key, data };
  return data;
}

function saveLocalCandidates(pack) {
  ensureLibrary();
  pack.version = 1;
  pack.updatedAt = new Date().toISOString();
  fs.writeFileSync(candidatesFile(), JSON.stringify(pack, null, 2), "utf8");
  _candPack = { key: null, data: null };
  return candidatesFile();
}

// Built-in entries a candidate would collide with (same type + name).
function builtinCandidateConflicts(c) {
  return DETECT_CANDIDATES
    .filter((b) => b.type === c.type && b.name.toLowerCase() === String(c.name || "").toLowerCase())
    .map((b) => `${b.type} ${b.name}`);
}

// Built-ins first, then local entries; a local entry with a built-in's key never shadows it.
function allCandidates() {
  const local = loadLocalCandidates().candidates;
  const builtinKeys = new Set(DETECT_CANDIDATES.map((b) => `${b.type}::${b.name.toLowerCase()}`));
  return [
    ...DETECT_CANDIDATES.map((c) => ({ ...c, origin: "builtin" })),
    ...local.map((c) => ({ ...c, origin: "local", shadowed: builtinKeys.has(`${c.type}::${c.name.toLowerCase()}`) })),
  ];
}

// Executables/scripts found in a directory - proposals only, nothing is recorded.
const PROPOSAL_EXTS = new Set(["exe", "bat", "cmd", "ps1", "sh", "mjs", "cjs", "py", "jar"]);
function proposeCandidates(dir, maxFiles = 500) {
  const groups = new Map();
  for (const f of walkFiles(dir, maxFiles)) {
    const ext = path.extname(f).toLowerCase().replace(".", "");
    if (!PROPOSAL_EXTS.has(ext)) {
      const s = sniffFileType(f);
      if (!(s && s.type === "executable")) continue;
    }
    const key = ext || "no-ext";
    const g = groups.get(key) || { ext: key, count: 0, samples: [], dirs: [] };
    g.count++;
    if (g.samples.length < 5) {
      g.samples.push(f);
      const d = sanitizePath(path.dirname(f), "dirs", 3, []);
      if (!g.dirs.includes(d)) g.dirs.push(d);
    }
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 40);
}

// Key management (v2): derive an AES-256 key from a master secret + random salt via
// HKDF-SHA256, replacing v1's "raw hex key file". Even if the key file is copied away,
// it cannot be decrypted without the master secret.
// Master secret source priority: env DSH_LIBRARY_MASTER_KEY > .library.master file
// (generated alongside the library; v1 raw files remain readable for compatibility).
import { randomBytes, createCipheriv, createDecipheriv, hkdfSync } from "node:crypto";
import { deflateRawSync, inflateRawSync } from "node:zlib";

// Dangerous/sensitive markers (keywords). The CJK terms are kept intentionally: they are
// functional regexes that match Chinese sensitive content, not translatable prose. They are
// also the ONLY non-ASCII content in this file - everything else is plain ASCII English, so
// the plugin's own output stays readable on the legacy consoles it warns about.
const SENSITIVE_PATTERNS = [
  /(勒索|ransom)/i, /(木马|trojan)/i, /(病毒|virus|worm)/i, /(后门|backdoor)/i,
  /(键盘记录|keylog)/i, /(窃取|steal|exfil)/i, /(恶意|malware)/i,
  /(api[_-]?key|secret|token|password|passwd|credential)/i,
  /(银行卡|身份证|passport|ssn|社保)/i,
  /(凭证|私钥|private[_-]?key)/i,
];

function isSensitive(obj) {
  const blob = [obj.name, obj.description, obj.summary, obj.path, (obj.tags || []).join(" ")].join(" ");
  return SENSITIVE_PATTERNS.some((re) => re.test(blob));
}

// v2 key file: {v:2, salt, info}. v1 legacy format is a raw hex string (kept for compat).
function keyFile() {
  return path.join(libraryDir(), ".library.key");
}
function masterFile() {
  return path.join(libraryDir(), ".library.master");
}

function getMasterSecret() {
  // Env var first; otherwise .library.master (generated on first use: random 32 bytes, base64).
  if (process.env.DSH_LIBRARY_MASTER_KEY) return Buffer.from(process.env.DSH_LIBRARY_MASTER_KEY, "utf8");
  const mf = masterFile();
  if (fs.existsSync(mf)) return Buffer.from(fs.readFileSync(mf, "utf8").trim(), "base64");
  const m = randomBytes(32);
  fs.writeFileSync(mf, m.toString("base64"), "utf8");
  return m;
}

function getOrCreateKey() {
  const kf = keyFile();
  // v1 compat: a raw 64-hex file is used directly as the key.
  if (fs.existsSync(kf)) {
    const raw = fs.readFileSync(kf, "utf8").trim();
    if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, "hex"); // v1 raw hex
    try {
      const j = JSON.parse(raw);
      if (j && j.v === 2) {
        // v2: derive via HKDF-SHA256 from [master secret + salt].
        const master = getMasterSecret();
        const salt = Buffer.from(j.salt, "hex");
        const derived = hkdfSync("sha256", master, salt, Buffer.from(j.info || "mega-index-map:v2", "utf8"), 32);
        return derived;
      }
    } catch {}
  }
  // First run: generate a v2 key file.
  const salt = randomBytes(16);
  const info = Buffer.from("mega-index-map:v2", "utf8");
  const derived = hkdfSync("sha256", getMasterSecret(), salt, info, 32);
  fs.writeFileSync(kf, JSON.stringify({ v: 2, salt: salt.toString("hex"), info: info.toString("utf8") }), "utf8");
  return derived;
}

// Encrypt-isolate a sensitive object as {sens:1, iv, tag, ct}; plaintext never enters the library.
function encryptSensitive(obj) {
  const key = getOrCreateKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plain = JSON.stringify(obj);
  let ct = cipher.update(plain, "utf8", "hex");
  ct += cipher.final("hex");
  const tag = cipher.getAuthTag();
  return { sens: 1, iv: iv.toString("hex"), tag: tag.toString("hex"), ct };
}

function decryptSensitive(record) {
  if (!record || record.sens !== 1) return record;
  try {
    const key = getOrCreateKey();
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(record.iv, "hex"));
    decipher.setAuthTag(Buffer.from(record.tag, "hex"));
    let plain = decipher.update(record.ct, "hex", "utf8");
    plain += decipher.final("utf8");
    return JSON.parse(plain);
  } catch {
    return { __decryptError: true };
  }
}

// Store an object: sensitive -> encrypt-isolate (plaintext never stored), else store as-is.
// Sensitive objects expose only {type, name, source, sensitive:true, createdAt, __content}.
function storeObject(index, obj) {
  if (isSensitive(obj)) {
    const cipherObj = encryptSensitive(obj);
    const meta = {
      id: obj.id,
      type: obj.type,
      name: obj.name,
      source: obj.source,
      sensitive: true,
      createdAt: obj.createdAt,
      __content: cipherObj,
    };
    index.objects.push(meta);
    return true;
  }
  index.objects.push(obj);
  return false;
}

// Commit one record: store object + refresh timestamp + persist + append log. Returns sensitivity.
function commitRecord(index, obj, disposition, detail) {
  const sens = storeObject(index, obj);
  index.generatedAt = new Date().toISOString();
  saveIndex(index);
  appendLog({ op: "record", type: obj.type, name: obj.name, source: obj.source, disposition, detail: detail + (sens ? " (sensitive, encrypted)" : "") });
  return sens;
}

function ensureLibrary() {
  const dir = libraryDir();
  fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(payloadDir(), { recursive: true });
  return dir;
}

function loadIndex() {
  ensureLibrary();
  const file = indexFile();
  if (!fs.existsSync(file)) {
    return { version: 1, generatedAt: null, objects: [] };
  }
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    // Corrupt library file: back it up before returning empty, so the next record
    // doesn't overwrite-and-lose the salvageable remnants.
    try {
      const bak = path.join(libraryDir(), `index.json.corrupt-${Date.now()}`);
      fs.copyFileSync(file, bak);
    } catch {}
    return { version: 1, generatedAt: null, objects: [] };
  }
}

function saveIndex(index) {
  ensureLibrary();
  const file = indexFile();
  // NOTE: synchronous write keeps the read-modify-write cycle atomic on the single
  // JS thread. Do NOT add awaits into the record/index write path, or concurrent tool
  // calls could interleave and lose updates (DSH runs up to maxParallelToolCalls).
  fs.writeFileSync(file, JSON.stringify(index, null, 2), "utf8");
  return file;
}

// ---------- Local format pack: per-install personalisation of the format library ----------
// Built-in coverage is necessarily finite, while every machine carries its own formats
// (CAD/CAM, DAW, engine, in-house tooling). The local pack lets *this* installation teach
// itself what it actually meets, without patching the plugin: magic signatures, plain-text
// extensions and name rules, kept at $DSH_HOME/library/formats.local.json.
// Safety rules: built-ins are always matched first, so a local entry can never shadow a
// known format; conflicts are refused rather than merged. `library_format scan` only
// *proposes* candidates (with evidence) - nothing is learned without explicit samples,
// because a directory an intruder can write to must not be able to teach a fake format.
function localFormatsFile() {
  return path.join(libraryDir(), "formats.local.json");
}

function emptyLocalPack() {
  return { version: 1, updatedAt: null, formats: [], textExtensions: [], nameRules: [] };
}

function parseHexSig(v) {
  if (Array.isArray(v)) {
    const out = v.map(Number);
    return out.length && out.length <= 32 && out.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? out : null;
  }
  const parts = String(v || "").trim().replace(/0x/gi, "").replace(/[,\s]+/g, " ").split(" ").filter(Boolean);
  if (!parts.length || parts.length > 32) return null;
  const out = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,2}$/i.test(p.replace(/^0x/i, "").trim() || p)) return null;
    const n = parseInt(p.replace(/^0x/i, ""), 16);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out.push(n);
  }
  return out;
}

function normalizeLocalPack(raw) {
  const d = emptyLocalPack();
  if (!raw || typeof raw !== "object") return d;
  d.updatedAt = raw.updatedAt || null;
  for (const f of Array.isArray(raw.formats) ? raw.formats : []) {
    const sig = parseHexSig(f && f.sig);
    if (!sig || !f.format) continue;
    d.formats.push({
      format: String(f.format).slice(0, 40),
      type: String(f.type || "document"),
      sig,
      ext: (Array.isArray(f.ext) ? f.ext : []).map((e) => String(e).toLowerCase().replace(/^\./, "")).filter(Boolean),
      note: String(f.note || "").slice(0, 200),
      createdAt: f.createdAt || null,
    });
  }
  for (const e of Array.isArray(raw.textExtensions) ? raw.textExtensions : []) {
    const s = String(e).toLowerCase().replace(/^\./, "");
    if (s) d.textExtensions.push(s);
  }
  for (const r of Array.isArray(raw.nameRules) ? raw.nameRules : []) {
    try {
      d.nameRules.push({ re: new RegExp(String(r.re), "i"), role: String(r.role || "local"), expect: r.expect || null, note: String(r.note || "").slice(0, 200) });
    } catch {}
  }
  return d;
}

let _localPack = { key: null, data: null };

// Cached by file mtime+size, so a hand-edited pack is picked up without a restart.
function loadLocalFormats() {
  let key = "absent";
  try {
    const st = fs.statSync(localFormatsFile());
    key = `${st.mtimeMs}:${st.size}`;
  } catch {
    key = "absent";
  }
  if (_localPack.data && _localPack.key === key) return _localPack.data;
  let data = emptyLocalPack();
  if (key !== "absent") {
    try {
      data = normalizeLocalPack(JSON.parse(fs.readFileSync(localFormatsFile(), "utf8")));
    } catch {
      data = emptyLocalPack();
      data.__corrupt = true;
    }
  }
  _localPack = { key, data };
  return data;
}

function saveLocalFormats(pack) {
  ensureLibrary();
  pack.version = 1;
  pack.updatedAt = new Date().toISOString();
  fs.writeFileSync(localFormatsFile(), JSON.stringify(pack, null, 2), "utf8");
  _localPack = { key: null, data: null };
  return localFormatsFile();
}

// Built-in signatures a candidate prefix could collide with (either direction).
function builtinSigConflicts(sig) {
  const hits = [];
  for (const entry of FILE_SIGNATURES) {
    const a = entry.sig;
    const n = Math.min(a.length, sig.length);
    let same = true;
    for (let i = 0; i < n; i++) if (a[i] !== sig[i]) { same = false; break; }
    if (same) hits.push(`${entry.format} (${a.map((b) => b.toString(16).padStart(2, "0")).join(" ")})`);
  }
  return [...new Set(hits)];
}

// Longest common byte prefix across the sample headers (capped at 16 bytes).
function commonPrefix(bufs) {
  const list = bufs.filter((b) => b && b.length);
  if (!list.length) return [];
  const min = Math.min(16, ...list.map((b) => b.length));
  const out = [];
  for (let i = 0; i < min; i++) {
    const b = list[0][i];
    if (list.every((x) => x[i] === b)) out.push(b);
    else break;
  }
  return out;
}

function hexSig(arr) {
  return arr.map((b) => b.toString(16).padStart(2, "0")).join(" ");
}

// ---------- Format report: user-generated, user-delivered contribution ----------
// The goal is to collect the formats real machines have that the library still cannot
// identify. The report is built and written locally; it carries no file names, no paths and
// no file contents; nothing in this path touches the network; and delivery is manual - by
// the user, after inspecting exactly what is inside. Nothing is ever sent automatically.
function reportsDir() {
  return path.join(libraryDir(), "reports");
}

const PLUGIN_VERSION = (() => {
  try {
    return String(JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version || "unknown");
  } catch {
    return "unknown";
  }
})();

// CRC-32 (required by ZIP) - tiny table-driven version, no dependency.
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

// Minimal ZIP writer (deflate, UTF-8 names) so the report opens everywhere, dependency-free.
function zipBuffer(entries) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, "utf8");
    const data = Buffer.from(e.data, "utf8");
    const packed = deflateRawSync(data);
    const useDeflate = packed.length < data.length;
    const body = useDeflate ? packed : data;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x0800, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    parts.push(lh, name, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += lh.length + name.length + body.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cd, end]);
}

// Shared walker: files whose type the library cannot identify (binary only - plain text is
// already covered by the text path). Used by `scan` (local proposals, may carry sample
// paths) and `report` (contribution archive - never carries paths).
function collectUnidentified(dir, maxFiles, maxSamples = 3, withPaths = true) {
  const max = Math.min(Math.max(maxFiles || 1000, 1), 20000);
  const files = [];
  const walk = (d) => {
    if (files.length >= max) return;
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (files.length >= max) return;
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (e.isFile()) files.push(p);
    }
  };
  walk(dir);
  const groups = new Map();
  for (const f of files) {
    const base = path.basename(f);
    if (base.startsWith(".")) continue;
    const ext = path.extname(base).toLowerCase().replace(".", "");
    if (!ext) continue;
    if (sniffFileType(f)) continue;
    if (contentKind(f) === "text") continue;
    const g = groups.get(ext) || { ext, count: 0, sampleCount: 0, samples: [], heads: [] };
    g.count++;
    if (g.heads.length < maxSamples) {
      g.sampleCount++;
      if (withPaths) g.samples.push(f);
      const h = readHeader(f, 16);
      if (h) g.heads.push(h);
    }
    groups.set(ext, g);
  }
  return { scanned: files.length, groups };
}

// ---------- Format relationships (deps), user-level sanitising, passphrase sealing ----------
// Dependency collection records which formats reference which other formats. Only format
// names/extensions are kept (never paths or file names), so the result is format knowledge
// rather than user data; DLL names are opt-in. Paths, when a user asks for them, are the
// only user-level fields - they are sanitised by default and can be sealed with a
// passphrase the USER holds (they can open it again any time; nobody else can).

function walkFiles(dir, maxFiles) {
  const max = Math.min(Math.max(maxFiles || 1000, 1), 20000);
  const files = [];
  const walk = (d) => {
    if (files.length >= max) return;
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (files.length >= max) return;
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (e.isFile()) files.push(p);
    }
  };
  walk(dir);
  return files;
}

function readCapped(filePath, maxBytes) {
  try {
    const fd = fs.openSync(filePath, "r");
    const size = fs.fstatSync(fd).size;
    const n = Math.min(size, maxBytes);
    const b = Buffer.alloc(n);
    fs.readSync(fd, b, 0, n, 0);
    fs.closeSync(fd);
    return b;
  } catch {
    return null;
  }
}

// Entry names inside a ZIP/OPC container (local file headers).
function zipEntryNames(buf, max = 400) {
  const out = [];
  let i = 0;
  while (i + 30 <= buf.length && out.length < max) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x03 && buf[i + 3] === 0x04) {
      const compSize = buf.readUInt32LE(i + 18);
      const nameLen = buf.readUInt16LE(i + 26);
      const extraLen = buf.readUInt16LE(i + 28);
      if (i + 30 + nameLen <= buf.length) {
        const nm = buf.subarray(i + 30, i + 30 + nameLen).toString("utf8");
        if (nm) out.push(nm);
        i += 30 + nameLen + extraLen + compSize;
        continue;
      }
    }
    i++;
  }
  return out;
}

// PE import table: the DLL names an executable/library depends on (Windows side of a
// dependency graph). Bounded and defensive - any malformed header returns null.
function peImports(buf, maxDlls = 64) {
  try {
    if (!buf || buf.length < 0x40 || buf[0] !== 0x4d || buf[1] !== 0x5a) return null;
    const peOff = buf.readUInt32LE(0x3c);
    if (peOff + 24 > buf.length || buf.readUInt32LE(peOff) !== 0x00004550) return null;
    const coff = peOff + 4;
    const numSections = buf.readUInt16LE(coff + 2);
    const optSize = buf.readUInt16LE(coff + 16);
    const opt = coff + 20;
    const ddOff = opt + (buf.readUInt16LE(opt) === 0x20b ? 112 : 96);
    if (ddOff + 16 > buf.length) return null;
    const importRva = buf.readUInt32LE(ddOff + 8);
    if (!importRva) return null;
    const secOff = opt + optSize;
    const sections = [];
    for (let i = 0; i < numSections && i < 96; i++) {
      const s = secOff + i * 40;
      if (s + 40 > buf.length) break;
      sections.push({ va: buf.readUInt32LE(s + 12), vsize: buf.readUInt32LE(s + 8), raw: buf.readUInt32LE(s + 20), rawSize: buf.readUInt32LE(s + 16) });
    }
    const rva2off = (rva) => {
      for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return s.raw + (rva - s.va);
      return null;
    };
    const desc = rva2off(importRva);
    if (desc == null) return null;
    const out = [];
    for (let i = 0; i < 256; i++) {
      const d = desc + i * 20;
      if (d + 20 > buf.length) break;
      const nameRva = buf.readUInt32LE(d + 12);
      if (!nameRva) break;
      const no = rva2off(nameRva);
      if (no == null || no >= buf.length) break;
      let end = no;
      while (end < buf.length && buf[end] !== 0 && end - no < 260) end++;
      const nm = buf.subarray(no, end).toString("latin1").trim();
      if (nm) out.push(nm);
      if (out.length >= maxDlls) break;
    }
    return out;
  } catch {
    return null;
  }
}

// Extensions referenced by a text file (project/source/markup) - format->format edges only.
// Single-letter extensions are real (.h/.c/.s/.m), but prose abbreviations ("e.g", "i.e.")
// are not, so those are filtered out.
const SINGLE_LETTER_EXTS = new Set(["h", "c", "s", "m", "f", "r", "o", "a", "d", "i"]);
// Only *known* extensions count as references: source code is full of dotted member access
// (Console.WriteLine, .ActiveCfg, Microsoft.NET.Sdk) that would otherwise look like a
// reference to a "writeline"/"activecfg"/"net" format.
const LINKABLE_EXTS = new Set(["dll", "exe", "lib", "obj", "res", "o", "so", "dylib", "pyd", "map", "il", "class", "pch", "idb", "exp"]);
function refsFromText(text) {
  const out = new Set();
  for (const m of text.matchAll(/[A-Za-z0-9_\-.]{1,120}?\.([A-Za-z][A-Za-z0-9]{0,9})\b/g)) {
    const e = m[1].toLowerCase();
    if (e.length === 1 && !SINGLE_LETTER_EXTS.has(e)) continue;
    if (!EXT_FAMILY[e] && !LINKABLE_EXTS.has(e)) continue;
    out.add(e);
  }
  return out;
}

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Replace user/host/date identifiers with placeholders so a path carries structure but not
// identity. `dirs` keeps only the directory part, `full` keeps the whole sanitised path.
function sanitizePath(p, mode = "full", depth = 3, extra = []) {
  let s = String(p || "").replace(/\\/g, "/");
  s = s.replace(/^[A-Za-z]:/, "<drive>");
  s = s.replace(/\/Users\/[^/]+/gi, "/<user>").replace(/\/home\/[^/]+/gi, "/<user>");
  s = s.replace(/\/(AppData)\/[^/]+\/[^/]+/gi, "/$1/<user>");
  s = s.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "<uuid>");
  s = s.replace(/\b(?:session|tmp|\.tmp)-?[A-Za-z0-9_-]{4,}/gi, "<id>");
  s = s.replace(/\b\d{4}-\d{2}-\d{2}(?:[T_]\d{2}[-:]\d{2}[-:]\d{2})?\b/g, "<date>");
  for (const [needle, tag] of [[os.homedir(), "<home>"], [os.hostname(), "<host>"], [os.userInfo().username, "<user>"], ...extra.map((e) => [e, "<excluded>"])]) {
    if (needle && String(needle).length > 2) s = s.replace(new RegExp(escapeRe(String(needle).replace(/\\/g, "/")), "gi"), tag);
  }
  if (mode === "dirs") {
    const parts = path.posix.dirname(s).split("/").filter(Boolean);
    return "<root>/" + parts.slice(-Math.max(1, depth)).join("/");
  }
  return s;
}

// Passphrase sealing: the user holds the passphrase, so they can always reopen it locally
// (op=unseal) and decide for themselves whether anyone else ever can.
function sealWithPassphrase(passphrase, obj) {
  const salt = randomBytes(16);
  const key = Buffer.from(hkdfSync("sha256", Buffer.from(String(passphrase), "utf8"), salt, Buffer.from("mega-index-map:seal:v1", "utf8"), 32));
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  let ct = cipher.update(JSON.stringify(obj), "utf8", "hex");
  ct += cipher.final("hex");
  return { v: 1, kdf: "hkdf-sha256", salt: salt.toString("hex"), iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), ct };
}

function unsealWithPassphrase(passphrase, rec) {
  try {
    const key = Buffer.from(hkdfSync("sha256", Buffer.from(String(passphrase), "utf8"), Buffer.from(rec.salt, "hex"), Buffer.from("mega-index-map:seal:v1", "utf8"), 32));
    const d = createDecipheriv("aes-256-gcm", key, Buffer.from(rec.iv, "hex"));
    d.setAuthTag(Buffer.from(rec.tag, "hex"));
    let plain = d.update(rec.ct, "hex", "utf8");
    plain += d.final("utf8");
    return JSON.parse(plain);
  } catch {
    return { __unsealError: true };
  }
}

// Dependency aggregation over a directory: format -> format edges. Paths never enter the
// result; DLL names only when explicitly requested.
function collectDeps(dir, maxFiles, wantNames) {
  const files = walkFiles(dir, maxFiles);
  const edges = new Map();
  const dllNames = new Set();
  let inspected = 0;
  for (const f of files) {
    const head = readHeader(f, 4);
    if (!head || head.length < 4) continue;
    let from = path.extname(f).toLowerCase().replace(".", "");
    if (!from) continue;
    const sn = sniffFileType(f);
    if (sn && sn.format) from = sn.format;
    let refs = [];
    const isZip = head[0] === 0x50 && head[1] === 0x4b;
    const isPE = head[0] === 0x4d && head[1] === 0x5a;
    try {
      if (isZip) {
        const buf = readCapped(f, 4 * 1024 * 1024);
        if (buf) refs = [...new Set(zipEntryNames(buf).map((n) => path.extname(n).toLowerCase().replace(".", "")).filter(Boolean))];
      } else if (isPE) {
        const dlls = peImports(readCapped(f, 16 * 1024 * 1024));
        if (dlls && dlls.length) {
          refs = ["dll"];
          if (wantNames) dlls.forEach((d) => dllNames.add(d));
        }
      } else if (contentKind(f) === "text") {
        const buf = readCapped(f, 512 * 1024);
        if (buf) refs = [...refsFromText(buf.toString("utf8"))];
      }
    } catch {}
    if (!refs.length) continue;
    inspected++;
    for (const to of refs.slice(0, 30)) {
      if (!to || to === from) continue;
      const k = `${from}->${to}`;
      edges.set(k, (edges.get(k) || 0) + 1);
    }
  }
  const list = [...edges.entries()]
    .map(([k, count]) => {
      const idx = k.indexOf("->");
      return { from: k.slice(0, idx), to: k.slice(idx + 2), count };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 300);
  return { scanned: files.length, inspected, edges: list, dllNames: [...dllNames].sort().slice(0, 200) };
}

// Read one entry out of a ZIP built by zipBuffer (used to reopen a sealed layer).
function zipReadEntry(buf, wantName) {
  let i = 0;
  while (i + 30 <= buf.length) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x03 && buf[i + 3] === 0x04) {
      const method = buf.readUInt16LE(i + 8);
      const compSize = buf.readUInt32LE(i + 18);
      const nameLen = buf.readUInt16LE(i + 26);
      const extraLen = buf.readUInt16LE(i + 28);
      if (i + 30 + nameLen <= buf.length) {
        const nm = buf.subarray(i + 30, i + 30 + nameLen).toString("utf8");
        const dataStart = i + 30 + nameLen + extraLen;
        if (nm === wantName) {
          const data = buf.subarray(dataStart, dataStart + compSize);
          try { return method === 8 ? inflateRawSync(data) : data; } catch { return null; }
        }
        i = dataStart + compSize;
        continue;
      }
    }
    i++;
  }
  return null;
}

function draftsDir() {
  return path.join(reportsDir(), "drafts");
}

function resolveDraft(idOrPath) {
  const raw = String(idOrPath || "");
  if (raw && fs.existsSync(raw) && fs.statSync(raw).isFile()) return raw;
  try {
    const hits = fs.readdirSync(draftsDir()).filter((f) => f.includes(raw)).sort();
    if (hits.length) return path.join(draftsDir(), hits[hits.length - 1]);
  } catch {}
  return null;
}

function makeId(type, sourceWorkspace, name) {
  const slug = String(name || "").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  // Time base + random suffix to avoid same-millisecond collisions for identical type+name.
  const stamp = Date.now().toString(36) + "-" + randomBytes(4).toString("hex");
  return `${type}-${slug || "obj"}-${stamp}`;
}

// ---------- Model-facing tools ----------

const name = "mega-index-map";
const inject = ["tools"];

// Register default media providers (ffprobe + MediaInfo).
registerDefaultMediaProvider();

function apply(ctx) {
  // ---- (4) Prevent waking outside DeepSeek Harness ----
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
      "Record a tool/file/env/product/knowledge/work record into the cross-workspace Library. One object per call; type and source are required.",
    parameters: {
      type: {
        type: "string",
        required: true,
        description: "Object type: tool|plugin|env|file|product|knowledge|persona|image|document|table|audio|work_record|log|workspace|reference|other",
      },
      name: { type: "string", required: true, description: "Object name" },
      source: { type: "string", required: true, description: "Source workspace/directory" },
      path: { type: "string", description: "Absolute path of the object, or an address for env/port" },
      description: { type: "string", description: "One-line purpose/description" },
      tags: {
        type: "array",
        items: { type: "string" },
        description: "Filter/retrieval tags",
      },
      summary: { type: "string", description: "Extra structured summary (may be multiline)" },
      links: {
        type: "array",
        items: { type: "string" },
        description: "Associate related objects: ids or 'type:name:source' keys",
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
    async execute(args) {
      if (!OBJ_TYPES.has(args.type)) {
        throw new Error(`library_record: invalid type "${args.type}", allowed: ${[...OBJ_TYPES].join(", ")}`);
      }
      if (!args.name || !args.source) {
        throw new Error("library_record: name and source are required");
      }
      const index = loadIndex();
      const name = clampField(args.name, "name");
      const source = clampField(args.source, "source");
      const path = clampField(args.path || "", "path");
      const description = clampField(args.description || "", "description");
      const tags = (args.tags || []).filter((t) => typeof t === "string");
      const summary = clampField(args.summary || "", "summary");
      const related = (args.links || []).filter((l) => typeof l === "string");

      // Change detection: find the same-key existing object (type+name+source). A sensitive
      // object is stored as an encrypted meta, so decrypt it before fingerprinting, otherwise
      // comparison would be wrong (sensitive objects would be repeatedly misjudged as changed).
      const rawExisting = index.objects.find(
        (o) => o.type === args.type && o.name === name && o.source === source
      );
      const existing = rawExisting && rawExisting.__content
        ? decryptSensitive(rawExisting.__content)
        : rawExisting;
      const newFp = fingerprint({ path, description, summary, tags, related });
      const disposition = dispositionFor(args.type);

      if (existing && fingerprint(existing) !== newFp) {
        // Content changed -> route by type.
        if (disposition === "verify") {
          // Auto-verifiable (tool/plugin/env): record the change, notify DSH to check and report to the user.
          const obj = {
            id: makeId(args.type, source, name),
            type: args.type,
            name,
            source,
            path,
            description,
            tags,
            summary,
            related,
            createdAt: new Date().toISOString(),
            changedAt: new Date().toISOString(),
          };
          const sens = commitRecord(index, obj, disposition, "content changed, recorded and notify DSH to check");
          return {
            id: obj.id,
            ok: true,
            count: index.objects.length,
            changed: true,
            disposition: "verify",
            message: `"${name}" differs from the last indexed result; a new version was recorded${sens ? " (sensitive content detected, stored encrypted)" : ""}. Please have DSH check the object's actual state (path/service/version consistency) and report the result to the user.`,
          };
        }
        // Immutable-file class: do not auto-overwrite; force user confirmation.
        // (1) Media evidence: for media-type immutable files, probe metadata via silent
        // ffprobe/MediaInfo and attach the evidence for the user to judge.
        const MEDIA_TYPES = new Set(["image", "audio", "video", "document", "file"]);
        let mediaNote = "";
        if (MEDIA_TYPES.has(args.type) && path) {
          const mf = await mediaFingerprint(path);
          if (mf.ok) mediaNote = `\nMedia evidence: ${mf.detail}`;
          else mediaNote = `\nMedia evidence: unavailable (${mf.detail})`;
        }
        appendLog({ op: "record", type: args.type, name, source, disposition, detail: "content changed, awaiting user confirmation" + (mediaNote ? " (with media evidence)" : "") });
        return {
          id: existing.id,
          ok: false,
          count: index.objects.length,
          changed: true,
          disposition: "confirm",
          message: `"${name}" differs from the last indexed result (immutable-file class). Not auto-overwriting; the user must confirm the change or explain it before it is written/discarded.${mediaNote}Report the judgment to the user.`,
        };
      }

      // Unchanged or first record.
      if (existing) {
        // Already exists and unchanged -> do not rewrite or duplicate; just return.
        appendLog({ op: "record", type: args.type, name, source, disposition, detail: "unchanged (not re-recorded)" });
        return { id: existing.id, ok: true, count: index.objects.length, changed: false, disposition, sensitive: !!(rawExisting && rawExisting.__content) };
      }
      // First record: write.
      const obj = {
        id: makeId(args.type, source, name),
        type: args.type,
        name,
        source,
        path,
        description,
        tags,
        summary,
        related,
        createdAt: new Date().toISOString(),
      };
      const sens = commitRecord(index, obj, disposition, "first record");
      return { id: obj.id, ok: true, count: index.objects.length, changed: false, disposition, sensitive: sens };
    },
  }));

  // ---- library_index: rebuild/dedupe index (+ conflict report) ----
  ctx.tools.register(defineTool({
    name: "library_index",
    description:
      "Rebuild/dedupe the Library index (by type+name+source), sort by createdAt, and rewrite index.json. Conflicting same-key objects are reported, not silently dropped. Returns count, store path, and conflicts.",
    parameters: {},
    output: {
      schema: { type: "object", additionalProperties: false, properties: { count: { type: "number" }, store: { type: "string" }, conflicts: { type: "array", items: { type: "object", additionalProperties: true } } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    async execute() {
      const index = loadIndex();
      const seen = new Map();
      const conflicts = [];
      // Guard against old objects with missing fields polluting the dedupe key or losing objects.
      const dedup = index.objects.filter((o) => {
        const key = [o.type, o.name, o.source].map((v) => String(v ?? "")).join("::");
        if (seen.has(key)) {
          // Same key but different content -> record the conflict (preserve dropped version info).
          const prev = seen.get(key);
          if (fingerprint(prev) !== fingerprint(o)) {
            conflicts.push({ key, kept: prev.id, dropped: o.id });
          }
          return false;
        }
        seen.set(key, o);
        return true;
      });
      dedup.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
      index.objects = dedup;
      index.generatedAt = new Date().toISOString();
      saveIndex(index);
      appendLog({ op: "index", type: null, name: null, source: null, disposition: null, detail: `rebuilt index, ${dedup.length} objects, ${conflicts.length} conflicts` });
      return { count: dedup.length, store: indexFile(), conflicts };
    },
  }));

  // ---- library_query: search the Library (index/use/research/learn) ----
  ctx.tools.register(defineTool({
    name: "library_query",
    description:
      "Search Library objects by keyword (name/description/summary/source), type, and tags. Use to inherit past records, research what a workspace used, or locate a path/service/record.",
    parameters: {
      query: { type: "string", description: "Free-text keyword" },
      type: { type: "string", description: "Filter by type: tool|plugin|env|file|product|knowledge|persona|image|document|table|audio|work_record|log|workspace|reference|other" },
      tags: {
        type: "array",
        items: { type: "string" },
        description: "Filter by tags",
      },
      limit: { type: "number", description: "Max results, default 20, max 100" },
      cursor: { type: "string", description: "Pagination cursor (pass previous nextCursor)" },
      pageSize: { type: "number", description: "Page size per page (defaults to limit)" },
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
    async execute(args) {
      if (args.type && !OBJ_TYPES.has(args.type)) {
        throw new Error(`library_query: invalid type "${args.type}", allowed: ${[...OBJ_TYPES].join(", ")}`);
      }
      const index = loadIndex();
      const q = (args.query || "").toLowerCase().trim();
      const limit = Math.min(Math.max(args.limit || 20, 1), 100);
      let results = index.objects;
      if (args.type && OBJ_TYPES.has(args.type)) {
        results = results.filter((o) => o.type === args.type);
      }
      if (Array.isArray(args.tags) && args.tags.length) {
        const tags = args.tags.map((t) => String(t).toLowerCase());
        results = results.filter((o) => tags.every((t) => (o.tags || []).some((x) => String(x).toLowerCase() === t)));
      }
      if (q) {
        results = results.filter((o) =>
          [o.name, o.description, o.summary, o.source, o.path, (o.tags || []).join(" ")]
            .join(" ")
            .toLowerCase()
            .includes(q)
        );
      }
      // Sensitive objects expose only metadata (sensitive:true + public fields); no auto-decrypt
      // and no leaking of the __content cipher block.
      const safeAll = results
        .map((o) => {
          if (o.sensitive || o.sens === 1) {
            return { id: o.id, type: o.type, name: o.name, source: o.source, sensitive: true, createdAt: o.createdAt };
          }
          const { __content, ...rest } = o;
          return rest;
        })
        .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
      // Pagination cursor: stable-sorted safeAll, offset anchored by "items already fetched".
      const pageSize = Math.min(Math.max(args.pageSize || limit, 1), 100);
      const offset = args.cursor ? parseInt(args.cursor, 10) || 0 : 0;
      const page = safeAll.slice(offset, offset + pageSize);
      const nextCursor = offset + pageSize < safeAll.length ? String(offset + pageSize) : null;
      return { count: safeAll.length, nextCursor, results: page };
    },
  }));

  // ---- (3) library_detect: scan known tools/environments/toolchains and register them ----
  // Registers only existing candidates; installing missing ones requires an instruction
  // plus a per-item report (this tool only registers by default).
  ctx.tools.register(defineTool({
    name: "library_detect",
    description:
      "Scan machine tools/environments/toolchains and register the ones that exist into the Library (bootstraps the index on install/init; never installs anything). Scans the built-in list plus this machine's local candidate pack, so a private toolchain or service recorded once is recognised on every later scan. op=list shows both lists; op=add/remove manage the local pack (built-ins always win, collisions are refused unless confirm:true); op=propose dir=<directory> only *proposes* executables found there for you to decide about. Proposing records nothing and no candidate is ever executed - a path is only recorded and checked for existence.",
    parameters: {
      op: { type: "string", description: "scan (default) | list | add | remove | propose" },
      force: { type: "boolean", description: "scan: re-register even if already present; default skips already-registered items" },
      cross: { type: "boolean", description: "scan: cross-check scanned items against known objects; list items not yet in the Library" },
      type: { type: "string", description: "add: tool | env" },
      name: { type: "string", description: "add/remove: candidate name" },
      path: { type: "string", description: "add: absolute path (or a URL for a service env)" },
      alts: { type: "array", items: { type: "string" }, description: "add: alternative paths across platforms (optional)" },
      desc: { type: "string", description: "add: what the tool/env is for" },
      dir: { type: "string", description: "propose: directory to look for executables/scripts" },
      maxFiles: { type: "number", description: "propose: max files to inspect; default 500" },
      confirm: { type: "boolean", description: "add: proceed despite a collision with a built-in candidate" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          ok: { type: "boolean" }, op: { type: "string" }, file: { type: "string" }, note: { type: "string" },
          builtin: { type: "number" }, local: { type: "number" },
          candidates: { type: "array", items: { type: "object", additionalProperties: true } },
          proposals: { type: "array", items: { type: "object", additionalProperties: true } },
          conflicts: { type: "array", items: { type: "string" } },
          removed: { type: "number" },
          found: { type: "number" }, registered: { type: "number" },
          results: { type: "array", items: { type: "object", additionalProperties: true } },
          cross: { type: "array", items: { type: "object", additionalProperties: true } },
        },
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const op = String(args.op || "scan").toLowerCase();
      const file = candidatesFile();
      const pack = loadLocalCandidates();

      if (op === "list") {
        const list = allCandidates();
        return {
          ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: pack.candidates.length,
          candidates: list.map((c) => ({ type: c.type, name: c.name, path: c.path, desc: c.desc, origin: c.origin, shadowed: !!c.shadowed })),
          note: fs.existsSync(file)
            ? `local candidate pack loaded; ${list.filter((c) => c.shadowed).length} local entr(ies) shadowed by built-ins`
            : "no local candidate pack yet (op=add or op=propose create one)",
        };
      }

      if (op === "add") {
        const type = args.type === "env" ? "env" : args.type === "tool" ? "tool" : null;
        if (!type) return { ok: false, op, file, note: 'add needs type: "tool" or "env"' };
        const name = String(args.name || "").trim();
        const p = String(args.path || "").trim();
        if (!name || !p) return { ok: false, op, file, note: "add needs name and path" };
        const conflicts = builtinCandidateConflicts({ type, name });
        if (conflicts.length && !args.confirm) {
          return { ok: false, op, file, conflicts, note: `refused: ${name} is already a built-in candidate - pass confirm:true only if you really want a local duplicate (the built-in still wins during scans)` };
        }
        const next = normalizeCandidatePack(pack);
        next.candidates = next.candidates.filter((c) => !(c.type === type && c.name.toLowerCase() === name.toLowerCase()));
        next.candidates.push({
          type, name, path: p,
          alts: (Array.isArray(args.alts) ? args.alts : []).map(String),
          desc: String(args.desc || "").slice(0, 300),
          createdAt: new Date().toISOString(),
        });
        saveLocalCandidates(next);
        appendLog({ op: "candidate-add", type, name, source: "local", disposition: null, detail: `local candidate recorded (exists now: ${fs.existsSync(p)})` });
        return {
          ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: next.candidates.length, conflicts,
          note: `recorded ${type} ${name}${fs.existsSync(p) ? "" : " (path does not exist yet - scans will skip it until it does)"}`,
        };
      }

      if (op === "remove") {
        const name = String(args.name || "").trim().toLowerCase();
        if (!name) return { ok: false, op, file, note: "remove needs name" };
        const next = normalizeCandidatePack(pack);
        const before = next.candidates.length;
        next.candidates = next.candidates.filter((c) => c.name.toLowerCase() !== name);
        saveLocalCandidates(next);
        return { ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: next.candidates.length, removed: before - next.candidates.length, note: `removed ${before - next.candidates.length} local candidate(s)` };
      }

      if (op === "propose") {
        if (!args.dir) return { ok: false, op, note: "propose needs dir", proposals: [] };
        const proposals = proposeCandidates(args.dir, args.maxFiles || 500).map((g) => ({
          ext: g.ext, count: g.count, dirs: g.dirs,
          samples: g.samples,
          suggested: g.samples.slice(0, 3).map((s) => ({ type: "tool", name: path.basename(s).replace(/\.[^.]+$/, ""), path: s, desc: `found in ${path.dirname(s)}` })),
        }));
        return {
          ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: pack.candidates.length, proposals,
          note: `${proposals.length} executable/script group(s) proposed; nothing was recorded - use op=add for the ones you want`,
        };
      }

      const index = loadIndex();
      const force = !!args.force;
      const results = [];
      const conflicts = [];
      let registered = 0;
      for (const c of allCandidates()) {
        if (c.shadowed) {
          conflicts.push(`${c.type} ${c.name} (local entry shadowed by the built-in of the same name)`);
          continue;
        }
        const resolved = resolveCandidatePath(c);
        const exists = !!resolved;
        results.push({ type: c.type, name: c.name, desc: c.desc, origin: c.origin, path: resolved || c.path, exists });
        if (!exists) continue;
        // Skip if already registered (unless force).
        const dup = index.objects.find((o) => o.type === c.type && o.name === c.name && o.source === "detect");
        if (dup && !force) continue;
        const obj = {
          id: dup ? dup.id : makeId(c.type, "detect", c.name),
          type: c.type,
          name: c.name,
          source: "detect",
          path: resolved,
          description: c.desc,
          tags: ["tool", "env"].includes(c.type) ? [c.type, "detect", c.origin === "local" ? "local" : "builtin"] : ["detect"],
          summary: "",
          createdAt: new Date().toISOString(),
        };
        // Replace old same-key object (force re-scan) or append.
        if (dup) index.objects[index.objects.indexOf(dup)] = obj;
        else index.objects.push(obj);
        registered++;
      }
      index.generatedAt = new Date().toISOString();
      saveIndex(index);
      appendLog({ op: "detect", type: null, name: null, source: "detect", disposition: null, detail: `scan complete, ${registered} existing items to register` });
      // Cross-check against known objects: scanned but not-yet-registered items, to remind the static map.
      const cross = [];
      if (args.cross) {
        const knownKeys = new Set(index.objects.filter((o) => o.source === "detect").map((o) => `${o.type}::${o.name}`));
        for (const c of allCandidates()) {
          if (c.shadowed) continue;
          const resolved = resolveCandidatePath(c);
          if (resolved && !knownKeys.has(`${c.type}::${c.name}`)) {
            cross.push({ type: c.type, name: c.name, path: resolved, origin: c.origin, note: "scanned but not yet registered in Library (consider adding to workspace-map manually)" });
          }
        }
      }
      const found = results.filter((r) => r.exists).length;
      return {
        ok: true, op: "scan", file, builtin: DETECT_CANDIDATES.length, local: pack.candidates.length,
        found, registered, results, cross, conflicts,
        note: `${found} candidate(s) exist (${DETECT_CANDIDATES.length} built-in + ${pack.candidates.length} local), ${registered} to register${conflicts.length ? `, ${conflicts.length} shadowed by built-ins` : ""}`,
      };
    },
  }));

  // ---- library_sniff: true type from magic bytes + declared-vs-actual (forgery) check ----
  // A file can claim to be something it is not: an unknown extension, or worse a name that
  // imitates DSH's own output (session/storage/attachment/config/temp). The declared
  // identity is compared with the magic-byte truth and any contradiction is flagged.
  ctx.tools.register(defineTool({
    name: "library_sniff",
    description:
      "Identify a file's true type from magic header bytes, independent of a spoofable extension, and flag name/content contradictions (a file claiming to be JSON/YAML/an image or a DSH artifact whose bytes say otherwise). Pass `path` for one file, or `dir` to sweep a directory (temp/session/storage) for mismatches. Returns {type, format, note, declared, artifact, spoofed, flags}.",
    parameters: {
      path: { type: "string", description: "Absolute path of one file to identify" },
      dir: { type: "string", description: "Directory to sweep for mismatches (alternative to path)" },
      maxFiles: { type: "number", description: "Max files inspected in dir mode; default 500" },
      deep: { type: "boolean", description: "Recurse into subdirectories in dir mode; default true" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          ok: { type: "boolean" }, detected: { type: "boolean" }, type: { type: "string" }, format: { type: "string" },
          note: { type: "string" }, declared: { type: "string" }, artifact: { type: "string" }, artifactNote: { type: "string" },
          sensitive: { type: "boolean" }, temp: { type: "boolean" }, spoofed: { type: "boolean" }, flags: { type: "array", items: { type: "string" } },
          scanned: { type: "number" }, mismatches: { type: "array", items: { type: "object", additionalProperties: true } },
        },
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      if (args.path) {
        const a = assessFile(args.path);
        return { ...a, ok: true, scanned: 1, mismatches: [] };
      }
      const dir = args.dir;
      if (!dir) return { ok: false, detected: false, type: null, format: null, note: "missing path or dir", spoofed: false, flags: [], scanned: 0, mismatches: [] };
      const max = Math.min(Math.max(args.maxFiles || 500, 1), 5000);
      const deep = args.deep !== false;
      const files = [];
      const walk = (d) => {
        if (files.length >= max) return;
        let ents;
        try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
        for (const e of ents) {
          if (files.length >= max) return;
          const p = path.join(d, e.name);
          if (e.isDirectory()) { if (deep) walk(p); continue; }
          if (e.isFile()) files.push(p);
        }
      };
      walk(dir);
      const mismatches = [];
      for (const f of files) {
        const a = assessFile(f);
        if (a.spoofed) mismatches.push({ path: a.path, declared: a.declared, artifact: a.artifact, type: a.type, format: a.format, flags: a.flags });
      }
      return {
        ok: true, detected: true, type: null, format: null, spoofed: mismatches.length > 0, flags: [],
        note: `${files.length} file(s) inspected${files.length >= max ? ` (capped at ${max})` : ""}, ${mismatches.length} mismatch(es)`,
        scanned: files.length, mismatches,
      };
    },
  }));

  // ---- library_format: personalise THIS install's format library (local pack) ----
  // Built-in coverage is fixed and finite; every machine has its own formats. This tool
  // inspects the local pack, proposes unidentified types found on this machine, and
  // registers what the user confirms. Built-ins always win; conflicts are refused unless
  // explicitly confirmed, so nothing local can shadow or forge a known format.
  ctx.tools.register(defineTool({
    name: "library_format",
    description:
      "Inspect and extend this installation's format library. op=list shows the local pack and the last report date; op=scan proposes file types the library cannot identify in a directory; op=learn registers a magic signature intersected from explicit sample files; op=add registers a signature, a plain-text extension, or a name rule by hand; op=remove drops a local entry; op=deps reports which formats reference which other formats (extensions only; DLL names opt-in); op=draft writes a reviewable checklist of candidates (optionally keeping the raw context locally, encrypted); op=report builds a small contribution archive from a directory or from selected draft items - extensions, magic prefixes, counts and format relationships, with paths omitted by default, sanitised when requested, or sealed under a passphrase you hold (op=unseal reopens it). Built-ins are always matched first and conflicts are refused unless confirm:true. Scanning alone never learns anything and this tool performs no network I/O - reports are delivered manually by the user.",
    parameters: {
      op: { type: "string", required: true, description: "list | scan | learn | add | remove | draft | deps | report | unseal" },
      dir: { type: "string", description: "scan/report: directory to inspect" },
      maxFiles: { type: "number", description: "scan/report: max files to inspect; default 1000 (scan) / 1500 (report)" },
      out: { type: "string", description: "draft/report: output path; defaults to $DSH_HOME/library/reports[/drafts]/<kind>-<timestamp>.zip|json" },
      draft: { type: "string", description: "report: draft id or path to build the archive from (only the items you select)" },
      include: { type: "array", items: { type: "string" }, description: "report: item ids from the draft to include (e.g. [\"f1\",\"f3\"]); \"all\" or includeAll:true for every item" },
      includeAll: { type: "boolean", description: "report: include every item of the draft" },
      pathDetail: { type: "string", description: "draft/report: user-level path detail - none (default, no paths at all) | dirs (sanitised directory names) | full (sanitised paths)" },
      depth: { type: "number", description: "draft/report: directory depth kept in dirs mode; default 3" },
      excludeDir: { type: "array", items: { type: "string" }, description: "draft/report: literal strings to replace with <excluded> in any path" },
      deps: { type: "boolean", description: "report: collect format->format relationships; default true" },
      names: { type: "boolean", description: "deps/report: include imported DLL names (treated as user-level, sealable); default false" },
      seal: { type: "string", description: "report: passphrase to seal the user-level fields (paths, DLL names) with AES-256-GCM - you keep the passphrase and can reopen it locally with op=unseal" },
      passphrase: { type: "string", description: "unseal: the passphrase used when sealing" },
      file: { type: "string", description: "unseal: the archive containing a sealed layer" },
      keepLocal: { type: "boolean", description: "draft: also keep the RAW unredacted context locally as an encrypted Library object (open with library_decrypt)" },
      ext: { type: "string", description: "learn/add/remove: file extension without the dot" },
      paths: { type: "array", items: { type: "string" }, description: "learn: sample file paths of that type (2+ recommended; headers are intersected)" },
      bytes: { type: "number", description: "learn: how many leading bytes of the intersected prefix to store; default 8 (drops version/build fields), min 2 max 16" },
      format: { type: "string", description: "learn/add: format name to register (defaults to the extension)" },
      type: { type: "string", description: "learn/add: family - document|image|audio|video|archive|executable|database|font|model" },
      sig: { type: "string", description: "add: magic bytes as hex, e.g. \"50 4f 43 50\"" },
      textExtension: { type: "string", description: "add: register a plain-text extension instead (e.g. myext)" },
      nameRule: { type: "string", description: "add: regex matched against name/path, defining a local artifact role" },
      role: { type: "string", description: "add: role name used with nameRule" },
      expect: { type: "string", description: "add: expected family for nameRule (enables mismatch checks on it)" },
      note: { type: "string", description: "learn/add: short human note" },
      confirm: { type: "boolean", description: "learn/add: proceed despite a built-in conflict or an unusually short signature" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          ok: { type: "boolean" }, op: { type: "string" }, file: { type: "string" }, note: { type: "string" },
          bytes: { type: "number" },
          lastReport: { type: "object", additionalProperties: true },
          entries: { type: "array", items: { type: "object", additionalProperties: true } },
          mail: { type: "object", additionalProperties: true },
          preview: { type: "string" },
          unidentifiedCount: { type: "number" },
          draft: { type: "string" },
          keptLocalId: { type: "string" },
          paths: { type: "string" },
          pathDetail: { type: "string" },
          deps: { type: "array", items: { type: "object", additionalProperties: true } },
          dllNames: { type: "array", items: { type: "string" } },
          sealed: { type: "object", additionalProperties: true },
          builtin: { type: "object", additionalProperties: true },
          local: { type: "object", additionalProperties: true },
          learned: { type: "object", additionalProperties: true },
          scanned: { type: "number" },
          unidentified: { type: "array", items: { type: "object", additionalProperties: true } },
          conflicts: { type: "array", items: { type: "string" } },
          verified: { type: "array", items: { type: "object", additionalProperties: true } },
          removed: { type: "number" },
        },
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const op = String(args.op || "").toLowerCase();
      const packFile = localFormatsFile();
      const builtin = { signatures: FILE_SIGNATURES.length, textExtensions: TEXT_EXTENSIONS.length, zipPackages: Object.keys(ZIP_PACKAGE_FORMATS).length, dshArtifacts: DSH_ARTIFACTS.length };
      const summary = (p) => ({
        formats: p.formats.map((f) => ({ format: f.format, type: f.type, sig: hexSig(f.sig), bytes: f.sig.length, ext: f.ext, note: f.note })),
        textExtensions: p.textExtensions,
        nameRules: p.nameRules.map((r) => ({ re: String(r.re), role: r.role, expect: r.expect })),
        updatedAt: p.updatedAt,
      });
      const pack = loadLocalFormats();

      if (op === "list") {
        // Report cadence is a *reminder for the user*, never an automatic send.
        let lastReport = null;
        const at = (ms) => ({ at: new Date(ms).toISOString(), daysSince: Math.floor((Date.now() - ms) / 86400000) });
        try {
          const recs = loadIndex().objects.filter((o) => Array.isArray(o.tags) && o.tags.includes("format-report"));
          recs.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
          if (recs.length) {
            const t = Date.parse(recs[0].createdAt) || Date.now();
            lastReport = { file: recs[0].path || null, name: recs[0].name || null, ...at(t) };
          }
        } catch {}
        if (!lastReport) {
          try {
            const zips = fs.readdirSync(reportsDir()).filter((f) => f.endsWith(".zip")).sort();
            if (zips.length) {
              const newest = path.join(reportsDir(), zips[zips.length - 1]);
              lastReport = { file: newest, name: zips[zips.length - 1], ...at(fs.statSync(newest).mtimeMs) };
            }
          } catch {}
        }
        if (lastReport) lastReport.reminderDue = lastReport.daysSince >= 60;
        const hint = lastReport && lastReport.reminderDue
          ? ` - it has been ${lastReport.daysSince} days since the last format report; run op=report if you want to contribute again`
          : " - op=report builds a local format report you can choose to send (nothing is uploaded automatically)";
        return { ok: true, op, file: packFile, builtin, local: summary(pack), lastReport, note: (fs.existsSync(packFile) ? "local pack loaded" : "no local pack yet (add/learn creates it)") + hint };
      }

      if (op === "scan") {
        if (!args.dir) return { ok: false, op, note: "scan needs dir", scanned: 0, unidentified: [] };
        const { scanned, groups } = collectUnidentified(args.dir, args.maxFiles || 1000, 3, true);
        const unidentified = [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 25).map((g) => {
          const prefix = commonPrefix(g.heads);
          const suggestion = prefix.slice(0, 8);
          return {
            ext: g.ext, count: g.count, sampleCount: g.sampleCount, samples: g.samples,
            commonPrefix: prefix.length ? hexSig(prefix) : null,
            prefixBytes: prefix.length,
            suggestedSig: suggestion.length ? hexSig(suggestion) : null,
            conflicts: suggestion.length >= 2 ? builtinSigConflicts(suggestion) : [],
          };
        });
        return { ok: true, op, file: packFile, builtin, scanned, unidentified, note: `${unidentified.length} unidentified type(s) proposed; nothing was learned - call op=learn with samples to register one` };
      }

      // ---- draft: a checklist of candidates the user reviews before anything is built ----
      if (op === "draft") {
        if (!args.dir) return { ok: false, op, note: "draft needs dir", scanned: 0, unidentified: [] };
        const pathMode = ["none", "dirs", "full"].includes(String(args.pathDetail || "").toLowerCase()) ? String(args.pathDetail).toLowerCase() : "none";
        const depth = Math.min(Math.max(parseInt(args.depth, 10) || 3, 1), 8);
        const excl = (Array.isArray(args.excludeDir) ? args.excludeDir : []).map(String);
        const { scanned, groups } = collectUnidentified(args.dir, args.maxFiles || 1500, 6, true);
        const items = [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 200).map((g, i) => {
          const prefix = commonPrefix(g.heads);
          const suggestion = prefix.slice(0, 8);
          return {
            id: `f${i + 1}`,
            ext: g.ext, count: g.count, sampleCount: g.sampleCount,
            commonPrefix: prefix.length ? hexSig(prefix) : null,
            prefixBytes: prefix.length,
            suggestedSig: suggestion.length ? hexSig(suggestion) : null,
            conflicts: suggestion.length >= 2 ? builtinSigConflicts(suggestion) : [],
            dirs: pathMode === "none" ? [] : [...new Set(g.samples.map((s) => sanitizePath(s, "dirs", depth, excl)))].slice(0, 4),
            samplePaths: pathMode === "full" ? g.samples.map((s) => sanitizePath(s, "full", depth, excl)) : [],
          };
        });
        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
        const draft = { version: 1, createdAt: new Date().toISOString(), source: args.dir, localOnly: "this draft file stays on this machine: it keeps the raw source path so a later op=report can re-scan for dependencies - share the archive, not the draft", scanned, pathDetail: pathMode, depth, excluded: excl, deps: args.deps !== false, items };
        const draftFile = args.out || path.join(draftsDir(), `draft-${stamp}.json`);
        fs.mkdirSync(path.dirname(draftFile), { recursive: true });
        fs.writeFileSync(draftFile, JSON.stringify(draft, null, 2), "utf8");
        let keptLocalId = null;
        if (args.keepLocal) {
          // Preserve the RAW (unredacted) context locally, encrypted with this install's
          // library key: nothing is lost, and only this machine can open it.
          const raw = { draft, rawSamples: [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 200).map((g, i) => ({ id: `f${i + 1}`, ext: g.ext, count: g.count, samples: g.samples })) };
          const index = loadIndex();
          const id = makeId("knowledge", "local", `format-draft-${stamp}`);
          index.objects.push({
            id, type: "knowledge", name: `format draft (raw, encrypted) ${stamp}`, source: "local",
            description: `Unredacted format-draft context: ${items.length} unidentified type(s) with raw sample paths; encrypted with this install's library key - open with library_decrypt`,
            tags: ["format-draft", "local", "format"], summary: `mega-index-map ${PLUGIN_VERSION}`, sensitive: true,
            createdAt: new Date().toISOString(), __content: encryptSensitive(raw),
          });
          index.generatedAt = new Date().toISOString();
          saveIndex(index);
          keptLocalId = id;
        }
        return {
          ok: true, op, file: draftFile, scanned, unidentifiedCount: items.length, keptLocalId,
          entries: items.slice(0, 60).map((it) => ({ name: it.id, ext: it.ext, count: it.count })),
          preview: items.slice(0, 40).map((it) => `${it.id.padEnd(5)} .${it.ext.padEnd(9)} x${String(it.count).padEnd(6)} prefix=${it.commonPrefix ?? "(none)"}${it.dirs.length ? "  dirs=" + it.dirs.join(", ") : ""}`).join("\n"),
          note: `draft written locally: ${items.length} candidate(s), nothing sent - review, then op=report draft=${path.basename(draftFile)} include=<ids|all>${keptLocalId ? `; raw context kept encrypted as ${keptLocalId}` : ""}`,
        };
      }

      // ---- deps: which formats reference which other formats (no paths, opt-in DLL names) ----
      if (op === "deps") {
        if (!args.dir) return { ok: false, op, note: "deps needs dir" };
        const r = collectDeps(args.dir, args.maxFiles || 2000, !!args.names);
        return {
          ok: true, op, scanned: r.scanned, unidentifiedCount: r.inspected,
          deps: r.edges, dllNames: args.names ? r.dllNames : [],
          preview: r.edges.slice(0, 40).map((e) => `${e.from} -> ${e.to}  x${e.count}`).join("\n"),
          note: `${r.edges.length} format relationship(s) from ${r.inspected} inspected file(s): extensions only${args.names ? ", plus DLL names (treat as user-level)" : ""}`,
        };
      }

      // ---- unseal: reopen a sealed layer locally with the user's own passphrase ----
      if (op === "unseal") {
        const file = args.file || args.path;
        if (!file || !fs.existsSync(file)) return { ok: false, op, note: "unseal needs file=<sealed archive>" };
        if (!args.passphrase) return { ok: false, op, note: "unseal needs passphrase (the one you sealed with)" };
        const entry = zipReadEntry(fs.readFileSync(file), "sealed.json");
        if (!entry) return { ok: false, op, note: "that archive has no sealed layer" };
        const plain = unsealWithPassphrase(args.passphrase, JSON.parse(entry.toString("utf8")));
        if (plain.__unsealError) return { ok: false, op, note: "wrong passphrase (or the sealed layer is corrupted)" };
        return { ok: true, op, file, preview: JSON.stringify(plain, null, 2).split("\n").slice(0, 40).join("\n"), note: "sealed layer opened locally; nothing left this machine" };
      }

      // ---- report: build a small, inspectable contribution archive (local, no network) ----
      if (op === "report") {
        let pathMode = ["none", "dirs", "full"].includes(String(args.pathDetail || "").toLowerCase()) ? String(args.pathDetail).toLowerCase() : "none";
        let depth = Math.min(Math.max(parseInt(args.depth, 10) || 3, 1), 8);
        let excl = (Array.isArray(args.excludeDir) ? args.excludeDir : []).map(String);
        let items, scanned, sourceDir = args.dir || null, prefDeps = true, fromDraft = null;
        if (args.draft) {
          const dp = resolveDraft(args.draft);
          if (!dp) return { ok: false, op, note: `draft not found: ${args.draft}` };
          const d = JSON.parse(fs.readFileSync(dp, "utf8"));
          fromDraft = dp;
          sourceDir = d.source || sourceDir;
          scanned = d.scanned || 0;
          prefDeps = d.deps !== false;
          // The draft already recorded how much path detail the user chose - keep it unless
          // this call overrides it explicitly.
          if (!args.pathDetail && ["none", "dirs", "full"].includes(String(d.pathDetail || ""))) pathMode = String(d.pathDetail);
          if (args.depth === undefined && d.depth) depth = Math.min(Math.max(parseInt(d.depth, 10) || 3, 1), 8);
          if (!args.excludeDir && Array.isArray(d.excluded) && d.excluded.length) excl = d.excluded.map(String);
          const want = Array.isArray(args.include) ? args.include.map(String) : String(args.include || "").split(",").map((s) => s.trim()).filter(Boolean);
          if (!want.length && args.includeAll !== true) {
            // Nothing preselected: return the checklist instead of quietly taking everything.
            return {
              ok: false, op, file: dp, unidentifiedCount: d.items.length,
              preview: d.items.slice(0, 40).map((it) => `${it.id.padEnd(5)} .${it.ext.padEnd(9)} x${String(it.count).padEnd(6)} prefix=${it.commonPrefix ?? "(none)"}`).join("\n"),
              note: "draft loaded - nothing was written. Choose what to include: include=[\"f1\",\"f3\"] (or includeAll:true), then run again",
            };
          }
          const all = want.includes("all") || args.includeAll === true;
          items = all ? d.items : d.items.filter((it) => want.includes(it.id));
          if (!items.length) return { ok: false, op, file: dp, note: "no matching ids in that draft (use include=f1,f3 or includeAll:true)" };
        } else {
          if (!args.dir) return { ok: false, op, note: "report needs dir (or draft)", scanned: 0, unidentified: [] };
          const fresh = collectUnidentified(args.dir, args.maxFiles || 1500, 6, pathMode !== "none");
          scanned = fresh.scanned;
          items = [...fresh.groups.values()].sort((a, b) => b.count - a.count).slice(0, 200).map((g, i) => {
            const prefix = commonPrefix(g.heads);
            const suggestion = prefix.slice(0, 8);
            return {
              id: `f${i + 1}`,
              ext: g.ext, count: g.count, sampleCount: g.sampleCount,
              commonPrefix: prefix.length ? hexSig(prefix) : null,
              prefixBytes: prefix.length,
              suggestedSig: suggestion.length ? hexSig(suggestion) : null,
              conflicts: suggestion.length >= 2 ? builtinSigConflicts(suggestion) : [],
              dirs: pathMode === "none" ? [] : [...new Set(g.samples.map((s) => sanitizePath(s, "dirs", depth, excl)))].slice(0, 4),
              samplePaths: pathMode === "full" ? g.samples.map((s) => sanitizePath(s, "full", depth, excl)) : [],
            };
          });
        }
        const unidentified = items.map((it) => ({
          ext: it.ext, count: it.count, sampleCount: it.sampleCount,
          commonPrefix: it.commonPrefix, prefixBytes: it.prefixBytes, suggestedSig: it.suggestedSig, conflicts: it.conflicts,
        }));
        // User-level fields: paths, and DLL names when asked for. Everything else is format knowledge.
        const userLevel = {};
        if (pathMode !== "none") {
          const dirs = [...new Set(items.flatMap((it) => it.dirs || []))].slice(0, 300);
          if (dirs.length) userLevel.dirs = dirs;
          if (pathMode === "full") {
            const sp = items.flatMap((it) => it.samplePaths || []).slice(0, 300);
            if (sp.length) userLevel.samplePaths = sp;
          }
        }
        const depsOn = args.deps !== undefined ? !!args.deps : prefDeps;
        let depsData = null;
        if (depsOn && sourceDir) {
          const dd = collectDeps(sourceDir, args.maxFiles || 1500, !!args.names);
          depsData = { edges: dd.edges.slice(0, 200), inspected: dd.inspected, dllCount: dd.dllNames.length };
          if (args.names && dd.dllNames.length) userLevel.dllNames = dd.dllNames;
        }
        const report = {
          report: "mega-index-map format report",
          reportVersion: 2,
          plugin: name,
          pluginVersion: PLUGIN_VERSION,
          generatedAt: new Date().toISOString(),
          pathDetail: pathMode,
          fromDraft: fromDraft ? path.basename(fromDraft) : null,
          privacy: "Collected: file extensions, magic-byte prefixes, counts, format->format relationships, plugin version, local pack entries (no notes). NOT collected: file contents and credentials. Directory information is user-level and controlled by you: omitted at pathDetail=none (default), sanitised with ...<drive>/<home>/<user>/<host>/<uuid>/<date>... placeholders at dirs (directory names only) or full (also sample file names), or sealed under your own passphrase. DLL names are user-level and opt-in.",
          scannedFiles: scanned,
          builtin,
          localPack: {
            formats: pack.formats.map((f) => ({ format: f.format, type: f.type, sig: hexSig(f.sig), ext: f.ext })),
            textExtensions: pack.textExtensions,
            nameRules: pack.nameRules.map((r) => ({ role: r.role, expect: r.expect })),
          },
          deps: depsData,
          unidentified,
        };
        const extraFiles = [];
        if (args.seal && Object.keys(userLevel).length) {
          const fieldCount = Object.values(userLevel).reduce((n, v) => n + v.length, 0);
          report.sealed = { fields: fieldCount, layers: Object.keys(userLevel), kdf: "hkdf-sha256/aes-256-gcm", howToOpen: "library_format op=unseal file=<this archive> passphrase=<yours>" };
          extraFiles.push({ name: "sealed.json", data: JSON.stringify(sealWithPassphrase(args.seal, { userLevel }), null, 2) });
        } else if (Object.keys(userLevel).length) {
          Object.assign(report, userLevel);
        }
        const manifest = [
          `${report.report} - v${report.reportVersion}`,
          `plugin       : ${report.plugin} ${report.pluginVersion}`,
          `generated at : ${report.generatedAt}`,
          `files scanned: ${scanned}`,
          `unidentified : ${unidentified.length} type(s)`,
          `path detail  : ${pathMode}${pathMode === "dirs" ? " (directory names only, sanitised: <drive>/<home>/<user>/<host>/<uuid>/<date>)" : pathMode === "full" ? " (sanitised paths incl. sample file names)" : " (no directory information at all)"}`,
          `dependencies : ${depsData ? `${depsData.edges.length} format relationship(s) - format names only` : "not collected"}`,
          report.sealed ? `sealed layer : ${report.sealed.fields} field(s) - sealed with YOUR passphrase, openable only by you (see below)` : null,
          "",
          "Contents of this archive:",
          "  report.json  - machine-readable summary (extensions, magic prefixes, counts, dependencies)",
          "  manifest.txt - this human-readable summary",
          report.sealed ? "  sealed.json  - AES-256-GCM layer you can reopen with op=unseal; cannot be read without your passphrase" : null,
          "",
          args.seal ? "Your passphrase protects the user-level layer, so you can share the archive without sharing paths." : "NOT included, by design: file names, file contents, user name, host name, credentials.",
          pathMode === "none" ? "You chose paths=none, so no directory information is present at all." : "Directory information present is sanitised, but please read it before sending.",
          "",
          "How to send it (manual - your decision, after reading this):",
          "  to     : seimuontei@gmail.com",
          `  subject: [format report] mega-index-map ${report.pluginVersion}`,
          "  attach : this .zip",
          "  (or upload it yourself, e.g. gigafile.nu, and send the link)",
          "",
          "This plugin performs no network I/O for reports: nothing was uploaded or e-mailed for you.",
          "",
          "Top unidentified types:",
          ...unidentified.slice(0, 40).map((u) => `  .${u.ext}  x${String(u.count).padEnd(6)} samples=${u.sampleCount}  prefix=${u.commonPrefix ?? "(none)"}`),
          ...(depsData && depsData.edges.length ? ["", "Format relationships (top 20):", ...depsData.edges.slice(0, 20).map((e) => `  ${e.from} -> ${e.to}  x${e.count}`)] : []),
        ].filter((l) => l !== null).join("\n");
        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
        const outFile = args.out || path.join(reportsDir(), `format-report-${stamp}.zip`);
        fs.mkdirSync(path.dirname(outFile), { recursive: true });
        const reportJson = JSON.stringify(report, null, 2);
        // manifest gets a UTF-8 BOM so plain Windows tools (Notepad, mail preview) show it correctly.
        const buf = zipBuffer([{ name: "report.json", data: reportJson }, { name: "manifest.txt", data: "\uFEFF" + manifest }, ...extraFiles]);
        fs.writeFileSync(outFile, buf);
        // Record the produced archive in the Library (so library_query and the cadence
        // reminder can find it no matter where it was written).
        const index = loadIndex();
        const obj = {
          id: makeId("file", "local", `format-report-${stamp}`),
          type: "file",
          name: `format report ${stamp}`,
          source: "local",
          path: outFile,
          description: `Format-library contribution archive: ${unidentified.length} unidentified type(s) out of ${scanned} scanned file(s); extensions, magic prefixes and format relationships; paths=${pathMode}${report.sealed ? `, ${report.sealed.fields} user-level field(s) sealed` : ""}; built locally, not sent`,
          tags: ["format-report", "local", "format"],
          summary: `mega-index-map ${PLUGIN_VERSION}, ${buf.length} bytes`,
          createdAt: new Date().toISOString(),
        };
        index.objects.push(obj);
        index.generatedAt = obj.createdAt;
        saveIndex(index);
        appendLog({ op: "format-report", type: "format", name: null, source: "local", disposition: null, detail: `report written locally: ${unidentified.length} unidentified type(s), paths=${pathMode}${report.sealed ? ", sealed" : ""}, ${buf.length} bytes (not sent)` });
        return {
          ok: true, op, file: outFile, bytes: buf.length, scanned, unidentifiedCount: unidentified.length,
          pathDetail: pathMode,
          deps: depsData ? depsData.edges : [],
          dllNames: args.names ? userLevel.dllNames || [] : [],
          sealed: report.sealed || null,
          entries: [
            { name: "report.json", bytes: Buffer.byteLength(reportJson) },
            { name: "manifest.txt", bytes: Buffer.byteLength(manifest) },
            ...extraFiles.map((f) => ({ name: f.name, bytes: Buffer.byteLength(f.data) })),
          ],
          mail: { to: "seimuontei@gmail.com", subject: `[format report] mega-index-map ${PLUGIN_VERSION}`, attachment: outFile },
          preview: manifest.split("\n").slice(0, 28).join("\n"),
          note: `report written locally (${buf.length} bytes, ${unidentified.length} unidentified type(s), paths=${pathMode}${report.sealed ? `, ${report.sealed.fields} field(s) sealed with your passphrase` : ""}) - nothing was uploaded; review manifest.txt, then send it yourself if you choose to`,
        };
      }

      if (op === "learn") {
        const ext = String(args.ext || "").replace(/^\./, "").toLowerCase();
        const paths = (Array.isArray(args.paths) ? args.paths : []).filter((p) => typeof p === "string");
        if (!ext || !paths.length) return { ok: false, op, note: "learn needs ext and at least one sample path", conflicts: [] };
        const heads = paths.filter((p) => fs.existsSync(p)).map((p) => readHeader(p, 16)).filter(Boolean);
        if (!heads.length) return { ok: false, op, note: "no readable sample path", conflicts: [] };
        const prefix = commonPrefix(heads);
        // The intersected prefix often includes version/build fields, so only the first
        // `bytes` bytes (default 8) are stored - a signature that also matches the next
        // release of the same format. Everything is reported for review.
        const wantBytes = Math.min(Math.max(parseInt(args.bytes, 10) || 8, 2), 16);
        const sig = prefix.slice(0, wantBytes);
        const truncated = prefix.length > sig.length;
        const conflicts = builtinSigConflicts(sig);
        const short = sig.length < 4;
        if (heads.length < 2) conflicts.push("only one sample: a shared prefix is not evidence (use 2+ files)");
        if ((conflicts.length || short) && !args.confirm) {
          return { ok: false, op, file: packFile, conflicts, learned: { samplePrefix: hexSig(prefix), bytes: prefix.length, stored: hexSig(sig), storedBytes: sig.length }, note: `refused: ${short ? "signature shorter than 4 bytes" : "signature collides with a built-in format"} - pass confirm:true to override` };
        }
        const format = String(args.format || ext).slice(0, 40);
        const entry = { format, type: String(args.type || "document"), sig, ext: [ext], note: String(args.note || `locally learned (.${ext})`).slice(0, 200), createdAt: new Date().toISOString() };
        const next = normalizeLocalPack({ ...pack, formats: [...pack.formats.filter((f) => f.format !== format && !f.ext.includes(ext)), entry] });
        saveLocalFormats(next);
        const verified = paths.filter((p) => fs.existsSync(p)).map((p) => {
          const r = sniffFileType(p);
          return { path: p, format: r ? r.format : null, ok: !!(r && r.format === format) };
        });
        appendLog({ op: "format-learn", type: "format", name: format, source: "local", disposition: null, detail: `learned ${hexSig(sig)} for .${ext} from ${heads.length} sample(s)` });
        return { ok: true, op, file: packFile, builtin, local: summary(loadLocalFormats()), conflicts, verified, learned: { samplePrefix: hexSig(prefix), bytes: prefix.length, stored: hexSig(sig), storedBytes: sig.length, truncated }, note: `learned ${format} = ${hexSig(sig)} (.${ext})${truncated ? ` - intersected prefix was ${prefix.length} bytes, stored first ${sig.length} for version tolerance` : ""}; verified on ${verified.filter((v) => v.ok).length}/${verified.length} sample(s)` };
      }

      if (op === "add") {
        const next = normalizeLocalPack(pack);
        const conflicts = [];
        let what = "";
        if (args.textExtension) {
          const e = String(args.textExtension).replace(/^\./, "").toLowerCase();
          if (!e) return { ok: false, op, note: "empty textExtension" };
          if (TEXT_EXTENSIONS.includes(e)) conflicts.push(`.${e} is already a built-in text extension`);
          if (conflicts.length && !args.confirm) return { ok: false, op, conflicts, note: "redundant with a built-in (pass confirm:true to keep it anyway)" };
          if (!next.textExtensions.includes(e)) next.textExtensions.push(e);
          what = `text extension .${e}`;
        } else if (args.nameRule) {
          let re;
          try { re = new RegExp(String(args.nameRule), "i"); } catch (err) { return { ok: false, op, note: `invalid nameRule regex: ${err.message}` }; }
          next.nameRules.push({ re, role: String(args.role || "local"), expect: args.expect || null, note: String(args.note || "").slice(0, 200) });
          what = `name rule /${re.source}/ role=${args.role || "local"}`;
        } else {
          const sig = parseHexSig(args.sig);
          if (!sig) return { ok: false, op, note: "add needs sig (hex bytes), textExtension, or nameRule" };
          const format = String(args.format || "").slice(0, 40);
          if (!format) return { ok: false, op, note: "add with sig needs format" };
          conflicts.push(...builtinSigConflicts(sig));
          if (sig.length < 4) conflicts.push("prefix shorter than 4 bytes");
          if (conflicts.length && !args.confirm) return { ok: false, op, conflicts, note: "refused (pass confirm:true to override)" };
          const ext = String(args.ext || "").replace(/^\./, "").toLowerCase();
          next.formats = next.formats.filter((f) => f.format !== format);
          next.formats.push({ format, type: String(args.type || "document"), sig, ext: ext ? [ext] : [], note: String(args.note || "").slice(0, 200), createdAt: new Date().toISOString() });
          what = `signature ${format} = ${hexSig(sig)}`;
        }
        saveLocalFormats(next);
        appendLog({ op: "format-add", type: "format", name: args.format || args.textExtension || args.role || null, source: "local", disposition: null, detail: what });
        return { ok: true, op, file: packFile, local: summary(loadLocalFormats()), conflicts, note: `added ${what}` };
      }

      if (op === "remove") {
        const ext = String(args.ext || "").replace(/^\./, "").toLowerCase();
        const format = String(args.format || "");
        if (!ext && !format) return { ok: false, op, note: "remove needs ext or format" };
        const next = normalizeLocalPack(pack);
        const before = next.formats.length + next.textExtensions.length + next.nameRules.length;
        next.formats = next.formats.filter((f) => f.format !== format && !(ext && f.ext.includes(ext)));
        next.textExtensions = next.textExtensions.filter((e) => e !== ext);
        next.nameRules = next.nameRules.filter((r) => r.role !== format);
        const after = next.formats.length + next.textExtensions.length + next.nameRules.length;
        saveLocalFormats(next);
        return { ok: true, op, file: packFile, removed: before - after, local: summary(loadLocalFormats()), note: `removed ${before - after} local entr(ies)` };
      }

      return { ok: false, op, note: `unknown op "${args.op}", allowed: list, scan, learn, add, remove, draft, deps, report, unseal` };
    },
  }));

  // ---- library_decrypt: manually decrypt a sensitive object (never auto-decrypt) ----
  ctx.tools.register(defineTool({
    name: "library_decrypt",
    description:
      "Manually decrypt an encrypted-isolated sensitive object (sensitive:true). Call only when the user explicitly needs to read its content; never auto-decrypt in queries. Returns the decrypted object (or as-is if not sensitive).",
    parameters: {
      id: { type: "string", required: true, description: "Object id of a sensitive item (from library_query)" },
    },
    output: {
      schema: { type: "object", additionalProperties: true, properties: { ok: { type: "boolean" }, object: { type: "object", additionalProperties: true }, message: { type: "string" } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const index = loadIndex();
      const rec = index.objects.find((o) => o.id === args.id);
      if (!rec) throw new Error(`library_decrypt: object id "${args.id}" not found`);
      // A sensitive object is stored as {..., __content: cipherObj}; only decrypt if __content exists.
      if (rec.__content && rec.__content.sens === 1) {
        const plain = decryptSensitive(rec.__content);
        if (plain && plain.__decryptError) {
          appendLog({ op: "decrypt", type: null, name: null, source: null, disposition: null, detail: `decrypt failed id=${args.id}` });
          return { ok: false, object: null, message: "decrypt failed (key mismatch or corrupted data)" };
        }
        appendLog({ op: "decrypt", type: null, name: null, source: null, disposition: null, detail: `manual decrypt id=${args.id}` });
        return { ok: true, object: plain };
      }
      return { ok: true, object: rec };
    },
  }));

  // ---- library_export: export/migrate the Library to standard JSON/NDJSON ----
  ctx.tools.register(defineTool({
    name: "library_export",
    description:
      "Export the Library to JSON or NDJSON. Sensitive objects stay encrypted (no plaintext). Use for cross-machine migration, backup, or sharing. path optional; defaults to a timestamped export file.",
    parameters: {
      format: { type: "string", description: "json | ndjson; default json" },
      path: { type: "string", description: "Absolute export target path; defaults to the library directory" },
    },
    output: {
      schema: { type: "object", additionalProperties: false, properties: { ok: { type: "boolean" }, file: { type: "string" }, count: { type: "number" } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value) }],
    },
    async execute(args) {
      const index = loadIndex();
      const format = args.format === "ndjson" ? "ndjson" : "json";
      // Sensitive objects are exported with their encrypted __content block intact (NOT
      // decrypted, NOT dropped), so a migrated library can still decrypt them later.
      const exportable = index.objects.map((o) => {
        if (o.__content) {
          const { sensitive, ...rest } = o;
          return { ...rest, sensitive: true, __content: o.__content };
        }
        return o;
      });
      const out = args.path || path.join(libraryDir(), `export-${Date.now()}.${format === "ndjson" ? "ndjson" : "json"}`);
      if (format === "ndjson") {
        fs.writeFileSync(out, exportable.map((o) => JSON.stringify(o)).join("\n") + "\n", "utf8");
      } else {
        fs.writeFileSync(out, JSON.stringify({ version: 1, generatedAt: new Date().toISOString(), objects: exportable }, null, 2), "utf8");
      }
      appendLog({ op: "export", type: null, name: null, source: null, disposition: null, detail: `exported ${exportable.length} objects to ${out}` });
      return { ok: true, file: out, count: exportable.length };
    },
  }));

  // ---- library_encoding: detect system default encoding and give indicative guidance ----
  // Reports the host's system default encoding, whether it is UTF-8 compatible, and (if not)
  // region-aware indicative commands to switch to UTF-8 so the plugin lands without mojibake.
  ctx.tools.register(defineTool({
    name: "library_encoding",
    description:
      "Detect the host's system default encoding and report UTF-8 compatibility plus region-aware advice (Japan/Korea/SE Asia/China-Taiwan/Europe/LatAm). The library persists as UTF-8; a non-UTF-8 default can mojibake external output and file reads. Use to advise setting UTF-8.",
    parameters: {},
    output: {
      schema: { type: "object", additionalProperties: false, properties: { utf8: { type: "boolean" }, codepage: { type: "number" }, label: { type: "string" }, hints: { type: "array", items: { type: "object", additionalProperties: true } } } },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    async execute() {
      const enc = detectSystemEncoding();
      const hints = enc.utf8
        ? [{ region: "all", note: "System default encoding is UTF-8; no adaptation needed." }]
        : INDICATIVE_ENCODING_HINTS.filter((h) => enc.codepage == null || h.codepages.includes(enc.codepage));
      appendLog({ op: "encoding", type: null, name: null, source: null, disposition: null, detail: `detected ${enc.label} (utf8=${enc.utf8})` });
      return { utf8: enc.utf8, codepage: enc.codepage, label: enc.label, hints };
    },
  }));

  // ---- library_adb: legitimate Android device management via adb ----
  // Wraps the developer-side ADB operations only (no Metasploit/DoS/SMS/bulk-privacy-copy).
  ctx.tools.register(defineTool({
    name: "library_adb",
    description:
      "Manage an Android device over ADB using legitimate developer operations only: devices, restart-server, reboot, reboot-recovery, reboot-bootloader, shell, info-system, info-cpu, info-memory, device-details, bugreport, install, uninstall, list-packages, logcat, push, pull, launch, screenshot, screenrecord, root-check, remote-connect. Requires USB debugging; use on your own test device only.",
    parameters: {
      action: {
        type: "string",
        required: true,
        description: "Operation: devices|restart-server|reboot|reboot-recovery|reboot-bootloader|shell|info-system|info-cpu|info-memory|device-details|bugreport|install|uninstall|list-packages|logcat|push|pull|launch|screenshot|screenrecord|root-check|remote-connect",
      },
      device: { type: "string", description: "Device serial (from 'devices'); omit for single device" },
      command: { type: "string", description: "Shell command (action=shell)" },
      package: { type: "string", description: "Package (action=install/uninstall/launch)" },
      apk: { type: "string", description: "Local APK path (action=install)" },
      local: { type: "string", description: "Local file/folder path (push/pull, screenshot/screenrecord output)" },
      remote: { type: "string", description: "Device path (push/pull)" },
      target: { type: "string", description: "ip:port (action=remote-connect)" },
      lines: { type: "number", description: "Logcat line count (default 100)" },
      seconds: { type: "number", description: "Screenrecord seconds (default 10, max 180)" },
      record: { type: "boolean", description: "Record the operation as a work_record" },
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
    async execute(args) {
      const action = args.action;
      const cfg = ADB_ACTIONS[action];
      if (!cfg) {
        throw new Error(`library_adb: unknown action "${action}", allowed: ${Object.keys(ADB_ACTIONS).join(", ")}`);
      }
      for (const k of cfg.need || []) {
        if (!args[k]) throw new Error(`library_adb: action "${action}" requires "${k}"`);
      }
      const device = args.device || "";
      let result;
      if (cfg.restart) {
        // kill-server / start-server are global (no -s).
        const k = await runAdb(["kill-server"]);
        const s = await runAdb(["start-server"]);
        result = { ok: s.ok || k.ok, code: s.code || k.code, out: (k.out + "\n" + s.out).trim(), err: (k.err + "\n" + s.err).trim() };
      } else if (cfg.details) {
        const props = ["ro.product.model", "ro.product.brand", "ro.product.manufacturer", "ro.build.version.release", "ro.build.version.sdk", "ro.product.device"];
        let out = "";
        let ok = false;
        for (const p of props) {
          const r = await runAdb(["shell", "getprop", p], { device });
          if (r.ok) { ok = true; out += `${p}=${r.out.trim()}\n`; }
        }
        result = { ok, code: ok ? 0 : -1, out, err: ok ? "" : "no device property returned" };
      } else if (cfg.screenshot || cfg.screenrecord) {
        const isShot = !!cfg.screenshot;
        ensureLibrary();
        const remote = `/sdcard/mega-index-${isShot ? "shot" : "rec"}-${Date.now()}.${isShot ? "png" : "mp4"}`;
        const secs = Math.min(Math.max(args.seconds || 10, 1), 180);
        const capArgs = isShot
          ? ["shell", "screencap", "-p", remote]
          : ["shell", "screenrecord", "--time-limit", String(secs), remote];
        const cap = await runAdb(capArgs, { device, timeoutMs: isShot ? 30000 : (secs + 10) * 1000 });
        if (!cap.ok) {
          result = cap;
        } else {
          const local = args.local || path.join(payloadDir(), `${isShot ? "shot" : "rec"}-${Date.now()}.${isShot ? "png" : "mp4"}`);
          const pull = await runAdb(["pull", remote, local], { device });
          await runAdb(["shell", "rm", remote], { device });
          result = { ok: pull.ok, code: pull.code, out: pull.out, err: pull.err, local };
        }
      } else {
        result = await runAdb(cfg.args(args), { device, timeoutMs: cfg.timeoutMs });
      }
      let recorded = false;
      if (args.record) {
        const index = loadIndex();
        const obj = {
          id: makeId("work_record", "adb", action),
          type: "work_record",
          name: `adb:${action}`,
          source: "adb",
          path: device || String(result.out || "").split("\n")[0].slice(0, 300),
          description: `adb ${action}${device ? " on " + device : ""}`,
          tags: ["adb", "android"],
          summary: String(result.out || result.err || "").slice(0, 2000),
          createdAt: new Date().toISOString(),
        };
        commitRecord(index, obj, "confirm", "adb operation record");
        recorded = true;
      }
      appendLog({ op: "adb", type: null, name: null, source: "adb", disposition: null, detail: `action=${action} device=${device || "(auto)"} ok=${result.ok}` });
      return { ok: result.ok, action, code: result.code, out: result.out, err: result.err, ...(result.local ? { local: result.local } : {}), recorded };
    },
  }));
}

export { name, inject, apply };
