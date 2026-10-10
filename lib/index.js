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

// Register built-in media analysis engines: ffprobe (codecs/duration/streams) + MediaInfo.
// Both are generic fallback providers (match always true); mediaFingerprint tries each
// in order and returns on the first success.
// Neither engine is assumed to sit anywhere in particular: resolution goes env var -> conventional
// locations -> this machine's local candidate pack -> PATH. So a normal install is found as-is, and a
// tool kept at a personal location is found through the pack that `library_detect op=add` seeded.
function registerDefaultMediaProvider() {
  // 1) ffprobe engine (codecs/duration/streams) - resolve across platforms.
  const ffprobe = resolveTool(
    "FFPROBE_PATH",
    [
      "/usr/bin/ffprobe", "/usr/local/bin/ffprobe", "/opt/homebrew/bin/ffprobe", "/opt/local/bin/ffprobe", "/snap/bin/ffprobe", // macOS/Linux
    ],
    "ffprobe",
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
      "/usr/bin/mediainfo", "/usr/local/bin/mediainfo", "/opt/homebrew/bin/mediainfo", "/opt/local/bin/mediainfo", "/snap/bin/mediainfo", // macOS/Linux
    ],
    "mediainfo",
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
//   2) a per-platform list of common absolute paths (if file exists), or a bare command name from PATH
//   3) this machine's local candidate pack - where per-install locations belong (see localPackCandidate)
//   4) PATH lookup of the bare command name (PATHEXT-aware on Windows)
// Returns the best candidate string, or null if nothing looks usable.
function resolveTool(envName, candidates, commandName, packName) {
  if (process.env[envName]) return process.env[envName];
  for (const c of candidates) {
    if (/[\\/]/.test(c)) {
      if (fs.existsSync(c)) return c;
    } else {
      const found = resolveOnPath(c);
      if (found) return found;
    }
  }
  const local = packName ? localPackCandidate(packName) : null;
  if (local) return local;
  const onPath = resolveOnPath(commandName);
  if (onPath) return onPath;
  // Last resort: bare command name - spawn will resolve it from PATH.
  return commandName || null;
}

// A tool installed at a machine-specific location belongs in the local candidate pack, so the built-in
// lists can stay machine-neutral. Matches the entry whose name equals the wanted word, or that contains
// it as a whole word ("MediaInfo CLI", "adb (platform-tools)"). Existence checking only - never executed.
function localPackCandidate(want) {
  const key = String(want || "").toLowerCase();
  if (!key) return null;
  let pack = null;
  try { pack = loadLocalCandidates(); } catch { return null; }
  const entries = (pack && pack.candidates) || [];
  const words = (n) => String(n || "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const entry = entries.find((x) => String(x.name || "").toLowerCase() === key) ||
    entries.find((x) => words(x.name).includes(key));
  if (!entry) return null;
  try { return resolveCandidatePath(entry); } catch { return null; }
}

// Which PowerShell hosts the native report dialog on Windows. Both PowerShell 7 (pwsh.exe) and
// Windows PowerShell 5.1 (powershell.exe) can run the WinForms dialog with -STA, so prefer 7 - the
// shell modern Windows installs and the one this machine defaults to - and fall back to 5.1 so the
// dialog still works on a stock Windows without it. PWSH_PATH / POWERSHELL_PATH override, and the
// search for 7 mirrors how a harness finds it: the standard install location first, then every PATH
// entry, which also covers portable copies and the Microsoft Store alias.
function dialogShell() {
  if (process.env.PWSH_PATH) return process.env.PWSH_PATH;
  const programFiles = process.env.ProgramFiles || "C:\\Program Files";
  const candidates = [path.join(programFiles, "PowerShell", "7", "pwsh.exe")];
  for (const entry of String(process.env.PATH || "").split(path.delimiter)) {
    const dir = entry.trim().replace(/^"|"$/g, "");
    if (dir) candidates.push(path.join(dir, "pwsh.exe"));
  }
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  if (process.env.POWERSHELL_PATH) return process.env.POWERSHELL_PATH;
  return "powershell.exe";
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
    ["/usr/bin/adb", "/usr/local/bin/adb", "/opt/homebrew/bin/adb", "/opt/local/bin/adb", "/snap/bin/adb", "~/.local/bin/adb"],
    "adb",
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
  // Unix: derive from the locale. POSIX precedence is LC_ALL, then LC_CTYPE, then LANG.
  const lang = (process.env.LC_ALL || process.env.LC_CTYPE || process.env.LANG || "").trim();
  // "C" and "POSIX" mean "no locale at all", i.e. plain ASCII - which is valid UTF-8. Reporting
  // them as a legacy code page (with regional advice) would be wrong.
  if (!lang || /^(c|posix)(?:\.|$)/i.test(lang)) return { codepage: null, label: "C/POSIX (plain ASCII)", utf8: true };
  if (/utf-?8/i.test(lang)) return { codepage: null, label: "UTF-8", utf8: true };
  // Parse "<language>[_<COUNTRY>][.<codeset>][@modifier]" instead of matching bare substrings:
  // a two-letter sequence inside a longer word is not a language code, and "en_GB" or "KOI8-R"
  // used to be read as Chinese (gb) and Korean (ko) respectively.
  const m = lang.match(/^([A-Za-z]{2,3})(?:[_-]([A-Za-z]{2}))?(?:\.([^@]+))?(?:@.*)?$/);
  const code = m ? m[1].toLowerCase() : "";
  const country = m && m[2] ? m[2].toLowerCase() : "";
  const codeset = m && m[3] ? m[3].toLowerCase() : "";
  const whole = lang.toLowerCase();
  if (/koi8/.test(codeset) || /koi8/.test(whole)) return { codepage: 20866, label: "KOI8-R", utf8: false };
  if (/euc.?jp/.test(codeset)) return { codepage: 51932, label: "EUC-JP", utf8: false };
  if (/shift.?jis|sjis|932/.test(codeset) || code === "ja") return { codepage: 932, label: "Shift-JIS", utf8: false };
  if (/euc.?kr|uhc|949/.test(codeset) || code === "ko") return { codepage: 949, label: "EUC-KR/CP949", utf8: false };
  // Traditional Chinese locales are Big5, not GBK: check them before the generic zh rule.
  if (/big5|950/.test(codeset) || (code === "zh" && ["tw", "hk", "mo"].includes(country))) return { codepage: 950, label: "Big5", utf8: false };
  if (/gb|936/.test(codeset) || code === "zh") return { codepage: 936, label: "GBK/GB2312", utf8: false };
  if (/8859-?1|latin-?1|28591/.test(codeset) || /8859-1|latin-?1/.test(whole)) return { codepage: 28591, label: "ISO-8859-1 (Latin-1)", utf8: false };
  if (/1252/.test(codeset)) return { codepage: 1252, label: "Windows-1252", utf8: false };
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

// A zero-byte file and a path that does not exist are NOT the same finding, and neither is a
// directory passed where a file was expected: readHeader() returns no bytes in all three cases,
// so contentKind() alone would report every one of them as "empty". Check the path first.
function pathKind(filePath) {
  try {
    const st = fs.statSync(filePath);
    if (st.isDirectory()) return { kind: "directory", note: "path is a directory, not a file" };
    if (!st.isFile()) return { kind: "special", note: "path is not a regular file (device, socket or pipe)" };
    if (st.size === 0) return { kind: "empty", note: "file is empty (0 bytes)" };
    return null; // a real, non-empty file: let the bytes decide
  } catch (e) {
    if (e && e.code === "ENOENT") return { kind: "missing", note: "path does not exist" };
    return { kind: "unreadable", note: `path cannot be read (${String((e && e.code) || "error")})` };
  }
}

// Families whose members are never plain text, and formats that are (in practice) always
// text - used to flag contradictions that carry no magic signature at all. `.log` is
// deliberately NOT in the text set: Office diagnostic logs are binary on this machine.
const BINARY_FAMILIES = new Set(["image", "audio", "video", "archive", "executable", "database", "font", "model"]);
const ALWAYS_TEXT_EXTS = new Set(["json", "jsonl", "ndjson", "yaml", "yml", "txt", "md", "csv", "ini", "env", "sln", "xml", "html", "htm"]);

function assessFile(filePath) {
  const base = path.basename(filePath);
  const ext = path.extname(base).toLowerCase().replace(".", "");
  const pre = pathKind(filePath);
  const sniff = pre ? null : sniffFileType(filePath);
  const declared = declaredFamily(ext);
  const artifact = dshArtifactOf(filePath);
  const kind = pre ? pre.kind : contentKind(filePath);
  const flags = [];
  if (sniff && declared && sniff.type !== declared) flags.push(`name claims ${declared} (.${ext}) but content is ${sniff.type}/${sniff.format}`);
  if (sniff && artifact && artifact.expect && sniff.type !== artifact.expect) flags.push(`DSH role "${artifact.role}" expects ${artifact.expect} but content is ${sniff.type}/${sniff.format}`);
  if (sniff && artifact && !artifact.expect && sniff.type === "executable") flags.push(`executable content inside DSH artifact role "${artifact.role}"`);
  // No signature matched: fall back to the raw text/binary verdict.
  if (!sniff && kind === "text" && declared && BINARY_FAMILIES.has(declared)) flags.push(`name claims ${declared} (.${ext}) but content is plain text`);
  if (!sniff && kind === "binary" && ALWAYS_TEXT_EXTS.has(ext)) flags.push(`name claims text (.${ext}) but content is binary and matches no known signature`);
  // These five are declared strings in the output schema, and the harness refuses the entire
  // call when a declared string arrives as null - so "nothing matched" reads as "" here.
  return {
    path: filePath,
    declared: declared ?? "",
    artifact: artifact ? artifact.role : "",
    artifactNote: artifact ? artifact.note : "",
    sensitive: !!(artifact && artifact.sensitive),
    temp: TEMP_NAME_RE.test(base),
    kind,
    detected: !!sniff,
    type: sniff ? sniff.type : "",
    format: sniff ? sniff.format : "",
    note: pre ? pre.note : sniff ? sniff.note : "no known signature matched",
    spoofed: flags.length > 0,
    flags,
  };
}

// (3) Known handy tools/environments/toolchains (registered on scan; installing missing ones requires
// an instruction + report). Deliberately machine-neutral:
//   - a `path` with no separator is a COMMAND NAME and is resolved from PATH (with `alts` covering the
//     conventional per-OS locations), so a normal installation is found wherever the user put it;
//   - an `env` entry may name a location in the owner's own words - the folder variables the OS
//     publishes (%ProgramFiles%, %ProgramFiles(x86)%, %ProgramW6432%, %CommonProgramFiles%,
//     %LOCALAPPDATA%, %APPDATA%, %USERPROFILE%, %SystemRoot%) or a root a toolchain publishes about
//     itself (%GOROOT%, %JAVA_HOME%, %ANDROID_HOME%, %ANDROID_SDK_ROOT%, %UV_INSTALL_DIR%, %GOPATH%,
//     %CARGO_HOME%, %CONDA_PREFIX%, %VSINSTALLDIR%), or the POSIX equivalents (~/${HOME}, ${XDG_*}).
//     Nothing here names a literal absolute layout: the OS and each tool are asked where they put
//     themselves, which is also the only way a localised or relocated Windows stays correct;
//   - a location that rotates with its version - the WDK's 10.0.<build> folder, a Visual Studio
//     instance folder - is declared as the folder that holds it plus `pick: "newest"` (optionally
//     `mustHave` a subfolder), so the newest installed one is derived from the disk instead of a
//     version literal that rots;
//   - anything specific to THIS machine belongs in the local candidate pack (below), which is
//     per-install and is seeded with `library_detect op=propose` plus `op:add`.
// A path that does not exist - or whose declared variable is unset - is skipped by
// resolveCandidatePath(), so an entry that never applies costs nothing. FFPROBE_PATH /
// MEDIAINFO_PATH / ADB_PATH override the media and device engines.
const DETECT_CANDIDATES = [
  { type: "tool", name: "MediaInfo", path: "mediainfo", alts: ["/usr/bin/mediainfo", "/usr/local/bin/mediainfo", "/opt/homebrew/bin/mediainfo", "/opt/local/bin/mediainfo", "/snap/bin/mediainfo"], desc: "media metadata analysis (CLI)" },
  { type: "tool", name: "ffmpeg", path: "ffmpeg", alts: ["/usr/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/opt/homebrew/bin/ffmpeg", "/opt/local/bin/ffmpeg", "/snap/bin/ffmpeg"], desc: "transcoding / media processing" },
  { type: "tool", name: "ffprobe", path: "ffprobe", alts: ["/usr/bin/ffprobe", "/usr/local/bin/ffprobe", "/opt/homebrew/bin/ffprobe", "/opt/local/bin/ffprobe", "/snap/bin/ffprobe"], desc: "media probing (alternative fingerprint source)" },
  { type: "tool", name: "uv", path: "uv", alts: ["${UV_INSTALL_DIR}/uv", "~/.local/bin/uv", "%USERPROFILE%\\.local\\bin\\uv.exe", "/usr/local/bin/uv", "/opt/homebrew/bin/uv", "/opt/local/bin/uv", "/snap/bin/uv"], desc: "Python package/interpreter manager" },
  { type: "tool", name: "Go", path: "go", alts: ["%GOROOT%\\bin\\go.exe", "${GOROOT}/bin/go", "/usr/local/go/bin/go", "/opt/homebrew/bin/go", "/opt/local/bin/go", "/snap/bin/go"], desc: "Go toolchain" },
  { type: "tool", name: "Git", path: "git", alts: ["%ProgramFiles%\\Git\\cmd\\git.exe", "/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git", "/opt/local/bin/git", "/snap/bin/git"], desc: "Git" },
  { type: "tool", name: "Node.js", path: "node", alts: ["%ProgramFiles%\\nodejs\\node.exe", "/usr/local/bin/node", "/opt/homebrew/bin/node"], desc: "Node.js runtime" },
  { type: "tool", name: "Python", path: "python3", alts: ["%LOCALAPPDATA%\\Programs\\Python\\python.exe", "python", "/usr/local/bin/python3", "/opt/homebrew/bin/python3"], desc: "Python runtime" },
  { type: "tool", name: "adb", path: "adb", alts: ["%ANDROID_HOME%\\platform-tools\\adb.exe", "%ANDROID_SDK_ROOT%\\platform-tools\\adb.exe", "%LOCALAPPDATA%\\Android\\Sdk\\platform-tools\\adb.exe", "${ANDROID_HOME}/platform-tools/adb", "${ANDROID_SDK_ROOT}/platform-tools/adb", "${HOME}/Android/Sdk/platform-tools/adb", "~/.local/bin/adb", "/usr/bin/adb", "/usr/local/bin/adb", "/opt/homebrew/bin/adb", "/opt/local/bin/adb", "/snap/bin/adb"], desc: "Android platform tools" },
  { type: "env", name: "DSH_HOME", path: process.env.DSH_HOME || path.join(os.homedir(), ".dsh"), desc: "DSH home directory (host navigation)" },
  { type: "env", name: "DSH temp dir", path: process.env.TEMP || process.env.TMP || os.tmpdir(), desc: "DSH/Windows scratch area: per-run .tmpXXXXXX dirs, payload/log/err files (library_sniff dir mode can sweep it)" },
  { type: "env", name: "Windows SDK", path: "%ProgramFiles(x86)%\\Windows Kits\\10", alts: ["%ProgramFiles%\\Windows Kits\\10"], desc: "Windows development SDK (the location the OS itself declares)" },
  { type: "env", name: "WDK (Windows Driver Kit)", path: "%ProgramFiles(x86)%\\Windows Kits\\10\\Include", pick: "newest", mustHave: "km", alts: ["%ProgramFiles%\\Windows Kits\\10\\Include"], desc: "WDK: km/wdf headers, wdf libs, Inf2Cat/stampinf (the newest driver-kit build on this machine, derived from the include folder)" },
  { type: "env", name: "Microsoft Office (ClickToRun)", path: "%ProgramFiles%\\Microsoft Office\\root\\Office16", alts: ["%ProgramFiles(x86)%\\Microsoft Office\\root\\Office16", "%CommonProgramFiles%\\Microsoft Shared\\OFFICE16"], desc: "Office ClickToRun install: Word/Excel/PowerPoint/Access/Outlook/Publisher/OneNote (COM automation; ACE DB engine for accdb/mdb)" },
  { type: "env", name: "Visual Studio 2022", path: "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Community", alts: ["%VSINSTALLDIR%", "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Professional", "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Enterprise", "%ProgramFiles%\\Microsoft Visual Studio\\2022\\BuildTools"], desc: "Visual Studio 2022 (any edition, the vendor's default location; VSINSTALLDIR honoured when it is set)" },
  { type: "env", name: "Visual Studio 2026", path: "%ProgramFiles%\\Microsoft Visual Studio\\18\\Community", alts: ["%ProgramFiles%\\Microsoft Visual Studio\\18\\Professional", "%ProgramFiles%\\Microsoft Visual Studio\\18\\Enterprise", "%ProgramFiles%\\Microsoft Visual Studio\\18\\BuildTools"], desc: "Visual Studio 2026 / 18.x (any edition, the vendor's default location)" },
];

// ---------- Declared values: the owner's own words, never a literal layout ----------
// A candidate may write a location with the value its owner publishes: %VAR% (Windows), ${VAR} or $VAR
// (POSIX) and ~ for the home directory. The OS declares its own folders, a toolchain declares its root,
// and both are read from the environment - no command substitution, nothing is executed to expand one.
// A reference to an unset variable resolves to nothing at all: a fabricated root would be worse than no
// candidate, because it could point at another user's or another product's tool.
function declaredEnv(name) {
  const direct = process.env[name];
  if (direct !== undefined && direct !== null && direct !== "") return direct;
  if (process.platform !== "win32") return null;
  const lower = name.toLowerCase();
  for (const k of Object.keys(process.env)) {
    if (k.toLowerCase() === lower && process.env[k]) return process.env[k];
  }
  return null;
}

function expandDeclared(p) {
  if (typeof p !== "string" || !p) return null;
  if (p === "~" || p.startsWith("~/") || p.startsWith("~\\")) {
    const home = os.homedir();
    if (!home) return null;
    const rest = p.slice(1).replace(/^[\\/]+/, "");
    return rest ? path.join(home, rest) : home;
  }
  let missing = null;
  const sub = (name) => {
    const v = declaredEnv(name);
    if (v === null || v === undefined || v === "") {
      missing = missing || name;
      return `%${name}%`;
    }
    return v;
  };
  const out = p
    .replace(/%([A-Za-z_][A-Za-z0-9_()]*)%/g, (_m, n) => sub(n))
    .replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, n) => sub(n))
    .replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_m, n) => sub(n));
  return missing ? null : out;
}

// A version-rotating folder (the WDK's 10.0.<build> include folder, a Visual Studio instance folder):
// read the folder that holds it and take the newest child that really carries what is wanted, so the
// version is learned from the disk rather than written down here.
function pickNewest(base, mustHave) {
  let names;
  try { names = fs.readdirSync(base, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name); } catch { return null; }
  const ranked = names
    .map((n) => ({ n, key: String(n).split(/[^0-9]+/).filter(Boolean).map((x) => Number(x)).filter((x) => Number.isFinite(x)) }))
    .sort((a, b) => {
      const len = Math.max(a.key.length, b.key.length);
      for (let i = 0; i < len; i++) {
        const d = (b.key[i] || 0) - (a.key[i] || 0);
        if (d) return d;
      }
      return a.n.localeCompare(b.n);
    });
  for (const { n } of ranked) {
    const candidate = path.join(base, n);
    if (!mustHave) return candidate;
    try {
      // `mustHave` both filters (only a build that really carries the piece counts) and completes the
      // path, so the seed can say "the newest driver-kit build's km folder" without naming a version.
      if (fs.existsSync(path.join(candidate, mustHave))) return path.join(candidate, mustHave);
    } catch { /* unreadable: try the next build */ }
  }
  return null;
}

// Resolve a bare command name from PATH. Used for the neutral seed above, so a tool installed the normal
// way is found without naming anyone's disk layout. Returns null for anything containing a separator.
function resolveOnPath(name) {
  if (!name || /[\\/]/.test(name)) return null;
  const dirs = String(process.env.PATH || "")
    .split(path.delimiter)
    .map((d) => d.trim().replace(/^"|"$/g, ""))
    .filter(Boolean);
  const suffixes = process.platform === "win32"
    ? (/\.[A-Za-z0-9]+$/.test(name) ? [""] : String(process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM").split(";").filter(Boolean))
    : [""];
  for (const d of dirs) {
    for (const s of suffixes) {
      const p = path.join(d, name + s);
      try {
        if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
      } catch { /* unreadable entry: try the next one */ }
    }
  }
  return null;
}

// Resolve a DETECT candidate's actual existing path across path + alts.
function resolveCandidatePath(c) {
  const declared = [c.path, ...(c.alts || [])].filter(Boolean).map(expandDeclared);
  for (const p of declared) {
    if (!p) continue;                      // a declared value that is unavailable: skip, never guess
    if (!/[\\/]/.test(p)) {
      const onPath = resolveOnPath(p);
      if (onPath) return onPath;
      continue;
    }
    if (c.pick === "newest") {
      const newest = pickNewest(p, c.mustHave);
      if (newest) return newest;
      continue;
    }
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// ---------- Declared identity: what a tool says about itself, read statically ----------
// The same discipline a plugin catalogue uses on a binary: read the file's own headers and resources,
// and never load, link, register or execute it. A Windows image that carries a VS_VERSIONINFO resource
// states its own ProductName / ProductVersion / CompanyName, so a scan can report the tool's own words
// instead of a description typed here by hand - which is the only description that stays true as
// versions move. Every read is bounded to the exact byte range needed, every field access is
// bounds-checked, and anything absent, truncated or unreadable yields null: a failed read must never
// turn into a guess. Only images with such a resource can answer (Windows .exe/.dll); on other
// platforms this simply reports nothing.
function readAt(fd, offset, length) {
  if (offset < 0 || length <= 0 || length > (1 << 20)) return null;
  try {
    const b = Buffer.alloc(length);
    const got = fs.readSync(fd, b, 0, length, offset);
    return got === length ? b : b.subarray(0, got);
  } catch { return null; }
}
const u16 = (b, o) => (b && o + 2 <= b.length ? b.readUInt16LE(o) : null);
const u32 = (b, o) => (b && o + 4 <= b.length ? b.readUInt32LE(o) : null);

// Walk a VS_VERSIONINFO node: {wLength, wValueLength, wType, szKey, value, children}. Bounded depth and
// child count, and a UTF-16 read that stops at the first NUL.
function peVersionNode(buf, off, end, depth) {
  if (depth > 4 || off + 6 > end) return null;
  const wLength = u16(buf, off);
  const wValueLength = u16(buf, off + 2);
  const wType = u16(buf, off + 4);
  if (!wLength || off + wLength > end) return null;
  // szKey: UTF-16LE, NUL-terminated, then padded to a 4-byte boundary.
  let key = "";
  for (let i = off + 6; i + 1 < off + wLength && key.length < 128; i += 2) {
    const c = u16(buf, i);
    if (c === null || c === 0) break;
    key += String.fromCharCode(c);
  }
  const keyBytes = (key.length + 1) * 2;
  const valueStart = off + 6 + keyBytes + ((4 - ((6 + keyBytes) % 4)) % 4);
  const valueBytes = wType === 1 ? wValueLength * 2 : wValueLength;   // type 1 = text: length in characters
  const value = valueBytes > 0 && valueStart + valueBytes <= off + wLength ? buf.subarray(valueStart, valueStart + valueBytes) : null;
  const childrenStart = valueStart + valueBytes + ((4 - (valueBytes % 4)) % 4);
  const children = [];
  let cursor = childrenStart;
  while (cursor + 6 <= off + wLength && children.length < 64) {
    const child = peVersionNode(buf, cursor, off + wLength, depth + 1);
    if (!child || !child.length) break;
    children.push(child);
    cursor += child.length + ((4 - (child.length % 4)) % 4);
  }
  return { length: wLength, key, value, children };
}
function utf16Text(buf) {
  if (!buf) return "";
  let s = "";
  for (let i = 0; i + 1 < buf.length && s.length < 256; i += 2) {
    const c = buf.readUInt16LE(i);
    if (!c) break;
    s += String.fromCharCode(c);
  }
  return s.trim();
}

function declaredIdentity(filePath) {
  let fd = null;
  try {
    let st;
    try { st = fs.statSync(filePath); } catch { return null; }
    if (!st.isFile() || st.size < 0x40 || st.size > 0x7FFFFFFF) return null;   // 2 GiB: a real cap, and 1<<31 would be negative
    fd = fs.openSync(filePath, "r");
    const dos = readAt(fd, 0, 0x40);
    if (!dos || u16(dos, 0) !== 0x5A4D) return null;                       // "MZ"
    const peOff = u32(dos, 0x3C);
    if (peOff === null || peOff <= 0) return null;
    const head = readAt(fd, peOff, 24);
    if (!head || head.toString("latin1", 0, 4) !== "PE\u0000\u0000") return null;
    const numSections = u16(head, 6);
    const optSize = u16(head, 20);
    if (!numSections || !optSize || numSections > 96) return null;
    const opt = readAt(fd, peOff + 24, optSize);
    if (!opt) return null;
    const magic = u16(opt, 0);
    const dirBase = magic === 0x20B ? 112 : magic === 0x10B ? 96 : null;
    if (dirBase === null || optSize < dirBase + 16) return null;
    const rsrcRva = u32(opt, dirBase + 8 * 2);                             // data directory 2 = resources
    const rsrcSize = u32(opt, dirBase + 8 * 2 + 4);
    if (!rsrcRva || !rsrcSize) return null;
    const sections = readAt(fd, peOff + 24 + optSize, Math.min(numSections, 96) * 40);
    if (!sections) return null;
    let rsrcRaw = null;
    for (let i = 0; i < numSections; i++) {
      const s = i * 40;
      const va = u32(sections, s + 12);
      const rawSize = u32(sections, s + 16);
      const raw = u32(sections, s + 20);
      if (va === null || raw === null) break;
      if (rsrcRva >= va && rsrcRva < va + Math.max(rawSize || 0, 1)) { rsrcRaw = raw + (rsrcRva - va); break; }
    }
    if (rsrcRaw === null) return null;
    // Directory walk: type RT_VERSION (16) -> name/id 1 -> first language -> data entry.
    const dirHeader = readAt(fd, rsrcRaw, 16);
    if (!dirHeader) return null;
    const walk = (base, want) => {
      const h = base === rsrcRaw ? dirHeader : readAt(fd, base, 16);
      if (!h) return null;
      const named = u16(h, 12) || 0;
      const ids = u16(h, 14) || 0;
      const total = Math.min(named + ids, 512);
      const entries = readAt(fd, base + 16, total * 8);
      if (!entries) return null;
      for (let i = 0; i < total; i++) {
        const id = u32(entries, i * 8);
        const off = u32(entries, i * 8 + 4);
        if (id === null || off === null) continue;
        if (want === null || id === want) return { id, off };
      }
      return null;
    };
    const typeEntry = walk(rsrcRaw, 16);
    if (!typeEntry || !(typeEntry.off & 0x80000000)) return null;
    const nameEntry = walk(rsrcRaw + (typeEntry.off & 0x7FFFFFFF), 1);
    if (!nameEntry || !(nameEntry.off & 0x80000000)) return null;
    // Third level: the language directory. Take its first entry, which is a DATA entry whose offset is
    // relative to the resource base (a set high bit would mean another directory, which is not expected
    // for RT_VERSION).
    const langBase = rsrcRaw + (nameEntry.off & 0x7FFFFFFF);
    const langHead = readAt(fd, langBase, 24);
    if (!langHead) return null;
    if (!((u16(langHead, 12) || 0) + (u16(langHead, 14) || 0))) return null;
    const langFirst = u32(langHead, 20);
    if (langFirst === null || (langFirst & 0x80000000)) return null;
    const dataEntry = readAt(fd, rsrcRaw + langFirst, 16);
    if (!dataEntry) return null;
    const dataRva = u32(dataEntry, 0);
    const dataSize = u32(dataEntry, 4);
    if (!dataRva || !dataSize || dataRva < rsrcRva) return null;
    const dataOff = rsrcRaw + (dataRva - rsrcRva);
    const vbuf = readAt(fd, dataOff, Math.min(dataSize, 64 * 1024));
    if (!vbuf) return null;
    const root = peVersionNode(vbuf, 0, vbuf.length, 0);
    if (!root || root.key !== "VS_VERSION_INFO") return null;
    const info = { product: "", version: "", productVersion: "", fileVersion: "", fixedFileVersion: "", vendor: "", description: "" };
    // VS_FIXEDFILEINFO sits in the root value: dwFileVersionMS/LS give a version when no string does.
    let fixed = "";
    if (root.value && root.value.length >= 16) {
      const ms = u32(root.value, 8);
      const ls = u32(root.value, 12);
      if (ms !== null && ls !== null) fixed = `${ms >>> 16}.${ms & 0xFFFF}.${ls >>> 16}.${ls & 0xFFFF}`;
    }
    for (const sfi of root.children.filter((c) => c.key === "StringFileInfo")) {
      for (const table of sfi.children) {
        for (const entry of table.children) {
          const text = utf16Text(entry.value);
          if (!text) continue;
          const k = entry.key.toLowerCase();
          if (k === "productname" && !info.product) info.product = text;
          else if (k === "productversion" && !info.productVersion) info.productVersion = text;
          else if (k === "fileversion" && !info.fileVersion) info.fileVersion = text;
          else if (k === "companyname" && !info.vendor) info.vendor = text;
          else if (k === "filedescription" && !info.description) info.description = text;
        }
      }
    }
    // The fields stay apart on purpose: a product version and a file version are different claims, and
    // the fixed-file-info copy can disagree with both. `version` is the one to show, not the only one kept.
    info.fixedFileVersion = fixed;
    info.version = info.productVersion || info.fileVersion || fixed;
    const any = info.product || info.version || info.vendor || info.description;
    if (!any) return null;
    return { ...info, note: "read from the image's own version resource; the file was not executed" };
  } catch {
    return null;
  } finally {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* already gone */ } }
  }
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
import { deflateRawSync, inflateRawSync, zstdDecompressSync } from "node:zlib";

// Dangerous/sensitive markers (keywords). The CJK terms are kept intentionally: they are
// functional regexes that match Chinese sensitive content, not translatable prose. They are
// also the ONLY non-ASCII content in this file - everything else is plain ASCII English, so
// the plugin's own output stays readable on the legacy consoles it warns about.
const SENSITIVE_PATTERNS = [
  /(勒索|ransom)/i, /(木马|trojan)/i, /(病毒|virus|worm)/i, /(后门|backdoor)/i,
  /(键盘记录|keylog)/i, /(窃取|steal|exfil)/i, /(恶意|malware)/i,
  // `token` is matched only with a qualifier or a separator, deliberately: the bare word is ordinary
  // technical prose ("the shingle text", "text without word spaces is one word"), and matching it
  // encrypted two harmless library records before this was narrowed. Credential-shaped tokens -
  // access_token, refresh token, bearer, `token: value` - still match, and `secret` stays
  // unconditional because the five-stage selfcheck depends on it.
  /(api[_-]?key|secret|(?:access|refresh|bearer|auth|session|api|csrf|xsrf|id)[\s_-]?token|token["']?\s*[:=]|password|passwd|credential)/i,
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
  // 0600 on POSIX: the master secret must not be world-readable. Windows ignores the mode and
  // relies on the profile ACL instead.
  fs.writeFileSync(mf, m.toString("base64"), { encoding: "utf8", mode: 0o600 });
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
  fs.writeFileSync(kf, JSON.stringify({ v: 2, salt: salt.toString("hex"), info: info.toString("utf8") }), { encoding: "utf8", mode: 0o600 });
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

// Commit one record under the write lock: store the object, persist it, then log it.
// Returns { sensitive, count }; the count comes from the locked write, so it includes updates
// made by another process in the meantime.
function commitRecord(obj, disposition, detail) {
  const out = updateIndex((index) => {
    const sensitive = storeObject(index, obj);
    return { sensitive, count: index.objects.length };
  });
  appendLog({ op: "record", type: obj.type, name: obj.name, source: obj.source, disposition, detail: detail + (out.sensitive ? " (sensitive, encrypted)" : "") });
  return out;
}

function ensureLibrary() {
  const dir = libraryDir();
  fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(payloadDir(), { recursive: true });
  return dir;
}

function loadIndex() {
  // A library directory that cannot be created must not make every read throw: if the index file
  // is already there and readable, reading it is the best answer we can give.
  try {
    ensureLibrary();
  } catch { /* fall through to a plain read attempt */ }
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
  try {
    ensureLibrary();
  } catch (e) {
    throw new Error(`library is not writable at ${libraryDir()} (${String((e && e.code) || e)}): nothing was saved`);
  }
  const file = indexFile();
  // NOTE: synchronous write keeps the read-modify-write cycle atomic on the single
  // JS thread. Across processes (the DSH plugin, the MCP server and the CLI can share one
  // library) the lock below is what keeps concurrent writers from losing updates.
  // The write itself goes through a temp file + rename so a crash, a kill or a full disk cannot
  // leave a truncated index.json behind: readers then see either the old or the new file, never
  // half of one. renameSync is atomic on the same filesystem, and the temp file is a sibling so
  // that it always is.
  const tmp = `${file}.tmp-${process.pid}`;
  const payload = JSON.stringify(index, null, 2);
  try {
    fs.writeFileSync(tmp, payload, "utf8");
    // On Windows a rename over a file that another process holds open fails (EPERM/EBUSY/EACCES),
    // and readers here are deliberately lock-free, so a concurrent read can block the swap. Retry
    // briefly; if the swap still cannot happen, fall back to writing in place, because keeping the
    // record matters more than keeping the crash-safety of the rename.
    for (let attempt = 0; ; attempt++) {
      try {
        fs.renameSync(tmp, file);
        break;
      } catch (e) {
        const transient = ["EPERM", "EACCES", "EBUSY", "EAGAIN"].includes(e && e.code);
        if (!transient || attempt >= 9) {
          fs.writeFileSync(file, payload, "utf8");
          appendLog({ op: "save", type: null, name: null, source: null, disposition: null, detail: `atomic rename blocked (${String((e && e.code) || e)}); wrote index in place instead` });
          try { fs.rmSync(tmp, { force: true }); } catch {}
          break;
        }
        sleepSync(25 + attempt * 10);
      }
    }
  } catch (e) {
    try { fs.rmSync(tmp, { force: true }); } catch {}
    throw e;
  }
  return file;
}

// ---------- Cross-process write lock ----------
// The same $DSH_HOME/library can be open in several harnesses at once. Reads and writes are
// read-modify-write cycles, so two processes that interleave them lose one of the updates.
// The lock is deliberately forgiving: it is taken with an exclusive create, it takes over a lock
// whose owner died (older than staleMs), and if it still cannot get in within waitMs it writes
// anyway with a logged warning - a user's Library must never be blocked forever.
function lockFile() {
  return path.join(libraryDir(), ".lock");
}

function sleepSync(ms) {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    const end = Date.now() + ms;
    while (Date.now() < end) { /* last-resort spin */ }
  }
}

function acquireLibraryLock({ waitMs = 2000, staleMs = 30000 } = {}) {
  ensureLibrary();
  const file = lockFile();
  const started = Date.now();
  let announced = false;
  for (;;) {
    try {
      const fd = fs.openSync(file, "wx");
      fs.writeSync(fd, `${process.pid} ${new Date().toISOString()}\n`);
      fs.closeSync(fd);
      return { ok: true, file, waitedMs: Date.now() - started };
    } catch (e) {
      if (e.code !== "EEXIST") return { ok: false, file, waitedMs: 0, reason: e.code || e.message };
    }
    // Someone holds it: is the holder gone?
    try {
      const age = Date.now() - fs.statSync(file).mtimeMs;
      if (age > staleMs) {
        appendLog({ op: "lock", type: null, name: null, source: null, disposition: null, detail: `taking over a stale lock (${Math.round(age / 1000)}s old)` });
        fs.rmSync(file, { force: true });
        continue;
      }
    } catch {
      continue; // vanished between the checks: try to create it again
    }
    if (Date.now() - started >= waitMs) {
      if (!announced) {
        announced = true;
        appendLog({ op: "lock", type: null, name: null, source: null, disposition: null, detail: `lock busy after ${waitMs}ms; writing anyway (last write wins)` });
      }
      return { ok: false, file, waitedMs: Date.now() - started, reason: "timeout" };
    }
    sleepSync(25);
  }
}

function releaseLibraryLock(lock) {
  if (!lock || !lock.ok) return;
  try {
    fs.rmSync(lock.file, { force: true });
  } catch {}
}

// Every read-modify-write cycle on the index goes through here, so no writer is left unlocked.
function updateIndex(mutator) {
  const lock = acquireLibraryLock();
  try {
    const index = loadIndex();
    const result = mutator(index);
    index.generatedAt = new Date().toISOString();
    saveIndex(index);
    return result;
  } finally {
    releaseLibraryLock(lock);
  }
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
    // A name rule must come from a pattern STRING. A live RegExp serialises to {} and would turn
    // into the wildly permissive /[object Object]/i, so anything unrepresentable is dropped
    // rather than silently matching unrelated files.
    const source = typeof r?.source === "string" ? r.source : typeof r?.re === "string" ? r.re : null;
    if (!source) continue;
    let re;
    try {
      re = new RegExp(source, "i");
    } catch {
      continue; // unrepresentable pattern: skip it instead of matching everything
    }
    d.nameRules.push({ re, source, role: String(r.role || "local"), expect: r.expect || null, note: String(r.note || "").slice(0, 200) });
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
  // Canonical on-disk shape: name rules keep their pattern SOURCE (plus flags), never a live
  // RegExp - RegExp objects serialise to {} and reload as a match-everything pattern.
  const onDisk = {
    version: pack.version,
    updatedAt: pack.updatedAt,
    formats: pack.formats,
    textExtensions: pack.textExtensions,
    nameRules: pack.nameRules.map((r) => ({ source: String(r.source || r.re?.source || ""), flags: "i", role: r.role, expect: r.expect ?? null, note: r.note ?? "" })),
  };
  fs.writeFileSync(localFormatsFile(), JSON.stringify(onDisk, null, 2), "utf8");
  _localPack = { key: null, data: null };
  return localFormatsFile();
}

// A pack write is a read-modify-write cycle exactly like an index write, so it takes the same
// cross-process lock and re-reads the pack inside it. Without that, two processes that each read,
// add an entry and write would silently lose one of the additions: a pack has no per-entry merge.
// `mutate` receives a freshly read pack and returns { pack, result }; returning no pack means the
// call only validated and nothing is written.
function updateLocalFormats(mutate) {
  const lock = acquireLibraryLock();
  try {
    _localPack = { key: null, data: null }; // the cached copy may predate another process's write
    const out = mutate(loadLocalFormats()) || {};
    if (out.pack) saveLocalFormats(out.pack);
    return out.result;
  } finally {
    releaseLibraryLock(lock);
  }
}

function updateLocalCandidates(mutate) {
  const lock = acquireLibraryLock();
  try {
    _candPack = { key: null, data: null };
    const out = mutate(loadLocalCandidates()) || {};
    if (out.pack) saveLocalCandidates(out.pack);
    return out.result;
  } finally {
    releaseLibraryLock(lock);
  }
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

// ---------- Format report delivery: a native window, never a console ----------
// The report is only ever delivered by the user. This opens the platform's own GUI - a Windows
// dialog built with WinForms, zenity/kdialog/osascript on Linux/macOS - so the user can read what
// is inside the archive and then choose: send it with their own mail client, save a copy, open the
// folder, or delete it. Every action is an explicit click, the plugin still performs no network
// I/O, and when no GUI is available the caller gets plain instructions instead.
const REPORT_MAIL_TO = "seimuontei@gmail.com";

function latestReportFile() {
  try {
    const zips = fs.readdirSync(reportsDir()).filter((f) => f.endsWith(".zip"));
    if (!zips.length) return null;
    const withTime = zips.map((f) => {
      const p = path.join(reportsDir(), f);
      return { p, t: fs.statSync(p).mtimeMs };
    });
    withTime.sort((a, b) => b.t - a.t);
    return withTime[0].p;
  } catch {
    return null;
  }
}

// How to hand the archive over, without any GUI (servers, SSH, unsupported platform).
function reportDeliveryInstructions(file) {
  return {
    mail: { to: REPORT_MAIL_TO, subject: `[format report] mega-index-map ${PLUGIN_VERSION}`, attachment: file },
    steps: [
      `1. Review the archive (it holds report.json + manifest.txt):  ${file}`,
      `2. Send it yourself to ${REPORT_MAIL_TO} with subject "[format report] mega-index-map ${PLUGIN_VERSION}"`,
      "   - an e-mail cannot carry the attachment automatically: attach the .zip in your own mail client",
      "   - or upload it yourself to a file host of your choice and send the link",
      "3. Prefer to keep it local? Do nothing: nothing has been, or will be, transmitted.",
    ],
    note: "nothing was sent and no network I/O was performed",
  };
}

// Windows: a real dialog (read-only preview + explicit actions), built with WinForms.
function windowsReportDialogScript() {
  return [
    'param([string]$ReportPath, [string]$ManifestPath, [string]$ResultPath, [string]$MailTo, [string]$Subject, [string]$Body, [int]$AutoCloseMs = 0, [switch]$SelfTest)',
    "Add-Type -AssemblyName System.Windows.Forms",
    "Add-Type -AssemblyName System.Drawing",
    "[System.Windows.Forms.Application]::EnableVisualStyles()",
    "$choice = $null",
    "$savedTo = $null",
    "$nl = [Environment]::NewLine",
    "$form = New-Object System.Windows.Forms.Form",
    '$form.Text = "mega-index-map - file format report"',
    "$form.ClientSize = New-Object System.Drawing.Size(700, 528)",
    '$form.StartPosition = "CenterScreen"',
    '$form.FormBorderStyle = "FixedDialog"',
    "$form.MaximizeBox = $false",
    "$form.MinimizeBox = $false",
    "$title = New-Object System.Windows.Forms.Label",
    '$title.Text = "A file format report was prepared on this computer."',
    '$title.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)',
    "$title.SetBounds(16, 14, 668, 22)",
    "$form.Controls.Add($title)",
    "$info = New-Object System.Windows.Forms.Label",
    '$info.Text = ("It lists only file types this plugin could not identify: extensions, magic byte prefixes, counts and format relationships." + $nl + "No file names, no folder paths and no file contents are included. Nothing is sent automatically - the choice is yours.")',
    "$info.SetBounds(16, 42, 668, 46)",
    "$form.Controls.Add($info)",
    "$preview = New-Object System.Windows.Forms.TextBox",
    "$preview.Multiline = $true",
    "$preview.ReadOnly = $true",
    '$preview.ScrollBars = "Vertical"',
    "$preview.WordWrap = $false",
    '$preview.Font = New-Object System.Drawing.Font("Consolas", 8.25)',
    "$preview.SetBounds(16, 94, 668, 330)",
    "if (Test-Path $ManifestPath) { $preview.Text = (Get-Content -Raw -Encoding UTF8 $ManifestPath) }",
    "$preview.SelectionStart = 0",
    "$form.Controls.Add($preview)",
    "$chkFolder = New-Object System.Windows.Forms.CheckBox",
    '$chkFolder.Text = "Also open the folder with this file selected, so I can attach it"',
    "$chkFolder.Checked = $true",
    "$chkFolder.SetBounds(16, 434, 500, 22)",
    "$form.Controls.Add($chkFolder)",
    "$btnEmail = New-Object System.Windows.Forms.Button",
    '$btnEmail.Text = "Send by e-mail..."',
    "$btnEmail.SetBounds(16, 470, 140, 34)",
    "$form.Controls.Add($btnEmail)",
    "$btnSave = New-Object System.Windows.Forms.Button",
    '$btnSave.Text = "Save a copy..."',
    "$btnSave.SetBounds(164, 470, 130, 34)",
    "$form.Controls.Add($btnSave)",
    "$btnFolder = New-Object System.Windows.Forms.Button",
    '$btnFolder.Text = "Open folder"',
    "$btnFolder.SetBounds(302, 470, 110, 34)",
    "$form.Controls.Add($btnFolder)",
    "$btnDelete = New-Object System.Windows.Forms.Button",
    '$btnDelete.Text = "Delete report"',
    "$btnDelete.SetBounds(420, 470, 120, 34)",
    "$form.Controls.Add($btnDelete)",
    "$btnClose = New-Object System.Windows.Forms.Button",
    '$btnClose.Text = "Close"',
    "$btnClose.SetBounds(548, 470, 136, 34)",
    "$form.Controls.Add($btnClose)",
    "$form.CancelButton = $btnClose",
    "$btnFolder.Add_Click({ if (Test-Path $ReportPath) { Start-Process explorer.exe -ArgumentList ('/select,\"' + $ReportPath + '\"') } })",
    '$btnEmail.Add_Click({ if ($chkFolder.Checked -and (Test-Path $ReportPath)) { Start-Process explorer.exe -ArgumentList (\'/select,"\' + $ReportPath + \'"\') }; Start-Process ("mailto:" + $MailTo + "?subject=" + [uri]::EscapeDataString($Subject) + "&body=" + [uri]::EscapeDataString($Body)); $script:choice = "email"; $form.Close() })',
    '$btnSave.Add_Click({ $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Title = "Save a copy of the format report"; $dlg.Filter = "Zip archive (*.zip)|*.zip"; $dlg.FileName = [System.IO.Path]::GetFileName($ReportPath); if ($dlg.ShowDialog() -eq "OK") { Copy-Item -LiteralPath $ReportPath -Destination $dlg.FileName -Force; $script:savedTo = $dlg.FileName; [System.Windows.Forms.MessageBox]::Show(("Saved to:" + $nl + $script:savedTo), "mega-index-map", "OK", "Information") | Out-Null } })',
    '$btnDelete.Add_Click({ $answer = [System.Windows.Forms.MessageBox]::Show("Delete this report from your computer? Nothing was ever sent, so deleting it withdraws it.", "Delete report", "YesNo", "Warning"); if ($answer -eq "Yes") { Remove-Item -LiteralPath $ReportPath -Force -ErrorAction SilentlyContinue; $script:choice = "delete"; $form.Close() } })',
    '$btnClose.Add_Click({ $script:choice = "close"; $form.Close() })',
    "if ($SelfTest) { $st = New-Object System.Windows.Forms.Timer; $st.Interval = 1500; $st.Add_Tick({ $st.Stop(); if (-not $choice) { $script:choice = \"selftest\" }; $form.Close() }); $st.Start() }",
    "if ($AutoCloseMs -gt 0) { $ac = New-Object System.Windows.Forms.Timer; $ac.Interval = $AutoCloseMs; $ac.Add_Tick({ $ac.Stop(); if (-not $choice) { $script:choice = \"timeout\" }; $form.Close() }); $ac.Start() }",
    "[void]$form.ShowDialog()",
    '$action = "closed"',
    "if ($choice) { $action = $choice }",
    '$result = @{ action = $action; savedTo = $savedTo; at = (Get-Date).ToUniversalTime().ToString("o") }',
    "$json = $result | ConvertTo-Json -Compress",
    "# PowerShell 5.1 adds a BOM with -Encoding UTF8, which breaks JSON.parse on the other side,",
    "[System.IO.File]::WriteAllText($ResultPath, $json, (New-Object System.Text.UTF8Encoding($false)))",
    "$form.Dispose()",
  ].join("\n");
}

// Linux/macOS: zenity, then kdialog, then osascript, each in a loop so the user can read the
// manifest before deciding. The shell performs the redirection, so the result never has to
// travel through a stdout pipe.
function posixReportDialogScript() {
  const info = "A file format report was prepared on this computer. It lists only file types this plugin could not identify: extensions, magic byte prefixes, counts and format relationships. No file names, no folder paths and no file contents are included. Nothing is sent automatically - the choice is yours.";
  return [
    "#!/bin/sh",
    "# Report delivery dialog for Linux and macOS (zenity, kdialog or osascript).",
    'REPORT="$1"; MANIFEST="$2"; RESULT="$3"; MAILTO="$4"; SUBJECT="$5"; SUBJECT_ENC="$6"',
    `TEXT="${info}"`,
    'HEAD="mega-index-map - file format report"',
    'write_result() { printf \'{"action":"%s"}\\n\' "$1" > "$RESULT"; }',
    'open_any() {',
    '  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$1" >/dev/null 2>&1; return 0; fi',
    '  if command -v open >/dev/null 2>&1; then open "$1" >/dev/null 2>&1; return 0; fi',
    '  return 1',
    "}",
    'mail_url() { printf "mailto:%s?subject=%s" "$MAILTO" "$SUBJECT_ENC"; }',
    "if command -v zenity >/dev/null 2>&1; then",
    "  while : ; do",
    '    SEL=$(zenity --radiolist --title="$HEAD" --text="$TEXT" --column=Pick --column=Action TRUE "Send by e-mail" FALSE "View contents" FALSE "Open folder" FALSE "Delete report" FALSE "Close" --height=460 --width=720 2>/dev/null | tail -n 1)',
    '    SEL=${SEL##*|}',
    "    case \"$SEL\" in",
    '      "Send by e-mail") open_any "$(mail_url)"; write_result email; break ;;',
    '      "View contents") zenity --text-info --title="$HEAD" --filename="$MANIFEST" --width=760 --height=520 2>/dev/null ; continue ;;',
    '      "Open folder") open_any "$(dirname "$REPORT")"; write_result folder; break ;;',
    '      "Delete report") rm -f "$REPORT"; write_result delete; break ;;',
    '      *) write_result close; break ;;',
    "    esac",
    "  done",
    "elif command -v kdialog >/dev/null 2>&1; then",
    "  while : ; do",
    '    SEL=$(kdialog --title "$HEAD" --menu "$TEXT" 1 "Send by e-mail" 2 "View contents" 3 "Open folder" 4 "Delete report" 5 "Close" 2>/dev/null)',
    "    case \"$SEL\" in",
    '      1) open_any "$(mail_url)"; write_result email; break ;;',
    '      2) kdialog --title "$HEAD" --textbox "$MANIFEST" 760 520 2>/dev/null ; continue ;;',
    '      3) open_any "$(dirname "$REPORT")"; write_result folder; break ;;',
    '      4) rm -f "$REPORT"; write_result delete; break ;;',
    '      *) write_result close; break ;;',
    "    esac",
    "  done",
    "elif command -v osascript >/dev/null 2>&1; then",
    "  while : ; do",
    `    BTN=$(osascript -e 'button returned of (display dialog "${info}" with title "mega-index-map - file format report" buttons {"Send by e-mail", "View contents", "Open folder", "Delete report", "Close"} default button 1)' 2>/dev/null)`,
    "    case \"$BTN\" in",
    '      "Send by e-mail") open_any "$(mail_url)"; write_result email; break ;;',
    '      "View contents") open_any "$MANIFEST"; continue ;;',
    '      "Open folder") open_any "$(dirname "$REPORT")"; write_result folder; break ;;',
    '      "Delete report") rm -f "$REPORT"; write_result delete; break ;;',
    '      *) write_result close; break ;;',
    "    esac",
    "  done",
    "else",
    '  write_result unavailable',
    "fi",
  ].join("\n");
}

// Open the dialog and wait for the user's decision (or for autoCloseMs / self-test to end it).
async function runReportDialog(reportPath, opts = {}) {
  const manifest = zipReadEntry(fs.readFileSync(reportPath), "manifest.txt");
  const text = manifest ? manifest.toString("utf8").replace(/^\uFEFF/, "") : "manifest.txt could not be read from the archive.";
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mega-index-map-dialog-"));
  const manifestPath = path.join(dir, "manifest.txt");
  const resultPath = path.join(dir, "result.json");
  const scriptPath = path.join(dir, process.platform === "win32" ? "dialog.ps1" : "dialog.sh");
  fs.writeFileSync(manifestPath, "\uFEFF" + text, "utf8");
  fs.writeFileSync(scriptPath, process.platform === "win32" ? windowsReportDialogScript() : posixReportDialogScript(), "utf8");

  const subject = `[format report] mega-index-map ${PLUGIN_VERSION}`;
  const body = "Attached: the format report archive prepared by mega-index-map. It contains file extensions, magic-byte prefixes, counts and format relationships only - no file names, no folder paths and no file contents. Please attach the .zip that is selected in the folder window.";
  let command;
  let args;
  if (process.platform === "win32") {
    // PowerShell 7 when present, else Windows PowerShell 5.1; both host the WinForms dialog in STA.
    command = dialogShell();
    args = ["-STA", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", scriptPath,
      "-ReportPath", reportPath, "-ManifestPath", manifestPath, "-ResultPath", resultPath,
      "-MailTo", REPORT_MAIL_TO, "-Subject", subject, "-Body", body];
    if (opts.selfTest) args.push("-SelfTest");
    if (opts.autoCloseMs > 0) args.push("-AutoCloseMs", String(opts.autoCloseMs));
  } else {
    command = "sh";
    // the encoded subject keeps the mailto: URL valid on Linux/macOS desktop handlers
    args = [scriptPath, reportPath, manifestPath, resultPath, REPORT_MAIL_TO, subject, encodeURIComponent(subject)];
  }
  // Reported back to the caller so the shell that actually ran the dialog is never a guess.
  const shellName = path.basename(command);

  const cleanup = () => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  };

  const child = spawn(command, args, { stdio: "ignore", windowsHide: true, detached: false });
  let launchError = null;
  const finished = new Promise((resolve) => {
    let waited = 0;
    const cap = Math.max(opts.timeoutMs || 0, opts.autoCloseMs || 0, 60000);
    const tick = setInterval(() => {
      waited += 250;
      if (fs.existsSync(resultPath)) {
        clearInterval(tick);
        let result = null;
        try {
          // tolerate a BOM: Windows PowerShell may add one even though the dialog writes ASCII JSON
          result = JSON.parse(fs.readFileSync(resultPath, "utf8").replace(/^\uFEFF/, "").trim());
        } catch {}
        resolve(result);
        return;
      }
      if (waited >= cap) { clearInterval(tick); resolve(null); }
    }, 250);
    // A dialog program that cannot even start (powershell.exe/sh missing, EACCES) never writes a
    // result file: without this the caller would sit until the 60 s cap and then be told "pending",
    // which reads like the user is still deciding. Resolve at once and report the same
    // "unavailable" verdict the script's own no-desktop-toolkit path produces.
    child.on("error", (e) => { launchError = e; clearInterval(tick); resolve(null); });
  });
  const result = await finished;
  cleanup();
  if (!result) {
    if (launchError) {
      const why = String((launchError && (launchError.code || launchError.message)) || "unknown").slice(0, 60);
      return { action: "unavailable", gui: false, shell: shellName, note: `the dialog program could not be started (${why}); nothing was sent` };
    }
    return { action: child.exitCode === null ? "pending" : "unavailable", gui: false, shell: shellName, note: "the dialog did not report back; no report was sent" };
  }
  const action = result.action || "closed";
  // "unavailable" means the script found no desktop toolkit: that host has no GUI to show.
  return { action, savedTo: result.savedTo || null, gui: action !== "unavailable", at: result.at || null, shell: shellName };
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

// ---------- Reading DSH's own sessions: the host's conversation store, decoded locally ----------
// DSH keeps one directory per session under $DSH_HOME/sessions/<workspace>/<session-id>/ and writes
// session.jsonl.zstd: an append-only stream in which every record is its own zstd frame. That detail
// decides how this has to be read. A public zstd decoder stops at the first frame - measured on a 56 MB
// session it decoded exactly one record - whereas locating frames by the zstd magic and decoding them
// one at a time read all 162,050 of them (111.7 MB of JSONL, ~7 s). The host's own persistence carries a
// private multi-frame decoder for the same reason. A session that was exported ("Download this Session
// log as a ZIP") is read the other way: the archive is a ZIP whose root holds session*.jsonl, subagent
// logs sit under subagents/<id>/, and attachments under media/ and files/ (listed, never decoded).
//
// Everything here is a local read under $DSH_HOME: no network, no execution, and the transcript text is
// returned only when a caller explicitly asks for it. A frame that will not decode is counted, never
// guessed at - a torn tail is the usual reason, and the host repairs those itself on the next open.
const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]);
// Node gained a zstd decoder in v23.8; on an older runtime the session reader says so instead of
// reporting every frame as unreadable.
const ZSTD_AVAILABLE = typeof zstdDecompressSync === "function";
const SESSION_FILE_RE = /^session(\.[vV]\d+)?\.jsonl(\.zstd)?$/;
const SESSION_ARCHIVE_MEMBER_RE = /(^|\/)session(\.[vV]\d+)?\.jsonl$/;

function dshSessionsDir() {
  return path.join(dshHomeDir(), "sessions");
}

function zstdFrameOffsets(buf) {
  const offsets = [];
  let i = 0;
  while ((i = buf.indexOf(ZSTD_MAGIC, i)) !== -1) {
    offsets.push(i);
    i += ZSTD_MAGIC.length;
  }
  return offsets;
}

// Decode a whole plain-text JSONL body, or the frames of a zstd stream, into records - bounded by a
// record count, a character budget and optionally a window of frames (the head or the tail).
function decodeSessionBuffer(buf, opts) {
  const { firstFrames = 0, lastFrames = 0, maxRecords = 0, maxChars = 0, tolerateCutTail = false } = opts || {};
  const zstd = buf.length > 4 && buf.subarray(0, 4).equals(ZSTD_MAGIC);
  let pieces;
  let frames = 1;
  let failed = 0;
  if (zstd) {
    const offsets = zstdFrameOffsets(buf);
    frames = offsets.length;
    let index = offsets.map((_, i) => i);
    if (firstFrames || lastFrames) {
      const keep = new Set();
      for (let i = 0; i < Math.min(firstFrames || 0, offsets.length); i++) keep.add(i);
      for (let i = Math.max(0, offsets.length - (lastFrames || 0)); i < offsets.length; i++) keep.add(i);
      index = [...keep].sort((a, b) => a - b);
    }
    pieces = [];
    let cutTail = false;
    for (let k = 0; k < index.length; k++) {
      const fi = index[k];
      const start = offsets[fi];
      const end = fi + 1 < offsets.length ? offsets[fi + 1] : buf.length;
      try {
        pieces.push(zstdDecompressSync(buf.subarray(start, end)).toString("utf8"));
      } catch {
        // A caller that read only the head of a file hands us a buffer that ends mid-frame; that last
        // frame is cut off, not corrupt, and must not be reported as an unreadable one.
        if (tolerateCutTail && k === index.length - 1) cutTail = true;
        else failed++;
      }
    }
  } else {
    pieces = [buf.toString("utf8")];
  }
  const records = [];
  let chars = 0;
  let truncated = false;
  for (const piece of pieces) {
    for (const line of piece.split("\n")) {
      if (!line.trim()) continue;
      if (maxRecords && records.length >= maxRecords) { truncated = true; break; }
      if (maxChars && chars + line.length > maxChars) { truncated = true; break; }
      chars += line.length;
      let obj = null;
      try { obj = JSON.parse(line); } catch { obj = { type: "(unparsed)" }; }
      records.push(obj);
    }
    if (truncated) break;
  }
  return { frames, failed, cutTail: typeof cutTail === "boolean" ? cutTail : false, records, chars, truncated, zstd };
}

// The text of one record, across the shapes DSH writes: user/message holds blocks in data.content,
// assistant/message and tool/result hold a message object, tool/call holds a name and arguments.
function sessionBlocksText(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(sessionBlocksText).filter(Boolean).join("\n");
  if (value && typeof value === "object") {
    if (typeof value.text === "string") return value.text;
    if (value.content !== undefined) return sessionBlocksText(value.content);
  }
  return "";
}
function sessionRecordText(rec) {
  const d = (rec && rec.data) || {};
  const type = String((rec && rec.type) || "");
  if (type === "user/message") return sessionBlocksText(d.content);
  if (type === "assistant/message") return sessionBlocksText(d.message && d.message.content !== undefined ? d.message.content : d.message);
  if (type === "tool/result") return sessionBlocksText(d.message && d.message.content !== undefined ? d.message.content : d.message);
  if (type === "tool/call") {
    const arg = typeof d.arguments === "string" ? d.arguments : JSON.stringify(d.arguments === undefined ? {} : d.arguments);
    return `${d.name || "tool"}(${String(arg).slice(0, 400)})`;
  }
  return "";
}
// The session header is the first record; its fields sit on the record itself in the versions seen so
// far, with a data wrapper in others - accept both rather than guessing one and reading nulls.
function sessionHeader(rec) {
  if (!rec) return {};
  const out = {};
  for (const [k, v] of Object.entries(rec)) if (k !== "data") out[k] = v;
  if (rec.data && typeof rec.data === "object") for (const [k, v] of Object.entries(rec.data)) if (out[k] === undefined) out[k] = v;
  return out;
}
function sessionTitle(records) {
  for (const rec of records) {
    if (rec && rec.type === "session/title" && rec.data && typeof rec.data.title === "string") return rec.data.title;
  }
  return "";
}

// A bounded walk of the session store: directories holding session files, and exported ZIP archives.
function listSessionSources(dir, maxFiles) {
  const live = [];
  const archives = [];
  const walk = (d, depth) => {
    if (live.length + archives.length >= maxFiles) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (live.length + archives.length >= maxFiles) return;
      const full = path.join(d, e.name);
      if (e.isDirectory()) { if (depth < 6) walk(full, depth + 1); continue; }
      if (SESSION_FILE_RE.test(e.name)) live.push(full);
      else if (/\.zip$/i.test(e.name)) archives.push(full);
    }
  };
  walk(path.resolve(dir), 0);
  return { live, archives };
}

// Resolve what a caller names as a session: a session file, a session directory, a ZIP, a ZIP member
// ("<zip>#<member>"), or a fragment of a session id.
function resolveSessionTarget(target) {
  const raw = String(target || "").trim();
  if (!raw) return null;
  const hash = raw.indexOf("#");
  if (hash > 0) {
    const zip = path.resolve(raw.slice(0, hash));
    const member = raw.slice(hash + 1);
    if (!fs.existsSync(zip)) return null;
    const buf = fs.readFileSync(zip, null);
    const entry = zipReadEntry(buf, member);
    if (!entry) return null;
    return { kind: "archive-member", path: zip, member, buf: entry, size: entry.length };
  }
  const abs = path.resolve(raw);
  if (fs.existsSync(abs)) {
    const st = fs.statSync(abs);
    if (st.isFile()) {
      if (/\.zip$/i.test(abs)) return { kind: "archive", path: abs, size: st.size };
      return { kind: "file", path: abs, size: st.size };
    }
    if (st.isDirectory()) {
      const { live } = listSessionSources(abs, 8);
      if (live.length) {
        const newest = live.map((f) => ({ f, m: fs.statSync(f).mtimeMs })).sort((a, b) => b.m - a.m)[0].f;
        return { kind: "file", path: newest, size: fs.statSync(newest).size };
      }
      for (const e of fs.readdirSync(abs)) if (/\.zip$/i.test(e)) return { kind: "archive", path: path.join(abs, e), size: fs.statSync(path.join(abs, e)).size };
      return null;
    }
  }
  // A fragment of an id: search the session store for the first directory or file that contains it.
  const { live, archives } = listSessionSources(dshSessionsDir(), 4000);
  const hit = live.find((f) => f.toLowerCase().includes(raw.toLowerCase()));
  if (hit) return { kind: "file", path: hit, size: fs.statSync(hit).size };
  const zip = archives.find((f) => f.toLowerCase().includes(raw.toLowerCase()));
  if (zip) return { kind: "archive", path: zip, size: fs.statSync(zip).size };
  return null;
}

function readSessionBuffer(resolved) {
  if (resolved.kind === "archive-member") return { buf: resolved.buf, member: resolved.member };
  return { buf: fs.readFileSync(resolved.path, null), member: null };
}

// ---------- Mining the session history for what this Library actually indexes ----------
// A conversation is mostly conversation; what a Library wants from it is the handful of facts about THIS
// machine that came up in passing - a tool that was used and really exists here, a path that is real, a
// local endpoint, an environment variable that is set, a file format that appeared. Measured here: 246
// sessions decompress to 1,509 MB and 1,478,647 records, read in 70.8 s. Nothing like that volume can be
// stored, and it should not be: mining is existence-filtered, so a name that does not resolve on this
// machine is dropped rather than recorded, and every mined row carries source "session-mining" and a
// name derived from the fact itself - which makes a later pass replace the earlier one instead of piling up.
const MINED_SOURCE = "session-mining";
const MINED_PATH = /(?<![A-Za-z0-9_$])(?:[A-Za-z]:[\\/][^\s"'`<>|?*\[\]]+|\/(?:usr|opt|home|etc|var|srv|mnt)\/[^\s"'`<>|?*\[\]]+)/g;
const MINED_EXEC = /\b([A-Za-z0-9_.+-]+\.(?:exe|cmd|bat|ps1|sh|bash|py|mjs|cjs|js|jar|lua|pl))\b/gi;
const MINED_TICK = /`([A-Za-z0-9_.+-]{1,40})`/g;
const MINED_ENDPOINT = /\b(?:https?:\/\/)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0):(\d{2,5})\b/g;
const MINED_ENVVAR = /%([A-Za-z_][A-Za-z0-9_]*)%|\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;
const MINED_EXT_STEM = /\b(?![.\d])[A-Za-z0-9_][A-Za-z0-9_.+-]{0,40}\.([A-Za-z][A-Za-z0-9]{0,7})\b/g;
// A host name is not a file format: these read as extensions all the time.
const MINED_TLD = new Set(["com", "net", "org", "edu", "gov", "info", "biz", "xyz", "top", "site", "online", "io", "ai", "co", "me", "tv", "app", "dev", "cn", "jp", "kr", "tw", "hk", "sg", "us", "uk", "de", "fr", "ru", "nl", "se", "it", "es", "br", "au", "ca", "in", "id", "th", "vn", "ph", "my"]);
const MINED_EXT_TICK = /`\.([A-Za-z][A-Za-z0-9]{0,7})`/g;
// Names an installer leaves behind are real files and useless facts.
const MINED_NOISE = /^(?:unins\d*|uninstall|uninstaller|setup|install|installer|remove|update|helper|crashpad_handler|elevate)$/i;

// Every timestamp this plugin writes is UTC ISO-8601 - markers, ordering and supersede decisions all
// compare on one ruler - but a report is read by a person on a local clock, so the host's UTC offset
// travels with the times instead of being guessed at.
function timezoneInfo() {
  if (timezoneInfo.cached) return timezoneInfo.cached;
  const offsetMinutes = -new Date().getTimezoneOffset();
  const abs = Math.abs(offsetMinutes);
  const sign = offsetMinutes >= 0 ? "+" : "-";
  const utcOffset = sign + String(Math.floor(abs / 60)).padStart(2, "0") + ":" + String(abs % 60).padStart(2, "0");
  let name = "";
  try { name = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { name = ""; }
  const localNow = new Date(Date.now() + offsetMinutes * 60000).toISOString().replace("Z", utcOffset);
  timezoneInfo.cached = { offsetMinutes, name, utcOffset, localNow };
  return timezoneInfo.cached;
}

function miningStateFile() { return path.join(libraryDir(), "bootstrap-state.json"); }
function miningProgressFile() { return path.join(libraryDir(), "bootstrap-progress.jsonl"); }
function readMiningState() {
  try { return JSON.parse(fs.readFileSync(miningStateFile(), "utf8")); } catch { return null; }
}
// Every step is a line, so progress is visible while it happens rather than only at the end.
function writeMiningState(state) {
  try {
    ensureLibrary();
    // The state file also carries the resume marker, so a progress write must never drop \`seen\`: when the
    // caller's state does not have it, carry the one already on disk forward (regression: the closing
    // progress write used to erase the marker, which made every pass re-read the whole history).
    let seen = state.seen;
    if (!seen) {
      try {
        const prev = JSON.parse(fs.readFileSync(miningStateFile(), "utf8"));
        seen = (prev && prev.seen) || (prev && prev.last && prev.last.seen) || null;
      } catch { seen = null; }
    }
    const payload = seen ? { ...state, seen } : state;
    fs.writeFileSync(miningStateFile(), JSON.stringify(payload, null, 2) + "\n", "utf8");
    fs.appendFileSync(miningProgressFile(), JSON.stringify({ at: new Date().toISOString(), phase: state.phase, sessionsDone: state.sessionsDone, sessionsTotal: state.sessionsTotal, file: state.currentFile || null, records: state.records, found: state.found, added: state.added, updated: state.updated }) + "\n", "utf8");
  } catch { /* progress must never break the pass */ }
}

// Existence is what separates a fact from a mention: a path that is not on this machine, a name that does
// not resolve, a variable that is not set are all mentions, and mentions are dropped here.
function mineSessionText(text, sink) {
  const exists = (candidate) => {
    if (sink.stat.has(candidate)) return sink.stat.get(candidate);
    let ok = false;
    try { ok = fs.existsSync(candidate); } catch { ok = false; }
    sink.stat.set(candidate, ok);
    return ok;
  };
  const add = (type, name, path_, desc, tag) => {
    const key = `${type}::${name}`;
    const known = sink.seen.get(key);
    if (known) { known.hits++; return; }
    const rec = { type, name, path: path_ || "", description: desc, tags: [tag, "mined"], hits: 1 };
    sink.seen.set(key, rec);
    sink.records.push(rec);
  };
  for (const m of text.matchAll(MINED_PATH)) {
    // A path in a session arrives with its separators doubled (the host escapes them in JSON),
    // so normalise it: the Library should hold one canonical spelling of one fact.
    let p = m[0].replace(/[.,;:)\]]+$/, "").replace(/[\\/]{2,}/g, "\\");
    try { p = path.normalize(p); } catch { /* keep what we have */ }
    if (!p || MINED_NOISE.test(path.basename(p).replace(/\.[^.]+$/, ""))) continue;
    if (!exists(p)) continue;
    let isDir = false;
    try { isDir = fs.statSync(p).isDirectory(); } catch { isDir = false; }
    const name = path.basename(p) || p;
    if (isDir) add("env", `${name} (directory)`, p, "directory seen in a session and present on this machine", "mined:dir");
    else if (/\.(exe|cmd|bat|ps1|sh|py|mjs|cjs|js|jar)$/i.test(p)) add("tool", name.replace(/\.[^.]+$/, ""), p, "executable seen in a session and present on this machine", "mined:tool");
    else add("file", name, p, "file seen in a session and present on this machine", "mined:file");
  }
  for (const m of text.matchAll(MINED_EXEC)) {
    const base = m[1];
    let resolved = null;
    try { if (fs.existsSync(m[0])) resolved = m[0]; } catch { resolved = null; }
    if (!resolved) resolved = resolveOnPath(base);
    if (!resolved) continue;
    if (MINED_NOISE.test(base.replace(/\.[^.]+$/, ""))) continue;
    add("tool", base.replace(/\.[^.]+$/, ""), resolved, `tool named in a session and resolvable on this machine (${base})`, "mined:tool");
  }
  for (const m of text.matchAll(MINED_TICK)) {
    const token = m[1];
    if (token.length < 2 || /[\\/]/.test(token) || !/^[A-Za-z][A-Za-z0-9_.+-]*$/.test(token)) continue;
    const resolved = resolveOnPath(token);
    if (!resolved) continue;
    if (MINED_NOISE.test(token.replace(/\.[^.]+$/, ""))) continue;
    add("tool", token.replace(/\.[^.]+$/, ""), resolved, "command named in a session and resolved from PATH", "mined:tool");
  }
  for (const m of text.matchAll(MINED_ENDPOINT)) {
    add("env", `localhost:${m[1]}`, `http://127.0.0.1:${m[1]}`, "local endpoint mentioned in a session (recorded, never probed: this plugin does no network I/O)", "mined:endpoint");
  }
  for (const m of text.matchAll(MINED_ENVVAR)) {
    const name = m[1] || m[2];
    if (!name) continue;
    const value = declaredEnv(name);
    if (value === null || value === undefined || value === "") continue;
    add("env", `%${name}%`, String(value).slice(0, 300), "environment variable mentioned in a session and set on this machine", "mined:env");
  }
  const lead = (ext) => {
    if (!ext || ext.length < 2 || !/[A-Za-z]/.test(ext) || MINED_TLD.has(ext)) return;
    // EXT_FAMILY is this plugin's own answer to "is this extension known" - text, ZIP packages and the
    // binary families - so a lead is only something that list does not already cover.
    if (EXT_FAMILY[ext] || FILE_SIGNATURES.some((s) => (s.ext || []).includes(ext))) return;
    add("reference", `.${ext}`, "", "file format mentioned in a session that this format library does not know yet - consider library_format op=propose or op=learn", "mined:ext");
  };
  // A stem before the dot (report.tfpk) or a backticked bare extension is a format mention; a bare
  // ".ext" in CSS or prose text is not - which is where the noise came from, so it is no longer accepted.
  for (const m of text.matchAll(MINED_EXT_STEM)) {
    const stem = m[0].slice(0, m[0].length - m[1].length - 1);
    if (!/[0-9_-]/.test(stem)) continue;      // a plain identifier is a code member, not a file name
    lead(m[1].toLowerCase());
  }
  for (const m of text.matchAll(MINED_EXT_TICK)) lead(m[1].toLowerCase());
}

function mineSessionFile(file, sink) {
  let buf = null;
  try { buf = fs.readFileSync(file, null); } catch { return { records: 0, failed: 0, frames: 0 }; }
  const offsets = zstdFrameOffsets(buf);
  let failed = 0;
  let records = 0;
  for (let k = 0; k < offsets.length; k++) {
    const start = offsets[k];
    const end = k + 1 < offsets.length ? offsets[k + 1] : buf.length;
    let text;
    try { text = zstdDecompressSync(buf.subarray(start, end)).toString("utf8"); } catch { failed++; continue; }
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      records++;
      let rec = null;
      try { rec = JSON.parse(line); } catch { continue; }
      const type = String(rec.type || "");
      if (type === "tool/call" || type === "tool/result" || type === "user/message" || type === "assistant/message") {
        mineSessionText(sessionRecordText(rec), sink);
      }
    }
  }
  return { records, failed, frames: offsets.length };
}

// Replace by key, never pile up: the same type+name+source is the same fact learned again, so the newer
// knowledge wins and the older row is superseded (the index keeps the newest, the log keeps the change).
function upsertMined(records) {
  const stamped = new Date().toISOString();
  return updateIndex((index) => {
    let added = 0;
    let updated = 0;
    for (const rec of records) {
      const obj = {
        id: makeId(rec.type, MINED_SOURCE, rec.name),
        type: rec.type,
        name: rec.name,
        source: MINED_SOURCE,
        path: rec.path || "",
        description: rec.description,
        tags: rec.tags,
        summary: `seen ${rec.hits} time(s) in the session history; mined ${stamped}`,
        createdAt: stamped,
      };
      const at = index.objects.findIndex((o) => o.type === rec.type && o.name === rec.name && o.source === MINED_SOURCE);
      if (at >= 0) { index.objects[at] = obj; updated++; } else { index.objects.push(obj); added++; }
    }
    return { added, updated };
  });
}

// The pass itself. Every step writes its progress before the next one starts, it resumes from the marker,
// and it stops on a budget rather than holding the host open indefinitely.
async function runSessionMining(opts) {
  const { budgetMs = 600000, maxSessions = 0, dir = dshSessionsDir(), log = null } = opts || {};
  const startedAt = Date.now();
  const state = readMiningState() || {};
  state.seen = (state.last && state.last.seen) || state.seen || {};
  const { live, archives } = listSessionSources(path.resolve(dir), 100000);
  const files = [...live, ...archives];
  const pending = files.filter((f) => {
    try { const st = fs.statSync(f); return state.seen[f] !== `${st.size}:${Math.floor(st.mtimeMs)}`; } catch { return false; }
  });
  const total = maxSessions > 0 ? Math.min(pending.length, maxSessions) : pending.length;
  const sink = { seen: new Map(), records: [], stat: new Map() };
  const base = {
    timezone: timezoneInfo(),
    phase: total ? "mining" : "complete",
    startedAt: new Date(startedAt).toISOString(),
    updatedAt: new Date().toISOString(),
    sessionsTotal: total,
    sessionsDone: 0,
    currentFile: null,
    budgetMs,
    records: 0,
    found: 0,
    added: 0,
    updated: 0,
  };
  writeMiningState(base);
  if (log && typeof log.info === "function") {
    log.info(`[mega-index-map] session mining: ${total} of ${files.length} session file(s) to read (budget ${Math.round(budgetMs / 1000)}s)`);
  }

  let stopped = null;
  let done = 0;
  const seen = { ...state.seen };
  for (let i = 0; i < total; i++) {
    if (Date.now() - startedAt > budgetMs) { stopped = "budget"; break; }
    const file = pending[i];
    base.currentFile = file;
    base.sessionsDone = i;
    writeMiningState(base);
    const res = mineSessionFile(file, sink);
    base.records += res.records;
    try { const st = fs.statSync(file); seen[file] = `${st.size}:${Math.floor(st.mtimeMs)}`; } catch { /* gone: leave it out */ }
    done++;
    // Hand the event loop back periodically: a long read must not look like a freeze.
    if (i % 20 === 19) await new Promise((resolve) => setImmediate(resolve));
    if (log && typeof log.info === "function" && (i === total - 1 || (i + 1) % 20 === 0)) {
      log.info(`[mega-index-map] session mining ${i + 1}/${total}: ${path.basename(path.dirname(file))} (${res.records} record(s), ${sink.records.length} candidate(s))`);
    }
  }
  const counted = upsertMined(sink.records);
  const finalState = {
    ...base,
    phase: stopped ? "partial" : "complete",
    sessionsDone: done,
    currentFile: null,
    updatedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    tookMs: Date.now() - startedAt,
    searched: files.length,
    found: sink.records.length,
    added: counted.added,
    updated: counted.updated,
    done: !stopped,
    note: stopped
      ? `stopped on the ${Math.round(budgetMs / 1000)}s budget after ${done} session(s); the next run continues with the rest`
      : `read ${done} session(s) and ${base.records} record(s); ${counted.added} new fact(s), ${counted.updated} replaced`,
  };
  // The marker keeps what makes the next run cheap (path -> size:mtime), bounded so a long history cannot
  // grow it without limit; the per-run numbers live in `last`.
  const seenKeys = Object.keys(seen);
  const bounded = seenKeys.length > 50000 ? Object.fromEntries(seenKeys.slice(-50000).map((k) => [k, seen[k]])) : seen;
  try {
    ensureLibrary();
    fs.writeFileSync(miningStateFile(), JSON.stringify({ seen: bounded, done: (state.done || 0) + done, last: finalState }, null, 2) + "\n", "utf8");
  } catch { /* the state file is a convenience, not the source of truth */ }
  writeMiningState(finalState);
  return finalState;
}

// ---------- Session notice: ask the Library before walking the disk ----------
// A host that has no hint about this Library answers "where is tool X" by walking the filesystem -
// minutes of I/O and a great many tokens for something already recorded here. DSH lets a plugin
// prepend text to the first user message of a session; this is that notice, and it is the same
// mechanism the disk-guard plugin uses for its path discipline. Injected once per session, never into
// a subagent's session, never when the session already carries user messages, and never when the
// config turns it off.
//
// The default wording is English/ASCII, because this package ships ASCII-only text. Put your own
// wording - any language - in $DSH_HOME/mega-index-prompt.md and it replaces the default wholesale,
// the same override convention disk-guard uses.
function dshHomeDir() {
  return process.env.DSH_HOME || path.join(os.homedir(), ".dsh");
}
function libraryPromptFile() {
  return path.join(dshHomeDir(), "mega-index-prompt.md");
}
// The notice wants to say how much is already recorded, not to re-read the index on every step.
function libraryCounts() {
  const now = Date.now();
  if (libraryCounts.cached && now - libraryCounts.cached.at < 60000) return libraryCounts.cached.value;
  let objects = 0;
  let candidates = 0;
  try { objects = (JSON.parse(fs.readFileSync(indexFile(), "utf8")).objects || []).length; } catch { objects = 0; }
  try { candidates = (JSON.parse(fs.readFileSync(candidatesFile(), "utf8")).candidates || []).length; } catch { candidates = 0; }
  const value = { objects, candidates };
  libraryCounts.cached = { at: now, value };
  return value;
}
function buildLibraryPrompt() {
  const { objects, candidates } = libraryCounts();
  return [
    "[mega-index-map - consult the Library first] Injected by the plugin; it replaces a filesystem scan.",
    `1. This machine's Library: ${libraryDir()} - ${objects} record(s) and ${candidates} tool/environment candidate(s), with paths and the versions the tools state about themselves.`,
    "2. Looking for a tool, SDK, runtime, service or environment fact? -> library_detect op=list first (op=scan refreshes). Only if that misses, search the disk.",
    "3. Looking for an object, a keyword, or what a workspace used before? -> library_query (keyword/type/tags/source).",
    "4. What is this file really, is the name lying? -> library_sniff. Extending the format library -> library_format. Do not read header bytes by hand.",
    "5. Is a directory fully recorded, or has the disk drifted from the records? -> library_index op=audit dir=<path> (read-only), then op=index confirm=true to register what is missing.",
    "6. A recorded path is meant to be used as it stands. If the object has moved, record the new version with library_record: the newest version supersedes the older one.",
    "7. Record what you find worth reusing (tool/file/env/knowledge/work record) with library_record, so no later session has to look again.",
    "8. The Library has no answer only then: scan as a last resort, and record what the scan found - that is what makes this cost a one-off instead of a habit.",
    "Set $DSH_HOME/mega-index-prompt.md to replace this text, or config injectPrompt:false to silence it.",
  ].join("\n");
}

async function apply(ctx, config) {
  const settings = config && typeof config === "object" ? config : {};
  // First-run behaviour. "blocking" reads the whole session history before this Library registers its
  // tools (the default, so an installed Library is never half-indexed); "gate" starts it and lets the host
  // boot; "off" waits for an explicit op=bootstrap. Whichever it is, the pass is resumable, budgeted and
  // visible step by step in E:dsh-home/library/bootstrap-progress.jsonl.
  const bootstrapMode = ["off", "gate", "blocking"].includes(String(settings.bootstrap)) ? String(settings.bootstrap) : "blocking";
  const bootstrapBudgetMs = clampInt(settings.bootstrapBudgetMs, 300000, 1000, 3600000);
  const bootstrapMaxSessions = clampInt(settings.bootstrapMaxSessions, 0, 0, 100000);
  // ---- (4) Prevent waking outside DeepSeek Harness ----
  // Only register tools in a DSH host environment, identified by the DSH_HOME env var
  // (which the DSH host always sets). Outside DSH (bare node, other agent frameworks),
  // no library tools are registered, so the plugin cannot be woken externally.
  if (!process.env.DSH_HOME) {
    appendLog({ op: "gate", type: null, name: null, source: null, disposition: null, detail: "not a DSH host, refusing to register tools" });
    return;
  }

  // ---- First-run pass: mine the session history before claiming to be installed ----
  if (bootstrapMode !== "off") {
    const pass = async () => {
      try {
        const report = await runSessionMining({ budgetMs: bootstrapBudgetMs, maxSessions: bootstrapMaxSessions, log: ctx.logger });
        if (ctx.logger && typeof ctx.logger.info === "function") ctx.logger.info(`[mega-index-map] session mining ${report.phase} - ${report.note}`);
        return report;
      } catch (e) {
        // A pass that fails must not take the host down with it: the failure is recorded in the state file
        // and reported by library_sessions op=status, and the tools still come up.
        const detail = e && e.message ? e.message : String(e);
        writeMiningState({ phase: "failed", updatedAt: new Date().toISOString(), note: detail });
        if (ctx.logger && typeof ctx.logger.warn === "function") ctx.logger.warn(`[mega-index-map] session mining failed: ${detail}`);
        return null;
      }
    };
    if (bootstrapMode === "blocking") await pass();
    else pass();
    if (ctx.logger && typeof ctx.logger.info === "function") {
      ctx.logger.info(`[mega-index-map] first-run bootstrap mode: ${bootstrapMode}`);
    }
  }

  // ---- library_record: record one encountered object into the library ----
  ctx.tools.register(defineTool({
    name: "library_record",
    description:
      "Record a tool/file/env/product/knowledge/work record into the cross-workspace Library, so no later session has to look for it again. Use it whenever something reusable turns up - a tool or script found on this machine, a built artifact, an environment fact (endpoint, port, path), a research conclusion, a work record - and whenever a recorded object has changed (the same key is fingerprinted, so the change is routed, and the newest version supersedes the older one). One object per call; type and source are required.",
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
      confirm: {
        type: "boolean",
        description:
          "Confirm a change to an immutable-class object (knowledge/reference and the rest of the confirm list), which is otherwise refused. Requires reason; the confirmation is written to the append-only log.",
      },
      reason: {
        type: "string",
        description:
          "What the user decided and why. Required with confirm=true, and recorded in the log as the trace of who allowed the change.",
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
          sensitive: { type: "boolean" },
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
          const committed = commitRecord(obj, disposition, "content changed, recorded and notify DSH to check");
          return {
            id: obj.id,
            ok: true,
            count: committed.count,
            changed: true,
            disposition: "verify",
            message: `"${name}" differs from the last indexed result; a new version was recorded${committed.sensitive ? " (sensitive content detected, stored encrypted)" : ""}. Please have DSH check the object's actual state (path/service/version consistency) and report the result to the user.`,
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
        // (2) The confirmation route. This guard exists so that a knowledge record cannot be *silently*
        // rewritten, not so that a wrongly recorded one can never be repaired - and a record can be
        // wrong for a reason that has nothing to do with its author, as happened when a rule for
        // sensitive content matched the ordinary word for a token and encrypted two harmless records.
        // A caller that has asked the user and been told to proceed passes confirm=true with reason,
        // and the change is written with the explanation in the append-only log. Without a reason it is
        // refused, because a confirmation that leaves no trace is indistinguishable from the silent
        // overwrite this guard was built to prevent.
        if (args.confirm === true) {
          if (!args.reason || !String(args.reason).trim()) {
            throw new Error(
              "library_record: confirm=true requires reason (what the user decided, and why) - an unexplained confirmation is not a trace",
            );
          }
          const confirmed = {
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
          const committed = commitRecord(confirmed, disposition, "content changed, confirmed by the user");
          appendLog({
            op: "record-confirm",
            type: args.type,
            name,
            source,
            disposition,
            detail: `user confirmed the change: ${String(args.reason).trim().slice(0, 300)}${mediaNote ? ` (with media evidence)` : ""}`,
          });
          return {
            id: confirmed.id,
            ok: true,
            count: committed.count,
            changed: true,
            disposition,
            sensitive: committed.sensitive,
            message: `"${name}" changed and was recorded with the user's confirmation; the explanation is in the log as record-confirm. Run library_index to let the newest version supersede the one it replaces.`,
          };
        }
        appendLog({ op: "record", type: args.type, name, source, disposition, detail: "content changed, awaiting user confirmation" + (mediaNote ? " (with media evidence)" : "") });
        return {
          id: existing.id,
          ok: false,
          count: index.objects.length,
          changed: true,
          disposition: "confirm",
          message: `"${name}" differs from the last indexed result (immutable-file class). Not auto-overwriting; the user must confirm the change or explain it before it is written/discarded.${mediaNote}Ask the user, then call again with confirm=true and reason="<what they decided>". Report the judgment to the user.`,
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
      const committed = commitRecord(obj, disposition, "first record");
      return { id: obj.id, ok: true, count: committed.count, changed: false, disposition, sensitive: committed.sensitive };
    },
  }));

  // ---- library_index: rebuild the index, or reconcile it with a directory ----

// ---- library_index: the tool itself ----
// ---------- Directory reconciliation: disk reality against the Library ----------
// A library drifts from the disk it describes: things appear that were never recorded, and records
// point at paths that no longer exist (recorded is not the same as addressable). `library_index`
// op=audit reports both directions and writes nothing; op=index registers what is missing, and only
// with an explicit confirmation. An indexer that would happily walk a whole drive is the very scan
// this plugin exists to replace, so a drive root is refused outright.
const AUDIT_SKIP = new Set(["node_modules", ".git", ".svn", ".hg", "$RECYCLE.BIN", "System Volume Information", "__pycache__", ".venv", "venv", ".cache"]);
const INDEXABLE_TOOL = /\.(exe|cmd|bat|ps1|sh|bash|mjs|cjs|js|py|rb|pl|jar|lua|awk|sed)$/i;

function auditKey(p) {
  const abs = path.resolve(String(p));
  // Windows paths are case-insensitive, so two records differing only in case are one location.
  return process.platform === "win32" ? abs.replace(/\\/g, "/").toLowerCase() : abs;
}

// A caller-supplied number, clamped: a tool argument is user input, so it never sets its own bounds.
function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function isDriveRoot(p) {
  const s = String(p == null ? "" : p).trim();
  if (!s) return true;
  try {
    const abs = path.resolve(s);
    return abs === path.parse(abs).root;
  } catch { return true; }
}

// Bounded walk: an explicit depth and an explicit entry ceiling, skipping the directories that are
// never the answer (dependency trees, VCS metadata, caches).
function auditWalk(root, depth, maxFiles) {
  const out = [];
  let truncated = false;
  const walk = (dir, level) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (out.length >= maxFiles) { truncated = true; return; }
      if (AUDIT_SKIP.has(e.name)) continue;
      const full = path.join(dir, e.name);
      out.push({ path: full, name: e.name, kind: e.isDirectory() ? "dir" : "file" });
      if (e.isDirectory() && level < depth) walk(full, level + 1);
    }
  };
  walk(path.resolve(root), 1);
  return { entries: out, truncated };
}

// Both directions at once: on-disk entries with no record, and records under this root whose path is gone.
function auditAgainstLibrary(root, depth, maxFiles) {
  const { entries, truncated } = auditWalk(root, depth, maxFiles);
  const index = loadIndex();
  const recorded = new Map();
  for (const o of index.objects) {
    if (!o.path) continue;
    recorded.set(auditKey(o.path), o);
  }
  const rootKey = auditKey(root);
  const missing = [];
  for (const e of entries) if (!recorded.has(auditKey(e.path))) missing.push(e);
  const dead = [];
  for (const o of index.objects) {
    if (!o.path) continue;
    const key = auditKey(o.path);
    if (key !== rootKey && !key.startsWith(rootKey.endsWith("/") ? rootKey : rootKey + "/")) continue;
    let alive = false;
    try { alive = fs.existsSync(o.path); } catch { alive = false; }
    if (!alive) dead.push({ type: o.type, name: o.name, source: o.source, path: o.path, createdAt: o.createdAt || null });
  }
  return {
    entries,
    truncated,
    scanned: { entries: entries.length, files: entries.filter((e) => e.kind === "file").length, dirs: entries.filter((e) => e.kind === "dir").length },
    missing,
    dead,
  };
}

  ctx.tools.register(defineTool({
    name: "library_index",
    description:
      "Use op=audit before walking a directory by hand to see what is in it, or to check whether the records still match the disk: this is the three-jobs tool on the Library index. op=rebuild (default): dedupe by type+name+source, sort by createdAt, rewrite index.json - when a key holds several versions the newest survives and the dropped ones are reported (and kept in the append-only log), so a rebuild never rolls a record back. op=audit dir=<path>: read-only reconciliation of a directory against the Library, in both directions - entries on disk with no record, and records under that root whose path no longer exists (recorded is not the same as addressable); nothing is written. op=index dir=<path> confirm=true: register the missing entries as records, with a bounded depth, an entry ceiling, an optional type and the sensitive-content rule applied (a sensitive name is skipped, never bulk-encrypted); a drive root is refused, because an indexer that walks a whole disk is the scan this Library exists to replace.",
    parameters: {
      op: { type: "string", description: "rebuild (default) | audit | index" },
      dir: { type: "string", description: "audit/index: absolute directory to reconcile" },
      depth: { type: "number", description: "audit/index: how many levels below dir to walk; default 2, max 6" },
      maxFiles: { type: "number", description: "audit/index: entry ceiling; default 200 (audit) / 50 (index), max 2000 / 500" },
      type: { type: "string", description: "index: force one object type; default: a tool for a script/executable by extension, a file otherwise" },
      includeDirs: { type: "boolean", description: "index: also register directories (as type workspace); default false" },
      confirm: { type: "boolean", description: "index: required - a bulk write is a decision, so it is never implicit" },
      reason: { type: "string", description: "index: what the confirmation was for; recorded in the append-only log" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          ok: { type: "boolean" },
          op: { type: "string" },
          count: { type: "number" },
          store: { type: "string" },
          superseded: { type: "number" },
          conflicts: { type: "array", items: { type: "object", additionalProperties: true } },
          dir: { type: "string" },
          scanned: { type: "object", additionalProperties: true },
          truncated: { type: "boolean" },
          recorded: { type: "number" },
          missing: { type: "number" },
          dead: { type: "number" },
          registered: { type: "number" },
          skippedSensitive: { type: "number" },
          samples: { type: "object", additionalProperties: true },
          note: { type: "string" },
        },
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const op = String((args && args.op) || "rebuild").toLowerCase();
      const dir = args && args.dir ? String(args.dir) : "";

      if (op === "audit" || op === "index") {
        if (!dir) return { ok: false, op, note: `${op} needs dir=<absolute directory>` };
        const abs = path.resolve(dir);
        if (isDriveRoot(abs)) {
          return { ok: false, op, dir: abs, note: "refused: a drive root is not an index scope - point this at a workspace, a downloads directory or a toolchain root (an indexer that walks a whole disk is the scan this Library replaces)" };
        }
        let isDir = false;
        try { isDir = fs.statSync(abs).isDirectory(); } catch { isDir = false; }
        if (!isDir) return { ok: false, op, dir: abs, note: `not a directory: ${abs}` };
        const depth = clampInt(args.depth, 2, 1, 6);
        const ceiling = op === "audit" ? clampInt(args.maxFiles, 200, 1, 2000) : clampInt(args.maxFiles, 50, 1, 500);
        const report = auditAgainstLibrary(abs, depth, ceiling);
        const samples = {
          missing: report.missing.slice(0, 20).map((e) => ({ kind: e.kind, path: e.path })),
          dead: report.dead.slice(0, 20),
        };
        if (op === "audit") {
          appendLog({ op: "audit", type: null, name: abs, source: abs, disposition: null, detail: `${report.missing.length} unrecorded, ${report.dead.length} dead path(s), ${report.scanned.entries} entr(ies) scanned` });
          return {
            ok: true, op, dir: abs, scanned: report.scanned, truncated: report.truncated,
            recorded: report.scanned.entries - report.missing.length, missing: report.missing.length, dead: report.dead.length,
            samples,
            note: `${report.missing.length} of ${report.scanned.entries} entr(ies) under this root are not recorded; ${report.dead.length} record(s) under it point at a path that no longer exists. Nothing was written - run op=index with confirm:true to register the missing ones.`,
          };
        }
        // op=index: a bulk registration is a decision, so it takes an explicit confirmation, and the
        // sensitive-content rule still decides what may be stored in the clear.
        if (args.confirm !== true) {
          return {
            ok: false, op, dir: abs, scanned: report.scanned, truncated: report.truncated,
            missing: report.missing.length, dead: report.dead.length, samples,
            note: "refused: op=index needs confirm:true (and a reason) - this would write records; run op=audit first to see what it would register",
          };
        }
        const forcedType = args.type ? String(args.type) : "";
        if (forcedType && !OBJ_TYPES.has(forcedType)) return { ok: false, op, dir: abs, note: `invalid type "${forcedType}", allowed: ${[...OBJ_TYPES].join(", ")}` };
        const includeDirs = args.includeDirs === true;
        const wanted = report.missing.filter((e) => e.kind === "file" || includeDirs);
        const stamped = new Date().toISOString();
        let skippedSensitive = 0;
        const toAdd = [];
        for (const e of wanted) {
          const name = e.kind === "file" ? e.name.replace(/\.[^.]+$/, "") || e.name : e.name;
          const type = forcedType || (e.kind === "dir" ? "workspace" : INDEXABLE_TOOL.test(e.name) ? "tool" : "file");
          const obj = {
            id: makeId(type, abs, name), type, name, source: abs, path: e.path,
            description: `${e.kind === "dir" ? "directory" : "file"} indexed under ${abs}`,
            tags: ["indexed", "audit", e.kind === "dir" ? "dir" : "file"], summary: "", createdAt: stamped,
          };
          if (isSensitive(obj)) { skippedSensitive++; continue; }
          toAdd.push(obj);
        }
        const registered = updateIndex((index) => {
          let n = 0;
          for (const obj of toAdd) {
            const dup = index.objects.find((o) => o.type === obj.type && o.name === obj.name && o.source === obj.source);
            if (dup) continue;
            index.objects.push(obj);
            n++;
          }
          return n;
        });
        appendLog({ op: "index-audit", type: null, name: abs, source: abs, disposition: "confirm", detail: `registered ${registered} of ${report.missing.length} unrecorded entr(ies)${skippedSensitive ? `, skipped ${skippedSensitive} sensitive name(s)` : ""}${args.reason ? ` - reason: ${String(args.reason).slice(0, 200)}` : ""}` });
        return {
          ok: true, op, dir: abs, scanned: report.scanned, truncated: report.truncated,
          missing: report.missing.length, dead: report.dead.length, registered, skippedSensitive,
          samples: { missing: samples.missing, dead: samples.dead },
          note: `registered ${registered} new record(s) from ${report.missing.length} unrecorded entr(ies)${skippedSensitive ? `; ${skippedSensitive} name(s) matched the sensitive rule and were left out` : ""}${report.dead.length ? `; ${report.dead.length} recorded path(s) under this root are dead and were left as they are - record a new version with library_record if the object moved` : ""}`,
        };
      }

      const seen = new Map();
      const conflicts = [];
      const superseded = [];
      // The whole read-modify-write runs under the lock: a rebuild must not overwrite a record
      // that another process wrote while this one was deduping.
      const count = updateIndex((index) => {
        // Guard against old objects with missing fields polluting the dedupe key or losing objects.
        // Same key can hold several versions (the verify route appends a new one), so the NEWEST
        // version survives - keeping the oldest would silently roll a record back.
        for (const o of index.objects) {
          const key = [o.type, o.name, o.source].map((v) => String(v ?? "")).join("::");
          const prev = seen.get(key);
          if (!prev) {
            seen.set(key, o);
            continue;
          }
          const prevAt = String(prev.createdAt ?? "");
          const curAt = String(o.createdAt ?? "");
          const newer = curAt > prevAt;
          const keep = newer ? o : prev;
          const drop = newer ? prev : o;
          if (fingerprint(keep) !== fingerprint(drop)) {
            conflicts.push({ key, kept: keep.id, dropped: drop.id });
          }
          superseded.push({ key, kept: keep.id, dropped: drop.id, droppedAt: drop.createdAt ?? null });
          seen.set(key, keep);
        }
        const dedup = [...seen.values()].sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
        index.objects = dedup;
        return dedup.length;
      });
      appendLog({ op: "index", type: null, name: null, source: null, disposition: null, detail: `rebuilt index, ${count} objects, ${conflicts.length} conflicts` });
      // A superseded version leaves the index here, so keep its identity in the append-only log:
      // that is what makes a change traceable afterwards.
      for (const s of superseded.slice(0, 200)) {
        appendLog({ op: "index-supersede", type: null, name: s.key, source: null, disposition: null, detail: `kept ${s.kept}, dropped ${s.dropped} (createdAt ${s.droppedAt})` });
      }
      return { ok: true, op: "rebuild", count, store: indexFile(), conflicts, superseded: superseded.length };
    },
  }));

  // ---- library_query: search the Library (index/use/research/learn) ----
  ctx.tools.register(defineTool({
    name: "library_query",
    description:
      "Ask the Library before researching anything again: what was recorded about a tool, a file, a service, a workspace, an environment fact or an earlier decision, across this machine's workspaces. Reach for this first whenever a task mentions something that may already exist - a path, a port, an endpoint, a toolchain, work from a previous session - instead of walking the filesystem or the other workspaces to find it. Searches name/description/summary/source by keyword, with type and tag filters and cursor pagination.",
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
      // A multi-word query means "find these things", not "find this exact phrase".
      //
      // This used to test `haystack.includes(q)` against the whole query string, so one word worked and
      // several words could never match anything. It failed *silently*: `count: 0` reads as "nothing is
      // recorded", which is indistinguishable from the truth. Measured on this machine - a topic
      // recorded minutes earlier returned 0 through a five-word query and 7 through one of its words.
      //
      // So terms are matched individually and results are ranked by how many terms they cover. A
      // one-term query is byte-for-byte the old behaviour. Splitting is Unicode-aware: a CJK query has
      // no spaces, so an ASCII-only splitter would shred it into empty pieces.
      const terms = q.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
      const haystack = (o) =>
        [o.name, o.description, o.summary, o.source, o.path, (o.tags || []).join(" ")]
          .join(" ")
          .toLowerCase();
      let relevance = null;
      if (terms.length <= 1) {
        results = results.filter((o) => haystack(o).includes(q));
      } else {
        const ranked = [];
        for (const o of results) {
          const h = haystack(o);
          let covered = 0;
          for (const t of terms) if (h.includes(t)) covered += 1;
          if (covered > 0) ranked.push({ o, covered });
        }
        // Ties keep their Library order, which is stable across calls.
        ranked.sort((a, b) => b.covered - a.covered);
        results = ranked.map((x) => x.o);
        relevance = new Map(results.map((o, i) => [o.id, i]));
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
        .sort((a, b) => {
          // When the query ranked by term coverage, that order wins: a ranking the next line reverses
          // is not a ranking. Otherwise the historical newest-first order is unchanged.
          if (relevance) {
            const ra = relevance.get(a.id);
            const rb = relevance.get(b.id);
            if (ra !== rb) return (ra || 0) - (rb || 0);
          }
          return String(b.createdAt).localeCompare(String(a.createdAt));
        });
      // Pagination cursor: stable-sorted safeAll, offset anchored by "items already fetched".
      // "" - never null - on the last page: the declared output schema types this field as a
      // string, and the harness refuses the entire call when a declared string arrives as null,
      // which made every single-page (i.e. narrow) query fail. "" stays falsy for callers.
      const pageSize = Math.min(Math.max(args.pageSize || limit, 1), 100);
      const offset = args.cursor ? parseInt(args.cursor, 10) || 0 : 0;
      const page = safeAll.slice(offset, offset + pageSize);
      const nextCursor = offset + pageSize < safeAll.length ? String(offset + pageSize) : "";
      return { count: safeAll.length, nextCursor, results: page };
    },
  }));

  // ---- (3) library_detect: scan known tools/environments/toolchains and register them ----
  // Registers only existing candidates; installing missing ones requires an instruction
  // plus a per-item report (this tool only registers by default).
  ctx.tools.register(defineTool({
    name: "library_detect",
    description:
      "Before looking for a tool, SDK, runtime, service or toolchain on this machine, come here: this answers with what is already known, each entry carrying its path and the product/version the file itself declares. That is the difference between one call and a filesystem- or registry-wide search. Registers the ones that exist into the Library (bootstraps the index on install/init; never installs anything). Scans the built-in list plus this machine's local candidate pack, so a private toolchain or service recorded once is recognised on every later scan. Locations are written in their owner's own words - a bare command name found on PATH, or a folder variable the OS or the toolchain declares (%ProgramFiles%, %GOROOT%, %ANDROID_HOME%, ~/${HOME} ...) - so nothing here assumes one machine's layout; the newest installed build is derived from disk where a location rotates with its version. Each existing result also carries `declared`: what the file itself states about itself (product/version/vendor, read from its own version resource, statically - the tool is never executed). op=list shows both lists; op=add/remove manage the local pack (built-ins always win, collisions are refused unless confirm:true); op=propose dir=<directory> only *proposes* executables found there for you to decide about. Proposing records nothing and no candidate is ever executed - a path is only recorded and checked for existence.",
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
        const entry = {
          type, name, path: p,
          alts: (Array.isArray(args.alts) ? args.alts : []).map(String),
          desc: String(args.desc || "").slice(0, 300),
          createdAt: new Date().toISOString(),
        };
        const total = updateLocalCandidates((fresh) => {
          const n = normalizeCandidatePack(fresh);
          n.candidates = n.candidates.filter((c) => !(c.type === type && c.name.toLowerCase() === name.toLowerCase()));
          n.candidates.push(entry);
          return { pack: n, result: n.candidates.length };
        });
        appendLog({ op: "candidate-add", type, name, source: "local", disposition: null, detail: `local candidate recorded (exists now: ${fs.existsSync(p)})` });
        return {
          ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: total, conflicts,
          note: `recorded ${type} ${name}${fs.existsSync(p) ? "" : " (path does not exist yet - scans will skip it until it does)"}`,
        };
      }

      if (op === "remove") {
        const name = String(args.name || "").trim().toLowerCase();
        if (!name) return { ok: false, op, file, note: "remove needs name" };
        const out = updateLocalCandidates((fresh) => {
          const n = normalizeCandidatePack(fresh);
          const before = n.candidates.length;
          n.candidates = n.candidates.filter((c) => c.name.toLowerCase() !== name);
          return { pack: n, result: { local: n.candidates.length, removed: before - n.candidates.length } };
        });
        return { ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: out.local, removed: out.removed, note: `removed ${out.removed} local candidate(s)` };
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

      const force = !!args.force;
      const results = [];
      const conflicts = [];
      const resolvable = [];
      for (const c of allCandidates()) {
        if (c.shadowed) {
          conflicts.push(`${c.type} ${c.name} (local entry shadowed by the built-in of the same name)`);
          continue;
        }
        const resolved = resolveCandidatePath(c);
        const exists = !!resolved;
        // What the file says about itself (static read; the tool is never executed). A directory or a
        // service URL simply has nothing to declare.
        let declared = null;
        if (resolved) {
          try {
            if (fs.statSync(resolved).isFile()) declared = declaredIdentity(resolved);
          } catch { declared = null; }
        }
        // A miss reports the path that was actually looked for (the declared value expanded), so the
        // entry reads as a real location on this machine rather than as a variable name.
        results.push({ type: c.type, name: c.name, desc: c.desc, origin: c.origin, path: resolved || expandDeclared(c.path) || c.path, exists, declared });
        if (exists) resolvable.push({ candidate: c, resolved, declared });
      }
      // Register under the write lock, re-reading the index so a concurrent record is not lost.
      const registered = updateIndex((index) => {
        let n = 0;
        for (const { candidate: c, resolved, declared } of resolvable) {
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
            // The tool's own words when the image carries them, so a later query can tell versions apart
            // without anyone re-typing them (and a mismatch against the recorded version stands out).
            summary: declared ? [declared.product, declared.version, declared.vendor].filter(Boolean).join(" ") : "",
            createdAt: new Date().toISOString(),
          };
          if (dup) index.objects[index.objects.indexOf(dup)] = obj;
          else index.objects.push(obj);
          n++;
        }
        return n;
      });
      appendLog({ op: "detect", type: null, name: null, source: "detect", disposition: null, detail: `scan complete, ${registered} existing items to register` });
      // Cross-check against known objects: scanned but not-yet-registered items, to remind the static map.
      const cross = [];
      if (args.cross) {
        const knownObjects = loadIndex().objects; // read-only view after the locked write
        const knownKeys = new Set(knownObjects.filter((o) => o.source === "detect").map((o) => `${o.type}::${o.name}`));
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
      "Before opening, parsing or guessing about a file, ask this: the header bytes decide the true type, independent of a spoofable extension, and name/content contradictions are flagged (a file claiming to be JSON/YAML/an image or a DSH artifact whose bytes say otherwise). Cheaper and more honest than trying to read a file whose format you are not sure of. Pass `path` for one file, or `dir` to sweep a directory (temp/session/storage) for mismatches. For one file it returns {type, format, note, declared, artifact, kind, spoofed, flags}; for a directory it returns {scanned, mismatches, spoofed}. A missing path, a directory passed as `path` and a zero-byte file get distinct `kind` values instead of all reading as empty.",
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
          path: { type: "string" }, kind: { type: "string" },
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
      if (!dir) return { ok: false, detected: false, type: "", format: "", note: "missing path or dir", spoofed: false, flags: [], scanned: 0, mismatches: [] };
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
        ok: true, detected: true, type: "", format: "", spoofed: mismatches.length > 0, flags: [],
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
      "Inspect and extend this installation's format library. op=list shows the local pack and the last report date; op=scan proposes file types the library cannot identify in a directory; op=learn registers a magic signature intersected from explicit sample files; op=add registers a signature, a plain-text extension, or a name rule by hand; op=remove drops a local entry; op=deps reports which formats reference which other formats (extensions only; DLL names opt-in); op=draft writes a reviewable checklist of candidates (optionally keeping the raw context locally, encrypted); op=report builds a small contribution archive from a directory or from selected draft items, and op=deliver shows such an archive in the platform's own window (a native dialog with a preview and Send by e-mail / Save a copy / Open folder / Delete buttons) so the USER decides whether it ever leaves the machine - pass headless:true on hosts without a desktop to get manual instructions instead. Paths are omitted by default, sanitised when requested, or sealed under a passphrase you hold (op=unseal reopens it). Built-ins are always matched first and conflicts are refused unless confirm:true. Scanning alone never learns anything and this tool performs no network I/O.",
    parameters: {
      op: { type: "string", required: true, description: "list | scan | learn | add | remove | draft | deps | report | deliver | unseal" },
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
      file: { type: "string", description: "deliver: the report archive to show (defaults to the newest one); unseal: the archive containing a sealed layer" },
      ui: { type: "boolean", description: "report: after writing the archive, show it in the platform's own dialog so the user decides (mail / save / open / delete); never an automatic send" },
      headless: { type: "boolean", description: "report/deliver: skip the dialog and return manual delivery instructions instead (servers, SSH, no GUI)" },
      autoCloseMs: { type: "number", description: "report/deliver: close the dialog automatically after N ms (0 = wait for the user)" },
      selfTest: { type: "boolean", description: "deliver: open the dialog and close it after ~1.5 s to verify that the window works on this host" },
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
          keptLocalId: { type: "string" },
          pathDetail: { type: "string" },
          deps: { type: "array", items: { type: "object", additionalProperties: true } },
          dllNames: { type: "array", items: { type: "string" } },
          sealed: { type: "object", additionalProperties: true },
          delivery: { type: "object", additionalProperties: true },
          action: { type: "string" },
          savedTo: { type: "string" },
          shell: { type: "string" },
          gui: { type: "boolean" },
          headless: { type: "boolean" },
          steps: { type: "array", items: { type: "string" } },
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
        // lastReport is omitted, not nulled, when this install has never built a report: the
        // declared output schema types it as an object, and the harness refuses the entire call
        // when a declared type arrives as null. Omitting keeps it falsy for callers.
        return {
          ok: true, op, file: packFile, builtin, local: summary(pack),
          ...(lastReport ? { lastReport } : {}),
          note: (fs.existsSync(packFile) ? "local pack loaded" : "no local pack yet (add/learn creates it)") + hint,
        };
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
        if (args.out && fs.existsSync(args.out) && fs.statSync(args.out).isDirectory()) return { ok: false, op, note: "out is an existing directory: give the file to write (e.g. out=<dir>/draft.json)" };
        fs.mkdirSync(path.dirname(draftFile), { recursive: true });
        fs.writeFileSync(draftFile, JSON.stringify(draft, null, 2), "utf8");
        let keptLocalId = null;
        if (args.keepLocal) {
          // Preserve the RAW (unredacted) context locally, encrypted with this install's
          // library key: nothing is lost, and only this machine can open it.
          const raw = { draft, rawSamples: [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 200).map((g, i) => ({ id: `f${i + 1}`, ext: g.ext, count: g.count, samples: g.samples })) };
          const id = makeId("knowledge", "local", `format-draft-${stamp}`);
          updateIndex((index) => {
            index.objects.push({
              id, type: "knowledge", name: `format draft (raw, encrypted) ${stamp}`, source: "local",
              description: `Unredacted format-draft context: ${items.length} unidentified type(s) with raw sample paths; encrypted with this install's library key - open with library_decrypt`,
              tags: ["format-draft", "local", "format"], summary: `mega-index-map ${PLUGIN_VERSION}`, sensitive: true,
              createdAt: new Date().toISOString(), __content: encryptSensitive(raw),
            });
          });
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
          ok: true, op, scanned: r.scanned,
          deps: r.edges, dllNames: args.names ? r.dllNames : [],
          preview: r.edges.slice(0, 40).map((e) => `${e.from} -> ${e.to}  x${e.count}`).join("\n"),
          note: `${r.edges.length} format relationship(s) from ${r.inspected} inspected file(s): extensions only${args.names ? ", plus DLL names (treat as user-level)" : ""}`,
        };
      }

      // ---- unseal: reopen a sealed layer locally with the user's own passphrase ----
      if (op === "unseal") {
        const file = args.file || args.path;
        if (!file) return { ok: false, op, note: "unseal needs file=<sealed archive>" };
        if (!fs.existsSync(file)) return { ok: false, op, note: `unseal: file not found: ${file}` };
        if (!fs.statSync(file).isFile()) return { ok: false, op, note: "unseal: that path is a directory, not an archive" };
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
          report.sealed ? "Your passphrase protects the user-level layer, so you can share the archive without sharing paths." : "NOT included, by design: file names, file contents, user name, host name, credentials.",
          pathMode === "none" ? "You chose paths=none, so no directory information is present at all." : "Directory information present is sanitised, but please read it before sending.",
          "",
          "How to send it (manual - your decision, after reading this):",
          `  to     : ${REPORT_MAIL_TO}`,
          `  subject: [format report] mega-index-map ${report.pluginVersion}`,
          "  attach : this .zip",
          "  (or upload it yourself to a file host of your choice and send the link)",
          "",
          "This plugin performs no network I/O for reports: nothing was uploaded or e-mailed for you.",
          "",
          "Top unidentified types:",
          ...unidentified.slice(0, 40).map((u) => `  .${u.ext}  x${String(u.count).padEnd(6)} samples=${u.sampleCount}  prefix=${u.commonPrefix ?? "(none)"}`),
          ...(depsData && depsData.edges.length ? ["", "Format relationships (top 20):", ...depsData.edges.slice(0, 20).map((e) => `  ${e.from} -> ${e.to}  x${e.count}`)] : []),
        ].filter((l) => l !== null).join("\n");
        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
        const outFile = args.out || path.join(reportsDir(), `format-report-${stamp}.zip`);
        if (args.out && fs.existsSync(args.out) && fs.statSync(args.out).isDirectory()) return { ok: false, op, note: "out is an existing directory: give the file to write (e.g. out=<dir>/report.zip)" };
        fs.mkdirSync(path.dirname(outFile), { recursive: true });
        const reportJson = JSON.stringify(report, null, 2);
        // manifest gets a UTF-8 BOM so plain Windows tools (Notepad, mail preview) show it correctly.
        const buf = zipBuffer([{ name: "report.json", data: reportJson }, { name: "manifest.txt", data: "\uFEFF" + manifest }, ...extraFiles]);
        fs.writeFileSync(outFile, buf);
        // Record the produced archive in the Library (so library_query and the cadence
        // reminder can find it no matter where it was written).
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
        updateIndex((index) => {
          index.objects.push(obj);
        });
        appendLog({ op: "format-report", type: "format", name: null, source: "local", disposition: null, detail: `report written locally: ${unidentified.length} unidentified type(s), paths=${pathMode}${report.sealed ? ", sealed" : ""}, ${buf.length} bytes (not sent)` });
        // Optional: hand the archive to the user in a native window right away (their choice,
        // never an automatic send).
        let delivery = null;
        if (args.ui && args.headless !== true) {
          const d = await runReportDialog(outFile, { autoCloseMs: parseInt(args.autoCloseMs, 10) || 0, selfTest: !!args.selfTest });
          delivery = { action: d.action, savedTo: d.savedTo, gui: d.gui, note: d.note || "the user chose what to do with the archive" };
          appendLog({ op: "format-deliver", type: "format", name: null, source: "local", disposition: null, detail: `delivery dialog: action=${d.action}` });
        }
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
          mail: { to: REPORT_MAIL_TO, subject: `[format report] mega-index-map ${PLUGIN_VERSION}`, attachment: outFile },
          delivery,
          preview: manifest.split("\n").slice(0, 28).join("\n"),
          note: `report written locally (${buf.length} bytes, ${unidentified.length} unidentified type(s), paths=${pathMode}${report.sealed ? `, ${report.sealed.fields} field(s) sealed with your passphrase` : ""}) - nothing was uploaded; ${delivery ? `the delivery dialog returned action=${delivery.action}` : "review manifest.txt, then send it yourself if you choose to"}`,
        };
      }

      // ---- deliver: show the report in a native window so the user decides what happens ----
      if (op === "deliver") {
        const file = args.file ? String(args.file) : latestReportFile();
        if (!file) return { ok: false, op, note: "no report archive found; run op=report first", steps: [] };
        if (!fs.existsSync(file)) return { ok: false, op, note: `report not found: ${file}`, steps: [] };
        if (!fs.statSync(file).isFile()) return { ok: false, op, note: `deliver: that path is a directory, not an archive: ${file}`, steps: [] };
        const instructions = reportDeliveryInstructions(file);
        if (args.headless) {
          return { ok: true, op, file, headless: true, gui: false, action: "instructions", ...instructions };
        }
        const d = await runReportDialog(file, { autoCloseMs: parseInt(args.autoCloseMs, 10) || 0, selfTest: !!args.selfTest });
        appendLog({ op: "format-deliver", type: "format", name: null, source: "local", disposition: null, detail: `delivery dialog: action=${d.action}${d.gui ? "" : " (no GUI available)"}` });
        const done = ["email", "save", "delete", "close", "folder", "selftest"].includes(d.action);
        return {
          ok: done || d.action === "timeout" || d.action === "pending",
          op, file, action: d.action, savedTo: d.savedTo, gui: d.gui, shell: d.shell || null,
          mail: instructions.mail,
          steps: d.gui ? [] : instructions.steps,
          preview: instructions.steps.slice(0, 1).join("\n"),
          note: d.gui
            ? `the user was asked in a native window and chose: ${d.action}${d.savedTo ? ` (saved to ${d.savedTo})` : ""} - the plugin transmitted nothing`
            : `no GUI was available (${d.action}); deliver it manually: ${instructions.mail.to}`,
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
        updateLocalFormats((fresh) => ({
          pack: normalizeLocalPack({ ...fresh, formats: [...fresh.formats.filter((f) => f.format !== format && !f.ext.includes(ext)), entry] }),
        }));
        const verified = paths.filter((p) => fs.existsSync(p)).map((p) => {
          const r = sniffFileType(p);
          return { path: p, format: r ? r.format : null, ok: !!(r && r.format === format) };
        });
        appendLog({ op: "format-learn", type: "format", name: format, source: "local", disposition: null, detail: `learned ${hexSig(sig)} for .${ext} from ${heads.length} sample(s)` });
        return { ok: true, op, file: packFile, builtin, local: summary(loadLocalFormats()), conflicts, verified, learned: { samplePrefix: hexSig(prefix), bytes: prefix.length, stored: hexSig(sig), storedBytes: sig.length, truncated }, note: `learned ${format} = ${hexSig(sig)} (.${ext})${truncated ? ` - intersected prefix was ${prefix.length} bytes, stored first ${sig.length} for version tolerance` : ""}; verified on ${verified.filter((v) => v.ok).length}/${verified.length} sample(s)` };
      }

      if (op === "add") {
        const conflicts = [];
        let what = "";
        // Build the change as an intent instead of mutating the copy read before the lock: the intent
        // is re-applied to the freshest pack inside the lock, so a concurrent add cannot be lost.
        let mutate = null;
        if (args.textExtension) {
          const e = String(args.textExtension).replace(/^\./, "").toLowerCase();
          if (!e) return { ok: false, op, note: "empty textExtension" };
          if (TEXT_EXTENSIONS.includes(e)) conflicts.push(`.${e} is already a built-in text extension`);
          if (conflicts.length && !args.confirm) return { ok: false, op, conflicts, note: "redundant with a built-in (pass confirm:true to keep it anyway)" };
          mutate = (fresh) => {
            const n = normalizeLocalPack(fresh);
            if (!n.textExtensions.includes(e)) n.textExtensions.push(e);
            return n;
          };
          what = `text extension .${e}`;
        } else if (args.nameRule) {
          let re;
          try { re = new RegExp(String(args.nameRule), "i"); } catch (err) { return { ok: false, op, note: `invalid nameRule regex: ${err.message}` }; }
          const rule = { re, source: String(args.nameRule), role: String(args.role || "local"), expect: args.expect || null, note: String(args.note || "").slice(0, 200) };
          mutate = (fresh) => {
            const n = normalizeLocalPack(fresh);
            n.nameRules.push(rule);
            return n;
          };
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
          const entry = { format, type: String(args.type || "document"), sig, ext: ext ? [ext] : [], note: String(args.note || "").slice(0, 200), createdAt: new Date().toISOString() };
          mutate = (fresh) => {
            const n = normalizeLocalPack(fresh);
            n.formats = n.formats.filter((f) => f.format !== format);
            n.formats.push(entry);
            return n;
          };
          what = `signature ${format} = ${hexSig(sig)}`;
        }
        updateLocalFormats((fresh) => ({ pack: mutate(fresh) }));
        appendLog({ op: "format-add", type: "format", name: args.format || args.textExtension || args.role || null, source: "local", disposition: null, detail: what });
        return { ok: true, op, file: packFile, local: summary(loadLocalFormats()), conflicts, note: `added ${what}` };
      }

      if (op === "remove") {
        const ext = String(args.ext || "").replace(/^\./, "").toLowerCase();
        const format = String(args.format || "");
        if (!ext && !format) return { ok: false, op, note: "remove needs ext or format" };
        const gone = updateLocalFormats((fresh) => {
          const n = normalizeLocalPack(fresh);
          const before = n.formats.length + n.textExtensions.length + n.nameRules.length;
          n.formats = n.formats.filter((f) => f.format !== format && !(ext && f.ext.includes(ext)));
          n.textExtensions = n.textExtensions.filter((e) => e !== ext);
          n.nameRules = n.nameRules.filter((r) => r.role !== format);
          const after = n.formats.length + n.textExtensions.length + n.nameRules.length;
          return { pack: n, result: { removed: before - after } };
        });
        return { ok: true, op, file: packFile, removed: gone.removed, local: summary(loadLocalFormats()), note: `removed ${gone.removed} local entr(ies)` };
      }

      return { ok: false, op, note: `unknown op "${args.op}", allowed: list, scan, learn, add, remove, draft, deps, report, deliver, unseal` };
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
      schema: { type: "object", additionalProperties: false, properties: { ok: { type: "boolean" }, file: { type: "string" }, count: { type: "number" }, message: { type: "string" } } },
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
      if (args.path && fs.existsSync(args.path) && fs.statSync(args.path).isDirectory()) {
        return { ok: false, file: args.path, count: 0, message: "path is a directory: give the file to write (e.g. path=<dir>/library-export.json)" };
      }
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
        commitRecord(obj, "confirm", "adb operation record");
        recorded = true;
      }
      appendLog({ op: "adb", type: null, name: null, source: "adb", disposition: null, detail: `action=${action} device=${device || "(auto)"} ok=${result.ok}` });
      return { ok: result.ok, action, code: result.code, out: result.out, err: result.err, ...(result.local ? { local: result.local } : {}), recorded };
    },
  }));

  // ---- library_sessions: read DSH's own conversation store, locally ----
  // The host writes every session to $DSH_HOME/sessions as one zstd frame per record; this decodes that
  // (and exported ZIP archives) so past conversations can be listed, read, tailed, searched and recorded.
  // Transcript text is only returned when a caller asks for it, and every op is bounded by default.
  ctx.tools.register(defineTool({
    name: "library_sessions",
    description:
      "Read this machine's own DSH sessions - the conversation store under $DSH_HOME/sessions, plus any exported session-log ZIP archives found there (DSH's own archive format: session*.jsonl at the root, subagents/<id>/..., attachments under media/ and files/). Use it to find what a past session decided, to resume where one left off, or to record a session into the Library. op=list enumerates sessions and archive members without reading transcripts (header and title only); op=read returns a structural summary unless content:true asks for the text (bounded); op=tail decodes only the last frames; op=search scans frames for a phrase and returns snippets; op=record writes a session into the Library as a log object (the sensitive-content rule still applies). Sessions are stored as one zstd frame per record, so frames are located by the zstd magic and decoded one at a time - a torn tail is counted, never guessed. Timestamps are UTC ISO-8601 and every response carries `timezone` (the host's UTC offset, its zone name and the current local time), so a local clock can be read straight off a report. op=bootstrap runs (or resumes) the first-run pass over the whole history, which mines what a Library actually indexes - tools that resolve on this machine, paths that exist, local endpoints, environment variables that are set, file formats this library does not know yet - replacing its own earlier rows rather than piling up; op=status reports that pass, step by step. Everything is a local read: nothing is uploaded, and no file is modified.",
    parameters: {
      op: { type: "string", description: "list (default) | read | tail | search | record | bootstrap | status" },
      target: { type: "string", description: "read/tail/record: a session file or directory, a ZIP archive, \"<zip>#<member>\", or a fragment of a session id" },
      dir: { type: "string", description: "list/search: directory to walk; default $DSH_HOME/sessions" },
      query: { type: "string", description: "search: the phrase to look for (case-insensitive)" },
      content: { type: "boolean", description: "read/record: include the actual message text, not only the structure; default false" },
      maxFiles: { type: "number", description: "list/search: how many sessions to look at; default 200 (list) / 40 (search), max 4000" },
      maxRecords: { type: "number", description: "read/tail: record ceiling; default 2000 (read) / 200 (tail), max 200000" },
      maxChars: { type: "number", description: "read/record: character ceiling for returned or recorded text; default 20000 (read) / 4000 (record), max 400000" },
      maxHits: { type: "number", description: "search: how many matches to return; default 40, max 500" },
      frames: { type: "number", description: "tail: how many trailing frames to decode; default 40, max 2000" },
      titles: { type: "boolean", description: "list: also read each session's title from its first frames; default true" },
      type: { type: "string", description: "record: object type for the recorded session; default log" },
      budgetMs: { type: "number", description: "bootstrap: time budget for the pass; default 300000, max 3600000" },
      maxSessions: { type: "number", description: "bootstrap: read at most this many sessions this run; default 0 (all pending)" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          ok: { type: "boolean" },
          op: { type: "string" },
          dir: { type: "string" },
          store: { type: "string" },
          sessions: { type: "number" },
          archives: { type: "number" },
          entries: { type: "array", items: { type: "object", additionalProperties: true } },
          target: { type: "string" },
          frames: { type: "number" },
          failed: { type: "number" },
          records: { type: "number" },
          truncated: { type: "boolean" },
          header: { type: "object", additionalProperties: true },
          title: { type: "string" },
          types: { type: "array", items: { type: "object", additionalProperties: true } },
          timeRange: { type: "object", additionalProperties: true },
          messages: { type: "array", items: { type: "object", additionalProperties: true } },
          hits: { type: "array", items: { type: "object", additionalProperties: true } },
          scanned: { type: "object", additionalProperties: true },
          recorded: { type: "object", additionalProperties: true },
          note: { type: "string" },
          phase: { type: "string" },
          timezone: { type: "object", additionalProperties: true },
          state: { type: "object", additionalProperties: true },
          marker: { type: "object", additionalProperties: true },
          progress: { type: "string" },
          sessionsTotal: { type: "number" },
          sessionsDone: { type: "number" },
          searched: { type: "number" },
          found: { type: "number" },
          added: { type: "number" },
          updated: { type: "number" },
          tookMs: { type: "number" },
          done: { type: "boolean" },
        },
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      const op = String((args && args.op) || "list").toLowerCase();
      const store = dshSessionsDir();
      // A runtime fact, stated up front: without a zstd decoder every frame would look unreadable, and a
      // silent zero would read as "no such session" rather than "this runtime cannot decode it".
      if (!ZSTD_AVAILABLE) {
        return { ok: false, op, store, note: "this runtime has no zstd decoder (node:zlib.zstdDecompressSync needs Node v23.8+, or v22.15+), and DSH writes its sessions compressed - the session store cannot be read here" };
      }

      // status: what the first-run pass has done so far, straight from its own state file.
      if (op === "status") {
        const state = readMiningState();
        const last = state && state.last ? state.last : state;
        return {
          ok: true, op, store,
          timezone: timezoneInfo(),
          state: last || { phase: "never-run" },
          marker: state ? { sessionsRemembered: Object.keys(state.seen || {}).length, sessionsMinedInTotal: state.done || 0 } : null,
          progress: miningProgressFile(),
          note: last
            ? `bootstrap phase "${last.phase}"${last.sessionsDone !== undefined ? `, ${last.sessionsDone}/${last.sessionsTotal} session(s)` : ""}${last.note ? ` - ${last.note}` : ""}; step-by-step lines are in ${miningProgressFile()}`
            : "the first-run pass has never run here",
        };
      }

      // bootstrap: run (or resume) the pass now. Blocking for this call, and safe to call again.
      if (op === "bootstrap") {
        const report = await runSessionMining({
          budgetMs: clampInt(args.budgetMs, 300000, 1000, 3600000),
          maxSessions: clampInt(args.maxSessions, 0, 0, 100000),
          dir: args.dir ? path.resolve(String(args.dir)) : store,
          log: ctx.logger,
        });
        return { ok: report.phase !== "failed", op, store, timezone: timezoneInfo(), ...report };
      }
      if (op !== "read" && op !== "tail" && op !== "record" && !fs.existsSync(store) && !args.dir) {
        return { ok: false, op, store, note: `no session store at ${store} - this host has no sessions directory, or DSH_HOME points elsewhere` };
      }

      if (op === "list") {
        const dir = path.resolve(args.dir ? String(args.dir) : store);
        if (!fs.existsSync(dir)) return { ok: false, op, dir, note: `not a directory: ${dir}` };
        const maxFiles = clampInt(args.maxFiles, 200, 1, 4000);
        const wantTitles = args.titles !== false;
        const { live, archives } = listSessionSources(dir, maxFiles);
        const entries = [];
        for (const file of live.slice(0, maxFiles)) {
          let st = null;
          try { st = fs.statSync(file); } catch { continue; }
          const head = fs.openSync(file, "r");
          let buf = null;
          try {
            const want = Math.min(st.size, 262144);
            buf = Buffer.alloc(want);
            const got = fs.readSync(head, buf, 0, want, 0);
            buf = buf.subarray(0, got);
          } catch { buf = null; } finally { fs.closeSync(head); }
          let header = {};
          let title = "";
          let frames = 0;
          let failed = 0;
          if (buf) {
            const decoded = decodeSessionBuffer(buf, { maxRecords: wantTitles ? 4000 : 1, maxChars: 4 * 1024 * 1024, tolerateCutTail: st.size > buf.length });
            frames = decoded.frames;
            failed = decoded.failed;
            const first = decoded.records.find((r) => r && r.type === "session");
            if (first) header = sessionHeader(first);
            if (wantTitles) title = sessionTitle(decoded.records);
          }
          entries.push({
            kind: "session",
            id: header.id || path.basename(path.dirname(file)),
            workspace: path.basename(path.dirname(path.dirname(file))),
            path: file,
            bytes: st.size,
            modifiedAt: new Date(st.mtimeMs).toISOString(),
            createdAt: header.createdAt || null,
            cwd: header.cwd || null,
            formatVersion: header.version === undefined ? null : header.version,
            agentPreset: header.agentPreset || null,
            frames,
            framesUnreadable: failed,
            title: title || null,
          });
        }
        for (const zip of archives.slice(0, maxFiles)) {
          let members = [];
          let st = null;
          try { st = fs.statSync(zip); members = zipEntryNames(fs.readFileSync(zip, null), 2000); } catch { members = []; }
          const logs = members.filter((m) => SESSION_ARCHIVE_MEMBER_RE.test(m));
          entries.push({
            kind: "archive",
            id: path.basename(zip).replace(/\.zip$/i, ""),
            path: zip,
            bytes: st ? st.size : null,
            modifiedAt: st ? new Date(st.mtimeMs).toISOString() : null,
            sessionLogs: logs,
            members: members.length,
            attachments: members.filter((m) => /^(media|files)\//.test(m)).length,
          });
        }
        appendLog({ op: "sessions-list", type: null, name: dir, source: dir, disposition: null, detail: `${live.length} session(s), ${archives.length} archive(s)` });
        return {
          ok: true, op, dir, store, timezone: timezoneInfo(), sessions: live.length, archives: archives.length, entries,
          note: `${live.length} session file(s) and ${archives.length} exported archive(s) under ${dir}${live.length > maxFiles || archives.length > maxFiles ? " (ceiling reached)" : ""}. Titles come from each session's own session/title record; nothing was decompressed beyond the head of each file.`,
        };
      }

      if (op === "read" || op === "tail" || op === "record") {
        const resolved = resolveSessionTarget(args.target);
        if (!resolved) return { ok: false, op, target: String(args.target || ""), note: "no such session: pass a session file, a session directory, a ZIP, \"<zip>#<member>\" or an id fragment" };
        if (resolved.kind === "archive") {
          const members = zipEntryNames(fs.readFileSync(resolved.path, null), 2000).filter((m) => SESSION_ARCHIVE_MEMBER_RE.test(m));
          return { ok: false, op, target: resolved.path, note: `that archive holds ${members.length} session log(s); name one as "<zip>#<member>"`, scanned: { members: members.slice(0, 20) } };
        }
        const { buf, member } = readSessionBuffer(resolved);
        const isTail = op === "tail";
        const maxRecords = clampInt(args.maxRecords, isTail ? 200 : 2000, 1, 200000);
        const maxChars = clampInt(args.maxChars, op === "record" ? 4000 : 20000, 1, 400000);
        const frames = clampInt(args.frames, 40, 1, 2000);
        const decoded = decodeSessionBuffer(buf, isTail ? { lastFrames: frames, maxRecords, maxChars: maxChars * 4 } : { maxRecords, maxChars: maxChars * 4 });
        const header = sessionHeader(decoded.records.find((r) => r && r.type === "session"));
        const title = sessionTitle(decoded.records);
        const histogram = new Map();
        for (const r of decoded.records) {
          const t = String((r && r.type) || "(none)");
          histogram.set(t, (histogram.get(t) || 0) + 1);
        }
        const times = decoded.records.map((r) => (r && typeof r.time === "number" ? r.time : null)).filter((t) => t !== null);
        const wantContent = args.content === true;
        const messages = [];
        let chars = 0;
        if (wantContent) {
          for (const r of decoded.records) {
            const t = String((r && r.type) || "");
            if (!/^(user\/message|assistant\/message|tool\/call|tool\/result)$/.test(t)) continue;
            const text = sessionRecordText(r);
            if (!text) continue;
            if (chars + text.length > maxChars) { messages.push({ seq: r.seq === undefined ? null : r.seq, type: t, text: `(${text.length} chars omitted - maxChars ${maxChars} reached)` }); break; }
            chars += text.length;
            messages.push({ seq: r.seq === undefined ? null : r.seq, type: t, text });
          }
        }
        const structure = {
          ok: true,
          timezone: timezoneInfo(),
          op,
          target: member ? `${resolved.path}#${member}` : resolved.path,
          frames: decoded.frames,
          failed: decoded.failed,
          records: decoded.records.length,
          truncated: decoded.truncated,
          header,
          title,
          types: [...histogram.entries()].sort((a, b) => b[1] - a[1]).slice(0, 24).map(([type, count]) => ({ type, count })),
          timeRange: times.length ? { from: new Date(Math.min(...times)).toISOString(), to: new Date(Math.max(...times)).toISOString() } : {},
          messages,
        };
        if (op !== "record") {
          structure.note = `${decoded.frames} frame(s)${isTail ? ` (last ${frames})` : ""} decoded, ${decoded.records.length} record(s)${decoded.failed ? `, ${decoded.failed} frame(s) unreadable (a torn tail is the usual reason)` : ""}${wantContent ? "" : "; pass content:true for the message text"}.`;
          appendLog({ op: `sessions-${op}`, type: null, name: structure.target, source: "sessions", disposition: null, detail: `${decoded.records.length} record(s), content=${wantContent}` });
          return structure;
        }
        const type = args.type ? String(args.type) : "log";
        if (!OBJ_TYPES.has(type)) return { ok: false, op, note: `invalid type "${type}", allowed: ${[...OBJ_TYPES].join(", ")}` };
        const summaryLines = [
          `DSH session ${header.id || path.basename(path.dirname(resolved.path))}`,
          `records: ${decoded.records.length}, frames: ${decoded.frames}${decoded.failed ? `, unreadable frames: ${decoded.failed}` : ""}`,
          `types: ${structure.types.slice(0, 8).map((t) => `${t.type}=${t.count}`).join(" ")}`,
        ];
        if (structure.timeRange.from) summaryLines.push(`time: ${structure.timeRange.from} .. ${structure.timeRange.to}`);
        if (messages.length) summaryLines.push("", ...messages.map((m) => `[${m.type}] ${m.text}`));
        const obj = {
          id: makeId(type, "sessions", title || header.id || path.basename(resolved.path)),
          type,
          name: title || header.id || path.basename(path.dirname(resolved.path)),
          source: "sessions",
          path: member ? `${resolved.path}#${member}` : resolved.path,
          description: `DSH session recorded from library_sessions${header.cwd ? ` (cwd ${header.cwd})` : ""}`,
          tags: ["session", "dsh", ...(header.cwd ? [`ws:${path.basename(header.cwd)}`] : [])],
          summary: summaryLines.join("\n").slice(0, maxChars),
          createdAt: new Date().toISOString(),
        };
        const committed = commitRecord(obj, "confirm", `session recorded (${decoded.records.length} record(s), content=${wantContent})`);
        return {
          ok: true, op, timezone: timezoneInfo(), target: structure.target, frames: decoded.frames, failed: decoded.failed,
          records: decoded.records.length, truncated: decoded.truncated, header, title,
          types: structure.types, timeRange: structure.timeRange,
          recorded: { id: obj.id, type, name: obj.name, sensitive: !!committed.sensitive, content: wantContent, chars: summaryLines.join("\n").length },
          note: `recorded as ${type} "${obj.name}"${committed.sensitive ? " (sensitive content detected, stored encrypted)" : ""}${wantContent ? "" : "; pass content:true to include the message text"}.`,
        };
      }

      if (op === "search") {
        const query = String(args.query || "").trim();
        if (!query) return { ok: false, op, note: "search needs query=<phrase>" };
        const dir = path.resolve(args.dir ? String(args.dir) : store);
        const maxFiles = clampInt(args.maxFiles, 40, 1, 4000);
        const maxHits = clampInt(args.maxHits, 40, 1, 500);
        const { live, archives } = listSessionSources(dir, maxFiles);
        const needle = query.toLowerCase();
        const hits = [];
        let scannedFiles = 0;
        let scannedRecords = 0;
        let unreadable = 0;
        const scanText = (label, text) => {
          for (const line of text.split("\n")) {
            if (!line || hits.length >= maxHits) continue;
            if (!line.toLowerCase().includes(needle)) continue;
            let rec = null;
            try { rec = JSON.parse(line); } catch { rec = null; }
            const at = line.toLowerCase().indexOf(needle);
            const snippet = line.slice(Math.max(0, at - 80), Math.min(line.length, at + needle.length + 120)).replace(/\s+/g, " ");
            hits.push({ source: label, type: rec && rec.type ? rec.type : null, seq: rec && rec.seq !== undefined ? rec.seq : null, time: rec && typeof rec.time === "number" ? new Date(rec.time).toISOString() : null, snippet });
            if (hits.length >= maxHits) return;
          }
        };
        for (const file of live.slice(0, maxFiles)) {
          if (hits.length >= maxHits) break;
          let st = null;
          try { st = fs.statSync(file); } catch { continue; }
          if (st.size > 256 * 1024 * 1024) { unreadable++; continue; }
          scannedFiles++;
          let buf = null;
          try { buf = fs.readFileSync(file, null); } catch { unreadable++; continue; }
          const offsets = zstdFrameOffsets(buf);
          const total = offsets.length;
          for (let fi = 0; fi < total && hits.length < maxHits; fi++) {
            const start = offsets[fi];
            const end = fi + 1 < total ? offsets[fi + 1] : buf.length;
            let text = "";
            try { text = zstdDecompressSync(buf.subarray(start, end)).toString("utf8"); } catch { unreadable++; continue; }
            for (const line of text.split("\n")) if (line.trim()) scannedRecords++;
            scanText(path.relative(dir, file).replace(/\\/g, "/"), text);
          }
        }
        for (const zip of archives.slice(0, maxFiles)) {
          if (hits.length >= maxHits) break;
          let buf = null;
          try { buf = fs.readFileSync(zip, null); } catch { unreadable++; continue; }
          for (const name of zipEntryNames(buf, 500).filter((m) => SESSION_ARCHIVE_MEMBER_RE.test(m))) {
            if (hits.length >= maxHits) break;
            const entry = zipReadEntry(buf, name);
            if (!entry) continue;
            scannedFiles++;
            scanText(`${path.basename(zip)}#${name}`, entry.toString("utf8"));
          }
        }
        appendLog({ op: "sessions-search", type: null, name: query, source: "sessions", disposition: null, detail: `${hits.length} hit(s) across ${scannedFiles} file(s)` });
        return {
          ok: true, op, query, dir, timezone: timezoneInfo(), hits,
          scanned: { files: scannedFiles, records: scannedRecords, unreadableFramesOrFiles: unreadable, sessionsSeen: live.length, archivesSeen: archives.length },
          note: `${hits.length} hit(s) in ${scannedFiles} file(s)${hits.length >= maxHits ? " (maxHits reached)" : ""}; every frame of each file was decoded and discarded as it went, so nothing but the snippets above is held.`,
        };
      }

      return { ok: false, op, note: `unknown op "${op}": use list (default), read, tail, search or record` };
    },
  }));

  // ---- Optional: the Library-first notice, prepended to a session's first user message ----
  // Off by default, on purpose. The tool descriptions already carry the "come here first" wording, and
  // those are in context for free; a per-session injection is the sledgehammer for a host that keeps
  // reaching for the filesystem anyway. Turn it on with config injectPrompt:true, and replace the
  // wording wholesale by writing $DSH_HOME/mega-index-prompt.md.
  if (settings.injectPrompt === true && typeof ctx.on === "function") {
    let override = null;
    try {
      const file = libraryPromptFile();
      if (fs.existsSync(file)) override = String(fs.readFileSync(file, "utf8")).trim() || null;
    } catch { override = null; }
    const injected = new Set();
    try {
      ctx.on("agent/pre-step", async (payload, next) => {
        let decision = null;
        try {
          decision = await next();
          if (!decision || decision.kind !== "enter" || !Array.isArray(decision.messages) || decision.messages.length === 0) return decision;
          if (payload && payload.signal && payload.signal.aborted) return decision;
          const session = payload && payload.agent && payload.agent.session;
          if (session && session.header && session.header.origin === "subagent") return decision;
          const sid = (session && session.id) || "unknown";
          if (injected.has(sid)) return decision;
          const userMessages = decision.messages.filter((m) => m && m.source && m.source.kind === "user");
          if (userMessages.length === 0) return decision;
          let seenUserEvents = 0;
          for (const e of (session && session.events) || []) if (e && e.type === "user/message") seenUserEvents++;
          if (seenUserEvents > 0) return decision;
          injected.add(sid);
          const text = override || buildLibraryPrompt();
          const first = userMessages[0];
          const messages = decision.messages.map((m) => (m === first ? { ...m, content: [{ type: "text", text }, ...(m.content || [])] } : m));
          if (ctx.logger && typeof ctx.logger.info === "function") {
            ctx.logger.info(`[mega-index-map] library-first notice injected into session ${sid} (${text.length} chars)`);
          }
          return { ...decision, messages };
        } catch (e) {
          if (ctx.logger && typeof ctx.logger.warn === "function") {
            ctx.logger.warn(`[mega-index-map] notice injection skipped: ${e && e.message ? e.message : e}`);
          }
          return decision;
        }
      });
    } catch (e) {
      if (ctx.logger && typeof ctx.logger.warn === "function") ctx.logger.warn(`[mega-index-map] could not register the notice hook: ${e && e.message ? e.message : e}`);
    }
  }
}

export { name, inject, apply };
