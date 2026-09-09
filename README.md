# mega-index-map (DSH cross-workspace interop Library)

A DeepSeek Harness (DSH) plugin: let Harness agents proactively record each workspace's **files, tools, environments, products, knowledge base, and work records** into an independent Library (`$DSH_HOME/library`), so that **existing and new conversations** can **index, use, research, and learn from** the objects DeepSeek has already recorded. This is a standard DSH plugin package: install/uninstall via `dsh plugin`, publishable to GitHub/npm.

## TL;DR

- This plugin provides a **Library storage + retrieval service** with nine tools: `library_record` (record + change detection), `library_index` (rebuild/dedupe/conflict report), `library_query` (search + pagination cursor), `library_detect` (scan & register local tools/environments), `library_sniff` (file-signature type identification), `library_decrypt` (manually decrypt sensitive objects), `library_export` (export/migrate), `library_encoding` (detect system encoding + region-aware indicative guidance), `library_adb` (legitimate Android device management over ADB).
- A companion **agent skill (mega-index)** guides the agent to **proactively** record encountered objects into the Library and to search past records.
- The Library lives at `$DSH_HOME/library` (independent of each workspace); upgrading/uninstalling the plugin does not affect it.

## Features

- 🗂️ **Cross-workspace interop**: objects from eight workspaces (a second drive root `~` dirs, `%TOOLCHAIN_HOME%`, QQ chat/slang under `qq-bridge`) and any workspace are recorded into one Library.
- 🤖 **Proactive recording**: the agent uses `library_record` on its own to record newly encountered objects (tool/file/env/product/knowledge/work record), not only when asked.
- 🔎 **Searchable**: `library_query` supports keyword + type + tags filtering; new conversations can inherit past records and research what another workspace used.
- 🧠 **Three-carrier coordination**: Library + `workspace-map` (map) + Hindsight memory (bank `coding-agent::DSH`) together achieve cross-workspace/cross-session interop.
- 🛡️ **Safe**: the library only writes under `$DSH_HOME/library`, never the C: drive, never records credentials; follows DSH disk discipline.
- 🔁 **Change-detection guardrail**: `library_record` compares the same-key object; on content change it routes by type — tools/plugins/env record a new version and notify DSH to check and report to the user; immutable files (persona/image/document/table/audio/work record/log) **do not auto-overwrite** and force user confirmation or explanation.
- 📺 **Media difference evidence**: for changes to image/audio/video/document files, silently probe media metadata (format/codec/duration/streams) via MediaInfo and attach the evidence for the user to judge.
- 🪟 **No popup**: all external tool invocation goes through `runSilent` (`windowsHide:true`), so the plugin never pops unwanted console windows.
- 🕵️ **Install-time self-scan**: `library_detect` scans this machine's known tools/environments/toolchains (MediaInfo/ffmpeg/uv/llm_toolkit_api/DSH_HOME/SDK/VS, etc.) and registers them; installing missing tools requires an instruction + report, and compatibility paths are maintained/built only on instruction.
- 🔒 **No waking outside DSH**: tools are registered only in a DSH host (presence of `DSH_HOME`); outside DSH (bare node, other agent frameworks) nothing is registered, so the plugin cannot be woken externally.
- 🔗 **Cross-object links**: `library_record` supports `links`, stored as `related`, connecting tools→dependencies→workspaces into an interop graph.
- 🕵️ **File signature recognition (magic bytes)**: `library_sniff` identifies an object's true type from header bytes (archives 7z/zip/rar/gzip/xz/zstd/xp3/zlib/ar/cab/rpm/wim, images PNG/JPEG/BMP/GIF/TIFF/WebP/TLG/AVIF/PSD/EXR/PSB/XCF/DjVu/HEIC/CDR/TGA, audio MP3/OGG/FLAC/APE/VST-preset/AU/AC3/DTS/TrueHD/SF2, video MOV/MKV/TS/FLV/SWF/ASF/RealMedia/MXF, fonts TTF/OTF/WOFF/WOFF2/TTC, databases SQLite/MDB, models ONNX/GGUF/GGML/GLB/HDF5/PMD/PMX/DirectX, PE/ELF/Mach-O executables, PDF/RTF/Inno-Setup/c4d/VDI/pickle/EPUB/MOBI/WARC/DWG/DWF/3DS/BLEND/OLE2/VHD/VHDX/QCOW2/NPY/PMM/VPD), independent of a spoofable extension — 7-Zip/Bandizip approach. `mediaFingerprint` analyzes via **ffprobe + MediaInfo dual engines**, falling back to signatures when both fail.
- ⚠️ **Dedupe/merge conflict report**: `library_index` reports `conflicts` when same-key objects differ, instead of silently dropping information.
- 📄 **Batch/stream search**: `library_query` supports `cursor`+`pageSize` pagination to avoid blowing the context on large libraries.
- 🔄 **workspace-map auto-discovery alignment**: `library_detect`'s `cross` option cross-checks scanned results against known objects and lists unregistered items.
- 📦 **Export/migrate**: `library_export` exports standard JSON/NDJSON (sensitive objects stay encrypted), for migration/backup.
- 🔐 **Sensitive/dangerous subject encrypt-isolation**: content matching sensitive markers (ransom/trojan/virus/private-key/credential, etc.) never enters plaintext logs/index; it is AES-256-GCM encrypt-isolated locally (`sensitive:true` metadata searchable, plaintext only via manual `library_decrypt`), offline by default and never pushed.
- 📝 **JSONL append log**: `$DSH_HOME/library/log.jsonl` appends record/index/detect operations and difference dispositions — generic, greppable, non-growing.
- 🌐 **Encoding adaptation**: the library always persists as UTF-8; `library_encoding` detects the host's system default encoding and issues region-aware indicative guidance (Japan/Korea/Southeast Asia/China-Taiwan/Europe/Latin America) to avoid mojibake on hosts whose system default is not UTF-8. Cross-platform (Windows `chcp` / Unix `locale`).
- 📱 **Android device management (legitimate subset)**: `library_adb` wraps developer-side ADB operations (devices/install/uninstall/launch/shell/logcat/screenshot/screenrecord/root-check/reboot/pull/push/remote-connect) via the local `adb` (auto-resolves `%TOOLCHAIN_HOME%\\adb.exe` on Windows or `adb` on PATH). It uses `runSilent` (no popup) and can `record` operations into the Library. Offensive ADB-Toolkit sections (Metasploit payload, hang-the-phone DoS, send SMS, bulk camera/downloads/WhatsApp/storage copy) are deliberately **not** implemented.

## Directory structure

```text
mega-index-map/
├── package.json             # DSH bundle plugin metadata (with dsh.bundle.patch)
├── README.md                # this file
├── LICENSE                  # MIT
├── cordis.patch.yml         # plugin mount declaration
├── lib/
│   ├── core.mjs             # cross-harness shared core (pure Node, no DSH dep)
│   └── index.js             # DSH host-side plugin (imports core.mjs)
├── mcp/
│   └── index.mjs            # MCP stdio server (9 tools, cross-harness)
├── cli/
│   └── index.mjs            # command-line driver
├── skills/
│   └── mega-index/
│       └── SKILL.md         # agent recording/query skill
└── .github/
    └── workflows/
        └── publish.yml      # OIDC auto-publish to npm + GitHub Release
```

## Installation

### Method A: install directly from GitHub (recommended)

```powershell
dsh plugin --profile web add github:Nesarf/mega-index-map
```

After install you can update it from DSH's **plugin management page**. If the network needs a proxy, set the proxy env vars first.

### Method B: local development install

Run from the **repository root** (where `package.json` lives, i.e. `%TOOLCHAIN_HOME%`):

```powershell
dsh plugin --profile web add link:.
```

⚠️ Do not write `link:.\mega-index-map` (there is no such subdirectory). If you move the source directory, re-run `add`.

### Method C: after publishing to npm

```powershell
dsh plugin --profile web add mega-index-map
```

### Install instructions for an AI

```
Please install the plugin mega-index-map.

Steps:
1. Ensure pnpm is available (if not: npm install -g pnpm).
2. Install into the web profile: dsh plugin --profile web add github:Nesarf/mega-index-map
   (or locally: dsh plugin --profile web add link:%TOOLCHAIN_HOME%)
3. If pnpm blocks build scripts, add the package key under allowBuilds in
   profiles/web/pnpm-workspace.yaml and retry.
4. Restart dsh web, then F5 refresh.

Verify: dsh --profile web --dump-config should show mega-index-map in bundles;
or have the agent run library_query and see the library path and recorded objects.
```

## Usage

### 1. Let the agent proactively record

After loading the `mega-index` skill (or per its guidance), the agent calls `library_record` during tasks:
- `type`: `tool|file|env|product|knowledge|work_record|workspace|reference|other` (plus extended types)
- `name`: object name; `source`: workspace/directory; `path`: absolute path; `description`: purpose; `tags`: whitelist tags; `summary`: structured summary.

### 2. Search the Library

New or any conversation uses `library_query`:
- keyword: e.g. `ffmpeg` / `game automation` / `vtuber daily`
- `type` filter: e.g. `type:"tool"`
- `tags` filter: e.g. `tags:["game"]`

### 3. Rebuild index

`library_index`: dedupe (type+name+source) + sort by time, rewrite `index.json`.

## Cross-harness (MCP / CLI)

Besides the DSH plugin, `mega-index-map` ships a **cross-harness** version so any agent framework
that supports MCP (Model Context Protocol) — Claude Code, Cursor, opencode, GitHub Copilot CLI —
can use the same Library. Both share the pure-Node core (`lib/core.mjs`).

### MCP server

Exposes the same 9 tools over MCP stdio. Register in any MCP client:

```json
{ "mcpServers": { "mega-index-map": { "command": "node", "args": ["./mcp/index.mjs"] } } }
```

Or run directly: `node ./mcp/index.mjs`.

### CLI

Command-line driver (same tools, no MCP runtime needed):

```bash
# via package bin (npm i -g mega-index-map), or:
node ./cli/index.mjs library_encoding
node ./cli/index.mjs library_record --type tool --name foo --source bar
node ./cli/index.mjs library_query --query ffmpeg
node ./cli/index.mjs sniff "path/to/file"
```

The library lives at `$DSH_HOME/library` (default `~/.dsh/library`) for DSH, MCP, and CLI alike, so
all three share one index.

## Library files

| File | Description |
|---|---|
| `$DSH_HOME/library/index.json` | index library (manifest + objects array) |
| `$DSH_HOME/library/objects/` | reserved directory for raw object payloads |
| `$DSH_HOME/library/log.jsonl` | append log (record/index operations + difference dispositions, one JSON per line) |

Default `$DSH_HOME` = `%TOOLCHAIN_HOME%` (this machine), i.e. the library is at `%TOOLCHAIN_HOME%\\library`. If `DSH_HOME` is unset, fall back to `~/.dsh/library`.

## Verification

```powershell
dsh --profile web --dump-config | Select-String -Pattern "mega-index"
# or have the agent run library_query and see the library path / object list
```

## Publishing to GitHub / npm

The repo includes `.github/workflows/publish.yml`: pushing to `main` triggers OIDC auto-publish to npm + GitHub Release creation (changelog generated from merged PRs; npm Trusted Publishing supported). Bump `package.json`'s `version` → push → release.

## Uninstall

```powershell
dsh plugin --profile web remove mega-index-map
```

## License

Open source under the **MIT License**; see [LICENSE](LICENSE).
