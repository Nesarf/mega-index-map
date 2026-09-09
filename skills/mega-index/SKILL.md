---
name: mega-index
description: Cross-workspace interop Library recording/query skill. Guides the agent to proactively record valuable objects (tools, files, environments, products, knowledge, work records) it encounters into the Library, and to search past records with the Library. Use for recording new objects, cross-workspace reuse, researching/learning another workspace's records, and letting new conversations inherit existing records.
whenToUse: When the user wants to persist a tool/file/environment/knowledge/record into the cross-workspace Library; when a new conversation wants to search objects accumulated in other workspaces; when the agent proactively records encountered objects while completing a task; or when coordinating with workspace-map for cross-workspace interop.
---

# mega-index (cross-workspace interop Library recording/query)

This skill works with the DSH plugin `mega-index-map`. The plugin maintains a cross-workspace object index library under `$DSH_HOME/library` and registers nine tools:
- `library_record`: record an object (type/name/source/path/description/tags/summary/links); with change detection and routing (verify/confirm); media-type changes carry **ffprobe+MediaInfo dual-engine** evidence
- `library_index`: rebuild/dedupe/sort the library; reports conflicts when same-key objects differ in content
- `library_query`: search the library (by keyword/type/tags); supports cursor+pageSize pagination
- `library_detect`: scan and register this machine's known handy tools/environments/toolchains (MediaInfo/ffmpeg/uv/DSH_HOME/SDK/VS, etc.); cross option cross-checks
- `library_sniff`: identify an object's true type from magic header bytes (archives 7z/zip/rar/gzip/xz/zstd/xp3/zlib/ar/cab/rpm/wim, images PNG/JPEG/BMP/GIF/TIFF/WebP/TLG/AVIF/PSD/EXR/PSB/XCF/DjVu/HEIC/CDR/TGA, audio MP3/OGG/FLAC/APE/VST-preset/AU/AC3/DTS/TrueHD/SF2, video MOV/MKV/TS/FLV/SWF/ASF/RealMedia/MXF, fonts TTF/OTF/WOFF/WOFF2/TTC, databases SQLite/MDB, models ONNX/GGUF/GGML/GLB/HDF5/PMD/PMX/DirectX, PE/ELF/Mach-O, PDF/RTF/Inno-Setup/c4d/VDI/pickle/EPUB/MOBI/WARC/DWG/DWF/3DS/BLEND/OLE2/VHD/VHDX/QCOW2/NPY/PMM/VPD), independent of extension (7-Zip/Bandizip approach)
- `library_decrypt`: manually decrypt an encrypted-isolated sensitive object (never auto-decrypt)
- `library_export`: export the library to standard JSON/NDJSON (sensitive objects stay encrypted), for migration/backup
- `library_encoding`: detect the host's system default encoding and give region-aware indicative guidance (Japan/Korea/Southeast Asia/China-Taiwan/Europe/Latin America) to avoid mojibake when the system default is not UTF-8
- `library_adb`: manage an Android device over ADB with **legitimate developer operations only** (devices/restart-server/reboot/reboot-recovery/reboot-bootloader/shell/info-system/info-cpu/info-memory/device-details/bugreport/install/uninstall/list-packages/logcat/push/pull/launch/screenshot/screenrecord/root-check/remote-connect). Offensive sections (Metasploit payload, hang-the-phone DoS, send SMS, bulk privacy copy) are intentionally **not** implemented. Use only on your own test device.

## When to proactively record (agent does this on its own during a task, not only when asked)

When working in any workspace, if you encounter an object worth reusing across workspaces, record it with `library_record`:
1. **An executable tool/script used** (e.g. `game-drive.ps1`, `ffmpeg`, `CrystalDiskInfo`) — record its path + purpose.
2. **A produced file/directory/build** (e.g. a vtuber daily report, an export package, a persona card) — record its path + description.
3. **An environment fact**: service endpoint, port, venv, install path, env var (e.g. `http://127.0.0.1:8100`, `%TOOLCHAIN_HOME%\\venvs\...`).
4. **A research conclusion/knowledge formed**: a workspace's architecture, convention, gotcha, decision.
5. **A work record**: session log, runtime state, milestone.

> Recording principle: **one object per `library_record` call**; pick the single most representative `type`; write the object's workspace/directory in `source`; use whitelist tags (workspace/tool/file/env/service/port/python/sdk/game/media/summary, etc.) for easier retrieval. Prefer recording several objects over cramming multiple objects into one entry.

## When to search the library (reuse / learn / inherit)

- A **new conversation** wants to know what another workspace recorded → `library_query` (optionally with `type`/`tags`/keyword).
- **Research/learn** what tools a workspace used and which paths it took → `library_query` filtered by `source` or `tags`, then read the entries; if needed, use the `workspace-map` skill to locate the actual file.
- **Cross-workspace reuse**: first search the library for the target object, get its `path`, then read/invoke as needed.

## Coordination with workspace-map

- `workspace-map` (the map) is a **manually maintained static overview**; `mega-index` (this skill + plugin) is an **agent-accumulated dynamic object library**.
- New object/discovery → `library_record` into the library; existing objects → both are searchable; the map leans "system inventory", the library leans "object-level records".
- Both write to Hindsight memory (bank `coding-agent::DSH` → env:machine), enabling cross-workspace/cross-session interop.

## Red lines

- The library only writes under `$DSH_HOME/library`; never write to the C: drive or arbitrary paths; never record secrets like credentials/tokens.
- `library_record` requires `type` within the plugin's enum; do not bypass the tool by editing library files directly.
- **Sensitive/dangerous subjects (ransom/trojan/virus/private-key/credential, etc.) are auto encrypt-isolated**: content never enters plaintext logs/index; only `sensitive:true` metadata is searchable; reading requires manual `library_decrypt`. The agent must not attempt to bypass the isolation or copy sensitive content into normal logs.

## Change detection and guardrail (important)

`library_record` first compares the content fingerprint of the same-key object (type+name+source). If it differs from the last index, it routes by type:

- **Auto-verifiable class (tool / plugin / env)**: the change **records a new version** and returns `disposition:"verify"` + a prompt. The agent should then **proactively check the object's actual state** (path/service/version consistency) and report the result to the user.
- **Immutable-file class (persona / image / document / table / audio / work_record / log, etc.)**: the change **does not auto-overwrite**; returns `disposition:"confirm"`. The agent should **switch to ask_user_question to have the user confirm the change or explain it**, then decide to write or discard.

> Purpose: shift the "responsibility for change" off the indexing plugin — auto-verifiable ones get checked by DSH, immutable files get acknowledged by the user — so the log does not accumulate unclaimed change entries.
