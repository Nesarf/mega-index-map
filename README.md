# mega-index-map

A cross-workspace interop Library. Agents record valuable objects they encounter - files, tools,
environments, products, knowledge, work records - into an independent library under
`$DSH_HOME/library`, so any conversation can index, use, research and learn from them.

## Tools

- `library_record` - record an object (file/tool/env/product/knowledge/work record)
- `library_index` - rebuild/dedupe/sort the library, report conflicts
- `library_query` - search (keyword/type/tags, cursor pagination)
- `library_detect` - scan & register machine tools/environments (built-in list + this machine's local candidate pack); `list`/`add`/`remove`/`propose` manage the pack
- `library_sniff` - true type from magic header bytes (108 signatures) + name/content forgery check; `dir` mode sweeps a directory for mismatches
- `library_format` - personalise *this install's* format library: `scan` proposes the types this machine has that the library cannot identify; `learn`/`add` register them (magic signature / text extension / name rule) into `$DSH_HOME/library/formats.local.json`; `remove` drops one; `deps` reports which formats reference which other formats (extensions only, DLL names opt-in); `draft` writes a reviewable checklist (optionally keeping the raw context locally, encrypted); `report` builds a small contribution archive from a directory or from the draft items **you** select; `deliver` shows such an archive in the platform's own window (a native dialog: preview + Send by e-mail / Save a copy / Open folder / Delete report); `unseal` reopens a sealed layer with your own passphrase
- `library_decrypt` - manually decrypt a sensitive object
- `library_export` - export to JSON/NDJSON
- `library_encoding` - detect system encoding + regional advice
- `library_adb` - Android device management over ADB (developer subset)

## Install

```powershell
dsh plugin --profile web add github:Nesarf/mega-index-map
```

## Notes

- The library lives at `$DSH_HOME/library` (default `~/.dsh/library`). Built-in format signatures
  are fixed; whatever this machine adds lives in `library/formats.local.json` - built-ins always win,
  so a local entry can never shadow a known format.
- Toolchains and services work the same way: `library_detect op=add` records a machine-specific
  tool/env into `library/candidates.local.json`, and every later scan recognises it alongside the
  built-in list. Built-ins always win (`op=propose` only suggests, `op=scan` never executes a
  candidate - a path is recorded and checked for existence, nothing more).
- Sensitive content (credentials, keys, etc.) is AES-256-GCM encrypt-isolated; only manual
  `library_decrypt` exposes it.
- Format reports are **local and manual**: `library_format op=report` writes a ~1.5 KB archive under
  `$DSH_HOME/library/reports` and prints what is inside. The plugin performs no network I/O and never
  sends anything - whether to deliver it (e-mail, file host, or not at all) is entirely your call.
- Directory information is yours to control: `pathDetail=none` (default) carries no paths at all,
  `dirs` keeps sanitised directory names only, `full` adds sample file names - always with
  `<drive>/<home>/<user>/<host>/<uuid>/<date>` substituted for identifying parts. Add `seal=<passphrase>`
  to encrypt that user-level layer with AES-256-GCM under a key derived from **your** passphrase:
  you can reopen it any time with `op=unseal`, and nobody else can. Encryption here protects your own
  data from exposure - it is never a way to hide anything from you, and it never enables transmission.
- **What happens to a report you send.** It is used for one purpose only: extending the built-in format
  library. If a format corpus is ever published, only format facts are published - extensions, magic
  bytes and format->format relationships; no directory paths, file names, DLL names or any third-party
  identifier ever enters a public set. A report you choose not to send stays on your machine, and
  deleting it is enough to withdraw it.
- MIT License. See [LICENSE](LICENSE).

## Contributing formats

Formats that a machine has and this build cannot identify are the most useful contribution:

1. `library_format op=draft dir=<directory>` writes a checklist (nothing is sent); add
   `keepLocal: true` to also keep the raw context encrypted on your own machine, so nothing is lost.
2. Review it, then `library_format op=report draft=<file> include=[...]` - or run
   `op=report dir=<directory>` directly. Both write a ~1.5 KB archive under `$DSH_HOME/library/reports`
   and print what is inside.
3. `library_format op=deliver` (or `op=report ui=true`) opens the archive in a **native window** -
   a Windows dialog with a read-only preview and `Send by e-mail...` / `Save a copy...` /
   `Open folder` / `Delete report` buttons; on Linux/macOS it uses zenity, kdialog or osascript.
   Sending opens **your own** mail client and selects the file in the folder window, because an
   e-mail cannot carry the attachment by itself. On hosts without a desktop, pass `headless: true`
   and you get the same information as plain instructions.
4. No GUI at all? Send it yourself (the manifest lists the address and subject), or open an issue with
   the contents of `manifest.txt` - by design it holds no paths or file names, so pasting it is safe.
   Keep it local instead and use `op=learn` if you would rather not share at all.
