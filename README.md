# mega-index-map

A cross-workspace interop Library. Agents record valuable objects they encounter — files, tools,
environments, products, knowledge, work records — into an independent library under
`$DSH_HOME/library`, so any conversation can index, use, research and learn from them.

## Tools

- `library_record` — record an object (file/tool/env/product/knowledge/work record)
- `library_index` — rebuild/dedupe/sort the library, report conflicts
- `library_query` — search (keyword/type/tags, cursor pagination)
- `library_detect` — scan & register known tools/environments
- `library_sniff` — true type from magic header bytes (108 signatures) + name/content forgery check; `dir` mode sweeps a directory for mismatches
- `library_format` — personalise *this install's* format library: `scan` proposes the types this machine has that the library cannot identify; `learn`/`add` register them (magic signature / text extension / name rule) into `$DSH_HOME/library/formats.local.json`; `remove` drops one; `deps` reports which formats reference which other formats (extensions only, DLL names opt-in); `draft` writes a reviewable checklist (optionally keeping the raw context locally, encrypted); `report` builds a small contribution archive from a directory or from the draft items **you** select, and `unseal` reopens a sealed layer with your own passphrase
- `library_decrypt` — manually decrypt a sensitive object
- `library_export` — export to JSON/NDJSON
- `library_encoding` — detect system encoding + regional advice
- `library_adb` — Android device management over ADB (developer subset)

## Install

```powershell
dsh plugin --profile web add github:Nesarf/mega-index-map
```

## Notes

- The library lives at `$DSH_HOME/library` (default `~/.dsh/library`). Built-in format signatures
  are fixed; whatever this machine adds lives in `library/formats.local.json` — built-ins always win,
  so a local entry can never shadow a known format.
- Sensitive content (credentials, keys, etc.) is AES-256-GCM encrypt-isolated; only manual
  `library_decrypt` exposes it.
- Format reports are **local and manual**: `library_format op=report` writes a ~1.5 KB archive under
  `$DSH_HOME/library/reports` and prints what is inside. The plugin performs no network I/O and never
  sends anything — whether to deliver it (e-mail, file host, or not at all) is entirely your call.
- Directory information is yours to control: `pathDetail=none` (default) carries no paths at all,
  `dirs` keeps sanitised directory names only, `full` adds sample file names — always with
  `<drive>/<home>/<user>/<host>/<uuid>/<date>` substituted for identifying parts. Add `seal=<passphrase>`
  to encrypt that user-level layer with AES-256-GCM under a key derived from **your** passphrase:
  you can reopen it any time with `op=unseal`, and nobody else can. Encryption here protects your own
  data from exposure — it is never a way to hide anything from you, and it never enables transmission.
- MIT License. See [LICENSE](LICENSE).
