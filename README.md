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
- `library_format` — personalise *this install's* format library: `scan` proposes the types this machine has that the library cannot identify; `learn`/`add` register them (magic signature / text extension / name rule) into `$DSH_HOME/library/formats.local.json`; `report` writes a small contribution archive (extensions + magic prefixes + counts, no names/paths/contents) that **you** may choose to send
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
- Format reports are **local and manual**: `library_format op=report` writes a ~1 KB archive under
  `$DSH_HOME/library/reports` and prints what is inside. The plugin performs no network I/O and never
  sends anything — whether to deliver it (e-mail, file host, or not at all) is entirely your call.
- MIT License. See [LICENSE](LICENSE).
