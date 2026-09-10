# mega-index-map

A cross-workspace interop Library. Agents record valuable objects they encounter — files, tools,
environments, products, knowledge, work records — into an independent library under
`$DSH_HOME/library`, so any conversation can index, use, research and learn from them.

## Tools

- `library_record` — record an object (file/tool/env/product/knowledge/work record)
- `library_index` — rebuild/dedupe/sort the library, report conflicts
- `library_query` — search (keyword/type/tags, cursor pagination)
- `library_detect` — scan & register known tools/environments
- `library_sniff` — identify a file's true type from magic header bytes (105 signatures)
- `library_decrypt` — manually decrypt a sensitive object
- `library_export` — export to JSON/NDJSON
- `library_encoding` — detect system encoding + regional advice
- `library_adb` — Android device management over ADB (developer subset)

## Install

```powershell
dsh plugin --profile web add github:Nesarf/mega-index-map
```

## Notes

- The library lives at `$DSH_HOME/library` (default `~/.dsh/library`).
- Sensitive content (credentials, keys, etc.) is AES-256-GCM encrypt-isolated; only manual
  `library_decrypt` exposes it.
- MIT License. See [LICENSE](LICENSE).
