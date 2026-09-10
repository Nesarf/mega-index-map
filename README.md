# mega-index-map

A cross-workspace Library for DeepSeek Harness. Agents record the objects they meet - files, tools,
environments, knowledge, work records - into `$DSH_HOME/library`, so any conversation can index,
search and reuse them.

## Tools

- `library_record` - record an object (change detection routes verify/confirm)
- `library_index` - rebuild/dedupe/sort the library, report conflicts
- `library_query` - search by keyword/type/tags, cursor pagination
- `library_detect` - scan and register this machine's tools/environments
- `library_sniff` - identify a file by its header bytes (108 signatures), independent of extension
- `library_format` - extend this machine's format library: `list` `scan` `learn` `add` `remove` `deps` `draft` `report` `deliver` `unseal`
- `library_decrypt` - read back an isolated sensitive object on request
- `library_export` - export to JSON/NDJSON
- `library_encoding` - report the host encoding and how to switch to UTF-8
- `library_adb` - developer-side Android device operations over ADB

## Install

```powershell
dsh plugin --profile web add github:Nesarf/mega-index-map
```

## Notes

- The library lives at `$DSH_HOME/library` (default `~/.dsh/library`). Additions learned on this
  machine live beside it and never override the built-in tables.
- Work stays local: the plugin performs no network I/O and transmits nothing on its own.
- MIT License. See [LICENSE](LICENSE).
