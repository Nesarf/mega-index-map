---
name: mega-index
description: Cross-workspace interop Library skill: record valuable objects (tools/files/env/products/knowledge/work records) and search past records.
whenToUse: When persisting a tool/file/env/knowledge/record into the Library, or searching objects from other workspaces.
---

# mega-index (cross-workspace interop Library)

Works with the `mega-index-map` plugin, which keeps a cross-workspace object library at `$DSH_HOME/library` and registers ten tools:

- `library_record` - record an object; change detection routes verify/confirm
- `library_index` - rebuild/dedupe/sort; reports conflicts
- `library_query` - search (keyword/type/tags, cursor pagination)
- `library_detect` - scan and register this machine's tools/environments; `list`/`add`/`remove`/`propose` manage a local candidate pack (built-ins always win; `propose` only suggests)
- `library_sniff` - identify a file by its header bytes (108 signatures); `dir` mode sweeps a directory
- `library_format` - extend this machine's format library: `scan` `learn` `add` `remove` `deps` `draft` `report` `deliver` `unseal` (local pack at `$DSH_HOME/library/formats.local.json`; built-ins always win, conflicts refused unless `confirm:true`)
- `library_decrypt` - read back an isolated sensitive object on request
- `library_export` - export to JSON/NDJSON
- `library_encoding` - report the host encoding + how to switch to UTF-8
- `library_adb` - developer-side Android device operations over ADB

## When to record

Record an object worth reusing across workspaces: a tool/script, a produced file/build, an environment fact (endpoint/port/path), a research conclusion, or a work record. One object per call; pick one `type`; set the object's workspace in `source`; use whitelist tags.

## When to search

- New conversation wants what another workspace recorded -> `library_query` (type/tags/keyword).
- Research what a workspace used -> filter by `source` or `tags`.
- Cross-workspace reuse -> search, get the `path`, then use it.

## Red lines

- Only write under `$DSH_HOME/library`; never C: or arbitrary paths; never record secrets.
- Don't edit library files directly; `library_record` requires a valid `type`.
- The plugin performs no network I/O: anything it produces stays local until a person chooses otherwise.

## Change detection

`library_record` fingerprints the same-key object; on content change it routes by type:

- **verify** (tool/plugin/env) - records a new version and notifies DSH to check the object's state.
- **confirm** (immutable files: persona/image/document/table/audio/work_record/log) - does not auto-overwrite; ask the user to confirm/explain.
