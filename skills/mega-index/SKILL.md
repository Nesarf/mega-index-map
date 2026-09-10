---
name: mega-index
description: Cross-workspace interop Library skill: record valuable objects (tools/files/env/products/knowledge/work records) and search past records.
whenToUse: When persisting a tool/file/env/knowledge/record into the Library, or searching objects from other workspaces.
---

# mega-index (cross-workspace interop Library)

Works with the `mega-index-map` plugin, which keeps a cross-workspace object library at `$DSH_HOME/library` and registers nine tools:

- `library_record` — record an object; change detection routes verify/confirm; media changes carry ffprobe+MediaInfo evidence
- `library_index` — rebuild/dedupe/sort; reports conflicts
- `library_query` — search (keyword/type/tags, cursor pagination)
- `library_detect` — scan & register known tools/environments
- `library_sniff` — true type from magic header bytes (107 signatures) + name/content forgery check; `dir` mode sweeps a directory (e.g. DSH temp/session dirs) for mismatches
- `library_decrypt` — manually decrypt a sensitive object
- `library_export` — export to JSON/NDJSON (sensitive stays encrypted)
- `library_encoding` — detect system encoding + regional advice
- `library_adb` — Android device management over ADB (developer subset)

## When to record

Record an object worth reusing across workspaces: a tool/script, a produced file/build, an environment fact (endpoint/port/path), a research conclusion, or a work record. One object per call; pick one `type`; set the object's workspace in `source`; use whitelist tags.

## When to search

- New conversation wants what another workspace recorded → `library_query` (type/tags/keyword).
- Research what a workspace used → filter by `source` or `tags`.
- Cross-workspace reuse → search, get the `path`, then use it.

## Red lines

- Only write under `$DSH_HOME/library`; never C: or arbitrary paths; never record secrets.
- Sensitive subjects (credentials/keys/ransom/etc.) are automatically encrypt-isolated; only `sensitive:true` metadata is searchable; reading needs manual `library_decrypt`.
- `library_record` requires a valid `type`; don't edit library files directly.

## Change detection

`library_record` fingerprints the same-key object; on content change it routes by type:

- **verify** (tool/plugin/env) — records a new version and notifies DSH to check the object's state.
- **confirm** (immutable files: persona/image/document/table/audio/work_record/log) — does not auto-overwrite; ask the user to confirm/explain.
