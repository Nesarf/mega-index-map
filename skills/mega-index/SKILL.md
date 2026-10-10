---
name: mega-index
description: Cross-workspace interop Library skill: ask the Library before researching, scanning or re-deriving something (a tool, an environment fact, a file's true type, a work record), and record what is worth reusing.
whenToUse: When a task mentions something that may already be recorded (a path, a port, an endpoint, a toolchain, an earlier decision), when something reusable turns up that should be recorded, or when checking whether a directory is fully indexed.
---

# mega-index (cross-workspace interop Library)

Works with the `mega-index-map` plugin, which keeps a cross-workspace object library at `$DSH_HOME/library` and registers ten tools.

**Ask the Library before you scan.** These tools exist so a question already answered does not cost a
filesystem walk: `library_query` first for anything that may have been recorded, `library_detect op=list`
before hunting for a tool, runtime or SDK, `library_sniff` before opening a file to guess its type, and
`library_index op=audit dir=<path>` before walking a directory to see what is in it. A recorded `path` is
meant to be used as it stands; if the object has moved, record the new version rather than hunting for it.
A host that keeps reaching for the disk anyway can turn on the plugin's `injectPrompt: true`, which
prepends this same advice to each session (wording replaceable at `$DSH_HOME/mega-index-prompt.md`).

- `library_record` - record an object; change detection routes verify/confirm
- `library_index` - `op=rebuild` dedupes/sorts and reports conflicts; `op=audit dir=<path>` reconciles a directory with the Library in both directions, read-only; `op=index dir=<path> confirm=true` registers the missing entries (drive roots refused)
- `library_query` - search (keyword/type/tags, cursor pagination)
- `library_detect` - scan and register this machine's tools/environments; `list`/`add`/`remove`/`propose` manage a local candidate pack (built-ins always win; `propose` only suggests)
- `library_sniff` - identify a file by its header bytes (108 signatures); `dir` mode sweeps a directory
- `library_format` - extend this machine's format library: `scan` `learn` `add` `remove` `deps` `draft` `report` `deliver` `unseal` (local pack at `$DSH_HOME/library/formats.local.json`; built-ins always win, conflicts refused unless `confirm:true`)
- `library_decrypt` - read back an isolated sensitive object on request
- `library_export` - export to JSON/NDJSON
- `library_encoding` - report the host encoding + how to switch to UTF-8
- `library_adb` - developer-side Android device operations over ADB
- `library_sessions` - read DSH's own sessions (and exported session-log ZIPs): `list` enumerates, `read` gives a bounded structural summary (`content: true` for the text), `tail` decodes only the last frames, `search` scans frames for a phrase, `record` writes a session into the Library as a log

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
- **confirm** (the immutable class: persona/image/document/table/audio/work_record/log, and the types that
  fall through to it - knowledge/reference/workspace/file/product/other) - does not auto-overwrite. Ask
  the user, then call again with `confirm: true` and `reason: "<what they decided>"`, which records the
  change and writes the explanation to the append-only log as `record-confirm`. `confirm` without a
  `reason` is refused on purpose: a confirmation that leaves no trace is the silent overwrite this route
  exists to prevent. Run `library_index` afterwards so the newest version supersedes the one it replaces.
- A record can be wrong for a reason that is nobody's decision - a mis-fire of the sensitive-content
  rule, for instance - and this route is how such a record is repaired rather than left encrypted.
