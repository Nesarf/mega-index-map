# mega-index-map

> Chinese documentation: [README.zh-CN.md](README.zh-CN.md)

A cross-workspace Library for DeepSeek Harness. Agents record the objects they meet - files, tools,
environments, knowledge, work records - into `$DSH_HOME/library`, so any conversation can index,
search and reuse them.

Every tool says when it is the cheaper answer, because that is what decides whether an agent asks the
Library or walks the filesystem: `library_query` before researching something again, `library_detect`
before looking for a tool or runtime, `library_sniff` before opening a file to guess its type, and
`library_index op=audit` before walking a directory to see what is in it. For a host that still reaches
for the disk, `injectPrompt: true` (plugin config) prepends a short notice to each session's first user
message - replace its wording wholesale with `$DSH_HOME/mega-index-prompt.md`.

## Tools

- `library_record` - record an object (change detection routes verify/confirm; a change to the immutable
  class is refused until the user decides, and is then recorded with `confirm: true` and a `reason`, which
  the log keeps as `record-confirm`)
- `library_index` - four jobs on the index: `op=rebuild` (default) dedupes/sorts and reports conflicts;
  `op=audit dir=<path>` reconciles a directory with the Library read-only, both directions - entries on
  disk with no record, and records whose path no longer exists (recorded is not the same as addressable);
  `op=index dir=<path> confirm=true` registers the missing entries, bounded by depth and an entry
  ceiling, with the sensitive-content rule applied (a file also gets a sha256 while we are standing on it).
  `op=verify` checks identity rather than existence: for every record that points at a regular file it
  recomputes the fingerprint and reports unchanged / changed / gone / never fingerprinted / unreadable -
  `gone` and `unreadable` stay separate findings, because a locked file is not a missing one. Read-only
  unless `confirm=true`, which also records the observed sha256 (how a baseline is established or
  refreshed); bounded by `maxFiles` and a time budget, with `after=<id>` as a cursor so a large library
  walks in slices. Above `maxHashBytes` (default 16 MiB) a file is hashed by size plus a head and a tail
  slice, and the result says `partial: true` rather than passing itself off as a full digest.
  `op=prune confirm=true` drops derived rows that no longer qualify - mined format leads seen fewer
  than `keepHits` times - so a rule tightened later can be applied to what is already recorded. A drive root is refused: an indexer that walks a whole
  disk is the scan this Library exists to replace
- `library_query` - search by keyword/type/tags, cursor pagination. A multi-word query is matched term by term and ranked by how many terms each object covers, so several words narrow results instead of requiring that exact phrase; a single word behaves as a plain substring search.
- `library_detect` - scan and register this machine's tools/environments. The built-in seed is
  machine-neutral: a bare command name is resolved from `PATH`, and a location is written in its owner's
  own words (`%ProgramFiles%`, `%GOROOT%`, `%ANDROID_HOME%`, `~`, `${HOME}`), with the newest installed
  build derived from disk where a location rotates with its version. A tool kept somewhere of your own
  goes into the per-install candidate pack with `add`, and `propose` suggests entries from a directory.
  A path that does not exist is skipped, and each existing result carries `declared`: what the file
  itself states about itself (product/version/vendor, read from its own version resource, statically -
  the tool is never executed)
- `library_sniff` - identify a file by its header bytes (108 signatures), independent of extension
- `library_format` - extend this machine's format library: `list` `scan` `learn` `add` `remove` `deps` `draft` `report` `deliver` `unseal`
- `library_decrypt` - read back an isolated sensitive object on request
- `library_export` - export to JSON/NDJSON
- `library_encoding` - report the host encoding and how to switch to UTF-8
- `library_adb` - developer-side Android device operations over ADB
- `library_sessions` - read this machine's own DSH sessions, and any exported session-log ZIP archive
  (DSH's archive format: `session*.jsonl` at the root, `subagents/<id>/...`, attachments under `media/`
  and `files/`). `op=list` enumerates sessions and archive members without reading transcripts;
  `op=read` returns a structural summary, and the message text only with `content: true`; `op=tail`
  decodes just the last frames; `op=search` scans frames for a phrase and returns snippets; `op=record`
  writes a session into the Library as a `log`; `op=bootstrap` runs the first-run pass described below;
  `op=status` reports it. Sessions are stored as one zstd frame per record, so
  frames are located by the zstd magic and decoded one at a time - a torn tail is counted, never guessed.
  Timestamps are UTC ISO-8601, and every response also carries `timezone` - the host's UTC offset,
  its zone name and the current local time - so a report can be read on a local clock without guessing.
  Local reads only: nothing is uploaded, no file is modified

### First run: mine the history before claiming to be installed

On its first start the plugin reads every session it can find and mines what a Library actually indexes -
tools that resolve on this machine, paths that exist, local endpoints, environment variables that are set,
and file formats this library does not know yet. Everything else in a conversation is dropped: a
246-session store (measured: 523 MB compressed, 1,509 MB decompressed, 1,478,647 records, read in 70.8 s)
leaves verified facts rather than a transcript archive: measured here, 253 sessions and 1,484,547 records
yielded 11,253 rows in about 49 minutes.
A format lead has to be seen at least twice to be recorded at all: in 1.5 million records an extension
mentioned once is usually a hash or a token, while a format that matters recurs. Mined rows carry
`source: session-mining` with a name derived from the fact itself, so a later pass replaces them instead
of piling up.

`bootstrap` decides how it runs: `blocking` (default - this Library registers its tools only after the
pass finishes), `gate` (it starts in the background and `op=status` reports it), or `off` (only an
explicit `op=bootstrap` runs it). `bootstrapBudgetMs` (default 300000) stops a pass cleanly, so a very
long history finishes over several starts instead of holding the host open, and it resumes where it
stopped. Every step is appended to `$DSH_HOME/library/bootstrap-progress.jsonl` with the current state in
`bootstrap-state.json` - one line per session, naming the file being read - so progress is visible while
it happens rather than only at the end.

### What a sensitive record can and cannot do

The sensitive-content rule is deliberate, and it is worth knowing exactly what it buys, because a record
about a *security tool* (a virus scanner, a signature rule set, a password vault, an encrypted-volume tool)
trips it for the plainest of reasons: the words that describe the domain are the words the patterns look
for. Such an object is stored encrypt-isolated, and it exposes only

```text
{ id, type, name, source, sensitive: true, createdAt, __content }
```

Everything else - `path`, `description`, `summary`, `tags` - is inside the encrypted blob. Three
consequences follow, and none of them is a fault:

- **It is findable by what it is called, not by what it says.** `library_query` can match the name and the
  source; a keyword that only appeared in its summary or tags will not find it.
- **`op=verify` skips it**, because its `path` lives in the blob and there is nothing to fingerprint. A
  report of `unchanged: 0` therefore does not cover sensitive records.
- **The body is one explicit step away**: `library_decrypt id=<id>` returns it, `library_export` keeps it
  encrypted on the way out, and every manual decrypt is written to the append-only log.

Rewording a description to slip past the patterns is not a workaround this plugin offers: it would evade a
deliberate boundary to gain readability and leave the record vaguer than it started. The honest route is
`library_index op=review`: with an id, a decision (`clear` or `revoke`) and a reason it either makes one
encrypted body readable or puts the rule back - per object, never by name or pattern, always written to the
append-only log, and a cleared object carries the review that let it through. `op=review` with no id lists
every object that carries one. Use it for records **about software** (a scanner, a rule set, a password
vault: the words that describe the domain are the words the patterns look for), never for the material
itself - a sample, a key or a credential path stays encrypted.

One more thing about samples, because it is easy to get backwards: **the Library seals references, never
material**. Encrypting a record about a quarantined sample hides *where the sample is and what it is
called*; it does not touch the file, which stays exactly where it is (this plugin only ever writes inside
`$DSH_HOME`). Software that learns from a corpus reads the corpus from disk, not from this index. What
makes that workable is keeping the two surrounding layers readable: the **directory records** that say
where a corpus lives, and the **tooling** that fetches, stores and scans it. Seal the individual items,
keep the anchors and the code visible, and a detector under development can still find everything it
needs - through the filesystem, which is where it was always going to read them from. The rule also
considers a record's `path` when deciding what is sensitive, so a sample named after its own hash is caught
by where it lives rather than by a word in its name.


## Install

```powershell
# first install
dsh plugin --profile web add github:Nesarf/mega-index-map
# upgrade an installed copy - `add` would report "resolution step is skipped" and leave the
# lockfile on the old commit, so an upgrade needs `update` by package name
dsh plugin --profile web update mega-index-map
```

## Notes

- The library lives at `$DSH_HOME/library` (default `~/.dsh/library`). Additions learned on this
  machine live beside it and never override the built-in tables.
- Work stays local: the plugin performs no network I/O and transmits nothing on its own.
- `library_index op=status` is the whole-library view in one read: object counts by type and source, how
  many records are encrypted and how many were cleared by a review, fingerprint coverage over the paths
  that can be fingerprinted, addresses versus paths, internal consistency (duplicate keys, missing fields,
  a sensitive flag without a blob), and the last disk-side findings quoted from the append-only log with
  their timestamps - so seeing the whole library never means walking the disk again.
- Measured cost at this machine's current scale - 11,649 objects, 6.0 MB index: a query takes about
  51 ms, recording one object 156 ms (it rewrites the index), a rebuild 124 ms (0 conflicts, 0 duplicates),
  and a status read 10 ms. At 5,000 objects the same three were 13 / 19 / 26 ms with a 2.3 MB index.
  Back up or migrate with `library_export`.
- Concurrent writers are serialised through a lock file: a lock whose owner died is taken over, and
  a busy one is waited for for up to two seconds before the write proceeds and says so in the log.
- This package and the sibling cross-harness build are read-only with respect to each other; nothing
  here writes outside `$DSH_HOME`, the OS temp directory or a path the caller passed in, and
  `scripts/check-isolation.mjs` enforces both directions (see [ISOLATION.md](ISOLATION.md)).
- Three things are held invariant and checked on every push: English/ASCII-only output,
  Windows/macOS/Linux portability, and UTF-8-safe handling of multi-language text.
  `npm run check` runs all of it (ASCII, consistency, portability, isolation), and
  `npm run selfcheck` runs the five-stage pass - smoke, traversal, proofread, traversal, smoke - keeping
  those three axes in view and reporting them per axis.
- MIT License. See [LICENSE](LICENSE).
