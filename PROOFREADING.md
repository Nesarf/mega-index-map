# Third-party proofreading

This repository is the DSH plugin edition. A sibling cross-harness edition shares the same lineage as
an MCP server plus a CLI; it is declared locally and no shipped file names it. This repository is
used as a read-only reference when proofreading that sibling, and this file is the durable
record of each pass, because the sibling has no version control of its own.

The direction rule is strict both ways:

- this repository is a reference for the sibling, never an input that modifies it;
- nothing found in the sibling is copied back into this repository's code without being
  adopted deliberately, here.

Each round states what was checked, what was found, and how the finding was verified. Every
claim below is backed by a re-runnable command: `npm run check` for the ASCII and consistency
invariants, plus the machine-local suites named per round, whose assertions are unchanged
copies of this repository's own suites.

## Round 1 - the sibling cross-harness edition, 2026-09-11

Two passes: portability and key-file permissions first, then the self-extending format library
and its documentation.

Checked and found correct, no change needed:

- format library, 27 checks: `scan` proposes unidentified types without learning anything,
  `learn` intersects a signature from explicit samples only, a single sample and disagreeing
  samples are both refused, a local signature can never shadow a built-in one, local text
  extensions and name rules apply as documented, and the persistence regression still holds
  (a malformed name rule on disk is dropped instead of becoming a match-everything pattern).
- native delivery dialog, 13 checks: the report window opens on this platform, returns the
  user's action, and nothing is transmitted.
- core smoke, 34 checks, and a symbol plus ASCII audit with 0 findings.

Fixed in the sibling tree, nothing in this repository changed:

- tool-count drift in four places, the registry holds 12 tools while the header comments and
  the documentation said 11, plus one registered tool missing from the documented list;
- an entry-point description that named a file the sibling tree does not contain;
- portability gaps in the tool search paths, and key files written without owner-only
  permissions on POSIX;
- five user-visible strings that made the sibling's native report window identify itself by
  this package's name.

Deliberately left alone, recorded so that a later round does not change them by accident:

- the sibling's report intake markers still carry this package's name, because those reports
  are read by this package's maintainer;
- the sibling's key-derivation domain separators are untouched, since changing them would
  invalidate anything already sealed with the old value.

## Round 2 - hardcoded values, 2026-09-11

A sweep for values baked into source instead of derived, resolved or configured: machine paths,
embedded endpoints, vendor names, duplicated versions and stale counts. Every hit was judged, so
that the intentional ones are recorded as decisions rather than left to be re-flagged.

Intentional and kept, by design:

- the machine-local seed catalogs (the candidate lists in both trees, and the media engine paths):
  each entry is existence-checked, carries cross-platform alternatives, and the media and device
  engines can be pointed elsewhere with `FFPROBE_PATH` / `MEDIAINFO_PATH` / `ADB_PATH`;
- the report intake address, kept in round 1 for the maintainer's own filtering;
- repository identity strings (package URLs, the install command) and the version field itself.

Fixed in this repository:

- the release workflow built its install line from a hardcoded `github:Nesarf/mega-index-map` while
  the changelog line one screen below already used `${GITHUB_REPOSITORY}` - both now derive it;
- two user-facing strings pointed at a specific third-party upload service; they now say "a file
  host of your choice" (identical guidance, no embedded vendor);
- the seed-list comment and the README `library_detect` line now state that the built-in paths
  describe one machine's layout, that missing paths are simply skipped, and how to seed your own.

Fixed in the sibling, which has no version control of its own:

- its MCP server advertised a second hardcoded version string while the core elsewhere reads the
  version from package.json; it now imports that single derived value (checked with a live MCP
  handshake - `initialize` reports the package version, not a literal);
- one tool description used two of the maintainer's own workspace names as examples; they are now
  neutral example paths;
- the workstation document claimed 10 tools in four places; the registry holds 12.

Audit tooling for the next pass: a dependency-free scanner (machine paths, embedded endpoints and
mail addresses, vendor names, duplicated versions, dates, GUIDs, ports, credential-shaped values)
plus a per-line dump for judgement. Note the trap: a naive drive-letter pattern also matches the
`s:/` inside `https://`, so the rule must exclude a letter preceded by a word character.

## Round 3 - full proofread and traversal of this repository, 2026-09-11

Scope: this repository alone. Every local suite was run (193 checks across 8 suites), together with
the 55-call traversal and its 1,600-file false-positive sweep, both repository invariants, and a new
runtime contract sweep that makes 99 calls (including malformed ones) and diffs the keys actually
returned against each tool's declared output schema. An independent adversarial read of
`lib/index.js` was commissioned as well; every one of its 16 findings was reproduced or refuted here
before anything changed, and three of them did not survive that check.

Fixed after reproduction:

- `library_sniff` reported a missing path, a directory passed as `path`, and a zero-byte file all as
  `kind: "empty"`, because the header reader returns no bytes in all three cases. It now reports
  distinct kinds (missing / directory / unreadable / special / empty) with a note, and its
  description says what each mode returns.
- The locale rules used on Linux and macOS matched language and country codes as bare substrings:
  KOI8-R was read as Korean, `en_GB` as Chinese, and `en_GB.ISO-8859-1` hit the gb rule before the
  ISO-8859-1 rule. The locale is now parsed as `<language>[_COUNTRY][.codeset]`, `C`/`POSIX` count
  as plain ASCII (which is valid UTF-8), and EUC-JP is recognised apart from Shift-JIS. Five
  regression checks were added to the POSIX suite.
- `library_format`'s output schema declared `draft` and `paths`, which no branch has ever returned.
- `op=deps` returned `unidentifiedCount: <files inspected>` - a key whose name promised something it
  did not contain.
- `op=report` advertised passphrase protection whenever `seal` was passed, even when the archive
  contained no sealed layer; it now follows the archive's actual state.
- A report dialog program that fails to launch (missing `powershell.exe`/`sh`, EACCES) left the
  caller waiting out the full 60 s cap and then reported "pending", which reads like a user still
  deciding. It now reports "unavailable" at once.
- `saveIndex` wrote `index.json` in place, so a crash, a kill or a full disk mid-write truncated it
  and the next read returned an empty library over the top of it. It now writes a sibling temp file
  and renames it into place.
- A library directory that cannot be created made every read throw, because `ensureLibrary` ran
  outside `loadIndex`'s try block; reads now degrade instead, and a failed write names the
  directory that is not writable.
- A directory passed where a file was expected reached `readFileSync`/`writeFileSync` as EISDIR in
  `op=unseal`, `op=deliver`, `op=report out`, `op=draft out` and `library_export path`. All five now
  refuse with a structured result.

Refuted, and recorded here so that a later round does not "fix" them:

- a non-array `tags`/`links` cannot reach `execute`: the harness validates arguments before the tool
  runs, which is why the same class of guard exists in the query tool for a different reason.
- `library_export` takes `path`, not `out`; that finding was built on a parameter name that does not
  exist, and the call it described silently exported to the default file instead.
- the locale fault does not reproduce on Windows at all: win32 reads the console code page, so the
  locale rules only ever apply on Linux and macOS.

Known gap, deliberately left as its own change: the two local-pack writes (`saveLocalCandidates`,
`saveLocalFormats`) are still unlocked read-modify-write cycles, so two processes sharing one
`$DSH_HOME` can lose a concurrent `library_format add/remove` or `library_detect add/remove`. The
commit message of `ade7910` states that both pack writes use the lock; that statement is wrong and
this line corrects it. Closing the gap means holding the lock across load-mutate-save at five call
sites, i.e. restructuring a verified file, so it is not folded into a proofreading pass.

Two declared keys cannot be observed headlessly and are not defects: `library_format.savedTo` needs
a human to press Save in the native window, and `library_adb.local` needs an attached device.

## Round 4 - isolation guard and a five-stage self-check, 2026-09-11

Added, so that the two-way read-only rule is enforced rather than assumed: `ISOLATION.md`, the static
scan in `scripts/check-isolation.mjs` (wired into `npm run check`, therefore into CI), its witness
mode (`snapshot` / `verify`), and a README pointer.

The self-check ran the sequence smoke, traversal, proofread, traversal, smoke - bracketed by a
snapshot before it and a verify after it - i.e. 193 suite checks twice, the 55-call traversal and its
1,600-file false-positive sweep twice, the three repository invariants plus the static and hardcoding
audits in the middle, and the sibling's own read-only cross-check as the reverse-direction witness.

The first smoke pass was clean and the second was not: the lock suite dropped to 5 of 8, with one
child process exiting 1 and 22 of 50 records lost. Everything else was identical in both passes.

Root cause, confirmed under stress: the temp-file-plus-rename from round 3. On Windows a rename over
a file another process holds open fails (EPERM/EBUSY/EACCES), and readers of the index are
deliberately lock-free, so a concurrent read blocked the swap, the write threw, and the child died. A
ten-round, two-process stress reproduced it in 2 of 10 rounds. The fix retries the rename briefly and
then writes in place, logging that the atomic swap was blocked, because never losing a record
outranks the crash-safety of the swap. After the fix: 10 of 10 stress rounds and five consecutive
lock-suite runs clean.

A finding about the witness itself: the verify reported two changed files, both in the sibling tree
(its `core.mjs` and a new `tools/selfcheck.mjs`). That is the sibling's own session at work, not this
package reaching across the boundary - the static guard proves there is no write path to reach with.
A snapshot can never tell "the sibling moved" from "we moved the sibling", so the witness now
attributes each difference to its side and exits 3 for a sibling-only move and 1 for a change to this
repository or to the user's library; the static guard is what closes the gap the snapshot leaves.

## Round 5 - the local-pack writes are locked, 2026-09-11

Closed the last unlocked read-modify-write cycle in this package. `library_format` learn/add/remove
and `library_detect` add/remove each read a local pack, changed it and wrote it back without the
cross-process lock, so two processes sharing one `$DSH_HOME` could read the same pack and the later
writer would silently drop the other's entries. The record for round 3 already noted that the commit
message of `ade7910` claimed otherwise; that claim is now true rather than corrected.

`updateLocalFormats` / `updateLocalCandidates` take the same lock as the index, re-read the pack
inside it, apply the caller's intent to that fresh pack, and save. The five write sites now express
their change as an intent instead of mutating a copy read before the lock.

Measured with two processes adding 25 formats and 25 candidates each, against the previous build and
the fixed one with the same harness:

- before: 0 of 5 rounds survived intact - formats 43 to 49 of 50, candidates as low as 2 of 50, and
  exit code 0, so the loss was completely silent;
- after: 5 of 5 rounds hold exactly 50 and 50, with no lock warnings in the library log.

The stress harness runs both builds side by side (`MEGA_PLUGIN`), so this test cannot quietly stop
detecting the defect. The five-stage self-check, both traversals, the three invariants, the runtime
contract sweep and the isolation witness all pass afterwards.

## Round 6 - the shell that hosts the dialog, and a full self-check, 2026-09-11

One portability change, and the pass that followed it.

Changed: the native delivery dialog no longer hardcodes `powershell.exe`. Both PowerShell 7 (`pwsh.exe`)
and Windows PowerShell 5.1 can host the WinForms dialog with `-STA`, so `dialogShell()` now prefers 7 -
the shell modern Windows installs and the one this machine defaults to - searching the standard install
location first and then every PATH entry (which also covers portable copies and the Microsoft Store
alias), and falling back to `POWERSHELL_PATH`/`powershell.exe`. `PWSH_PATH` overrides the choice, and the
deliver result reports `shell`, so which program ran the window is never a guess. The POSIX path is
untouched. Verified by a self-test deliver that really opened the window under pwsh 7.6.6.

The five-stage self-check afterwards: 193 suite checks twice, the traversal twice (59 of 59 assertions
and 0 flagged in the 1,600-file sweep, both times), the three repository invariants, the static audit
with 0 problems, the runtime contract sweep at 100 calls with one remaining unobservable key
(`library_adb.local`, which needs an attached device), and an isolation witness reporting 38 files -
both trees and the user's library - byte-identical across the whole run.

Environment note, recorded because it explains what the dialog was verified under: the host's default
PowerShell is version 7, which hosts the dialog; Windows PowerShell 5.1 is still present and remains the
fallback path in the code. Which shell a particular machine prefers is machine state, not repository
state, and it is kept in a local machine map rather than here.

Standing requirement for every pass, recorded 2026-09-11: each round must hold three axes explicitly -
English/ASCII-only output (except the documented CJK sensitive-content patterns), mainstream-OS
portability (nothing may assume Windows; Windows-specific code needs a POSIX counterpart, argv-only
spawns, `os.tmpdir()` for temp files and `path.delimiter` for PATH), and multi-language encoding
adaptation (UTF-8 in and out, an explicit encoding on every text read/write, a stated BOM policy, and
locale detection that cannot read a two-letter substring as a language or country code).

The three axes and the five stages are now executable rather than remembered: `npm run selfcheck`
(`scripts/selfcheck.mjs`) runs smoke, traversal, proofread, traversal, smoke, and reports the three axes
with a per-axis count, so a pass that silently drops one is visible. The static half of the axes is
enforced by `check-ascii.mjs` and `check-portability.mjs` on every push; the behavioural half is in the
self-check itself (encoding round trips, unicode paths, argv spawns, ASCII-only plugin vocabulary - user
data may of course be any language). `--plugin <path>` points the battery at another build, which is how
the checks are fault-injection tested: a non-ASCII note, an unenforced built-in clash and a BOM-prefixed
index each turn it red.

Next round: re-run the five-stage sequence after any change to the lock or the dialog, keep the edits
surgical and verified, and do not copy code between the two trees.

## Round 7 - machine-neutral seed (2026-09-11)

A review pointed at the built-in candidate list in `library_detect`: its entries named the maintainer's
own disks outside the system drive, which read as "this plugin was grown on one person's machine". The
claim was reproduced from the shipped source and then removed, in four parts.

1. `resolveCandidatePath()` and `resolveTool()` now resolve a bare command name from `PATH` (with
   `PATHEXT` on Windows, so `mediainfo` finds `mediainfo.exe`), and fall back to a name match inside the
   per-install candidate pack. That is what makes a neutral seed useful: a normal install is found where
   the user put it, and a tool kept somewhere unusual is found through the pack the user seeded.
2. `DETECT_CANDIDATES` is a machine-neutral list: bare command names plus vendor-default install
   locations and POSIX conventions (`/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/snap/bin`,
   `~/.local/bin`). 16 entries.
3. The media and device engines lost their personal paths the same way: `ffprobe`, `MediaInfo` and `adb`
   resolve env var -> conventional location -> local pack -> `PATH`, with `FFPROBE_PATH`,
   `MEDIAINFO_PATH` and `ADB_PATH` still overriding everything.
4. The maintainer's own locations were dealt with by kind, and none of them is written down here. The
   ones whose directories are already on `PATH` are found by the neutral seed with no help at all; the
   rest went into this install's local candidate pack - six entries in
   `$DSH_HOME/library/candidates.local.json`, added through the documented `library_detect op=add` path -
   with the object index verified byte-identical afterwards (the pack is a separate file from the index).

Verified, not asserted. A dedicated battery kept out of this tree (it is machine-specific scaffolding,
not a shipped test) checked:
(a) fault injection - re-introducing each fault turns `check-portability.mjs` red: a non-system-drive
seed path, a named user profile, and a `PATH` split on `";"` (that third one exposed a same-line blind
spot in rule 7, and the rule now also catches the regex form and a call chained over two lines);
(b) behaviour - a bare name resolves from a synthetic `PATH` entry, and against the real home the
neutral seed plus migrated pack resolves **16 entries with 0 lost** against the pre-change baseline of
14, gaining `Node.js` (on `PATH`) and `adb` (previously not in the seed at all);
(c) the engines - `ffprobe` answers through `PATH` and `MediaInfo` through the local pack, each proven in
its own process (engine paths resolve once at registration, so an override has to precede the import),
while masking both engines falls back to the header signature instead of claiming one.

A new portability rule (10) now enforces this: no non-system-drive path and no named user profile in the
shipped source, and at least one bare command name in the seed. `check-isolation.mjs` also stopped
naming the sibling tree absolutely - it now resolves it beside this checkout, `MEGA_INDEX_SIBLING`
overriding.
## Round 8 - the seed speaks in declared values, and identity is read statically (2026-09-11)

Removing the maintainer's paths left one kind of literal behind: vendor-default locations written as
`C:\Program Files\...`. The direction taken here is the one the sibling project already uses on binary
plugins - reverse-engineer the artefact and let its own declarations be the source of truth, read-only
and never executing it - applied to the candidate seed.

1. `expandDeclared()` resolves a location written the way its owner publishes it: `%VAR%` (Windows),
   `${VAR}` / `$VAR` (POSIX) and `~`. The OS declares its own folders, a toolchain declares its root, and
   nothing is executed to expand one - a reference to an unset variable resolves to nothing at all,
   because a fabricated root could point at another user's or another product's tool. The seed now
   carries 29 declared references across 78 locations, and **zero** literal drive paths.
2. `pickNewest()` derives a version-rotating folder from the disk: the WDK entry says "the newest build
   under `%ProgramFiles(x86)%\Windows Kits\10\Include` that actually carries `km`", so no
   `10.0.26100.0` literal has to rot. On this machine it resolves to exactly the path the old literal
   named.
3. `declaredIdentity()` reads what a tool says about itself from its own version resource
   (VS_VERSIONINFO: ProductName / ProductVersion / FileVersion / CompanyName / FileDescription, plus the
   fixed-file-info copy), bounded to the exact byte ranges needed and bounds-checked field by field. It
   spawns nothing and executes nothing. `library_detect op=scan` attaches the result to every existing
   candidate as `declared`, and the registered object's summary carries the tool's own words - the only
   description that stays true as versions move.
4. Portability rule 11 enforces all of it: no literal drive path in the seed, at least five declared
   references, `expandDeclared()` and `pickNewest()` must exist, and `declaredIdentity()` must contain no
   spawn or exec.

Verified against an independent oracle. Six binaries (Git, Node.js, signtool, MediaInfo, devenv, and the
running interpreter) match Windows' own `VersionInfo` API exactly. Two OS components (notepad, cmd) do
not - and that is the interesting case: the resource inside the file says `10.0.26100.8972` while
Windows reports the servicing layer's `10.0.26100.8875`, so the reader was checked against a second,
independent oracle: the raw UTF-16LE strings sitting in the file, which it matches. Four binaries
(ffmpeg, ffprobe, uv, go) carry no version resource at all - Windows reports nothing for them either, so
`null` is the correct answer rather than a guess. Failure modes were exercised too: text named `.exe`,
a truncated image, an empty file, an ELF file and a directory each return `null`.

Fault injection covers the new rules as well: a literal drive path in the seed, a seed stripped of every
declared value, and a `declaredIdentity()` that would run the tool each turn the invariant red. Two
faults also caught bugs in the *checker* itself: rule 11's message interpolated `${HOME}` as a template
variable and crashed exactly when it fired, and rule 7's path-split rule was blind to a split chained
over two lines (which the new resolver does). Both were fixed, and both are now covered by an injection.

The scan was then re-measured against the pre-change baseline for this machine: **16 resolvable with 0
lost** (baseline 14), gaining `Node.js` (on `PATH`) and `adb` (previously not in the seed at all). The
five-stage self-check grew to 73 checks (from 65) - it now declares the running interpreter through
`op=add`, scans it back and asserts the product name and version its own resource states, and asserts
that a non-image declares nothing; `npm run selfcheck` reports 73/73 with the three axes at 4/4, 39/39
and 30/30.

## Round 9 - the Library asks to be asked (2026-10-10)

The complaint this round answers: a host with no hint about this Library answers "where is tool X" by
walking the filesystem - minutes of I/O and a great many tokens for something already recorded here.

Two mechanisms were considered, and both were built, in the order that matters:

1. **The tool descriptions carry the trigger.** A tool catalogue is in context for free, so the cheapest
   prompt is a description that says when it is the cheaper answer. `library_record`, `library_query`,
   `library_detect`, `library_sniff` and `library_index` now open with that clause - ask the Library
   before researching, before hunting for a tool/runtime/SDK, before opening a file to guess its type,
   before walking a directory to see what is in it - and the skill's `description`/`whenToUse` say the
   same. The wording follows the pattern the volcano-separator MCP tools use ("What is running right
   now, with ages, ..."), which is what makes them get called at the right moment without any injection.
2. **An opt-in session notice**, off by default. `injectPrompt: true` registers one `agent/pre-step`
   hook that prepends a short notice to a session's first user message - the mechanism the disk-guard
   plugin uses for its path discipline, verified by reading its source rather than guessed: it needs no
   new injection point, since this plugin already declares `inject: ["tools"]`. The hook injects once per
   session, skips subagent sessions, leaves a session that already carries user messages alone, and
   swallows its own errors so a notice can never break a turn. The wording is replaceable wholesale at
   `$DSH_HOME/mega-index-prompt.md`; the shipped default is ASCII/English, because this package's
   shipping rule is ASCII-only.

Also in this round, `library_index` learned the other half - making the records match the disk:

- `op=audit dir=<path>` - read-only reconciliation in both directions: entries under that root with no
  record, and records under it whose path no longer exists. This is the "recorded is not the same as
  addressable" problem the 2026-10-06 audit left in the record, now answerable by one call.
- `op=index dir=<path> confirm=true` - registers the missing entries, bounded by `depth` (default 2, max
  6) and an entry ceiling, with `type`/`includeDirs` to shape what is written and the sensitive-content
  rule still deciding what may be stored in the clear (a sensitive name is skipped and counted, never
  bulk-encrypted). **A drive root is refused**: an indexer that would happily walk a whole disk is the
  very scan this Library exists to replace.

Verified by behaviour, not by reading: the self-check grew from 85 to **119 checks** and now walks a
fixture tree, asserts that `op=audit` reports the unrecorded entries and finds no dead path, that
`op=index` without `confirm` is refused *and writes nothing* (object count compared before and after),
that a confirmed `op=index` registers the entries and types them by kind (a `.ps1` becomes a tool, a
directory becomes a workspace), that a second audit then sees the tree as recorded, and that a record
pointing at a path the disk does not have is reported as dead. The notice is tested through a captured
hook: absent unless configured, registered with `injectPrompt:true`, reaching the first user message,
**ASCII-only**, injected once per session, skipped for a session with prior user messages and for a
subagent. Two of those checks failed on their first run for a reason worth keeping: the battery runs the
smoke stage twice, so a shared fixture directory and reused session ids made the second pass assert on
the first pass's state - both now carry a per-run suffix. `npm run selfcheck` reports 119/119, the three
axes at 6/6, 83/83 and 30/30, and the four invariants stay green.

## Round 10 - reading DSH's own sessions (2026-10-10)

What was asked for: let this Library unpack and read every DSH session, archived ones included, so a past
conversation does not have to be re-derived or re-scanned.

The format had to be discovered before anything could be written, and the discovery is the interesting
part. The store is 246 files in `$DSH_HOME/sessions/<workspace>/<session-id>/session.jsonl.zstd`, 524 MB,
and **a public zstd decoder reads one record out of it**: on a 56 MB session `zstdDecompressSync` and a
streaming `createZstdDecompress()` both stopped at the first frame ("Unknown frame descriptor"), while
locating frames by the zstd magic `28 B5 2F FD` and decoding them one at a time read 162,050 of 162,050
frames - 111.7 MB of JSONL, 220,881 records, ~7 s. The host does the same thing internally
(`dsh-session-persistence-jsonl` carries a private multi-frame decoder for exactly this reason). Record
shapes were learned from the files rather than assumed: the session header carries its fields at the top
level, `user/message.data.content` and `assistant/message.data.message.content` hold `[{type,text}]`
blocks, `tool/call` holds a name and arguments, and `session/title` gives each session its own title.
An archive, in DSH's words, is a ZIP from "Download this Session log": `session*.jsonl` at the root,
subagents under `subagents/<id>/`, attachments under `media/` and `files/`.

So the eleventh tool is `library_sessions`, with five bounded ops: `list` (header and title per session,
no transcript), `read` (structural summary; text only with `content: true`), `tail` (last frames only),
`search` (frame-by-frame, snippets only), `record` (writes a session into the Library as a `log`). Every
op is capped by records, characters, files, frames and hits; a frame that will not decode is counted, and
a head-read that ends mid-frame is reported as a cut frame rather than a corrupt one. Plain reads: nothing
is uploaded, no session file is modified.

Verified twice over. The self-check grew from 119 to **147 checks** (three axes 6/6, 111/111, 30/30) and
now writes a session the way the host writes one - one zstd frame per record plus a deliberately torn
trailing frame - then asserts the header, the title, the torn-frame count, structure-without-content,
`content:true` text, tail-only decoding, phrase search, a missing session being refused, recording into
the Library, and a hand-built exported ZIP read through `#member` (both listing its session members and
searching inside it). Against the real store, read-only: **246 sessions listed in 6.5 s, 246 with a
header cwd, 233 with a title, 0 unreadable frames**; `read` of a 3372-frame session in 131 ms with record
types and a time range; `tail` in 121 ms; `search` finding 30 hits across 49,263 records in 23 files in
1.6 s; and **0 of 246 session files changed** by the run (the real library was not touched - the test ran
against a temp home and only passed the real store as a read target).

Three of those bugs were only visible on the real store, which is why the real store was part of the
verification: the session header's fields sit on the record itself, so reading `record.data` gave 246
sessions with a null `cwd`, `createdAt` and `formatVersion`; the list path reads only the first 256 KB, so
its final frame is cut mid-frame by construction and 170 sessions were reported as having unreadable data;
and the "no session store here" guard asked for `args.dir`, which `read`/`tail`/`record` do not take, so
they refused any target they were given. A fourth was caught by the self-check rather than the store:
`zstdDecompressSync` had never been imported, and the per-frame try/catch swallowed the resulting
ReferenceError as "unreadable" - a silent zero that reads like "no such session". Besides importing it,
the reader now states the runtime capability up front (Node v23.8+, or v22.15+) instead of reporting every
frame as unreadable, and a test that swallows an error now has a test that would notice.
