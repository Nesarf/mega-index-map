# Isolation between this package and the sibling build

This repository (`mega-index-map`, the DSH plugin) and a sibling cross-harness build (an MCP server
plus CLI) share one lineage but must never touch each other's files. The sibling checkout is declared
locally - `MEGA_INDEX_SIBLING`, or `.isolation.local.json` beside this checkout, which never ships - so
no shipped file has to name it. The rule is two-way and absolute:

1. **This repository is read-only with respect to the sibling.** Nothing here may create, modify,
   move or delete anything under the sibling tree - not at build time, not at run time, not from a
   script, not from a test. The sibling may be read (to compare tables, to proofread), never written.
2. **The sibling is read-only with respect to this repository.** Nothing in the sibling tree may
   write into this repository either. Its own cross-check tool reads a file here and reports; that is
   the only permitted direction.

Both directions exist because the trees are deliberately separate: this one is the narrow DSH-only
plugin, the sibling is the wider universal build. Merging them silently would destroy the point of
having two.

## How the rule is enforced

- `scripts/check-isolation.mjs` - static rules, run by `npm run check` and therefore by CI on every
  push: no write-capable call in this repository may name the sibling or carry a hardcoded absolute
  path as its target, and this repository may not spawn a program pointed at the sibling. The guard is
  built from the locally declared path, so it bites on the machine that has the sibling without the name
  appearing in shipped source. When the sibling tree is present it is scanned the same way, in the
  opposite direction.
- Witness mode, for the read-only claim itself: `node scripts/check-isolation.mjs snapshot` records
  hashes of this repository, of the sibling tree (when declared) and of the real
  `$DSH_HOME/library/index.json`; `node scripts/check-isolation.mjs verify` re-hashes and fails if a
  single byte moved. Run the snapshot before a test or proofreading session and verify after it: a clean
  verify is the evidence that the session wrote to neither tree and did not disturb the user's own
  library.
- The reasoning behind each deliberate non-interaction is recorded in `PROOFREADING.md`.

## What this repository may write

Only these, and never anything else:

- the library under `$DSH_HOME/library` (index, payloads, local packs, logs, reports, drafts);
- files under the operating system's temp directory, for dialogs and probes;
- the output path a caller passes explicitly to a tool (`out`, `path`, `file` arguments).

Every write target is computed from `$DSH_HOME`, from `os.tmpdir()` or from a caller argument. A
hardcoded absolute path in a write call is treated as a defect by the isolation check, even if it
happens to point somewhere harmless.
