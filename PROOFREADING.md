# Third-party proofreading

This repository is the DSH plugin edition. A sibling cross-harness edition,
sibling-checkout, shares the same lineage as an MCP server plus a CLI. This repository is
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

## Round 1 - sibling-checkout, 2026-09-11

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

Next round: keep the edits surgical and verified, and do not copy code between the two trees.
