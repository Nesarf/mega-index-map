# `prune what=dead`: the pass that could not resume

A defect report from a workspace that consumes this Library, kept here (revised) because the numbers are the
argument and the boundaries it lists are the part a rewrite could lose. Everything below was measured against
this machine's Library; nothing about it is theoretical.

## What it was

`library_index op=prune what=dead` walks a candidate list that was **rebuilt from scratch on every call** and
stopped after `maxFiles` (default 500) or about 8 seconds, whichever came first. It then answered with
"... N not examined (bounded) - run it again to continue".

Running it again did **not** continue. The walk started at the same head, so `remaining` never fell and records
past the first slice were unreachable.

| call | args | checked | dead found | dropped | remaining |
| --- | --- | --- | --- | --- | --- |
| 1 | defaults | 169 | 0 | 0 | 12011 |
| 2 | defaults | 500 | 0 | 0 | 11680 |
| 3 | defaults | 500 | 0 | 0 | 11704 |
| 4 | defaults | 500 | 0 | 0 | 11700 |
| 5 | defaults | 500 | 0 | 0 | 11700 |
| 6 | `maxFiles: 20000` | 633 | 0 | 0 | 11568 |

Calls 4 and 5 are identical in `checked`/`remaining` - the second call did no new work. Call 6 shows the raised
`maxFiles` being honoured (633 > 500) with the **time budget** then binding, still from the same head.

The small movements in `remaining` are not progress: it was `candidates.length - checked`, and
`candidates.length` changes whenever the index does (an `op=index` registered 24 records between calls; an
`op=rebuild` dropped 4 superseded ones).

## Why it mattered

- A library that has ever had files deleted accumulates dead records monotonically: nothing could clear them,
  and every query kept returning paths that no longer exist.
- The note actively misled. A caller (human or agent) reads "run it again to continue", re-runs the default
  call, sees `checked: 500` again, and concludes it made progress.
- The read-only sibling `op=audit` reported the same set as a count, so the two ops disagreed about whether the
  cleanup was reachable at all. On this machine that set was 41 records (a plugin directory deleted the same
  day, all `source=session-mining`), which `op=audit dir=E:\...` listed without difficulty.

## What was wrong in the code

In the `prune` branch of `lib/index.js`, inside `if (what === "dead")`:

- the candidate list was recomputed from the whole index on every call, with no offset and no cursor;
- `remaining` was computed against that rebuilt list, so it described the head, not the work left;
- the returned note asserted continuation that the next call could not deliver.

`op=verify` in the same file already solved this shape for its own pass: it takes `after` as a cursor and
returns `nextAfter`, so a large library walks in slices. `what=dead` was the same kind of pass without the same
mechanism.

## The fix, as shipped

The cursor `op=verify` already uses, with one deliberate difference:

- **Candidates are sorted by id and the cursor is compared as an id, not as an array position.** A position
  moves whenever the index changes - a rebuild drops rows, an index run adds thousands - which is exactly how
  the walk silently returned to the head. Comparing ids is stable under that churn.
- `after` takes the id the previous call returned as `nextAfter`; a cursor whose own record has since vanished
  (pruned by an earlier slice, or superseded) resumes at the first candidate that sorts after it rather than
  starting over.
- `remaining` counts from the resume point, and `nextAfter` is null only when the walk really reached the end.
- The note names the cursor when work is left: `this call stopped at N of M; pass after: "<id>" to continue`.
- The schema descriptions for `after`, `maxFiles`, `budgetMs` and `nextAfter` say that `what=dead` reads them.

## What must not change while fixing this

These are the parts that are right; a rewrite could lose them:

- **The bound itself.** A pass that stat()s 12,000 paths in one call is not the goal; resumption is.
- **`unreadable` is not `gone`.** A locked file (`C:\pagefile.sys` on this machine) is kept and reported
  separately.
- **An address is not a path.** Records whose `path` is a URL are not candidates.
- **A sensitive record has no visible path**, so it survives by construction.
- **The atomic index write and the `appendLog({ op: "prune", ... })` entry.**

## Acceptance test

Four assertions in `scripts/selfcheck.mjs` encode this, under `op=prune what=dead`:

1. a bounded pass hands back a cursor;
2. the next call resumes after that cursor instead of re-walking the head;
3. the note names a cursor only when a next call would really continue;
4. following the cursor terminates the pass with nothing left.

They run in both smoke stages, so a regression shows up twice. The self-check loads the plugin from disk, so
these exercise the shipping code rather than a copy.

For the tool door, note that plugin code changes take effect only after the host restarts: until then a call
through `library_index` still runs the previous build.
