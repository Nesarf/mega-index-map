# PLAN.json templates

Four starting skeletons for `design/PLAN.json`, one per repository shape. Each template is a
**readable, self-contained plan**: copy it to your repository's `design/PLAN.json`, replace the
example goals with your own, then run `library_project op=plan root=<your repository>` and make
the `missing` list empty. A healthy plan reports an empty missing list, which is the reader's
whole point: a touched path that is not there, a judge that is not there, or an edge that points
nowhere is reported instead of being smoothed over.

| Template | Repository shape |
|---|---|
| `PLAN.minimal.json` | One goal, the field anatomy itself |
| `PLAN.capability.json` | A plugin or tool: one release root, one goal per capability |
| `PLAN.migration.json` | A stage-by-stage migration: settled plan, then one goal per stage |
| `PLAN.spec.json` | A specification layer with a reference implementation as its judge |

## The fields

| Field | Meaning |
|---|---|
| `id` | Stable identifier; the network's edges and every `missing` report refer to it. |
| `title` | One sentence on what the goal is. |
| `scope` | The layer: `release` for the whole-product roots, `capability` for the surfaces under them. |
| `status` | Where the goal is: `done`, `active`, `open` (and `blocked` where a goal is stuck). |
| `parent` | The parent goal's id, or `null` for a root. |
| `after` | Ordering edges: ids that must be done before this goal can honestly start. |
| `source` | Where the goal's facts came from: a document, a section, a tool. |
| `notes` | The record: for a done goal, the decision and its reason; for an open one, what is missing. |
| `touches` | Files or directories the goal changes. A directory stands for the files the map knows under it; every path must exist. |
| `verifiedBy` | The suites that judge the goal; every path must exist. |

Rules the reader enforces, so keep them in mind while replacing the examples:

1. every `touches` path must exist relative to the repository root;
2. every `verifiedBy` path must exist (a judge that is not there is reported);
3. every `parent` and `after` id must name a goal in the same file.

The templates themselves are judged: `scripts/test-regressions.mjs` copies each one into a fresh
fixture repository, reads it with `library_project op=plan`, and asserts the missing list is empty.
