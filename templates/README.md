# PLAN.json templates

A project map is made of five sections, and the templates cover each. A template is a
**readable, self-contained plan**: copy it to your repository's `design/PLAN.json`, replace the
example content with your own, then run `library_project op=plan root=<your repository>` and make
the `missing` list empty. A healthy plan reports an empty missing list, which is the reader's
whole point: a touched path that is not there, a judge that is not there, a structure entry that
is not there, or a declared section that was never written is reported instead of being smoothed
over.

## The five sections

| Section | What it holds | Where it lives |
|---|---|---|
| `structure` | The layout convention: what lives where and why. The live file/edge picture is what `op=map` computes, so the file keeps the convention, not a file list that drifts. | the `structure` block: `layout` sentence plus `entries` (directory to role). The `entries` paths must exist. |
| `units` | The detail per unit: each goal read for what it is, what it touches, and what judges it. | the `goals` array, read one row at a time. |
| `status` | The overall state: one summary sentence, the as-of date, and the metrics. | the `status` block: `summary`, `asOf`, `metrics`. |
| `plan` | The roadmap: the same goals read for their network - parents, order, statuses. | the `goals` array, read through `parent`/`after`/`status`. |
| `environment` | The world outside the repository: tools on PATH, runtimes, borrowed pieces. Carried through as written, never verified. | the `environment` block: `tools`, `runtimes`, `borrowed`. |

A `sections` declaration at the top says which of the five the file covers. Declaring one and not
writing it is a broken record. Without a declaration, the reader infers the coverage: goals cover
`units` and `plan`, and each of the three blocks covers its own section.

## The templates

| Template | Covers |
|---|---|
| `PLAN.sections.json` | All five sections in one unified map |
| `PLAN.structure.json` | `structure` alone |
| `PLAN.units.json` | `units` (and `plan`, since goals carry both) |
| `PLAN.status.json` | `status` alone |
| `PLAN.plan.json` | `plan` (and `units`) |
| `PLAN.environment.json` | `environment` alone |
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
