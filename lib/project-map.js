// library_project: given a project root, answer what it is made of, what imports what, and which tests a
// change touches.
//
// Why it lives in mega-index-map: the Library answers "what is on this machine", and this answers "what is
// inside one project". The same idea at a different scale.
//
// Language rules are data, not code: one record per language, naming its extensions and the regexes that pull
// module specifiers out of a source file. Adding a language means adding one record; the walk and the resolver
// are untouched.
import fs from "node:fs";
import path from "node:path";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", "target", "vendor",
  ".next", "coverage", ".cache", "__pycache__", ".venv", "venv", "bin", "obj",
]);

// One record per language: a name, the extensions it owns, and regexes whose capture group 1 is the module
// specifier. String-path loaders are listed on purpose - a source loaded by name at run time is still a
// dependency, and leaving them out makes a map that looks complete and is not.
const LANGUAGE_RULES = [
  {
    name: "js",
    extensions: [".mjs", ".js", ".cjs", ".mts", ".ts", ".tsx", ".jsx"],
    patterns: [
      /(?:^|[\s;])import\s+(?:[^"'`]*?\sfrom\s*)?["']([^"']+)["']/gm,
      /\brequire\(\s*["']([^"']+)["']\s*\)/g,
      /\bimport\(\s*["']([^"']+)["']\s*\)/g,
      /\b(?:loadUnit|loadFile|compileFile|runFile|readUnit|loadModule)\([^)]*?["']([^"']+)["']/g,
      // A suite writes the source it compiles into a command-line argument:
      //   spawnSync(node, ["bin/hmyr.mjs", "--compile", "self/x.hmoca", ...])
      // That is a real dependency: change that source and this suite goes red. It lives in .mjs,
      // so the rule belongs to this language rather than to hmoca - rules are chosen by the
      // extension of the file being scanned, and the first version put it in the wrong place on
      // 2026-11-02, raising the edge count by 5 while self/curve.hmoca's blast radius did not
      // grow at all. The quote and the comma sit between --compile and the path, not a space.
      /--(?:compile|run)["']?\s*,\s*["']([\w./\\-]+\.(?:hmoca|hmyr))/g,
      // A suite also writes tool scripts into command-line arguments:
      //   spawnSync(node, ["tools/curve-batch.mjs"], ...)
      // No import there, and it is still a real dependency: change that probe and this suite
      // goes red. Merged in from D:\himeyuri\tools\impact.mjs on 2026-11-02, same origin as
      // the rule above.
      /["']((?:tools|bin|src|test|vm)\/[A-Za-z0-9_./-]+\.mjs)["']/g,
      // The same file written the other way: path.join(ROOT, "tools", "hmget.mjs"), two
      // segments. The rule above wants one string starting with a directory name, so it cannot
      // see a split one - and that shape has been in D:\himeyuri all along
      // (test/hmget.test.mjs), just never measured.
      /path\.join\(\s*ROOT\s*,\s*["']([^"']+)["']\s*,\s*["']([^"']+\.mjs)["']\s*\)/g,
    ],
  },
  {
    name: "c",
    extensions: [".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"],
    patterns: [/^\s*#\s*include\s*["<]([^">]+)[">]/gm],
  },
  {
    name: "hmoca",
    extensions: [".hmoca", ".hmyr"],
    // Both spellings are recognised: the HMYR sources now write their import keyword in Han
    // characters (renamed on 2026-11-02), while this map used to look for the Latin word only -
    // so fifty-four .hmoca dependencies vanished silently and the edge count fell from 681 to 627.
    // A dependency the map cannot see is worse than no map: it makes a file look as though
    // nothing depends on it.
    //
    // The last two patterns were merged in from D:\himeyuri\tools\impact.mjs on 2026-11-02
    // (that repository's own map recognises both loading styles, while this one only read
    // import lines):
    //   loadUnit(path.join(ROOT, "self/x.hmoca")) - a loader call
    //
    // The command-line pattern (--compile plus a source path) sits under js, because it appears
    // in .mjs, and rules are chosen by the extension of the file being scanned.
    //
    // What was NOT merged is that map's third, loose pattern (any quoted .hmoca path). It is
    // right there: that side asks "which suites should I run after touching this file", and one
    // extra suite is just one wasted run. This side is a dependency graph, where a false edge
    // distorts "who depends on me" - the two uses tolerate false positives differently, so only
    // the exact half of both was merged.
    patterns: [
      /^\s*(?:import|\u5f15\u5165)\s+["']([^"']+)["']/gm,
      /\b(?:loadUnit|loadFile|compileFile|readUnit|loadModule)\s*\([^)]*?["']([^"']+)["']/g,
    ],
  },
  {
    name: "py",
    extensions: [".py"],
    patterns: [/^\s*from\s+([\w.]+)\s+import/gm, /^\s*import\s+([\w.]+)/gm],
  },
  {
    name: "rs",
    extensions: [".rs"],
    patterns: [/^\s*use\s+([\w:]+)/gm, /^\s*(?:pub\s+)?mod\s+(\w+)\s*;/gm],
  },
  {
    name: "go",
    extensions: [".go"],
    patterns: [/^\s*import\s+(?:\(\s*)?["']([^"']+)["']/gm],
  },
];

const RULE_BY_EXTENSION = new Map();
for (const rule of LANGUAGE_RULES) for (const ext of rule.extensions) RULE_BY_EXTENSION.set(ext, rule);

function walkFiles(root, out, limit) {
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= limit) return;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(full);
      } else if (entry.isFile()) {
        out.push(full);
      }
    }
  }
}

function countLines(file) {
  try {
    const source = fs.readFileSync(file, "utf8");
    if (!source) return 0;
    let lines = 1;
    for (let i = 0; i < source.length; i++) if (source.charCodeAt(i) === 10) lines++;
    return lines;
  } catch {
    return 0;
  }
}

// A test is a file under test/tests/spec/__tests__ or one whose name carries .test. / .spec. / _test.
function isTest(relative) {
  const lower = relative.toLowerCase();
  if (/(^|\/)(test|tests|spec|__tests__)(\/|$)/.test(lower)) return true;
  if (/\.(test|spec)\.[a-z0-9]+$/.test(lower)) return true;
  if (/_test\.[a-z0-9]+$/.test(lower)) return true;
  // A check script counts too. This repository keeps its suites in scripts/ as check-*.mjs, verify-*.mjs and
  // selfcheck.mjs, and a dependency map that calls none of them a test tells half the story: those files are
  // exactly what breaks when a tool's contract moves.
  if (/^scripts\/(check-|verify-|selfcheck)/.test(lower)) return true;
  return false;
}

const RESOLVE_TAILS = [
  "", ".mjs", ".js", ".ts", ".hmoca", ".hmyr", ".h", ".c", ".py", ".rs", ".go",
  "/index.mjs", "/index.js", "/index.ts", "/mod.rs", "/__init__.py",
];

// Resolve a specifier to a path inside the project; anything that lands outside is an external dependency.
function resolveSpecifier(fromRelative, specifier, known) {
  const clean = String(specifier).replace(/\\/g, "/");
  if (clean.startsWith(".")) {
    const base = path.posix.dirname(fromRelative);
    const joined = path.posix.normalize(path.posix.join(base, clean));
    for (const tail of RESOLVE_TAILS) if (known.has(joined + tail)) return { internal: joined + tail };
    return { external: clean };
  }
  for (const tail of RESOLVE_TAILS) if (known.has(clean + tail)) return { internal: clean + tail };
  return { external: clean };
}

export function buildMap(root, options = {}) {
  const limit = Number(options.limit) || 20000;
  const files = [];
  walkFiles(root, files, limit);
  const relatives = files.map((p) => path.relative(root, p).split(path.sep).join("/"));
  const known = new Set(relatives);

  const nodes = new Map();
  for (let i = 0; i < relatives.length; i++) {
    const relative = relatives[i];
    const extension = path.extname(relative).toLowerCase();
    const rule = RULE_BY_EXTENSION.get(extension);
    const out = [];
    const externalOut = [];
    if (rule) {
      let source = "";
      try {
        source = fs.readFileSync(files[i], "utf8");
      } catch {
        source = "";
      }
      for (const re of rule.patterns) {
        re.lastIndex = 0;
        let match;
        while ((match = re.exec(source)) !== null) {
          // When there is a second capture group, append it to the first:
          // path.join(ROOT, "tools", "hmget.mjs") is two segments, while a specifier is one.
          // Every other pattern has a single group, so match[2] is undefined and this is a no-op.
          const specifier = match[2] === undefined ? match[1] : match[1] + "/" + match[2];
          const resolved = resolveSpecifier(relative, specifier, known);
          if (resolved.internal) {
            if (resolved.internal !== relative && !out.includes(resolved.internal)) out.push(resolved.internal);
          } else if (resolved.external && !externalOut.includes(resolved.external)) {
            externalOut.push(resolved.external);
          }
        }
      }
    }
    nodes.set(relative, {
      relative,
      lines: countLines(files[i]),
      extension,
      language: rule ? rule.name : null,
      out,
      external: externalOut,
      test: isTest(relative),
      in: [],
    });
  }
  for (const node of nodes.values()) {
    for (const dep of node.out) {
      const target = nodes.get(dep);
      if (target) target.in.push(node.relative);
    }
  }
  return { root, nodes };
}

export function summarise(map) {
  const byExtension = {};
  const byLanguage = {};
  let lines = 0;
  let tests = 0;
  let edges = 0;
  const external = new Set();
  for (const node of map.nodes.values()) {
    const extKey = node.extension || "(none)";
    byExtension[extKey] = (byExtension[extKey] || 0) + 1;
    const langKey = node.language || "(unrecognised)";
    byLanguage[langKey] = (byLanguage[langKey] || 0) + 1;
    lines += node.lines;
    edges += node.out.length;
    if (node.test) tests++;
    for (const e of node.external) external.add(e);
  }
  const mostDependedOn = [...map.nodes.values()]
    .filter((node) => !node.test)
    .sort((a, b) => b.in.length - a.in.length)
    .slice(0, 10)
    .map((node) => ({ file: node.relative, dependedOnBy: node.in.length }));
  return { files: map.nodes.size, lines, edges, tests, external: external.size, byExtension, byLanguage, mostDependedOn };
}

// ---- what is on disk, not only what the graph reached ----
//
// SKIP_DIRS keeps compiled output and vendor trees out of the dependency graph on purpose. But a file
// that exists is a file somebody has to maintain or delete, so "the map" answered with only the
// reachable part is a report about the graph wearing the name of a report about the project. This
// inventory lists every file except .git and node_modules - the two that are genuinely not content -
// and marks each one with whether the graph reached it and, when it did not, which directory name in
// SKIP_DIRS explains that.
//
// Himeyuri is the case that forced this: its launcher lives in bin/hmyr.mjs, and bin is in SKIP_DIRS,
// so the one file a user runs first was absent from a map that said 694 files.
//
// Three directory names are folded rather than listed: the version store, installed dependencies and
// the run-time cache. They are not content - nobody maintains a cache entry - and on Himeyuri the
// cache alone is 6328 of 7022 files, which would bury the other 694 under a listing of its own
// leftovers. Everything else, dist and build and bin included, is listed one file at a time: those
// can hold something somebody has to account for, and 700 rows is a listing, not a flood.
const INVENTORY_OMIT = new Set([".git", "node_modules", ".cache"]);

function countFiles(dir) {
  let n = 0;
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) n++;
    }
  }
  return n;
}

export function inventory(root, map) {
  const files = [];
  const omitted = [];
  const walk = (current, relative) => {
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      const rel = relative ? relative + "/" + entry.name : entry.name;
      if (entry.isDirectory()) {
        if (INVENTORY_OMIT.has(entry.name)) omitted.push({ path: rel, files: countFiles(full) });
        else walk(full, rel);
      } else if (entry.isFile()) {
        const node = map.nodes.get(rel);
        const segments = rel.split("/");
        const skippedBy = segments.slice(0, -1).find((x) => SKIP_DIRS.has(x)) || null;
        let bytes = 0;
        try {
          bytes = fs.statSync(full).size;
        } catch {
          bytes = 0;
        }
        files.push({
          path: rel,
          bytes,
          // lines and language only for the files the graph read; null means "not analysed", which is
          // different from zero and must not be read as an empty file.
          lines: node ? node.lines : null,
          language: node ? node.language : null,
          test: node ? node.test : isTest(rel),
          dependedOnBy: node ? node.in.length : 0,
          mapped: Boolean(node),
          skippedBy,
        });
      }
    }
  };
  walk(root, "");
  files.sort((a, b) => a.path.localeCompare(b.path));
  const mapped = files.filter((f) => f.mapped).length;
  return {
    total: files.length,
    mapped,
    unmapped: files.length - mapped,
    bytes: files.reduce((n, f) => n + f.bytes, 0),
    omitted,
    files,
  };
}

// ---- what the project reaches for outside itself ----
//
// The graph already knows which specifiers it could not resolve inside the project, and until now that
// knowledge was collapsed into one number. It is the part an update has to watch most carefully: an
// outside path can be renamed, deleted or moved by somebody who has never heard of this repository,
// and nothing here would turn red. So each one is listed with its kind and, for the kinds where it
// makes sense, whether it is still there.
//
// Kinds are separated because the handling differs: builtin cannot be missing, package needs a
// resolution rule this map does not own, absolute and relative-outside can be stat'ed today.
function classifySpecifier(specifier, language) {
  const s = String(specifier);
  if (s.startsWith("node:")) return "builtin";
  // The language of the file doing the including says more than the name does. A C source includes
  // headers, and no reading of "stdio.h" can tell a system header from a project file - but the fact
  // that a .c file asked for it can. Same for a Python import: the standard library and a vendored
  // module look identical by name.
  if (language === "c") return "header";
  if (language === "py") return "python-module";
  if (/^[A-Za-z]:[\\/]/.test(s) || s.startsWith("\\\\") || s.startsWith("/")) return "absolute";
  if (s.startsWith(".")) return "relative-outside";
  if (s.includes("/") || s.includes("\\")) return "path-like";
  return "package";
}

export function outbound(map) {
  const bySpecifier = new Map();
  for (const node of map.nodes.values()) {
    for (const specifier of node.external) {
      if (!bySpecifier.has(specifier)) {
        bySpecifier.set(specifier, {
          specifier,
          kind: classifySpecifier(specifier, node.language),
          from: [],
          fromTests: 0,
          resolved: null,
          exists: null,
        });
      }
      const row = bySpecifier.get(specifier);
      row.from.push(node.relative);
      // How many of the referring files are tests. A name that only a test mentions is usually a
      // fixture the test invented, and that is worth seeing before treating it as a real dependency.
      if (node.test) row.fromTests++;
    }
  }
  const list = [...bySpecifier.values()];
  for (const item of list) {
    // Is it actually inside the project? A path that exists relative to the root is not an outside
    // dependency at all - it is a file the graph could not reach, and the usual reason is that its
    // directory sits in the skip table. Himeyuri is the case: bin/ is skipped, so its launcher was
    // reported here as though it came from somewhere else. Saying "inside" separates a real outside
    // dependency from a blind spot of the walk.
    try {
      const isRelative = !/^[A-Za-z]:[\\/]/.test(item.specifier) && !item.specifier.startsWith("file://") && !item.specifier.startsWith("\\\\");
      item.insideProject = isRelative ? fs.existsSync(path.join(map.root, item.specifier)) : false;
    } catch {
      item.insideProject = false;
    }
    if (item.kind === "absolute" || item.kind === "relative-outside") {
      try {
        const base = path.dirname(path.join(map.root, item.from[0]));
        const abs = item.kind === "absolute" ? item.specifier : path.resolve(base, item.specifier);
        item.resolved = abs;
        item.exists = fs.existsSync(abs);
      } catch {
        item.exists = false;
      }
    }
  }
  list.sort((a, b) => (a.kind === b.kind ? a.specifier.localeCompare(b.specifier) : a.kind.localeCompare(b.kind)));
  const kinds = {};
  for (const item of list) kinds[item.kind] = (kinds[item.kind] || 0) + 1;
  const missing = list.filter((item) => item.exists === false).map((item) => item.specifier);
  return { total: list.length, kinds, missing, items: list };
}

// ---- the plan: what the project is trying to become ----
//
// A map of files answers what a project is made of. It cannot answer what the project is for, and those
// two questions get asked together by anyone deciding what to do next. So the map reads a plan file when
// the repository keeps one and turns it into the same kind of network the code gets: goals with parents
// and order, goals linked to the files they touch, goals linked to the suites that judge them.
//
// The plan is data in the repository, not a format parsed out of prose. Prose can say a hundred things,
// and every reading of it is an interpretation; a file with one record per goal can be checked. A goal
// naming a test that is not there, a directory that has been deleted, or a parent that does not exist is
// a broken record, and this reports it rather than smoothing it over.
//
// Three files are looked for, so a project can choose where to keep it: design/PLAN.json for a
// repository with a design directory, PLAN.json at the root, or .project-plan.json beside the sources.
const PLAN_FILES = ["design/PLAN.json", "PLAN.json", ".project-plan.json"];

export function readPlan(root, map) {
  let file = null;
  for (const candidate of PLAN_FILES) {
    const full = path.join(root, candidate);
    if (fs.existsSync(full)) {
      file = full;
      break;
    }
  }
  if (!file) return null;
  const relative = path.relative(root, file).split(path.sep).join("/");
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    return { source: relative, error: "cannot read the plan: " + String((e && e.message) || e) };
  }

  const rows = Array.isArray(raw.goals) ? raw.goals : [];
  const byId = new Map();
  const missing = [];
  const edges = [];
  const goalFiles = [];

  const goals = rows.map((row, index) => {
    const id = String(row.id || "goal-" + index);
    const touches = Array.isArray(row.touches) ? row.touches.map(String) : [];
    const files = new Set();
    for (const touch of touches) {
      const clean = touch.split("\\").join("/").replace(/\/+$/, "");
      let stat = null;
      try {
        stat = fs.statSync(path.join(root, clean));
      } catch {
        stat = null;
      }
      if (!stat) {
        missing.push({ goal: id, kind: "touches", path: touch });
        continue;
      }
      if (stat.isDirectory()) {
        // A directory stands for everything under it that the graph knows about. Files that exist but
        // sit in a skipped directory are deliberately not pulled in: a goal naming a directory should
        // not silently grow to cover build output.
        const prefix = clean + "/";
        for (const rel of map.nodes.keys()) if (rel.startsWith(prefix)) files.add(rel);
      } else {
        files.add(clean);
      }
    }
    const verifiedBy = Array.isArray(row.verifiedBy) ? row.verifiedBy.map(String) : [];
    const tests = [];
    for (const t of verifiedBy) {
      const clean = t.split("\\").join("/");
      let exists = map.nodes.has(clean);
      if (!exists) {
        try {
          exists = fs.existsSync(path.join(root, clean));
        } catch {
          exists = false;
        }
      }
      if (exists) tests.push(clean);
      else missing.push({ goal: id, kind: "verifiedBy", path: t });
    }
    const goal = {
      id,
      title: String(row.title || ""),
      scope: String(row.scope || "task"),
      status: String(row.status || "open"),
      parent: row.parent ? String(row.parent) : null,
      after: Array.isArray(row.after) ? row.after.map(String) : [],
      source: row.source ? String(row.source) : null,
      notes: row.notes ? String(row.notes) : null,
      files: [...files].sort(),
      tests,
    };
    for (const f of goal.files) goalFiles.push({ goal: id, file: f });
    if (goal.parent) edges.push({ from: goal.parent, to: id, kind: "parent" });
    for (const a of goal.after) edges.push({ from: a, to: id, kind: "after" });
    byId.set(id, goal);
    return goal;
  });

  // An edge pointing at a goal that is not in the file is the same kind of broken record as a test that
  // is not there: the network claims a relationship it cannot resolve.
  for (const edge of edges) {
    if (!byId.has(edge.from)) missing.push({ goal: edge.to, kind: edge.kind, path: edge.from });
  }

  const byStatus = {};
  const byScope = {};
  for (const goal of goals) {
    byStatus[goal.status] = (byStatus[goal.status] || 0) + 1;
    byScope[goal.scope] = (byScope[goal.scope] || 0) + 1;
  }
  return {
    source: relative,
    title: raw.title ? String(raw.title) : null,
    total: goals.length,
    byStatus,
    byScope,
    goals,
    edges,
    goalFiles,
    missing,
  };
}

// The blast radius: walk "who imports me" backwards and hand back the files that would move, split into the
// ones a test suite owns.
export function affectedBy(map, target) {
  const clean = String(target || "").split(path.sep).join("/");
  if (!map.nodes.has(clean)) return null;
  const seen = new Set([clean]);
  const queue = [clean];
  while (queue.length) {
    const current = queue.pop();
    for (const from of map.nodes.get(current).in) {
      if (!seen.has(from)) {
        seen.add(from);
        queue.push(from);
      }
    }
  }
  const all = [...seen];
  const rest = all.filter((x) => x !== clean);
  return {
    target: clean,
    changed: rest.length,
    files: rest,
    tests: rest.filter((x) => map.nodes.get(x).test),
    direct: map.nodes.get(clean).in,
  };
}

// The one entry point a tool needs: give it op and arguments, get back a shape that can be written out as is.
export function projectMap(root, options = {}) {
  const map = buildMap(root, options);
  const op = options.op || "map";
  if (op === "affects") {
    // A change usually touches several files, and the question asked afterwards is which suites the set
    // makes necessary - not which one file does. So this takes a list, merges the blast radii, and keeps
    // the reason for each suite: the file whose change required it. A list without reasons invites
    // running everything "to be safe", which is the habit this map exists to replace.
    const targets = String(options.file || "")
      .split(",")
      .map((s) => s.trim().split("\\").join("/"))
      .filter(Boolean);
    if (!targets.length) {
      return { ok: false, root, op, error: "op=affects needs file=<path>; comma-separate it for several" };
    }
    const unknown = [];
    const each = [];
    for (const target of targets) {
      const one = affectedBy(map, target);
      if (!one) unknown.push(target);
      else each.push(one);
    }
    if (!each.length) {
      return { ok: false, root, op, error: "no such file in the project: " + unknown.join(", "), summary: summarise(map) };
    }
    const files = new Set();
    const direct = new Set();
    const reasons = new Map();
    for (const one of each) {
      for (const f of one.files) files.add(f);
      for (const d of one.direct) direct.add(d);
      for (const t of one.tests) {
        if (!reasons.has(t)) reasons.set(t, new Set());
        reasons.get(t).add(one.target);
      }
    }
    // The plan says which goals a set of files belongs to, and a goal whose files moved is a goal whose
    // judgement has to run. That is the link between "what I changed" and "what was this supposed to
    // achieve", and without it the suite list is complete but unexplained.
    const plan = readPlan(root, map);
    const goals = [];
    if (plan && Array.isArray(plan.goals)) {
      const touched = new Set([...targets, ...files]);
      for (const goal of plan.goals) {
        const hits = goal.files.filter((f) => touched.has(f));
        if (!hits.length) continue;
        goals.push({ id: goal.id, title: goal.title, status: goal.status, because: hits.slice(0, 12), tests: goal.tests });
      }
    }
    return {
      ok: true,
      root,
      op,
      targets,
      unknown,
      changed: files.size,
      files: [...files].sort(),
      direct: [...direct].sort(),
      tests: [...reasons.keys()].sort(),
      reasons: [...reasons.entries()]
        .map(([test, why]) => ({ test, because: [...why].sort() }))
        .sort((a, b) => a.test.localeCompare(b.test)),
      goals,
    };
  }
  const inv = inventory(root, map);
  const out = outbound(map);
  const plan = readPlan(root, map);
  // Three shapes, because the three uses differ. op=map is the glance: summary, the file count the graph
  // reached, the full list of what it did not reach, and the goals with their networks. op=inventory is
  // the ledger: every file with its size, lines and dependents, plus every outside path the project
  // reaches for - the thing to diff between two readings when asking what moved. op=plan is the goal
  // network alone, for when the question is what comes next rather than what exists.
  if (op === "inventory") {
    return { ok: true, root, op, inventory: inv, outbound: out, plan };
  }
  if (op === "plan") {
    return { ok: true, root, op, plan };
  }
  return {
    ok: true,
    root,
    op: "map",
    ...summarise(map),
    inventory: {
      total: inv.total,
      mapped: inv.mapped,
      unmapped: inv.unmapped,
      bytes: inv.bytes,
      omitted: inv.omitted,
      unmappedFiles: inv.files.filter((f) => !f.mapped).map((f) => ({ path: f.path, bytes: f.bytes, skippedBy: f.skippedBy })),
    },
    outbound: out,
    plan,
  };
}
