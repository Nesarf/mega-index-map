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
    patterns: [/^\s*import\s+["']([^"']+)["']/gm],
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
          const resolved = resolveSpecifier(relative, match[1], known);
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
    const result = affectedBy(map, options.file || "");
    if (!result) {
      return { ok: false, root, op, error: "no such file in the project: " + String(options.file || ""), summary: summarise(map) };
    }
    return { ok: true, root, op, ...result };
  }
  return { ok: true, root, op: "map", ...summarise(map) };
}
