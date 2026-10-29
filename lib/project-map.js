// 工程地图：给一个工程根，答它由什么组成、谁依赖谁、改一个文件会碰哪些测试。
//
// 为什么放在 mega-index-map 里：Library 那一层管「这台机器上有什么文件」，
// 而这一份管「一个工程内部长什么样」。同一套思路的另一种尺度。
//
// 语言规则是数据不是代码：每种语言一条记录，说清扩展名与抽 import 的正则。
// 加一门语言只要往 语言规则 里加一行，而不用改扫描逻辑。
import fs from "node:fs";
import path from "node:path";

const 跳过目录 = new Set([
  "node_modules", ".git", "dist", "build", "out", "target", "vendor",
  ".next", "coverage", ".cache", "__pycache__", ".venv", "venv", "bin", "obj",
]);

// 每种语言：扩展名 → 一组正则，捕获组 1 是模块说明符。
const 语言规则 = [
  {
    名: "js",
    扩展: [".mjs", ".js", ".cjs", ".mts", ".ts", ".tsx", ".jsx"],
    模式: [
      /(?:^|[\s;])import\s+(?:[^"'`]*?\sfrom\s*)?["']([^"']+)["']/gm,
      /\brequire\(\s*["']([^"']+)["']\s*\)/g,
      /\bimport\(\s*["']([^"']+)["']\s*\)/g,
      /\b(?:loadUnit|loadFile|compileFile|runFile|readUnit|loadModule)\([^)]*?["']([^"']+)["']/g,
    ],
  },
  {
    名: "c",
    扩展: [".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"],
    模式: [/^\s*#\s*include\s*["<]([^">]+)[">]/gm],
  },
  {
    名: "hmoca",
    扩展: [".hmoca", ".hmyr"],
    模式: [/^\s*import\s+["']([^"']+)["']/gm],
  },
  {
    名: "py",
    扩展: [".py"],
    模式: [/^\s*from\s+([\w.]+)\s+import/gm, /^\s*import\s+([\w.]+)/gm],
  },
  {
    名: "rs",
    扩展: [".rs"],
    模式: [/^\s*use\s+([\w:]+)/gm, /^\s*(?:pub\s+)?mod\s+(\w+)\s*;/gm],
  },
  {
    名: "go",
    扩展: [".go"],
    模式: [/^\s*import\s+(?:\(\s*)?["']([^"']+)["']/gm],
  },
];

const 规则表 = new Map();
for (const r of 语言规则) for (const e of r.扩展) 规则表.set(e, r);

function 遍历目录(root, 出, 上限) {
  const 栈 = [root];
  while (栈.length) {
    const 当前 = 栈.pop();
    let 项;
    try {
      项 = fs.readdirSync(当前, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const it of 项) {
      if (节点数够(出, 上限)) return;
      const p = path.join(当前, it.name);
      if (it.isDirectory()) {
        if (跳过目录.has(it.name)) continue;
        栈.push(p);
      } else if (it.isFile()) {
        出.push(p);
      }
    }
  }
}

function 节点数够(出, 上限) {
  return 出.length >= 上限;
}

function 数行数(p) {
  try {
    const 源 = fs.readFileSync(p, "utf8");
    if (!源) return 0;
    let n = 1;
    for (let i = 0; i < 源.length; i++) if (源.charCodeAt(i) === 10) n++;
    return n;
  } catch {
    return 0;
  }
}

// 测试的判据：在 test/tests/spec/__tests__ 目录里，或者文件名带 .test. / .spec. / _test.
function 是测试(相对) {
  const 低 = 相对.toLowerCase();
  if (/(^|\/)(test|tests|spec|__tests__)(\/|$)/.test(低)) return true;
  if (/\.(test|spec)\.[a-z0-9]+$/.test(低)) return true;
  if (/_test\.[a-z0-9]+$/.test(低)) return true;
  return false;
}

const 补全尾巴 = [
  "", ".mjs", ".js", ".ts", ".hmoca", ".hmyr", ".h", ".c", ".py", ".rs", ".go",
  "/index.mjs", "/index.js", "/index.ts", "/mod.rs", "/__init__.py",
];

// 把 import 说明符解析成工程内的相对路径；落不到工程内的记为外部依赖。
function 解析说明符(来源相对, 说明, 存在集) {
  const 净 = String(说明).replace(/\\/g, "/");
  if (净.startsWith(".")) {
    const 基 = path.posix.dirname(来源相对);
    const 拼 = path.posix.normalize(path.posix.join(基, 净));
    for (const 尾 of 补全尾巴) if (存在集.has(拼 + 尾)) return { 内部: 拼 + 尾 };
    return { 外部: 净 };
  }
  for (const 尾 of 补全尾巴) if (存在集.has(净 + 尾)) return { 内部: 净 + 尾 };
  return { 外部: 净 };
}

export function 建图(root, 选项 = {}) {
  const 上限 = Number(选项.上限) || 20000;
  const 文件们 = [];
  遍历目录(root, 文件们, 上限);
  const 相对们 = 文件们.map((p) => path.relative(root, p).split(path.sep).join("/"));
  const 存在集 = new Set(相对们);

  const 节点 = new Map();
  for (let i = 0; i < 相对们.length; i++) {
    const 相对 = 相对们[i];
    const 扩展 = path.extname(相对).toLowerCase();
    const 规则 = 规则表.get(扩展);
    const 出 = [];
    const 外 = [];
    if (规则) {
      let 源 = "";
      try {
        源 = fs.readFileSync(文件们[i], "utf8");
      } catch {
        源 = "";
      }
      for (const re of 规则.模式) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(源)) !== null) {
          const 解 = 解析说明符(相对, m[1], 存在集);
          if (解.内部) {
            if (解.内部 !== 相对 && !出.includes(解.内部)) 出.push(解.内部);
          } else if (解.外部 && !外.includes(解.外部)) {
            外.push(解.外部);
          }
        }
      }
    }
    节点.set(相对, {
      相对,
      行数: 数行数(文件们[i]),
      扩展,
      语言: 规则 ? 规则.名 : null,
      出,
      外,
      测试: 是测试(相对),
      入: [],
    });
  }
  for (const n of 节点.values()) {
    for (const d of n.出) {
      const t = 节点.get(d);
      if (t) t.入.push(n.相对);
    }
  }
  return { root, 节点 };
}

export function 概览(图) {
  const 按扩展 = {};
  const 按语言 = {};
  let 行 = 0;
  let 测试数 = 0;
  let 边 = 0;
  let 外部 = new Set();
  for (const n of 图.节点.values()) {
    const 键 = n.扩展 || "(无扩展)";
    按扩展[键] = (按扩展[键] || 0) + 1;
    const 语 = n.语言 || "(未识别)";
    按语言[语] = (按语言[语] || 0) + 1;
    行 += n.行数;
    边 += n.出.length;
    if (n.测试) 测试数++;
    for (const e of n.外) 外部.add(e);
  }
  const 最被依赖 = [...图.节点.values()]
    .filter((n) => !n.测试)
    .sort((a, b) => b.入.length - a.入.length)
    .slice(0, 10)
    .map((n) => ({ 文件: n.相对, 被依赖: n.入.length }));
  return { 文件: 图.节点.size, 行, 边, 测试: 测试数, 外部依赖: 外部.size, 按扩展, 按语言, 最被依赖 };
}

// 影响面：反向走「谁依赖我」，交回会因此动的文件与其中的测试。
export function 影响面(图, 目标) {
  const 净 = String(目标).split(path.sep).join("/");
  if (!图.节点.has(净)) return null;
  const 见 = new Set([净]);
  const 队 = [净];
  while (队.length) {
    const 当前 = 队.pop();
    for (const 上 of 图.节点.get(当前).入) {
      if (!见.has(上)) {
        见.add(上);
        队.push(上);
      }
    }
  }
  const 全部 = [...见];
  const 其余 = 全部.filter((x) => x !== 净);
  return {
    目标: 净,
    共: 其余.length,
    文件: 其余,
    测试: 其余.filter((x) => 图.节点.get(x).测试),
    直接: 图.节点.get(净).入,
  };
}

// 一条命令的入口：给 op 与参数，交回可以直接写出去的形状。
export function 工程地图(root, 选项 = {}) {
  const 图 = 建图(root, 选项);
  const op = 选项.op || "map";
  if (op === "affects") {
    const r = 影响面(图, 选项.file || "");
    if (!r) return { ok: false, root, 错误: "工程里没有这个文件：" + String(选项.file || ""), 概览: 概览(图) };
    return { ok: true, root, op, ...r };
  }
  return { ok: true, root, op: "map", ...概览(图) };
}
