# mega-index-map

> 英文原文：[README.md](README.md)

面向 DeepSeek Harness 的跨工作区资料库（Library）。Agent 把遇到的对象——文件、工具、环境、知识、
工作记录——记进 `$DSH_HOME/library`，任何会话都能索引、检索并复用它们。

## 工具

- `library_record` - 记录一个对象（带变更检测，走 verify/confirm 判定）
- `library_index` - 重建、去重、排序资料库，并报告冲突
- `library_query` - 按关键词、类型、标签检索，游标分页
- `library_detect` - 扫描并登记本机的工具与环境（内置清单是维护者那台机器的布局：不存在的路径会被
  跳过；用 `propose`、`add` 播种你自己的布局）
- `library_sniff` - 按文件头魔数判定真实类型（108 条签名），与扩展名无关
- `library_format` - 扩充本机的格式库：`list` `scan` `learn` `add` `remove` `deps` `draft` `report` `deliver` `unseal`
- `library_decrypt` - 按需读回被隔离的敏感对象
- `library_export` - 导出为 JSON/NDJSON
- `library_encoding` - 报告宿主编码，以及如何切到 UTF-8
- `library_adb` - 通过 ADB 做开发者侧的 Android 设备操作

## 安装

```powershell
dsh plugin --profile web add github:Nesarf/mega-index-map
```

## 说明

- 资料库位于 `$DSH_HOME/library`（默认 `~/.dsh/library`）。本机学到的扩充条目与它同处一地，
  **永不覆盖**内置表。
- 一切留在本机：插件不做任何网络 I/O，也不会自行外发任何内容。
- 实测开销随规模线性且很小：5,000 个对象时，查询约 13 ms、记录约 19 ms、重建约 26 ms（索引文件约
  2.3 MB）。备份与迁移用 `library_export`。
- 并发写入经锁文件串行化：持有者已死的锁会被接管；锁正忙时最多等两秒，之后照写并在日志里说明。
- 本包与同源的另一版本（跨 harness 版）**互不写入**：本包只写 `$DSH_HOME`、系统临时目录，或调用方
  显式给出的路径；`scripts/check-isolation.mjs` 对两个方向都强制（详见 [ISOLATION.md](ISOLATION.md)）。
- 三条不变量每次推送都检查：**英文/ASCII 输出**、**Windows/macOS/Linux 可移植**、**多语言文本的
  UTF-8 安全**。`npm run check` 跑全部四项检查（ASCII、一致性、可移植性、隔离）；`npm run selfcheck`
  跑五段自检——测通、遍历、校对、遍历、测通——并按轴分别报告。
- 本文件是仓库里唯一的本地化文档（也是 ASCII 不变量唯一的散文类例外），其余文本与代码仍为纯 ASCII。
- MIT 许可证，见 [LICENSE](LICENSE)。
