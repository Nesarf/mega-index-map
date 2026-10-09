# mega-index-map

> 英文原文：[README.md](README.md)

面向 DeepSeek Harness 的跨工作区资料库（Library）。Agent 把遇到的对象——文件、工具、环境、知识、
工作记录——记进 `$DSH_HOME/library`，任何会话都能索引、检索并复用它们。

每把工具的描述都写明了「什么时候它才是更省事的那条路」——因为这决定了 agent 是去问库，还是去
遍历文件系统：重新研究某个东西之前用 `library_query`，找工具或运行时之前用 `library_detect`，
打开文件猜类型之前用 `library_sniff`，手动翻目录看有什么之前用 `library_index op=audit`。如果宿主
仍然习惯性去扫盘，可开 `injectPrompt: true`（插件配置），它会把一段简短提示前置到每个会话的首条用户
消息；想换措辞就把文本写到 `$DSH_HOME/mega-index-prompt.md`，整体替换。

## 工具

- `library_record` - 记录一个对象（带变更检测，走 verify/confirm 判定；不可变类的变更会先被拒绝，等用户决定后再用 `confirm: true` 加 `reason` 记录，日志里留下 `record-confirm`）
- `library_index` - 索引上的三件事：`op=rebuild`（默认）去重排序并报告冲突；`op=audit dir=<路径>` 只读地把
  某目录与资料库对账，**双向**——磁盘上有、库里没记的条目，以及库里记着、路径已不存在的记录（「记过」不等于
  「还找得到」）；`op=index dir=<路径> confirm=true` 把缺的条目登记成记录，受深度与条目上限约束，并照样套用
  敏感内容规则。**盘根会被拒绝**：会自顾自走遍整块盘的索引器，正是这个库要替代的那种扫描
- `library_query` - 按关键词、类型、标签检索，游标分页。多词查询按词逐个匹配、并按每个对象覆盖了几个词排序，所以多写几个词是**收窄**结果而不是要求那串字连续出现；单个词仍是普通的子串匹配。
- `library_detect` - 扫描并登记本机的工具与环境。内置清单与具体机器无关：裸命令名从 `PATH` 解析，位置一律
  用它的所有者自己的说法来写（`%ProgramFiles%`、`%GOROOT%`、`%ANDROID_HOME%`、`~`、`${HOME}`），会随版本
  变动的目录则从磁盘上取「最新安装的那个」。放在自选位置的工具用 `add` 写进本机候选包，`propose` 可以从某个
  目录推荐条目；不存在的路径会被跳过。每条已存在的结果还带 `declared`：文件自己对自己的声明（产品名／版本／
  厂商，来自它自己的版本资源，纯静态读取——绝不执行该工具）
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
