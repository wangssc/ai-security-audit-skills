# Electron 攻击面审计

**你的应用里打包了一个 Chromium、一个 Node 运行时，和一份以用户权限运行的
JavaScript。这三样，这个工具从磁盘上全查一遍——大约两秒，全程不打开窗口。**

```bash
python scripts/audit.py "C:\Program Files\SomeApp\SomeApp.exe"
```

```
score    21/100   grade F (critical)
         fuse penalty 117, code penalty 23

FUSES
  [RISK] Run as Node                        enabled   safe=disabled
  [RISK] Embedded ASAR integrity            disabled  safe=enabled
  [RISK] Only load app from ASAR            disabled  safe=enabled

FINDINGS
  [critical] ES-001  nodeIntegration is enabled
             at Downloader.js:20
             webPreferences: {nodeIntegration: true}
```

这两份报告是真实的，放在 `references/examples/`：一个 2019 年的笔记应用得 27 分，
一个当前的 AI 桌面客户端得 21 分。两边都有活着的 critical 问题，厂商都没有对外说过。

---

## 问题在哪

Electron 把浏览器和 Node 进程塞进同一个二进制。这很高效，同时也是一把上了膛的枪：
「渲染你的界面」和「以用户身份执行代码」之间的边界，就是 `webPreferences` 里的几个
布尔值，而且每一个的默认值都是「好用」而不是「安全」。

出事的方式一点也不高级：

1. 2019 年某个功能需要在渲染进程里用 `fs`，于是有人写了 `nodeIntegration: true`。
2. 渲染进程加载了一个页面——可能是远程的，可能带第三方组件。
3. 任何能在这个页面里执行脚本的东西，现在都能 `require('child_process')`。

没有内存破坏，没有沙箱逃逸，没有利用链。一个配置项，一个 XSS，用户就没了。

而且从外面看不出来。应用看起来正常，安装包有签名，图标很精致。唯一知道真相的办法
是去读二进制和归档。

## 它查什么

**Fuses** —— 编译进二进制的开关板。工具靠哨兵字符串定位那张表，解码位置式的状态
数组，把九个 fuse 逐个和安全值比对。`RunAsNode: enabled` 的意思是：
`ELECTRON_RUN_AS_NODE=1 app.exe` 就能把你的签名应用变成一个 Node 解释器，带着你的
应用身份。`OnlyLoadAppFromAsar: disabled` 的意思是：归档旁边放一个松散的 `app/`
目录，启动时它赢。

**ASAR 完整性** —— 可执行文件准备加载的那份归档，是不是你签的那份；以及工具到底
在不在看对的文件。如果活的 `app.asar` 没了只剩 `app.asar.bak`，报告里会写它审的是
哪一份。

**应用代码** —— 20 条规则，扫的是应用自己的 JavaScript 和 HTML：

| 编号 | 级别 | 抓什么 |
| --- | --- | --- |
| ES-001 | critical | `nodeIntegration: true` |
| ES-002 | critical | `contextIsolation: false` |
| ES-003 | high | `sandbox: false` |
| ES-004 | critical | `webSecurity: false` |
| ES-005 | high | `allowRunningInsecureContent: true` |
| ES-006 | medium | `experimentalFeatures: true` |
| ES-007 | medium | `enableBlinkFeatures` |
| ES-008 | high | 明文 HTTP 加载远程内容 |
| ES-009 | high | 有特权的窗口加载远程内容 |
| ES-010 | medium | 没有 CSP |
| ES-011 | high | `shell.openExternal` 参数无校验 |
| ES-012 | high | `ipcMain` 处理器不校验发送方 |
| ES-013 | medium | 启用 `<webview>` |
| ES-014 | medium | 新窗口处理器返回 `allow` |
| ES-015 | medium | 没有 `will-navigate` 拦截 |
| ES-016 | high | preload 直接暴露模块 |
| ES-017 | medium | 没有权限请求处理器 |
| ES-018 | high | 更新源不验签 |
| ES-019 | medium | `remote` 模块 |
| ES-020 | low | 无条件打开 DevTools |

匹配前会剥掉注释，所以文档和注释掉的示例不会误报。默认排除 `node_modules`——
审计的是你维护的代码，让发布者去改依赖的默认值不可执行。

**guard 会压掉噪音。** `ES-011` 会看命中行和它上面四行，找 `new URL()`、
`protocol === 'https:'` 比较、或者白名单。有 guard 就压掉——而且被压掉的事实会记进
JSON，方便反过来审计这个审计工具。

## 为什么这比直接问模型强

你可以问模型「这个 Electron 应用安全吗」，它会很自信地回答。但它做不到这几件事：

- **读编译后二进制的 fuse 状态。** 没有 API。那些字节在 `.exe` 里一张哨兵分隔的
  表里，读它意味着定位哨兵、解码位置式状态数组、知道九个值各自对可利用性意味着
  什么。只读源码的模型根本看不到这一层。
- **判断可执行文件到底会加载哪份归档。** `resources/app.asar`、
  `resources/app/*.asar`、或者一份活得比正本还久的 `.bak`——解析顺序有讲究，猜错
  就是审错了程序。
- **区分「没找到」和「不存在」。** 读了 14 个文件没看到
  `setPermissionRequestHandler`，和读了 9,904 里的 120 个没看到，是两回事。工具
  记录扫描是否完整，并且拒绝从部分读取里断言缺失。
- **给出能区分的分数。** 线性扣分下，3 个问题的老应用和 20 个问题的新应用都是 0 分。
  指数衰减加 critical 封顶，让分数在差别很大的代码库之间还有意义。

## 安装

零依赖。Python 3.8+，只用标准库。

```bash
git clone https://github.com/<you>/electron-surface-audit
cd electron-surface-audit
python scripts/audit.py --help
```

作为 Agent Skill 使用：把整个目录丢进你的 skills 文件夹（`~/.claude/skills/`、
`~/.codex/skills/`，或者你的客户端扫的任意位置），`SKILL.md` 的 frontmatter 会告诉
agent 什么时候该用它。

## 用法

```bash
# 已安装的应用
python scripts/audit.py "C:\Program Files\Some App\Some App.exe"

# macOS bundle（自动找 Contents/Resources/app.asar）
python scripts/audit.py /Applications/Some\ App.app

# 只给归档——没有 fuse 数据，只查代码
python scripts/audit.py ./resources/app.asar

# 机器可读 + 报告文件
python scripts/audit.py ./app.asar --json --markdown audit.md

# CI 门禁
python scripts/audit.py ./app.asar --fail-on high   # 有 high 或 critical 就 exit 1
```

| 参数 | 默认 | 含义 |
| --- | --- | --- |
| `--json` | 关 | 输出 JSON |
| `--markdown FILE` | 关 | 同时写 Markdown 报告 |
| `--max-files N` | 400 | 最多读多少个脚本文件 |
| `--max-bytes N` | 32 MiB | 最多读多少字节源码 |
| `--include-deps` | 关 | 连 `node_modules` 一起扫 |
| `--fail-on LEVEL` | `high` | 达到这个级别就 exit 1；`none` 关闭 |

退出码：`0` 达标内无问题，`1` 有问题，`2` 目标读不到。

## 评分

```
penalty = Σ fuse 权重 + Σ 规则权重
score   = round(100 · e^(−penalty/90))
score   = min(score, 65)   只要存在 critical
```

fuse 权重：critical 25、high 12、medium 5、low 1。
规则权重：critical 20、high 10、medium 5、low 1。

等级：A ≥ 90、B ≥ 75、C ≥ 60、D ≥ 40、F 以下。

`not assessed` 是一个独立的结论。fuse 表和归档一个都读不到时，工具打
`not assessed` 而不是 100。**一个启动器桩和一个加固过的应用不能长得一样**——这一条
设计决定，是这个工具能在评审里用的原因。

## 覆盖边界（务必读）

- **只做静态。** 工具从不启动目标。运行时才知道的东西——窗口实际加载了哪个 URL、
  preload 实际暴露了什么、服务端有没有发 CSP——源码和字节给不了答案。
- **不做数据流分析。** `openExternal(x)` 里 `x` 在三个函数外被校验过，照样会报。
  这类当「需要人看一眼」，不当「确认有洞」。
- **缺失类检查依赖扫描范围。** `ES-010`、`ES-015`、`ES-017` 是「没找到」才触发。
  如果 `--max-files` 截断了扫描，这类结论会标 `partial_evidence: true`，要用更大
  预算重跑。
- **pre-fuse 构建。** Electron < 12 没有 fuse 表。这是关于 Electron 版本的结论，
  不是通行证。
- **一次一个应用。** 这里不审运行时、不审服务端、不单独审插件宿主。

## 修的时候按什么顺序

顺序有讲究：先配置后代码，先 critical 后 high。

1. **翻 fuse** —— 打包时用 `@electron/fuses` 改。运行时零成本，直接消掉一整类攻击。
2. **`webPreferences`** —— `nodeIntegration: false`、`contextIsolation: true`、
   `sandbox: true`。如果应用崩了，说明 preload 干得太多。
3. **IPC** —— 每个处理器都校验 `event.senderFrame.url`，把 payload 当不可信输入。
4. **`openExternal`** —— `new URL()`、只放 `https:`、比对主机白名单。
5. **更新器** —— 签名清单、固定密钥、应用前验证产物。

每改一步重跑一次。分数是进度条，不是目标：从 21 调到 60 的办法如果是删规则，那应用
是变得更糟了，不是更好。

## 目录

```
scripts/
  audit.py       入口、评分、文本与 Markdown 渲染
  fuses.py       fuse 表定位与解码
  fuse_map.py    九个 fuse：id、安全值、级别、为什么、怎么修
  asar.py        ASAR 读取（header 锚点、成员提取）
  rules.py       20 条源码规则，含 guard 与缺失检查
references/
  checklist.md   每条规则背后的推理：不修会怎样
  examples/      两份来自真实上架应用的报告
SKILL.md         agent 入口
```

## 已知限制，直说

- fuse 解码假设哨兵完整。把哨兵抹掉的厂商会得到 `no fuse table`，而不是一个猜测值。
- ASAR header 偏移能扛住重新打包，因为 JSON 是靠开头 token 定位、pickle 前缀是量出来
  的；但**成员表**被重写过的归档仍会解析成功并读出错字节。工具会报告它用的 header
  位置，让这个数字可核对。
- `ES-012` 跟不进辅助函数。它报模式，修复说明里写清楚 guard 该查什么。
- 级别说的是「装到用户机器上之后的可利用性」。同一条 `medium`，落在服务端渲染的营销
  站和落在银行客户端里，风险不是一回事——报告给你证据去做判断，不替你做判断。

## 许可

MIT，见 `LICENSE`。

工具实现的是 Electron 官方的安全清单，公开维护在
`electronjs.org/docs/latest/tutorial/security`。规则都带编号和出处，每一条建议都可以
回到原文核对，而不是靠断言。
