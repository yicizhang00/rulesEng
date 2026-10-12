# rulesEng — 交易所监管规则 DSL 与统一规则引擎

把散落在微服务里的监管规则收敛成声明式 DSL，上线前用形式化校验保证完备性，运行时无侵入接入事件流。

## 目录结构（Cargo Workspace）

```
rulesEng/
├── Cargo.toml                  # workspace 根
├── crates/
│   ├── rules-ast/              # 强类型 AST 节点
│   ├── rules-parser/           # pest 文法：DSL 文本 → AST
│   ├── rules-dictionary/       # DataDictionary：var 动态绑定
│   ├── rules-verifier/         # 死规则 / 动作冲突 / 覆盖缺口
│   ├── rules-runtime/          # 事件摄入、状态机、tick 评估
│   ├── rules-dispatcher/       # Alert trait
│   ├── rules-cli/              # CLI 入口 + e2e 测试
│   ├── rules-diff/             # 【二期】Semantic Diff: Tightened/Loosened/Equivalent
│   ├── rules-proof/            # 【二期】证据链: DecisionTree + 最小归因 + FNV 快照哈希
│   ├── rules-backtest/         # 【二期】双时钟 + Shadow Replay + 回测报告
│   └── rules-flatvm/           # 【二期】栈式字节码 VM（WASM/Cranelift 后端铺垫）
├── web/
│   └── index.html              # 【二期】浏览器端规则配置台（输入即校验 + 可视化）
├── examples/
├── 需求文档.md / 设计文档.md
└── greeting/                   # 旧原型保留
```

## 快速开始

```powershell
cargo build          # 编译整个 workspace
cargo test           # 跑 10 个 e2e 测试
cargo run -- demo    # 跑内置半年报 demo
cargo run -- verify examples/semi_annual.rules   # 只做静态校验
cargo run -- run    examples/with_var.rules      # 校验 + 跑 demo
```

## DSL 速览

```text
entity Company {
    key: code
    states: [NORMAL, SUSPENDED, TERMINATED]
    initial: NORMAL
}

stream SemiReports = Stream[DisclosureEvent].filter(event.type == "SEMI_ANNUAL")

contract SemiAnnualCompliance on Company {
    let deadline = 100000.0
    invariant:
        (now() > deadline) implies historically(exists(SemiReports), within: 60d)

    violation {
        severity: CRITICAL
        guard: DaysOverdue(deadline) > 5.0
        transition: NORMAL -> SUSPENDED
        emit: "Overdue > 5 days. Trading suspended."
    }
}
```

新增 `var` 动态字段（不改 Schema）：

```text
var audit_opinion_clean = DisclosureEvent.audit_opinion == "UNQUALIFIED"
```

新增 `until` 时序约束：

```text
invariant: until(always(state == SUSPENDED), historically(exists(RemediationReport), within: 365d))
```

## 已实现能力对照（设计文档 §6）

| 能力 | 状态 |
|---|---|
| entity / stream / signal / contract | ✅ |
| historically / always / eventually / implies | ✅ |
| until / within(T, p) | ✅ 解析 + 保守运行时语义 |
| var 动态绑定 + DataDictionary | ✅ |
| 多实体分桶（Company / Account / Security ...） | ✅ |
| 死规则检测（vacuous / tautology） | ✅ 常量折叠，生产可换 Z3 后端 |
| 动作冲突检测 | ✅ 同实体同状态互斥转移 |
| 覆盖缺口（未引用 stream / 死状态） | ✅ |
| var 必须登记检查 | ✅ |
| AlertDispatcher（内存 / stdout） | ✅ |
| `eventually` / `within` 的未来承诺语义 | ⏳ v1.5，需要定时回查 |
| Z3 后端替换 | ⏳ 当前为保守常量折叠，接口预留 |

## 二期扩展能力（本次新增）

| 方向 | crate | 状态 |
|---|---|---|
| 一、规则版本治理：Semantic Diff（Tightened / Loosened / Equivalent） | `rules-diff` | ✅ 4 tests |
| 二、证据链：DecisionTree + 最小归因 + 快照哈希 | `rules-proof` | ✅ 2 tests |
| 三、双时钟解耦 + Shadow Replay + 回测报告 | `rules-backtest` | ✅ 2 tests |
| 四、Flat Layout + 栈式字节码 VM（WASM 后端铺垫） | `rules-flatvm` | ✅ 2 tests |
| 五、浏览器端配置台（输入即校验 + 可视化） | `web/index.html` | ✅ 单文件可直接打开 |

打开 `web/index.html` 即可看到规则配置台：左侧 DSL 编辑，中间实时语法校验 + v1→v2 Semantic Diff 卡片，右侧规则清单。
Z3-in-WASM 接入点已在界面中标注，生产把 `z3-solver` npm 包编译为 wasm 即可把静态预览替换为真 SMT 求解。

## 测试结果

```
running 20 tests
... 全部通过（e2e 10 + diff 4 + proof 2 + backtest 2 + flatvm 2）
```
