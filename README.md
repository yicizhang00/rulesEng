# rulesEng — 时序约束 DSL 与统一监管规则引擎

把散落在微服务里的监管规则收敛成**声明式时序约束**，上线前用**时序模型检验**保证完备性，
运行时把事件流下沉为**扁平自动机 + 环形缓冲区**的原生扫描。

本项目的 DSL **刻意不是 Drools / EasyRules 那类产生式规则引擎**。产出式规则（RETE / PHREAK）
把"状态"与"计算"割裂：事实离散插入、动作脚本式副作用、时间只当一个普通字段。交易所核心
监管场景里，合规本质上谈的是**时间窗口内的流式聚合、时序滑动与状态演化**，
所以本引擎的语言原语不是 `when P then {...}`，而是**四类一阶公民**。

---

## 一、与 Drools 的路线差异

| 维度            | Drools / EasyRules（产生式）                | 本项目（时序约束）                                              |
| ------------- | ------------------------------------ | ------------------------------------------------------ |
| 核心原语          | Fact + Production Rule（LHS → RHS）    | **Entity / Stream / Metric / Spec** 四类一阶公民              |
| 时间            | 事实的一个字段（`timestamp`）                 | **一等算子**：`always` `historically` `eventually` `within` `until` `since` |
| 状态与计算         | 割裂：外部准备 `ctx.disclosure.days_overdue` | 融合：`metric` 是 DSL 内的**派生信号流**，可 `from <stream>.fold(...)` |
| 动态扩展指标        | 靠外挂参数 / 改 Schema                     | `metric M(p: T) -> T := expr where guard`，无需改 Schema    |
| 动作            | `then` 里的脚本副作用                       | **确定性状态迁移** `transition: A -> B`，受实体状态空间约束            |
| 校验维度          | 事实模式匹配、规则可达性                         | **时序模型检验**：状态转移完备性 + 因果死锁                             |
| 执行模型          | Fact 插入 → 重跑 RETE 网络 → 激活规则          | 事件 → 环形缓冲区 → **扁平自动机单向扫描**，零递归零分配                      |
| 反射 / AST 遍历   | 运行期仍依赖对象反射与节点匹配                      | 装载期编译为 `Vec<FlatOp>` / `Vec<AutoNode>`，运行期只做数组索引        |

**为什么这很重要**：如果只是把"条件判断"换层皮写成 `when ... then ...`、前面再挂几个 `var`，
那它本质上还是一个简陋版 Drools —— 微服务依然要到处写代码去算"是否逾期"、"逾期了几天"，
规则引擎退化为"单纯的 if-else 计算器"。

---

## 二、DSL 速览（四类一阶概念）

```text
// ── 概念 1a：Entity —— 实体生命周期 + 确定性状态迁移边 ─────────────────
entity Company(key: code) {
    states: [NORMAL, SUSPENDED, TERMINATED]
    initial: NORMAL
    terminal: [TERMINATED]

    transition Suspend {
        from: NORMAL
        to: SUSPENDED
        on: SemiAnnualDeadline        // 驱动该边的 spec
        emit: "trading suspended"
    }
    transition Reinstate { from: SUSPENDED to: NORMAL }
    transition Terminate { from: SUSPENDED to: TERMINATED }
}

// ── 概念 2：Stream & Event —— 事件流算子（投影 / 过滤 / 关联 / 窗口）──────
stream SemiAnnualReports := Event[DisclosureEvent]
    .filter(e => e.type == "SEMI_ANNUAL")
    .window(60d)

// ── 概念 1b：Metric —— 动态派生信号流（不是静态变量）────────────────────
//  形态 A：带 where 守卫的标量信号
metric DaysOverdue(c: Company, deadline: Timestamp) -> int :=
    days_between(now(), deadline) where now() > deadline

//  形态 B：直接对事件流做滑动折叠
metric CancelNotional(c: Account) -> float :=
    from Cancels.fold(0.0, (acc, t) => acc + t.amount)

//  形态 C：流上的聚合
metric ReportCount := from SemiAnnualReports.count()

// ── 概念 3 + 4：Spec —— 时序不变量 + 违规处置 ─────────────────────────
spec SemiAnnualDeadline on c: Company {
    given:
        let deadline = 100000.0

    invariant:
        (now() > deadline) implies
            historically(SemiAnnualReports.exists(r => r.code == c.code), within: 60d)

    violation {
        severity: CRITICAL
        guard: DaysOverdue(c, deadline) > 5
        transition: NORMAL -> SUSPENDED
        emit: "Overdue semi-annual disclosure > 5 days. Trading suspended."
    }
}
```

`spec` 声明的是**合法状态空间**（"这个不变量必须始终为真"），由引擎求解"何时被打破"——
而不是写"什么时候做什么"的过程触发器。

### 事件流算子（概念 2）

```text
stream Trades  := Event[TradeEvent].window(1h)
stream Cancels := Trades.filter(t => t.kind == "CANCEL")           // 过滤
stream Big     := Trades.map(t => t.amount).window(5m)             // 投影
stream Joined  := Trades.join(Enriched, (l, r) => l.code == r.code) // 关联
metric CancelRatio(c: Account) -> float :=
    ratio(Cancels.count(), Trades.count()) where Trades.count() > 0.0   // 流聚合调用
```

### 时序算子（概念 3）

| 算子                                              | 语义                          | 自动机记忆单元      |
| ----------------------------------------------- | --------------------------- | ------------ |
| `always(p)`                                     | 此后 p 恒成立（不变量）               | latch（一旦为假永久为假） |
| `historically(p, within: T)`                    | 过去 T 内 p 至少成立一次             | timers + 窗口回落 |
| `eventually(p, within: T)`                      | 未来 T 内 p 必成立（承诺）            | pending + 截止时刻 |
| `within(T, p)`                                  | 未来 T 内 p 至少成立一次             | pending + 截止时刻 |
| `until(p, q)`                                   | p 持续成立，直到 q 首次成立            | q 出现即 latch  |
| `since(p, q)`                                   | 过去某点 q 成立之后 p 一直成立          | q 出现后要求 p   |
| `p implies q`                                   | 违反条件：p 真且 q 假               | 三值折叠         |

### 兼容旧写法（自动 desugar）

| 旧写法                              | 新写法                                     |
| -------------------------------- | --------------------------------------- |
| `contract X on E`                | `spec X on E`                           |
| `signal f(x: T) -> T = e`        | `metric f(x: T) -> T := e`              |
| `var n = e`                      | `metric n := e`                         |
| `Stream[T]`                      | `Event[T]`                              |
| `rule X on E when P then {...}`  | `spec X on E { invariant: always(not (P)) ... }` |
| `exists(S)`                      | `S.exists()`                            |

旧文件无需改动即可继续解析（见 `crates/rules-parser/src/lib.rs::legacy_syntax_desugars_to_new_ast`）。

---

## 三、执行层：像 eBPF 一样扫描状态

```text
  event ──► 环形缓冲区 RingBuffer                每条流一个定长环，O(1) push / evict
        └─► 扁平自动机 TemporalAutomaton         Vec<AutoNode> 后序布局，单向 for 扫描
                   │                             状态 = u8/i64 数组（truth/latch/pending/timers）
                   │
                   └─► 不变量被打破 ──► 确定性状态迁移 + 告警
```

三个关键点：

1. **零递归、零 AST 遍历**。`Expr` 在装载期编译为线性 `Vec<FlatOp>`；
   `TemporalExpr` 编译为 `Vec<AutoNode>`，**子节点索引恒小于父节点索引**，
   于是每一拍只需一次 `for i in 0..nodes.len()` 的前向扫描。
2. **字符串驻留**。文本被驻留成 `u32`，字符串相等退化为整数比较；
   装载期还会预驻留所有"枚举常量"（状态名、字面标识符），
   因此 `state == SUSPENDED` 是 `u32` 比较而非指针追逐。
3. **扁平内存布局（SoA）**。动态指标编译为固定槽位偏移：数值走 `fields_num: Vec<f64>`，
   文本走 `fields_text: Vec<u32>`，配对槽通过 O(1) 的 `swap_fields` 换入换出。
4. **事件驱动而非轮询**。`ingest()` 在事件落地的**同一拍**推进受影响实体的状态机；
   `tick()` 只用于纯时钟推进（截止期到期）。

数值谓词自动走 `AtomKind::Flat` 原生字节码快路径（`flat_atom_ratio()` 可观测）；
含函数调用或事件字段路径的谓词暂时走宿主求值，直到 WASM 后端把 `Call` 也下沉。

---

## 四、时序模型检验（Drools 校验维度浅的补位）

`rules-verifier` 除了传统的死规则 / 动作冲突 / 覆盖缺口 / 类型检查，新增两类**时序维度**检查：

**1. 跨时间维度的状态转移完备性**

| 编码                                | 含义                                    |
| --------------------------------- | ------------------------------------- |
| `UNREACHABLE_STATE`               | 从 `initial` 出发 BFS 不可达的状态              |
| `STUCK_STATE`                     | 非终态却没有出边（迁移不完备）                       |
| `TERMINAL_STATE_HAS_EDGE`         | 终态竟然还有出边（状态空间不单调）                     |
| `UNDEFINED_TRANSITION_DRIVER`     | `transition ... on: X` 指向不存在/实体不一致的 spec |
| `UNDECLARED_TRANSITION`           | spec 的 `transition:` 与实体声明的边不一致       |
| `TRANSITION_DRIVER_MISMATCH`      | 边的 `on:` 绑定与 spec 声明不匹配                |

**2. 时序事件是否会因果死锁**

| 编码                        | 含义                                  |
| ------------------------- | ----------------------------------- |
| `CAUSAL_DEADLOCK_UNTIL`   | `until(p, q)` 的 q 恒假 → 永远等不到解除条件   |
| `CAUSAL_DEADLOCK_EVENTUALLY` | `eventually(p)` / `within(p)` 内 p 恒假 → 承诺永不兑现 |
| `UNSATISFIABLE_INVARIANT` | 不变量整体恒假 → 规则一上线就永久违反                |
| `IMPOSSIBLE_CONSEQUENT`   | 前提恒真且结论恒假 → 永远不会满足                  |

分级报告：`errors` 阻断入库，`warnings` 仅提示（`VerifyReport::is_ok()`）。

> 目前是保守常量折叠 + 区间传播；`rules-smt` 已预留 Z3 后端接口，接入后可从"保守判定"升级为"完备判定"。

---

## 五、目录结构（Cargo Workspace，14 crates）

```
rulesEng/
├── Cargo.toml
├── crates/
│   ├── rules-ast/          # 四类一阶概念的强类型 AST（Entity/Stream/Metric/Spec + TemporalExpr）
│   ├── rules-parser/       # pest 文法：DSL 文本 → AST（含旧语法 desugar）
│   ├── rules-flatvm/       # 扁平编译层：Interner + FlatOp 字节码 + RingBuffer
│   ├── rules-temporal/     # MTL → 扁平自动机（Always/Historically/Eventually/Until/Since）
│   ├── rules-runtime/      # 事件驱动引擎：投影入环 → 状态机推进 → 违规处置
│   ├── rules-verifier/     # 静态校验 + 时序模型检验（转移完备性 / 因果死锁）
│   ├── rules-dictionary/   # DataDictionary：外部数据源绑定
│   ├── rules-dispatcher/   # Alert trait
│   ├── rules-smt/          # 轻量符号求解（区间传播，Z3 后端接口预留）
│   ├── rules-cli/          # CLI 入口 + 34 个 e2e 测试
│   ├── rules-diff/         # 【二期】Semantic Diff: Tightened/Loosened/Equivalent
│   ├── rules-proof/        # 【二期】证据链: DecisionTree + 最小归因 + FNV 哈希
│   ├── rules-backtest/     # 【二期】双时钟 + Shadow Replay + 回测报告
│   └── rules-server/       # HTTP 控制面
├── web/                    # 规则配置台（Vue 3 + Vite + Element Plus + Vue Flow）
├── docs/
│   ├── sql/schema.sql
│   └── 差距分析报告.md
├── examples/               # semi_annual / until_rule / with_var / cancel_ratio
└── 需求文档.md / 设计文档.md
```

---

## 六、快速开始

```powershell
cargo build                                        # 编译整个 workspace
cargo test                                         # 全量 73 个测试
cargo run -p rules-cli -- demo                     # 半年报 demo（四类概念 + 自动机观测）
cargo run -p rules-cli -- verify examples/semi_annual.rules   # 静态校验（错误阻断，警告提示）
cargo run -p rules-cli -- run    examples/cancel_ratio.rules  # 校验 + 跑派生信号流 demo

# 后端（未配置 DATABASE_URL 则内存模式）
powershell -File start-server.ps1
# 前端（Vue 控制台，proxy /api /parse /verify → 127.0.0.1:8081）
powershell -File start-web.ps1
# 前端单测 / 构建
cd web; npm test; npm run build
```

`demo` 会打印编译后的自动机指标：

```
=== Compiled temporal automata ===
  spec SemiAnnualDeadline -> 4 nodes, flat_atom_ratio=0.00, window=5184000s
```

---

## 七、HTTP API（rules-server，默认 127.0.0.1:8081）

| 方法                  | 路径                            | 说明                                                                            |
| ------------------- | ----------------------------- | ----------------------------------------------------------------------------- |
| GET                 | `/health`                     | 存活探针                                                                          |
| POST                | `/parse`                      | DSL → AST JSON / 精确语法错误（含行列）                                                  |
| POST                | `/verify?rule_id=N`           | 分级校验报告 `{ok, status, errors[], warnings[]}`                                   |
| GET/POST/PUT/DELETE | `/api/groups[/:id]`           | 规则分组（层级；id=1 默认分组不可删）                                                         |
| GET                 | `/api/rules?group_id=N`       | 规则列表（可按分组过滤）                                                                  |
| GET                 | `/api/rules/:id`              | 规则详情（name/group_id/dsl/mode/cron/status/owner）                                |
| POST                | `/api/rules`                  | 新建规则：**先 parse+verify，errors 非空即拒绝入库**，通过后写 `rule_versions` + `rule_triggers` |
| PUT                 | `/api/rules/:id`              | 更新规则：同样走门禁，并追加一个版本快照                                                          |
| DELETE              | `/api/rules/:id`              | 删除规则（级联版本/触发器/绑定/动作）                                                          |
| GET                 | `/api/rules/:id/versions`     | 规则版本历史（dsl_text / ast_json / verify_report）                                   |
| GET/POST/PUT/DELETE | `/api/datasources[/:id]`      | 数据源 CRUD                                                                      |
| POST                | `/api/datasources/:id/test`   | 真实连接探测，返回表清单                                                                  |
| GET                 | `/api/datasources/:id/schema` | schema → table → column 三级树                                                   |
| GET/POST/DELETE     | `/api/bindings[/:id]`         | 变量→列绑定（`rule_id + var_name` 唯一，POST 为 upsert）                                 |
| GET/POST/DELETE     | `/api/actions[/:id]`          | 告警动作（类型白名单 sms/http/email/state_transition）                                   |

---

## 八、已实现能力对照

| 能力                                                       | 状态                              |
| -------------------------------------------------------- | ------------------------------- |
| Entity / Stream / Metric / Spec 四类一阶概念                    | ✅                              |
| 流算子：filter / map / window / fold / count·sum·avg·min·max / distinct / union | ✅（join / coGroup 仅解析） |
| Metric 三形态：标量（带 where）/ 流折叠 / 流聚合                        | ✅                              |
| MTL 算子全量：always / historically / eventually / within / until / since / implies | ✅ |
| 时序状态机编译为扁平自动机（零递归单向扫描）                                   | ✅                              |
| 环形缓冲区：O(1) push / evict，窗口顺序扫描                            | ✅                              |
| 字符串驻留 + 配对槽扁平布局 + 原生字节码快路径                                | ✅                              |
| 事件驱动推进（ingest 同拍 step）                                    | ✅                              |
| 状态转移完备性检验（6 项）                                           | ✅                              |
| 因果死锁检验（4 项）                                              | ✅                              |
| 死规则 / 动作冲突 / 覆盖缺口 / 类型检查 + 分级报告                           | ✅                              |
| 规则保存门禁（parse+verify 不通过禁止入库）                              | ✅                              |
| 规则版本 + 触发器 + 绑定 + 数据源 + 告警动作落库                            | ✅                              |
| 前端配置台：规则管理（Vue Flow 画布，生成时序 spec）/ 校验报告 / 数据源 / 动作       | ✅                              |
| 证据链 / Semantic Diff / 双时钟回测                                | ✅ crate 级（尚未接入 server/web）      |
| Z3 完备性判定                                                | ⏳ 接口预留，当前保守折叠                   |
| LLVM/WASM 状态机编译                                          | ⏳ 接口预留，当前为原生字节码快路径              |
| CDC 订阅 / cron 调度器 / 分布式 worker                          | ⏳ 未实现                           |

> 完整差距清单、假设与待确认事项见 `docs/差距分析报告.md`。

---

## 九、测试结果

```
cargo test --workspace   → 73 passed / 0 failed
  rules-cli e2e 34 / rules-temporal 9 / rules-server 7 / rules-flatvm 5 (+bench 1)
  rules-smt 5 / rules-parser 4 / rules-diff 4 / rules-verifier ...
  rules-proof 2 / rules-backtest 2

cd web && npm test       → 17 passed（tests/dsl.test.js）
cd web && npm run build  → ok
```
