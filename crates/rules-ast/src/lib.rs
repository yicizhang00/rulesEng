//! rules-ast —— 统一强类型 AST（v1.0 四模同构）。
//!
//! 本 AST **刻意不采用** Drools / EasyRules 的 Production-Rule（LHS → RHS）模型。
//! 产生式规则把"状态"与"计算"割裂：事实离散进入、动作脚本式副作用，规则语言退化为
//! `if-else` 计算器。这里把四类概念提升为一阶公民，并由一个 **执行模式（[`Mode`]）**
//! 描述符统摄四种落地形态：
//!
//! | 模式 | [`Mode`] | 语义载体 |
//! |---|---|---|
//! | A Verified | `Pure` | [`SpecDecl`] + [`Verdict`]（纯函数裁决） |
//! | B Drools 兼容 | `Stateful` | [`StatefulRuleDecl`] + [`WorkingFact`]（受限工作内存） |
//! | C 流式滑动窗口 | `Stream` | [`StreamDecl`] + [`Effect::LeaseUpdate`]（惩罚租约） |
//! | D DMN 决策表 | `DecisionTable` | [`DecisionTableDecl`]（符号表查表） |
//!
//! 四类一阶概念：
//!
//! | # | 概念 | 节点 | 语义 |
//! |---|------|------|------|
//! | 1 | **Entity & Signal** | [`EntityDecl`] / [`MetricDecl`] / [`StateVarDecl`] | 实体生命周期 + 持续计算的派生信号流（滑动折叠），而非外挂参数 |
//! | 2 | **Stream & Event** | [`StreamDecl`] / [`StreamOp`] | 事件流的投影 / 过滤 / 关联，带 lambda |
//! | 3 | **Temporal Invariant** | [`SpecDecl`] / [`TemporalExpr`] | 度量时序逻辑（MTL）：Always / Eventually / Within / Until / Implies |
//! | 4 | **StateMachine & Violation** | [`TransitionDecl`] / [`ViolationHandler`] / [`Verdict`] | 确定性状态迁移 + 抽象裁决，而非离散脚本副作用 |
//!
//! 所有节点带 [`Span`]（line/col）与可选 [`node_id`](NodeMeta) 用于报错回溯与前端画布锚定。

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 源码位置。解析时由 parser 填充。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Span {
    pub line: u32,
    pub col: u32,
}

/// FR1：所有 AST 节点统一携带的元信息（节点 id + 源码位置）。
///
/// `node_id` 由 parser 按出现顺序分配，前端画布与 AST 双向映射时以它作为稳定锚点。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NodeMeta {
    pub node_id: u32,
    pub span: Span,
}

// =====================================================================
// 执行模式（FR1：pure / stateful / stream / decision_table）
// =====================================================================

/// 执行模式修饰符。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Mode {
    /// 模式 A：形式化纯函数（Verified）。
    #[default]
    Pure,
    /// 模式 B：受限工作内存推导（Drools 兼容）。
    Stateful,
    /// 模式 C：高频流式滑动窗口与租约。
    Stream,
    /// 模式 D：DMN 决策表。
    DecisionTable,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pure" => Mode::Pure,
            "stateful" => Mode::Stateful,
            "stream" => Mode::Stream,
            "decision_table" | "decisionTable" | "dmn" => Mode::DecisionTable,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Pure => "pure",
            Mode::Stateful => "stateful",
            Mode::Stream => "stream",
            Mode::DecisionTable => "decision_table",
        }
    }
    /// 落库用的 `rules.mode` 枚举值（v1.0 DDL）。
    pub fn db_value(&self) -> &'static str {
        match self {
            Mode::Pure => "PURE",
            Mode::Stateful => "STATEFUL",
            Mode::Stream => "STREAM",
            Mode::DecisionTable => "DMN",
        }
    }
    /// 从落库枚举值还原。
    pub fn from_db(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "PURE" => Mode::Pure,
            "STATEFUL" => Mode::Stateful,
            "STREAM" => Mode::Stream,
            "DMN" => Mode::DecisionTable,
            _ => return None,
        })
    }
}

// =====================================================================
// 顶层
// =====================================================================

/// 一份规格文件 = 四类概念的集合（v1.0 四模同构）。
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SpecFile {
    /// 概念 1：实体生命周期（同时承载概念 4 的状态机边）。
    pub entities: Vec<EntityDecl>,
    /// 概念 2：事件流。
    pub streams: Vec<StreamDecl>,
    /// 概念 1：动态派生信号流（metric）。
    pub metrics: Vec<MetricDecl>,
    /// 概念 3：时序不变量 / 准入守卫规格。
    pub specs: Vec<SpecDecl>,
    // ---------- v1.0 新增 ----------
    /// 模式 D：DMN 决策表。
    #[serde(default)]
    pub decision_tables: Vec<DecisionTableDecl>,
    /// 模式 B：受限工作内存规则（Drools 兼容）。
    #[serde(default)]
    pub stateful_rules: Vec<StatefulRuleDecl>,
    /// FR1：参数化强类型变量声明（`var x: int range: 0..100`）。
    #[serde(default)]
    pub var_decls: Vec<VarDecl>,
    /// 实体 ↔ 数据源物理绑定（`bind: Datasource["x"].Table["y"]`）。
    #[serde(default)]
    pub binds: Vec<BindDecl>,
    /// FR1：本文件声明的主要执行模式（取首个契约块模式；缺省 `Pure`）。
    #[serde(default)]
    pub mode: Mode,
}

impl SpecFile {
    pub fn entity(&self, name: &str) -> Option<&EntityDecl> {
        self.entities.iter().find(|e| e.name == name)
    }
    pub fn stream(&self, name: &str) -> Option<&StreamDecl> {
        self.streams.iter().find(|s| s.name == name)
    }
    pub fn metric(&self, name: &str) -> Option<&MetricDecl> {
        self.metrics.iter().find(|m| m.name == name)
    }
    pub fn spec(&self, name: &str) -> Option<&SpecDecl> {
        self.specs.iter().find(|s| s.name == name)
    }
    pub fn decision_table(&self, name: &str) -> Option<&DecisionTableDecl> {
        self.decision_tables.iter().find(|d| d.name == name)
    }
    pub fn stateful_rule(&self, name: &str) -> Option<&StatefulRuleDecl> {
        self.stateful_rules.iter().find(|r| r.name == name)
    }
    /// 所有实体的状态名（供 DMN / 前端画布枚举使用）。
    pub fn all_state_names(&self) -> Vec<&str> {
        self.entities.iter().flat_map(|e| e.state_names()).collect()
    }
    /// 推断主模式：优先取显式模式，缺省按内容推断（有决策表 → DMN，有 stateful rule → STATEFUL）。
    pub fn inferred_mode(&self) -> Mode {
        if self.mode != Mode::Pure {
            return self.mode;
        }
        if !self.stateful_rules.is_empty() {
            return Mode::Stateful;
        }
        if !self.decision_tables.is_empty() {
            return Mode::DecisionTable;
        }
        if !self.streams.is_empty() {
            return Mode::Stream;
        }
        Mode::Pure
    }
}

// =====================================================================
// 概念 1a：Entity —— 实体生命周期
// =====================================================================

/// 实体声明：一个有序的状态空间 + 单调的迁移边集合。
///
/// 注意这里**不再有 `when/then`**：迁移边只是"合法状态空间"的一部分，
/// 真正决定何时迁移的是 [`SpecDecl`] 的时序不变量 / 裁决。
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct EntityDecl {
    pub name: String,
    /// 实例键字段（`key: code`）。运行时事件按该字段路由到实体实例。
    pub key: String,
    /// FR1：执行模式。
    #[serde(default)]
    pub mode: Mode,
    /// FR5：位向量状态常量（`states: [ A = 0x01, B = 0x02 ]`）。
    pub states: Vec<StateConst>,
    /// 初始状态名（位掩码语义下即初始置位的位）。
    pub initial: String,
    /// 终态集合：允许没有出边，且不允许再迁出（模型检验据此判定完备性）。
    pub terminal: Vec<String>,
    /// 状态机迁移边（概念 4）。
    pub transitions: Vec<TransitionDecl>,
    /// 模式 C：可写状态变量（`state var frozen_until: Timestamp = 0`），承载惩罚租约。
    #[serde(default)]
    pub state_vars: Vec<StateVarDecl>,
    /// FR8：物理绑定。
    #[serde(default)]
    pub binds: Vec<BindDecl>,
    /// FR1：范围约束（`var x: int range: 0..100` 挂在实体维度上）。
    #[serde(default)]
    pub var_decls: Vec<VarDecl>,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

impl EntityDecl {
    pub fn is_terminal(&self, state: &str) -> bool {
        self.terminal.iter().any(|t| t == state)
    }
    /// 从某状态出发的迁移边。
    pub fn edges_from<'a>(&'a self, state: &'a str) -> impl Iterator<Item = &'a TransitionDecl> {
        self.transitions.iter().filter(move |t| t.from == state)
    }
    /// 状态名列表（兼容旧 `Vec<String>` 语义）。
    pub fn state_names(&self) -> Vec<&str> {
        self.states.iter().map(|s| s.name.as_str()).collect()
    }
    /// 按名取位掩码（FR5）。
    pub fn mask_of(&self, name: &str) -> Option<u64> {
        self.states.iter().find(|s| s.name == name).and_then(|s| s.mask)
    }
    /// 该实体是否声明了位向量状态（全部状态都有显式 mask）。
    pub fn is_bitvec(&self) -> bool {
        !self.states.is_empty() && self.states.iter().all(|s| s.mask.is_some())
    }
    /// FR5：状态名 → 位的序号（无显式 mask 时按声明顺序隐式分配）。
    pub fn bit_of(&self, name: &str) -> Option<u32> {
        self.states.iter().position(|s| s.name == name).map(|i| i as u32)
    }
    pub fn state_var(&self, name: &str) -> Option<&StateVarDecl> {
        self.state_vars.iter().find(|v| v.name == name)
    }
}

/// FR5：位向量状态常量。`states: [ CSRC_APPROVED = 0x04 ]`。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StateConst {
    pub name: String,
    /// 位掩码（缺省时由 verifier/runtime 按声明顺序补齐 1<<i）。
    pub mask: Option<u64>,
}

impl StateConst {
    pub fn named(name: impl Into<String>) -> Self {
        StateConst { name: name.into(), mask: None }
    }
    pub fn masked(name: impl Into<String>, mask: u64) -> Self {
        StateConst { name: name.into(), mask: Some(mask) }
    }
    /// 兼容旧 `Vec<String>` 的 `.as_str()` 用法。
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

/// FR6 / FR2：可写实体状态变量（`state var frozen_until: Timestamp = 0`）。
///
/// 与 [`MetricDecl`] 的区别：metric 是**只读派生信号**，state var 是**可被
/// [`Effect::LeaseUpdate`] 单调推进的账本**（典型即惩罚租约 `frozen_until`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateVarDecl {
    pub name: String,
    pub ty: DataType,
    pub init: Expr,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

/// 确定性状态迁移：`from --(on: Spec)--> to`。
///
/// `on` 指向驱动该迁移的 [`SpecDecl`]；缺失表示该边由实体内部逻辑驱动。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TransitionDecl {
    pub name: String,
    pub from: String,
    pub to: String,
    pub on: Option<String>,
    pub emit: Option<String>,
    /// 该迁移是否由 OR 语义的位向量置位驱动（FR5）。
    #[serde(default)]
    pub bitwise: bool,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

impl TransitionDecl {
    pub fn new(name: impl Into<String>, from: impl Into<String>, to: impl Into<String>) -> Self {
        TransitionDecl {
            name: name.into(),
            from: from.into(),
            to: to.into(),
            on: None,
            emit: None,
            bitwise: false,
            meta: NodeMeta::default(),
            span: Span::default(),
        }
    }
}

// =====================================================================
// 概念 2：Stream & Event —— 事件流算子
// =====================================================================

/// 一条声明式事件流：`stream X := Event[T].filter(...).window(sliding(5s))`。
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct StreamDecl {
    pub name: String,
    pub source: StreamSource,
    /// 算子链，按书写顺序应用。
    pub ops: Vec<StreamOp>,
    /// FR1：该流所属执行模式（缺省由所属契约决定）。
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

impl StreamDecl {
    /// 该流最终绑定的底层事件类型（若来源于另一个流则递归回溯）。
    pub fn event_type<'a>(&'a self, all: &'a [StreamDecl]) -> Option<&'a str> {
        match &self.source {
            StreamSource::None => None,
            StreamSource::Event(t) => Some(t.as_str()),
            StreamSource::Events(v) => v.first().map(|s| s.as_str()),
            StreamSource::Ref(r) => all.iter().find(|s| s.name == *r)?.event_type(all),
        }
    }

    /// 该流接纳的**全部**事件类型（`Event[A, B]`）。
    pub fn event_types<'a>(&'a self, all: &'a [StreamDecl]) -> Vec<&'a str> {
        match &self.source {
            StreamSource::None => Vec::new(),
            StreamSource::Event(t) => vec![t.as_str()],
            StreamSource::Events(v) => v.iter().map(|s| s.as_str()).collect(),
            StreamSource::Ref(r) => all
                .iter()
                .find(|s| s.name == *r)
                .map(|s| s.event_types(all))
                .unwrap_or_default(),
        }
    }

    /// 静态窗口（来自 `.window(T)`），用于环形缓冲区容量与淘汰。
    pub fn window_secs(&self) -> Option<u64> {
        self.ops.iter().find_map(|op| match op {
            StreamOp::Window(w) => static_window_secs(&w.size),
            _ => None,
        })
    }

    /// 窗口语义（滑动 / 翻滚）。
    pub fn window_kind(&self) -> Option<WindowKind> {
        self.ops.iter().find_map(|op| match op {
            StreamOp::Window(w) => Some(w.kind),
            _ => None,
        })
    }

    /// 投影/过滤算子链中的 lambda（供 verifier 做引用收集）。
    pub fn lambdas(&self) -> impl Iterator<Item = &Lambda> {
        self.ops.iter().filter_map(|op| match op {
            StreamOp::Filter(l) | StreamOp::Map(l) => Some(l),
            StreamOp::Distinct(Some(l)) => Some(l),
            StreamOp::Aggregate { lambda: Some(l), .. } => Some(l),
            _ => None,
        })
    }
}

/// 流的数据来源。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum StreamSource {
    /// `Event[DisclosureEvent]` —— 底层事件类型（旧写法 `Stream[T]` 等价）。
    #[default]
    None,
    Event(String),
    /// `Event[OrderIntent, CancelIntent]` —— 多事件类型源（FR6 / 用例 1）。
    Events(Vec<String>),
    /// 引用另一条已声明的流（算子复用）。
    Ref(String),
}

/// 流算子（一阶：投影 / 过滤 / 关联 / 窗口 / 折叠）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StreamOp {
    /// `.filter(e => expr)` —— 保留满足谓词的事件。
    Filter(Lambda),
    /// `.map(e => expr)` —— 投影为派生值。
    Map(Lambda),
    /// `.window(sliding(T))` / `.window(T)` —— 滑动/翻滚窗口（环形缓冲区保留时长）。
    Window(WindowSpec),
    /// `.fold(init, (acc, e) => expr)` —— 滑动折叠，产出持续更新的派生信号。
    Fold { init: Expr, acc: String, item: String, body: Expr },
    /// `.count(lambda?)` / `.sum(...)` / `.avg(...)` / `.min(...)` / `.max(...)`。
    Aggregate { kind: AggKind, lambda: Option<Lambda> },
    /// `.join(Other, (l, r) => cond)` —— 流关联。
    Join { other: String, left: String, right: String, on: Expr },
    /// `.coGroup(Other, (l, r) => cond)` —— 协同分组（保留两侧未匹配项）。
    CoGroup { other: String, left: String, right: String, on: Expr },
    /// `.distinct(lambda?)` —— 按 key 去重。
    Distinct(Option<Lambda>),
    /// `.union(Other)` —— 并流。
    Union(String),
}

/// FR6：窗口规格。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowSpec {
    pub kind: WindowKind,
    pub size: Expr,
}

impl WindowSpec {
    /// 裸 `.window(T)` 形式（缺省滑动）。
    pub fn sliding(size: Expr) -> Self {
        WindowSpec { kind: WindowKind::Sliding, size }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WindowKind {
    /// 滑动窗口：每来一个事件都重算（时间片双端队列）。
    #[default]
    Sliding,
    /// 翻滚窗口：按固定周期切分。
    Tumbling,
}

impl WindowKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            WindowKind::Sliding => "sliding",
            WindowKind::Tumbling => "tumbling",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggKind {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

impl AggKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "count" => AggKind::Count,
            "sum" => AggKind::Sum,
            "avg" => AggKind::Avg,
            "min" => AggKind::Min,
            "max" => AggKind::Max,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            AggKind::Count => "count",
            AggKind::Sum => "sum",
            AggKind::Avg => "avg",
            AggKind::Min => "min",
            AggKind::Max => "max",
        }
    }
}

/// lambda：`e => e.report_type == "SEMI_ANNUAL"`，或双参 `(l, r) => l.id == r.id`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lambda {
    pub params: Vec<String>,
    pub body: Expr,
}

impl Lambda {
    /// 空参 lambda（用于旧写法 `.filter(event.type == "X")`，隐式绑定 `event`）。
    pub fn implicit(body: Expr) -> Self {
        Self { params: vec!["event".to_string()], body }
    }
    /// 是否使用了隐式 `event` 绑定（无显式箭头）。
    pub fn is_implicit(&self) -> bool {
        self.params.len() == 1 && self.params[0] == "event"
    }
}

// =====================================================================
// 概念 1b：Metric —— 动态派生信号流
// =====================================================================

/// 派生信号（`metric`）：不是静态变量，而是一个**持续计算的信号流**。
///
/// 三种形态：
/// 1. `metric DaysOverdue(c: Company, deadline: Timestamp) -> int :=
///        days_between(now(), deadline) where now() > deadline`
///    —— 带 `where` 守卫的标量信号（守卫不满足时信号取 0）；
/// 2. `metric Exposure := from Trades.fold(0.0, (acc, t) => acc + t.amount)`
///    —— 直接对事件流做滑动折叠的派生流；
/// 3. `metric ReportCount := from Approved.count()`
///    —— 流上的聚合。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricDecl {
    pub name: String,
    /// 形参列表（可为空 = 零元信号）。
    pub params: Vec<Param>,
    pub ret: DataType,
    pub body: MetricBody,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub ty: DataType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetricBody {
    /// 标量信号：`expr where guard`。
    Scalar {
        expr: Expr,
        /// `where` 守卫；为 None 表示无守卫。
        guard: Option<Expr>,
    },
    /// 派生流折叠：`from <stream>.fold(init, (acc, item) => body)`。
    StreamFold { stream: String, init: Expr, acc: String, item: String, body: Expr },
    /// 派生流聚合：`from <stream>.count()` 等。
    StreamAgg { stream: String, kind: AggKind },
}

impl MetricDecl {
    /// 该 metric 依赖的流名（若有）。
    pub fn source_stream(&self) -> Option<&str> {
        match &self.body {
            MetricBody::StreamFold { stream, .. } | MetricBody::StreamAgg { stream, .. } => {
                Some(stream.as_str())
            }
            MetricBody::Scalar { .. } => None,
        }
    }
}

/// FR1：参数化强类型变量声明 `var <name>: <type> [range: a..b] [= init]`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VarDecl {
    pub name: String,
    pub ty: DataType,
    /// 交集/阈值区间约束（送入 SMT 作为 DomainAxiom）。
    pub range: Option<(Expr, Expr)>,
    pub init: Option<Expr>,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

/// FR8：变量 → 数据源表字段的物理绑定。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BindDecl {
    pub datasource: String,
    pub table: String,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DataType {
    Int,
    #[default]
    Float,
    Bool,
    String,
    /// 时间点（秒）。
    Timestamp,
    /// 时长（秒）。
    Duration,
    /// FR1/FR5：定宽位向量（单调状态格）。
    BitVec,
}

impl DataType {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "int" | "Int" | "INT" => DataType::Int,
            "float" | "Float" | "FLOAT" => DataType::Float,
            "bool" | "Bool" | "BOOL" | "boolean" => DataType::Bool,
            "string" | "String" | "STRING" => DataType::String,
            "timestamp" | "Timestamp" | "Date" | "date" | "datetime" => DataType::Timestamp,
            "duration" | "Duration" => DataType::Duration,
            "bitvec" | "BitVec" | "bit_vector" | "Bitmask" => DataType::BitVec,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            DataType::Int => "int",
            DataType::Float => "float",
            DataType::Bool => "bool",
            DataType::String => "string",
            DataType::Timestamp => "timestamp",
            DataType::Duration => "duration",
            DataType::BitVec => "bitvec",
        }
    }
}

// =====================================================================
// 概念 3：Spec —— 时序不变量 / 准入守卫
// =====================================================================

/// 策略单元类型：准入守卫（先于业务执行）或时序不变量（持续成立）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PolicyKind {
    /// `guard N on Event[...] { when: ... verdict: DENY(...) }` —— PEP 前置快筛。
    Guard,
    /// `invariant N on Event[...] { ... }` / `spec N on c: E { invariant: ... }`。
    #[default]
    Invariant,
}

impl PolicyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyKind::Guard => "guard",
            PolicyKind::Invariant => "invariant",
        }
    }
}

/// 监管规格：把"合规"定义为一个必须**始终满足**的时序不变量，或一个**准入守卫**。
///
/// ```text
/// # 形态 1（v1.0 用例语法）
/// guard IsNotFrozen on Event[OrderIntent] {
///     when: now() < frozen_until
///     verdict: DENY(code: "ERR_SEAT_FROZEN", reason: "…")
/// }
/// # 形态 2（经典约定语法）
/// spec SemiAnnual on c: Company {
///     given: let deadline = 100000.0
///     invariant: (now() > deadline) implies historically(Reports.exists(...), within: 60d)
///     violation { severity: CRITICAL guard: ... transition: NORMAL -> SUSPENDED }
/// }
/// ```
///
/// 业务人员声明的是"合法状态空间是什么 / 什么输入必须被拒绝"，由引擎求解何时打破——
/// 而不是写"什么时候做什么"的过程触发器。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpecDecl {
    pub name: String,
    /// 被约束的实体类型。
    pub entity_name: String,
    /// 实体绑定变量（`on c: Company` 中的 `c`；旧写法缺省为实体名小写）。
    pub entity_var: String,
    /// FR1：执行模式。
    #[serde(default)]
    pub mode: Mode,
    /// 守卫 or 不变量。
    #[serde(default)]
    pub kind: PolicyKind,
    /// `on Event[A, B]` —— 触发事件类型（空 = 任意带实体键的事件）。
    #[serde(default)]
    pub events: Vec<String>,
    /// `given:` 局部绑定（`let period = ...`）。
    pub given: Vec<(String, Expr)>,
    /// 时序不变量（MTL）。违反 = 不变量为假。
    pub invariant: TemporalExpr,
    /// 违反后的处置（概念 4）。
    pub violation: ViolationHandler,
    /// v1.0：抽象裁决（`DENY(code, reason)` / `ALLOW`）。
    #[serde(default)]
    pub verdict: Verdict,
    /// v1.0：触发后的确定性副作用（租约更新 / 状态迁移 / 告警）。
    #[serde(default)]
    pub effects: Vec<Effect>,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

impl SpecDecl {
    /// 该 spec 是否需要在每个事件拍做 O(1) 快筛（属于 PEP 准入路径）。
    pub fn is_guard(&self) -> bool {
        self.kind == PolicyKind::Guard
    }
    /// 找到该 spec 上的租约更新副作用（FR6）。
    pub fn lease_update(&self) -> Option<(&str, &Expr)> {
        self.effects.iter().find_map(|e| match e {
            Effect::LeaseUpdate { target, expr } => Some((target.as_str(), expr)),
            _ => None,
        })
    }
    /// 该 spec 声明的状态迁移（若有）。
    pub fn declared_transition(&self) -> Option<(&str, &str)> {
        if let Some((f, t)) = &self.violation.transition {
            return Some((f.as_str(), t.as_str()));
        }
        self.effects.iter().find_map(|e| match e {
            Effect::Transition { from, to } => Some((from.as_str(), to.as_str())),
            _ => None,
        })
    }
}

/// 违规处置：确定性状态迁移 + 告警（经典 `violation { ... }` 语法）。
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ViolationHandler {
    pub severity: Severity,
    /// 只有 guard 为真才真正触发处置（用于"逾期 > 5 天"这类分级阈值）。
    pub guard: Option<Expr>,
    /// (from_state, to_state) —— 与实体声明的迁移边必须一致（verifier 校验）。
    pub transition: Option<(String, String)>,
    pub message: String,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

/// 抽象裁决（模式 A 的 RHS 只允许输出它，杜绝副作用黑盒）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Verdict {
    /// 放行。
    #[default]
    Allow,
    /// 拒绝：错误码 + 人类可读原因。
    Deny { code: String, reason: String },
}

impl Verdict {
    pub fn deny(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Verdict::Deny { code: code.into(), reason: reason.into() }
    }
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny { .. })
    }
    pub fn code(&self) -> Option<&str> {
        match self {
            Verdict::Deny { code, .. } => Some(code.as_str()),
            Verdict::Allow => None,
        }
    }
    pub fn reason(&self) -> Option<&str> {
        match self {
            Verdict::Deny { reason, .. } => Some(reason.as_str()),
            Verdict::Allow => None,
        }
    }
    /// 落库 / API 的稳定字符串表示。
    pub fn as_str(&self) -> String {
        match self {
            Verdict::Allow => "ALLOW".to_string(),
            Verdict::Deny { code, .. } => format!("DENY:{code}"),
        }
    }
}

/// 违规/触发后的确定性副作用（有限白名单，杜绝图灵完备）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Effect {
    /// FR6：惩罚租约单调推进 `LeaseUpdate(frozen_until = now() + 60s)`。
    LeaseUpdate { target: String, expr: Expr },
    /// FR5：位向量状态置位 `state |= to`（单调状态格）。
    Transition { from: String, to: String },
    /// 告警消息。
    Emit { message: String },
}

impl Effect {
    pub fn kind(&self) -> &'static str {
        match self {
            Effect::LeaseUpdate { .. } => "lease_update",
            Effect::Transition { .. } => "transition",
            Effect::Emit { .. } => "emit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Severity {
    #[default]
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_uppercase().as_str() {
            "INFO" => Severity::Info,
            "WARNING" => Severity::Warning,
            "CRITICAL" => Severity::Critical,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
        }
    }
}

// =====================================================================
// 概念 4 / 模式 B：受限工作内存规则（Drools 兼容）
// =====================================================================

/// 事实模式：`$acc: Account(trade_frequency_5s > 10)`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pattern {
    /// 绑定变量（`$acc`；缺省 `$this`）。
    pub binding: Option<String>,
    /// 事实类型名。
    pub type_name: String,
    /// 约束集合（逗号分隔，全部为合取）。
    pub constraints: Vec<Expr>,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

/// 规则 RHS 动作（受限白名单：只追加 / 撤回 / 裁决）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleAction {
    /// 只追加推导：`insert(SuspiciousTag { account_id: $acc.id, reason: "HighFrequency" })`。
    Insert { type_name: String, fields: Vec<(String, Expr)>, span: Span },
    /// 撤回（受限：仅允许撤回本规则插入的派生事实）。
    Retract { binding: String, span: Span },
    /// 裁决：`yield DENY(code: "...", reason: "...")`。
    Yield { verdict: Verdict, span: Span },
}

impl RuleAction {
    pub fn kind(&self) -> &'static str {
        match self {
            RuleAction::Insert { .. } => "insert",
            RuleAction::Retract { .. } => "retract",
            RuleAction::Yield { .. } => "yield",
        }
    }
}

/// 模式 B：一条受限工作内存规则（FR7）。
///
/// `rule "Derive_Suspicious_Account" stateful { when: ... then: ... }`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatefulRuleDecl {
    pub name: String,
    /// 正向模式（合取）。
    pub patterns: Vec<Pattern>,
    /// 负向模式（`not exists SuspiciousTag(...)`）。
    #[serde(default)]
    pub negatives: Vec<Pattern>,
    /// RHS 动作（只追加推导 / 裁决）。
    pub actions: Vec<RuleAction>,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

impl StatefulRuleDecl {
    /// 规则读取的事实类型集合（DAG 分析用）。
    pub fn reads(&self) -> Vec<&str> {
        self.patterns
            .iter()
            .chain(self.negatives.iter())
            .map(|p| p.type_name.as_str())
            .collect()
    }
    /// 规则写出（插入）的事实类型集合（DAG 分析用）。
    pub fn writes(&self) -> Vec<&str> {
        self.actions
            .iter()
            .filter_map(|a| match a {
                RuleAction::Insert { type_name, .. } => Some(type_name.as_str()),
                _ => None,
            })
            .collect()
    }
    /// 该规则产出的裁决（若有）——用于冲突检测。
    pub fn verdict(&self) -> Option<&Verdict> {
        self.actions.iter().find_map(|a| match a {
            RuleAction::Yield { verdict, .. } => Some(verdict),
            _ => None,
        })
    }
}

// =====================================================================
// 模式 D：DMN 决策表（FR3）
// =====================================================================

/// 决策表命中策略（OMG DMN 1.3 §8）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HitPolicy {
    /// 唯一命中（U）：任意两行条件互斥；SMT 必须证明其合取为 UNSAT。
    #[default]
    Unique,
    /// 首次命中（F）：按序求值，首条命中即终止。
    First,
    /// 优先级（P）：按输出优先级列仲裁。
    Priority,
    /// 收集（C）：返回全部命中结果集合。
    Collect,
}

impl HitPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "UNIQUE" | "U" => HitPolicy::Unique,
            "FIRST" | "F" => HitPolicy::First,
            "PRIORITY" | "P" => HitPolicy::Priority,
            "COLLECT" | "C" => HitPolicy::Collect,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            HitPolicy::Unique => "UNIQUE",
            HitPolicy::First => "FIRST",
            HitPolicy::Priority => "PRIORITY",
            HitPolicy::Collect => "COLLECT",
        }
    }
    /// DMN XML 的 `hitPolicy` 属性值（单字母）。
    pub fn dmn_code(&self) -> &'static str {
        match self {
            HitPolicy::Unique => "U",
            HitPolicy::First => "F",
            HitPolicy::Priority => "P",
            HitPolicy::Collect => "C",
        }
    }
}

/// 决策表输入条目（S-FEEL 子集）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InputEntry {
    /// `-`：任意值。
    Any,
    /// `in [a .. b]` —— 闭区间。
    Range { lo: Expr, hi: Expr },
    /// 单值/复合布尔表达式（S-FEEL `= x` / `> x` / 自由谓词）。
    Expr(Expr),
}

impl InputEntry {
    pub fn is_any(&self) -> bool {
        matches!(self, InputEntry::Any)
    }
}

/// 决策表规则行。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRow {
    pub inputs: Vec<InputEntry>,
    pub outputs: Vec<Expr>,
    /// `default => (...)` 兜底行。
    pub is_default: bool,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

/// 决策表：把 `(输入, 输出)` 符号表直接降维映射到 SMT 求解空间（FR3）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionTableDecl {
    pub name: String,
    /// 输入参数（决策表的 input clause）。
    pub params: Vec<Param>,
    /// 输出列（output clause）。
    pub outputs: Vec<Param>,
    pub hit_policy: HitPolicy,
    pub rows: Vec<DecisionRow>,
    #[serde(default)]
    pub meta: NodeMeta,
    #[serde(skip)]
    pub span: Span,
}

impl DecisionTableDecl {
    /// 非 default 的规则行。
    pub fn rule_rows(&self) -> impl Iterator<Item = &DecisionRow> {
        self.rows.iter().filter(|r| !r.is_default)
    }
    pub fn default_row(&self) -> Option<&DecisionRow> {
        self.rows.iter().find(|r| r.is_default)
    }
    /// 决策表的完整致因输入变量名（SMT 建模用）。
    pub fn input_names(&self) -> Vec<&str> {
        self.params.iter().map(|p| p.name.as_str()).collect()
    }
}

// =====================================================================
// 工作事实（模式 B 运行时）
// =====================================================================

/// 模式 B：工作内存中的一条事实。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkingFact {
    pub type_name: String,
    /// 事实字段（`account_id` → 值表达式求值结果）。
    pub fields: Vec<(String, Expr)>,
    /// 是否由推导插入（append-only）。
    pub derived: bool,
}

// =====================================================================
// 时序表达式（度量时序逻辑 MTL）
// =====================================================================

/// 时序谓词：一等公民。会被 `rules-temporal` 编译为扁平自动机。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TemporalExpr {
    /// 普通谓词升格（在自动机中被编译为原子字节码）。
    Predicate(Expr),
    /// `historically(p, within: T)` —— 过去 T 内 p 至少成立一次。
    Historically { expr: Box<TemporalExpr>, within: Option<Expr> },
    /// `always(p)` —— 之后 p 恒成立（不变量语义）。
    Always(Box<TemporalExpr>),
    /// `eventually(p, within: T)` —— 未来 T 内 p 必成立（承诺语义）。
    Eventually { expr: Box<TemporalExpr>, within: Option<Expr> },
    /// `until(p, q)` —— p 持续成立，直到 q 首次成立。
    Until { p: Box<TemporalExpr>, q: Box<TemporalExpr> },
    /// `since(p, q)` —— 过去某点 q 成立之后 p 一直成立。
    Since { p: Box<TemporalExpr>, q: Box<TemporalExpr> },
    /// `within(T, p)` —— 未来 T 内 p 至少成立一次（含 T=0 的即时语义）。
    Within { window: Expr, inner: Box<TemporalExpr> },
    /// `p implies q` —— 违反条件：p 真且 q 假。
    Implies(Box<TemporalExpr>, Box<TemporalExpr>),
    And(Box<TemporalExpr>, Box<TemporalExpr>),
    Or(Box<TemporalExpr>, Box<TemporalExpr>),
    Not(Box<TemporalExpr>),
    /// `Stream.exists(e => P)` / `.forall(...)` / `.count(...)` —— 流上的量化。
    StreamQuant { stream: String, quant: Quant, lambda: Option<Lambda> },
    /// FR6：边缘跃迁算子 `crosses_above(metric, k)` —— 仅在由下向上穿越阈值的瞬间为真。
    CrossesAbove { metric: String, threshold: Expr },
    /// FR6：`crosses_below(metric, k)`。
    CrossesBelow { metric: String, threshold: Expr },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Quant {
    Exists,
    Forall,
    Count,
}

impl Quant {
    pub fn as_str(&self) -> &'static str {
        match self {
            Quant::Exists => "exists",
            Quant::Forall => "forall",
            Quant::Count => "count",
        }
    }
}

// =====================================================================
// 标量表达式
// =====================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    Ident(String),
    /// `event.type` -> ["event", "type"]
    Path(Vec<String>),
    Number(f64),
    /// FR5：位掩码常量 `0x04`。
    Hex(u64),
    Str(String),
    Bool(bool),
    DurationLit(Duration),
    Binary { op: BinaryOp, left: Box<Expr>, right: Box<Expr> },
    UnaryNot(Box<Expr>),
    Call { func: String, args: Vec<Expr> },
    /// 决策表查询：`DetermineAmount(event.timestamp)` 的多返回值解构（用例 3）。
    ///
    /// 运行时会先求值 `call`，再按 `index` 取第 index 个输出。
    TableLookup { table: String, args: Vec<Expr>, index: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    And,
    Or,
    /// FR5：位与（`state & CSRC_APPROVED`）。
    BitAnd,
    /// FR5：位或（`state |= next_state`）。
    BitOr,
    BitXor,
    Shl,
    Shr,
}

impl BinaryOp {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "+" => BinaryOp::Add,
            "-" => BinaryOp::Sub,
            "*" => BinaryOp::Mul,
            "/" => BinaryOp::Div,
            "%" => BinaryOp::Mod,
            "==" => BinaryOp::Eq,
            "!=" => BinaryOp::Neq,
            ">" => BinaryOp::Gt,
            ">=" => BinaryOp::Gte,
            "<" => BinaryOp::Lt,
            "<=" => BinaryOp::Lte,
            "and" => BinaryOp::And,
            "or" => BinaryOp::Or,
            "&" => BinaryOp::BitAnd,
            "|" => BinaryOp::BitOr,
            "^" => BinaryOp::BitXor,
            "<<" => BinaryOp::Shl,
            ">>" => BinaryOp::Shr,
            _ => return None,
        })
    }
    pub fn is_comparison(&self) -> bool {
        matches!(
            self,
            BinaryOp::Eq | BinaryOp::Neq | BinaryOp::Gt | BinaryOp::Gte | BinaryOp::Lt | BinaryOp::Lte
        )
    }
    /// 是否属于线性算术（SMT 可判定片段）。
    pub fn is_linear_arith(&self) -> bool {
        matches!(self, BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod)
    }
}

// =====================================================================
// 便捷构造器（供 parser / 测试使用）
// =====================================================================

impl Expr {
    pub fn num(n: f64) -> Self {
        Expr::Number(n)
    }
    pub fn text(s: impl Into<String>) -> Self {
        Expr::Str(s.into())
    }
    pub fn ident(s: impl Into<String>) -> Self {
        Expr::Ident(s.into())
    }
    pub fn path(parts: &[&str]) -> Self {
        Expr::Path(parts.iter().map(|s| s.to_string()).collect())
    }
    pub fn bin(op: BinaryOp, l: Expr, r: Expr) -> Self {
        Expr::Binary { op, left: Box::new(l), right: Box::new(r) }
    }
    pub fn call(func: impl Into<String>, args: Vec<Expr>) -> Self {
        Expr::Call { func: func.into(), args }
    }
    /// 恒真谓词（流过滤缺省值）。
    pub fn always_true() -> Self {
        Expr::Bool(true)
    }
}

impl TemporalExpr {
    pub fn pred(e: Expr) -> Self {
        TemporalExpr::Predicate(e)
    }
    pub fn always(t: TemporalExpr) -> Self {
        TemporalExpr::Always(Box::new(t))
    }
    pub fn not(t: TemporalExpr) -> Self {
        TemporalExpr::Not(Box::new(t))
    }
    /// 静态时长（仅当窗口是字面量时）。
    pub fn static_secs(w: &Expr) -> Option<u64> {
        static_window_secs(w)
    }
}

/// 从窗口表达式提取静态秒数（`60d` -> 5184000）。动态窗口返回 None。
pub fn static_window_secs(w: &Expr) -> Option<u64> {
    match w {
        Expr::DurationLit(d) => Some(d.as_secs()),
        Expr::Number(n) => Some(*n as u64),
        _ => None,
    }
}

// =====================================================================
// FR7：模式 B 的因果有向图（DAG）检验
// =====================================================================

/// 事实推导环路的诊断报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCycle {
    /// 环路上的事实类型序列（首尾相同）。
    pub path: Vec<String>,
    /// 参与环路的规则名（用于精确定位）。
    pub rules: Vec<String>,
}

impl RuleCycle {
    pub fn message(&self) -> String {
        format!(
            "检测到循环依赖（事实推导有向图成环）：{}（涉及规则：{}）",
            self.path.join(" -> "),
            self.rules.join(", ")
        )
    }

    /// 英文诊断（面向日志管道 / 国际化前端）。
    pub fn message_en(&self) -> String {
        format!(
            "cyclic fact derivation detected: {} (rules: {})",
            self.path.join(" -> "),
            self.rules.join(", ")
        )
    }
}

/// 编译期因果有向图（DAG）检验。
///
/// **只用正向模式建边**：`not exists P` 是非单调否定守卫，它不构成
/// "读 P → 写 Q" 的因果依赖。若把否定条件也算作读边，则
/// `rule D { when: Account() not exists Tag() then: insert(Tag{...}) }`
/// 会被误判为自环——而它恰恰是 Drools 里最常见的终止性推导写法
/// （插入后否定条件失效，规则自然停火）。
pub fn check_rule_dag(rules: &[StatefulRuleDecl]) -> Result<(), RuleCycle> {
    use std::collections::{HashMap, HashSet};

    // type -> [(target_type, rule_name)]
    let mut edges: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    let mut nodes: HashSet<&str> = HashSet::new();
    for r in rules {
        for read in r.patterns.iter().map(|p| p.type_name.as_str()) {
            nodes.insert(read);
            for w in r.writes() {
                nodes.insert(w);
                edges.entry(read).or_default().push((w, r.name.as_str()));
            }
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        White,
        Grey,
        Black,
    }
    let mut color: HashMap<&str, Color> = nodes.iter().map(|n| (*n, Color::White)).collect();
    let mut stack: Vec<&str> = Vec::new();
    let mut rule_stack: Vec<&str> = Vec::new();

    fn dfs<'a>(
        node: &'a str,
        edges: &HashMap<&'a str, Vec<(&'a str, &'a str)>>,
        color: &mut HashMap<&'a str, Color>,
        stack: &mut Vec<&'a str>,
        rule_stack: &mut Vec<&'a str>,
    ) -> Option<RuleCycle> {
        color.insert(node, Color::Grey);
        stack.push(node);
        if let Some(nexts) = edges.get(node) {
            for (to, rule) in nexts {
                match color.get(to).copied().unwrap_or(Color::White) {
                    Color::Grey => {
                        let start = stack.iter().position(|s| s == to).unwrap_or(0);
                        let mut path: Vec<String> =
                            stack[start..].iter().map(|s| s.to_string()).collect();
                        path.push(to.to_string());
                        let mut rules: Vec<String> =
                            rule_stack[start..].iter().map(|s| s.to_string()).collect();
                        rules.push(rule.to_string());
                        return Some(RuleCycle { path, rules });
                    }
                    Color::White => {
                        rule_stack.push(rule);
                        if let Some(r) = dfs(to, edges, color, stack, rule_stack) {
                            return Some(r);
                        }
                        rule_stack.pop();
                    }
                    Color::Black => {}
                }
            }
        }
        color.insert(node, Color::Black);
        stack.pop();
        None
    }

    let all: Vec<&str> = nodes.iter().copied().collect();
    for n in all {
        if color.get(n).copied().unwrap_or(Color::White) == Color::White {
            if let Some(r) = dfs(n, &edges, &mut color, &mut stack, &mut rule_stack) {
                return Err(r);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_roundtrips_between_dsl_and_db() {
        for m in [Mode::Pure, Mode::Stateful, Mode::Stream, Mode::DecisionTable] {
            assert_eq!(Mode::parse(m.as_str()), Some(m));
            assert_eq!(Mode::from_db(m.db_value()), Some(m));
        }
    }

    #[test]
    fn verdict_deny_carries_code_and_reason() {
        let v = Verdict::deny("ERR_X", "bad");
        assert!(v.is_deny());
        assert_eq!(v.code(), Some("ERR_X"));
        assert_eq!(v.reason(), Some("bad"));
        assert_eq!(v.as_str(), "DENY:ERR_X");
        assert!(!Verdict::Allow.is_deny());
    }

    #[test]
    fn state_const_masks_and_bit_of() {
        let e = EntityDecl {
            name: "Company".into(),
            key: "code".into(),
            states: vec![
                StateConst::masked("A", 0x01),
                StateConst::masked("B", 0x02),
                StateConst::masked("C", 0x04),
            ],
            initial: "A".into(),
            ..Default::default()
        };
        assert!(e.is_bitvec());
        assert_eq!(e.mask_of("C"), Some(0x04));
        assert_eq!(e.bit_of("B"), Some(1));
        assert_eq!(e.state_names(), vec!["A", "B", "C"]);
    }

    #[test]
    fn hit_policy_parses_dmn_codes() {
        assert_eq!(HitPolicy::parse("U"), Some(HitPolicy::Unique));
        assert_eq!(HitPolicy::parse("collect"), Some(HitPolicy::Collect));
        assert_eq!(HitPolicy::Unique.dmn_code(), "U");
    }

    #[test]
    fn stateful_rule_dag_reads_and_writes() {
        let p = |t: &str| Pattern {
            binding: None,
            type_name: t.into(),
            constraints: vec![],
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        let r = StatefulRuleDecl {
            name: "R".into(),
            patterns: vec![p("Account")],
            negatives: vec![p("SuspiciousTag")],
            actions: vec![RuleAction::Insert {
                type_name: "SuspiciousTag".into(),
                fields: vec![],
                span: Span::default(),
            }],
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        assert_eq!(r.reads(), vec!["Account", "SuspiciousTag"]);
        assert_eq!(r.writes(), vec!["SuspiciousTag"]);
    }

    #[test]
    fn bitwise_operators_parse() {
        assert_eq!(BinaryOp::parse("&"), Some(BinaryOp::BitAnd));
        assert_eq!(BinaryOp::parse("<<"), Some(BinaryOp::Shl));
        assert!(!BinaryOp::BitAnd.is_comparison());
    }
}
