//! rules-ast — 强类型 AST 节点定义。
//!
//! 与设计文档《AST 结构定义》一一对应：
//! - Scope / Target: EntityDecl, StreamDecl
//! - Predicates: Expr, TemporalExpr
//! - Action: ViolationHandler
//! - 可扩展 Schema: VarDecl, SignalDecl
//!
//! 所有节点带 `Span`（line/col），用于报错回溯。

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 源码位置。解析时由 parser 填充。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Span {
    pub line: u32,
    pub col: u32,
}

// =====================================================================
// 顶层
// =====================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpecFile {
    pub entities: Vec<EntityDecl>,
    pub streams: Vec<StreamDecl>,
    pub signals: Vec<SignalDecl>,
    pub vars: Vec<VarDecl>,
    pub contracts: Vec<ContractDecl>,
    #[serde(skip)]
    pub span: Span,
}

// =====================================================================
// Scope / Target 层
// =====================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityDecl {
    pub name: String,
    pub key: String,
    pub states: Vec<String>,
    pub initial: String,
    #[serde(skip)]
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamDecl {
    pub name: String,
    pub event_type: String,
    pub filter: Expr,
    /// 提示性窗口（秒），由 runtime 用于过期淘汰。
    pub hint_window_secs: Option<u64>,
    #[serde(skip)]
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalDecl {
    pub name: String,
    pub param_name: String,
    pub entity_name: String,
    pub return_type: DataType,
    pub expr: Expr,
    #[serde(skip)]
    pub span: Span,
}

/// 动态变量：绑定运行时数据字典中的条目。
///
/// 设计层级四 —— 把 DSL 从"静态固定 Schema"升级为"运行时可扩展 Schema"。
/// 编译期不要求 `expr` 引用的字段在 schema 中存在。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VarDecl {
    pub name: String,
    pub expr: Expr,
    #[serde(skip)]
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataType {
    Int,
    Float,
    Bool,
    String,
    Timestamp,
}

// =====================================================================
// Contract / Action 层
// =====================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractDecl {
    pub name: String,
    pub entity_name: String,
    /// let x = expr; 局部绑定。
    pub bindings: Vec<(String, Expr)>,
    pub invariant: TemporalExpr,
    pub violation: ViolationHandler,
    #[serde(skip)]
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ViolationHandler {
    pub severity: Severity,
    /// 只有 guard 为真才真正触发处置。
    pub guard: Option<Expr>,
    /// (from_state, to_state)
    pub transition: Option<(String, String)>,
    pub message: String,
    #[serde(skip)]
    pub span: Span,
}

// =====================================================================
// 时序表达式
// =====================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TemporalExpr {
    /// 普通谓词升格。
    Predicate(Expr),
    /// historically(p, within: T) —— 过去 T 内 p 至少成立一次。
    Historically {
        expr: Box<TemporalExpr>,
        within: Option<Duration>,
    },
    /// always(p) —— 窗口内 p 恒成立。
    Always(Box<TemporalExpr>),
    /// eventually(p) —— 未来 T 内 p 必成立。
    Eventually(Box<TemporalExpr>),
    /// until(p, q) —— p 一直成立直到 q 首次成立。
    Until {
        p: Box<TemporalExpr>,
        q: Box<TemporalExpr>,
    },
    /// within(T, p) —— 未来 T 内 p 至少成立一次。
    WithinOp {
        window: Duration,
        inner: Box<TemporalExpr>,
    },
    /// P implies Q —— 违反条件：P 真且 Q 假。
    Implies(Box<TemporalExpr>, Box<TemporalExpr>),
    And(Box<TemporalExpr>, Box<TemporalExpr>),
    Or(Box<TemporalExpr>, Box<TemporalExpr>),
    Not(Box<TemporalExpr>),
}

// =====================================================================
// 标量表达式
// =====================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    Ident(String),
    /// event.type -> ["event", "type"]
    Path(Vec<String>),
    Number(f64),
    Str(String),
    DurationLit(Duration),
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    UnaryNot(Box<Expr>),
    Call {
        func: String,
        args: Vec<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    And,
    Or,
}

// =====================================================================
// 便捷构造器（供 parser / 测试使用）
// =====================================================================

impl Expr {
    pub fn num(n: f64) -> Self {
        Expr::Number(n)
    }
    pub fn path(parts: &[&str]) -> Self {
        Expr::Path(parts.iter().map(|s| s.to_string()).collect())
    }
    pub fn bin(op: BinaryOp, l: Expr, r: Expr) -> Self {
        Expr::Binary { op, left: Box::new(l), right: Box::new(r) }
    }
}
