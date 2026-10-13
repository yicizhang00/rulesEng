//! rules-temporal — 把**时序不变量**编译为扁平状态机（Temporal Automaton）。
//!
//! 这是"脱离 Drools / RETE"的核心：传统产生式引擎在每次事实插入时重跑 RETE 网络
//! （对象创建、拆装箱、堆内存遍历）。这里反过来——**先求解"合法状态空间"的形状**，
//! 把一个 MTL 公式编译成一台状态机，运行期只做两件事：
//!
//! 1. 按**拓扑序单向扫描**一个 `Vec<AutoNode>`（子节点索引恒小于父节点）；
//! 2. 更新两块**扁平状态数组**：`truth: Vec<u8>`（每节点真值）与
//!    `timers: Vec<i64>` / `latch: Vec<u8>` / `pending: Vec<u8>`（时序算子的记忆）。
//!
//! 特点：
//! - **零递归**：`step()` 是一个 `for i in 0..nodes.len()` 循环；
//! - **零分配**：状态数组在装载期分配一次，运行期只做 `u8` / `i64` 写入；
//! - **无 AST 驻留**：公式被折叠成节点数组 + 原子表，AST 不再参与执行；
//! - **可编译**：节点数组与原子表就是 IR，后续翻译为 WASM / eBPF 指令即可下沉到网卡旁。
//!
//! ## MTL 算子的状态机编码
//!
//! | 公式 | 记忆单元 | 转移 |
//! |---|---|---|
//! | `always(p)` | `truth`（latch） | `truth = truth ∧ p`，初值 1 |
//! | `historically(p, W)` | `truth` + `timers` | `p` 为真则置 1 并记时刻；超窗回落 0 |
//! | `eventually(p, W)` | `pending` + `timers` | `p` 未真则开启承诺并记截止；逾期即违反 |
//! | `until(p, q)` | `latch` | `q` 出现即永久满足，否则要求 `p` |
//! | `since(p, q)` | `latch` | `q` 出现过则此后要求 `p` |
//!
//! 原子谓词分三类：编译为扁平字节码的**数值/驻留文本**谓词、需要实体环境的标量谓词、
//! 需要事件上下文或环形缓冲区扫描的谓词。后两类通过 [`AtomHost`] 交由宿主求值。

use rules_ast::*;
use rules_flatvm::{Compiler, FlatProgram, Interner, SlotBinder};
use std::collections::HashMap;

// =====================================================================
// 原子谓词
// =====================================================================

/// 一个原子谓词的求值方式。
#[derive(Debug, Clone, PartialEq)]
pub enum AtomKind {
    /// 已编译为扁平字节码（只依赖槽位与常量）——**原生快路径**。
    Flat(Box<FlatProgram>),
    /// 需要实体环境（metric 实参、given 绑定、`now()`）的标量谓词。
    Scalar(Expr),
    /// 需要当前事件上下文的谓词（lambda 或隐式 `event`）。
    Event(Lambda),
    /// 环形缓冲区上的量化扫描：`Stream.exists(e => P)`。
    Stream {
        stream: String,
        quant: Quant,
        lambda: Option<Lambda>,
    },
}

impl AtomKind {
    /// 该原子是否走扁平字节码快路径。
    pub fn is_flat(&self) -> bool {
        matches!(self, AtomKind::Flat(_))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Atom {
    pub kind: AtomKind,
    /// 人类可读标签（用于告警轨迹与差分解说）。
    pub label: String,
}

impl Atom {
    fn flat(prog: FlatProgram, label: String) -> Self {
        Atom { kind: AtomKind::Flat(Box::new(prog)), label }
    }
    fn scalar(e: &Expr, label: String) -> Self {
        Atom { kind: AtomKind::Scalar(e.clone()), label }
    }
    /// 预留：纯事件谓词（`AtomKind::Event`）走 `Lambda` 求值的原子。
    /// 目前代码路径尚未构造它（数值谓词走 Flat、含字段路径的走 Scalar），
    /// 保留 API 供后续把事件谓词也下沉为编译产物时使用。
    #[allow(dead_code)]
    fn event(l: &Lambda, label: String) -> Self {
        Atom { kind: AtomKind::Event(l.clone()), label }
    }
    fn stream(stream: &str, quant: Quant, lambda: &Option<Lambda>) -> Self {
        let label = match lambda {
            Some(_) => format!("{stream}.{}(…)", quant.as_str()),
            None => format!("{stream}.{}()", quant.as_str()),
        };
        Atom {
            kind: AtomKind::Stream {
                stream: stream.to_string(),
                quant,
                lambda: lambda.clone(),
            },
            label,
        }
    }
}

// =====================================================================
// 状态机 IR
// =====================================================================

/// 状态机节点。子节点索引 **恒小于** 父节点索引（后序布局），
/// 因此 `step()` 可以单向扫描而无需递归。
#[derive(Debug, Clone, PartialEq)]
pub enum AutoNode {
    /// 叶子：引用 `atoms[i]`。
    Atom(u32),
    And(u32, u32),
    Or(u32, u32),
    Not(u32),
    Implies(u32, u32),
    /// `always(p)`：latch 语义。
    Always(u32),
    /// `historically(p, W)`：过去 W 内 p 至少真过一次。
    Historically { inner: u32, window: Option<Expr> },
    /// `eventually(p, W)`：未来 W 内 p 必真（承诺 + 逾期违反）。
    Eventually { inner: u32, window: Option<Expr> },
    /// `within(W, p)`：即时版 `eventually`。
    Within { inner: u32, window: Option<Expr> },
    /// `until(p, q)`。
    Until { p: u32, q: u32 },
    /// `since(p, q)`。
    Since { p: u32, q: u32 },
    /// FR6：`crosses_above(metric, k)` —— 引用 `edges[i]`，仅跃迁瞬间为真。
    CrossesAbove(u32),
    /// FR6：`crosses_below(metric, k)`。
    CrossesBelow(u32),
}

/// FR6：边缘跃迁算子的编译描述符。
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeSpec {
    /// 被观测的派生指标（metric / 裸标识符）。
    pub metric: String,
    /// 阈值。
    pub threshold: Expr,
    /// `true` = 由下向上穿越；`false` = 由上向下穿越。
    pub above: bool,
}

/// 边缘侧位：`UNKNOWN` 表示还没有观测过（首拍不触发告警）。
pub const EDGE_UNKNOWN: u8 = 0xFF;

impl AutoNode {
    pub fn kind(&self) -> &'static str {
        match self {
            AutoNode::Atom(_) => "atom",
            AutoNode::And(_, _) => "and",
            AutoNode::Or(_, _) => "or",
            AutoNode::Not(_) => "not",
            AutoNode::Implies(_, _) => "implies",
            AutoNode::Always(_) => "always",
            AutoNode::Historically { .. } => "historically",
            AutoNode::Eventually { .. } => "eventually",
            AutoNode::Within { .. } => "within",
            AutoNode::Until { .. } => "until",
            AutoNode::Since { .. } => "since",
            AutoNode::CrossesAbove(_) => "crosses_above",
            AutoNode::CrossesBelow(_) => "crosses_below",
        }
    }
    /// 子节点索引（后序遍历 / 布局自检用；生产路径不需要）。
    #[allow(dead_code)]
    fn children(&self) -> Vec<u32> {
        match self {
            AutoNode::Atom(_) => vec![],
            AutoNode::Not(a) | AutoNode::Always(a) => vec![*a],
            AutoNode::Historically { inner, .. }
            | AutoNode::Eventually { inner, .. }
            | AutoNode::Within { inner, .. } => vec![*inner],
            AutoNode::And(a, b)
            | AutoNode::Or(a, b)
            | AutoNode::Implies(a, b)
            | AutoNode::Until { p: a, q: b }
            | AutoNode::Since { p: a, q: b } => vec![*a, *b],
            // 边缘跃迁算子不引用其它节点，只引用 `edges[i]`
            AutoNode::CrossesAbove(_) | AutoNode::CrossesBelow(_) => vec![],
        }
    }
}

/// 编译产物：一台扁平时序状态机。
#[derive(Debug, Clone, PartialEq)]
pub struct TemporalAutomaton {
    /// 来源 spec 名。
    pub spec: String,
    pub entity: String,
    pub entity_var: String,
    /// 后序布局的节点数组。
    pub nodes: Vec<AutoNode>,
    /// 根节点索引（不变量整体）。
    pub root: u32,
    pub atoms: Vec<Atom>,
    /// 各节点初值（`always` / `eventually` 初值为真，其余为假）。
    pub init: Vec<u8>,
    /// 所有时序算子引用到的窗口上界（秒），用于环形缓冲区容量规划。
    pub window_hint: u64,
    /// FR6：边缘跃迁算子表。
    pub edges: Vec<EdgeSpec>,
}

impl TemporalAutomaton {
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// 快路径原子占比（用于观测编译质量）。
    pub fn flat_atom_ratio(&self) -> f64 {
        if self.atoms.is_empty() {
            return 0.0;
        }
        let flat = self.atoms.iter().filter(|a| a.kind.is_flat()).count();
        flat as f64 / self.atoms.len() as f64
    }

    /// 携带全部窗口上界（供 runtime 决定环形缓冲区容量）。
    pub fn max_window(&self) -> u64 {
        self.window_hint
    }

    /// 新建一份运行期状态（所有数组装载期分配一次）。
    pub fn new_state(&self) -> AutoState {
        let n = self.nodes.len();
        AutoState {
            truth: self.init.clone(),
            latch: vec![0; n],
            pending: vec![0; n],
            timers: vec![0; n],
            edge_side: vec![EDGE_UNKNOWN; self.edges.len()],
            violations: 0,
            steps: 0,
        }
    }

    /// 推进一拍。返回根节点真值（`true` = 不变量仍成立）。
    pub fn step(&self, st: &mut AutoState, host: &mut dyn AtomHost, now: u64) -> bool {
        st.steps += 1;
        // 窗口解析结果按节点缓存，避免重复求值。
        let mut resolved_windows: HashMap<u32, i64> = HashMap::new();

        for i in 0..self.nodes.len() {
            let idx = i as u32;
            let value: bool = match &self.nodes[i] {
                AutoNode::Atom(a) => host.eval_atom(&self.atoms[*a as usize]),
                AutoNode::And(a, b) => st.truth[*a as usize] > 0 && st.truth[*b as usize] > 0,
                AutoNode::Or(a, b) => st.truth[*a as usize] > 0 || st.truth[*b as usize] > 0,
                AutoNode::Not(a) => st.truth[*a as usize] == 0,
                AutoNode::Implies(a, b) => {
                    st.truth[*a as usize] == 0 || st.truth[*b as usize] > 0
                }
                AutoNode::Always(c) => st.truth[*c as usize] > 0 && st.truth[i] > 0,
                AutoNode::Historically { inner, window } => {
                    if st.truth[*inner as usize] > 0 {
                        st.timers[i] = now as i64;
                        true
                    } else if st.truth[i] > 0 {
                        let w = resolve(window, &mut resolved_windows, idx, host);
                        now as i64 - st.timers[i] <= w
                    } else {
                        false
                    }
                }
                AutoNode::Eventually { inner, window } | AutoNode::Within { inner, window } => {
                    if st.truth[*inner as usize] > 0 {
                        st.pending[i] = 0;
                        true
                    } else if st.pending[i] == 0 {
                        let w = resolve(window, &mut resolved_windows, idx, host);
                        st.pending[i] = 1;
                        st.timers[i] = now as i64 + w;
                        true
                    } else {
                        now as i64 <= st.timers[i]
                    }
                }
                AutoNode::Until { p, q } => {
                    if st.truth[*q as usize] > 0 {
                        st.latch[i] = 1;
                    }
                    st.latch[i] > 0 || st.truth[*p as usize] > 0
                }
                AutoNode::Since { p, q } => {
                    if st.truth[*q as usize] > 0 {
                        st.latch[i] = 1;
                    }
                    st.latch[i] > 0 && st.truth[*p as usize] > 0
                }
                // FR6：边缘跃迁 —— 只在"由下向上 / 由上向下穿越阈值"的那一拍为真，
                //       高位保持期间自动抑制（消除告警风暴），无任何后台定时器。
                AutoNode::CrossesAbove(e) | AutoNode::CrossesBelow(e) => {
                    let spec = &self.edges[*e as usize];
                    let above = spec.above;
                    let thr = host.scalar(&spec.threshold);
                    match host.metric_value(&spec.metric) {
                        None => false,
                        Some(v) => {
                            let side = if v >= thr { 1u8 } else { 0u8 };
                            let prev = st.edge_side[*e as usize];
                            st.edge_side[*e as usize] = side;
                            // 每一侧都必须显式给出**两侧**的侧位组合：
                            //   crosses_above —— 上一拍在阈值之下(0)、本拍在阈值之上(1)
                            //   crosses_below —— 上一拍在阈值之上(1)、本拍回落到之下(0)
                            // 早期版本把 `side == 1` 提到公共位置，导致 `crosses_below`
                            // 退化成"只要仍在阈值之上就每拍为真"，正是本算子要消除的告警风暴。
                            prev != EDGE_UNKNOWN
                                && if above {
                                    side == 1 && prev == 0
                                } else {
                                    side == 0 && prev == 1
                                }
                        }
                    }
                }
            };
            st.truth[i] = if value { 1 } else { 0 };
        }

        let root_ok = st.truth[self.root as usize] > 0;
        if !root_ok {
            st.violations += 1;
        }
        root_ok
    }

    /// 不变量被打破时的可读解说（用于告警轨迹 / 证据链）。
    pub fn explain(&self, st: &AutoState) -> String {
        let root = &self.nodes[self.root as usize];
        let base = match root {
            AutoNode::Implies(a, b) => {
                let a_ok = st.truth[*a as usize] > 0;
                let b_ok = st.truth[*b as usize] > 0;
                match (a_ok, b_ok) {
                    (true, false) => "implies: antecedent true, consequent false".to_string(),
                    (false, _) => "implies: antecedent false (vacuously ok)".to_string(),
                    _ => "implies: consequent true".to_string(),
                }
            }
            other => format!("{} violated", other.kind()),
        };
        let failing = self.failing_atoms(st);
        if failing.is_empty() {
            base
        } else {
            format!("{base} | failing: {}", failing.join(", "))
        }
    }

    /// 当前为假的原子标签。
    pub fn failing_atoms(&self, st: &AutoState) -> Vec<String> {
        let mut out = Vec::new();
        for node in &self.nodes {
            if let AutoNode::Atom(a) = node {
                let ai = *a as usize;
                if st.truth[self.node_index_of_atom(ai).unwrap_or(0)] == 0 {
                    out.push(self.atoms[ai].label.clone());
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    fn node_index_of_atom(&self, atom: usize) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| matches!(n, AutoNode::Atom(a) if *a as usize == atom))
    }
}

fn resolve(
    window: &Option<Expr>,
    cache: &mut HashMap<u32, i64>,
    node: u32,
    host: &mut dyn AtomHost,
) -> i64 {
    if let Some(v) = cache.get(&node) {
        return *v;
    }
    let v = match window {
        None => 0,
        Some(Expr::DurationLit(d)) => d.as_secs() as i64,
        Some(Expr::Number(n)) => *n as i64,
        Some(e) => host.window_secs(e),
    };
    cache.insert(node, v);
    v
}

/// 运行期状态：全部是**扁平数组**，装载期一次性分配。
#[derive(Debug, Clone, PartialEq)]
pub struct AutoState {
    /// 每个节点的真值（含时序算子的 latch）。
    pub truth: Vec<u8>,
    /// `until` / `since` 的"q 已出现"标志。
    pub latch: Vec<u8>,
    /// `eventually` / `within` 的"承诺已开启"标志。
    pub pending: Vec<u8>,
    /// 窗口起点 / 承诺截止时刻。
    pub timers: Vec<i64>,
    /// FR6：边缘跃迁算子的上一拍侧位（0=低于阈值，1=高于阈值，255=未知）。
    pub edge_side: Vec<u8>,
    pub violations: u64,
    pub steps: u64,
}

impl AutoState {
    /// 某个原子当前是否成立。
    pub fn atom_truth(&self, aut: &TemporalAutomaton, atom: usize) -> bool {
        aut.node_index_of_atom(atom)
            .map(|n| self.truth[n] > 0)
            .unwrap_or(false)
    }
}

// =====================================================================
// 宿主接口
// =====================================================================

/// 原子谓词的求值宿主（由 runtime 实现）。
///
/// 这层抽象让 `rules-temporal` 不依赖 runtime，也让"扁平字节码"与"值求值器"
/// 两条路径可以独立演进——后者将在 WASM 后端成熟后统一下沉。
pub trait AtomHost {
    fn eval_atom(&mut self, atom: &Atom) -> bool;
    /// 求值动态窗口表达式 → 秒。
    fn window_secs(&mut self, e: &Expr) -> i64;
    /// FR6：读取派生指标的当前数值（供边缘跃迁算子做侧位比较）。
    ///
    /// 默认返回 `None`（未知 → 边缘算子恒假），宿主可选择实现。
    fn metric_value(&mut self, _metric: &str) -> Option<f64> {
        None
    }
    /// FR6：求值阈值标量表达式。
    fn scalar(&mut self, e: &Expr) -> f64 {
        self.window_secs(e) as f64
    }
}

// =====================================================================
// 编译器
// =====================================================================

/// 编译一份 `SpecDecl` 的不变量。
///
/// `binder` 用于把符号解析到扁平槽位：若一个谓词的全部符号都能绑定，
/// 它就编译为 `AtomKind::Flat`（原生快路径）；否则退化为标量 / 事件求值。
pub fn compile_spec(
    spec: &SpecDecl,
    binder: &mut dyn SlotBinder,
    interner: &mut Interner,
) -> TemporalAutomaton {
    let mut c = AutomatonCompiler {
        nodes: Vec::new(),
        atoms: Vec::new(),
        init: Vec::new(),
        edges: Vec::new(),
        binder,
        interner,
        window_hint: 0,
    };
    let root = c.compile(&spec.invariant);
    TemporalAutomaton {
        spec: spec.name.clone(),
        entity: spec.entity_name.clone(),
        entity_var: spec.entity_var.clone(),
        root,
        nodes: c.nodes,
        atoms: c.atoms,
        init: c.init,
        window_hint: c.window_hint.max(1),
        edges: c.edges,
    }
}

struct AutomatonCompiler<'a> {
    nodes: Vec<AutoNode>,
    atoms: Vec<Atom>,
    init: Vec<u8>,
    edges: Vec<EdgeSpec>,
    binder: &'a mut dyn SlotBinder,
    interner: &'a mut Interner,
    window_hint: u64,
}

impl<'a> AutomatonCompiler<'a> {
    fn emit(&mut self, node: AutoNode, init: u8) -> u32 {
        self.nodes.push(node);
        self.init.push(init);
        (self.nodes.len() - 1) as u32
    }

    fn compile(&mut self, t: &TemporalExpr) -> u32 {
        match t {
            TemporalExpr::Predicate(e) => {
                let atom = self.make_atom(e);
                let idx = self.atoms.len() as u32;
                self.atoms.push(atom);
                self.emit(AutoNode::Atom(idx), 0)
            }
            TemporalExpr::Not(inner) => {
                let c = self.compile(inner);
                let child_init = self.init[c as usize];
                self.emit(AutoNode::Not(c), if child_init > 0 { 0 } else { 1 })
            }
            TemporalExpr::And(a, b) => {
                let (ia, ib) = (self.compile(a), self.compile(b));
                let (va, vb) = (self.init[ia as usize], self.init[ib as usize]);
                self.emit(AutoNode::And(ia, ib), if va > 0 && vb > 0 { 1 } else { 0 })
            }
            TemporalExpr::Or(a, b) => {
                let (ia, ib) = (self.compile(a), self.compile(b));
                let (va, vb) = (self.init[ia as usize], self.init[ib as usize]);
                self.emit(AutoNode::Or(ia, ib), if va > 0 || vb > 0 { 1 } else { 0 })
            }
            TemporalExpr::Implies(a, b) => {
                let (ia, ib) = (self.compile(a), self.compile(b));
                let (va, vb) = (self.init[ia as usize], self.init[ib as usize]);
                self.emit(
                    AutoNode::Implies(ia, ib),
                    if va == 0 || vb > 0 { 1 } else { 0 },
                )
            }
            TemporalExpr::Always(inner) => {
                let c = self.compile(inner);
                self.emit(AutoNode::Always(c), 1)
            }
            TemporalExpr::Historically { expr, within } => {
                let c = self.compile(expr);
                self.note_window(within);
                self.emit(
                    AutoNode::Historically { inner: c, window: within.clone() },
                    0,
                )
            }
            TemporalExpr::Eventually { expr, within } => {
                let c = self.compile(expr);
                self.note_window(within);
                self.emit(
                    AutoNode::Eventually { inner: c, window: within.clone() },
                    1,
                )
            }
            TemporalExpr::Within { window, inner } => {
                let c = self.compile(inner);
                self.note_window(&Some(window.clone()));
                self.emit(AutoNode::Within { inner: c, window: Some(window.clone()) }, 1)
            }
            TemporalExpr::Until { p, q } => {
                let (ip, iq) = (self.compile(p), self.compile(q));
                let vp = self.init[ip as usize];
                self.emit(AutoNode::Until { p: ip, q: iq }, vp)
            }
            TemporalExpr::Since { p, q } => {
                let (ip, iq) = (self.compile(p), self.compile(q));
                self.emit(AutoNode::Since { p: ip, q: iq }, 0)
            }
            TemporalExpr::CrossesAbove { metric, threshold } => {
                let e = self.edges.len() as u32;
                self.edges.push(EdgeSpec {
                    metric: metric.clone(),
                    threshold: threshold.clone(),
                    above: true,
                });
                self.emit(AutoNode::CrossesAbove(e), 0)
            }
            TemporalExpr::CrossesBelow { metric, threshold } => {
                let e = self.edges.len() as u32;
                self.edges.push(EdgeSpec {
                    metric: metric.clone(),
                    threshold: threshold.clone(),
                    above: false,
                });
                self.emit(AutoNode::CrossesBelow(e), 0)
            }
            TemporalExpr::StreamQuant { stream, quant, lambda } => {
                let atom = Atom::stream(stream, *quant, lambda);
                let idx = self.atoms.len() as u32;
                self.atoms.push(atom);
                self.emit(AutoNode::Atom(idx), 0)
            }
        }
    }

    fn note_window(&mut self, w: &Option<Expr>) {
        if let Some(secs) = w.as_ref().and_then(rules_ast::static_window_secs) {
            self.window_hint = self.window_hint.max(secs);
        }
    }

    /// 决定一个标量谓词走扁平字节码还是宿主求值。
    fn make_atom(&mut self, e: &Expr) -> Atom {
        let label = render_expr(e);
        // 事件字段 / 实体变量路径必须走宿主（它们不在静态槽位空间里）；
        // 含函数调用的谓词同样交给宿主，直到 WASM 后端把 `Call` 也下沉为原生指令。
        if references_context(e) || contains_call(e) {
            return Atom::scalar(e, label);
        }
        let mut probe = ProbeBinder { inner: self.binder, missed: false };
        let mut compiler = Compiler::new(&mut probe, self.interner);
        compiler.compile(e);
        let prog = compiler.finish();
        if probe.missed {
            Atom::scalar(e, label)
        } else {
            Atom::flat(prog, label)
        }
    }
}

/// 探测绑定器：记录是否存在未绑定符号。
struct ProbeBinder<'a> {
    inner: &'a mut dyn SlotBinder,
    missed: bool,
}

impl<'a> SlotBinder for ProbeBinder<'a> {
    fn bind(&mut self, name: &str) -> Option<rules_flatvm::Binding> {
        let out = self.inner.bind(name);
        if out.is_none() {
            self.missed = true;
        }
        out
    }
}

/// 该表达式是否引用了"上下文"（事件字段 / 实体变量路径 / 完全未绑定符号）。
fn references_context(e: &Expr) -> bool {
    match e {
        Expr::Path(_) => true,
        // 决策表查询必须由宿主求值（它要查表 + 取第 index 个输出列）
        Expr::TableLookup { .. } => true,
        Expr::Binary { left, right, .. } => references_context(left) || references_context(right),
        Expr::UnaryNot(inner) => references_context(inner),
        Expr::Call { args, .. } => args.iter().any(references_context),
        _ => false,
    }
}

/// 该表达式是否含函数调用（扁平字节码当前不含 `Call`）。
fn contains_call(e: &Expr) -> bool {
    match e {
        Expr::Call { .. } | Expr::TableLookup { .. } => true,
        Expr::Binary { left, right, .. } => contains_call(left) || contains_call(right),
        Expr::UnaryNot(inner) => contains_call(inner),
        _ => false,
    }
}

/// 极简表达式渲染（原子标签）。
pub fn render_expr(e: &Expr) -> String {
    match e {
        Expr::Ident(s) => s.clone(),
        Expr::Path(parts) => parts.join("."),
        Expr::Number(n) => format!("{n}"),
        Expr::Hex(h) => format!("0x{h:X}"),
        Expr::Str(s) => format!("\"{s}\""),
        Expr::Bool(b) => b.to_string(),
        Expr::DurationLit(d) => format!("{}s", d.as_secs()),
        Expr::UnaryNot(i) => format!("not {}", render_expr(i)),
        Expr::Binary { op, left, right } => {
            let o = match op {
                BinaryOp::Add => "+",
                BinaryOp::Sub => "-",
                BinaryOp::Mul => "*",
                BinaryOp::Div => "/",
                BinaryOp::Mod => "%",
                BinaryOp::Eq => "==",
                BinaryOp::Neq => "!=",
                BinaryOp::Gt => ">",
                BinaryOp::Gte => ">=",
                BinaryOp::Lt => "<",
                BinaryOp::Lte => "<=",
                BinaryOp::And => "and",
                BinaryOp::Or => "or",
                BinaryOp::BitAnd => "&",
                BinaryOp::BitOr => "|",
                BinaryOp::BitXor => "^",
                BinaryOp::Shl => "<<",
                BinaryOp::Shr => ">>",
            };
            format!("{} {} {}", render_expr(left), o, render_expr(right))
        }
        Expr::Call { func, args } => {
            let a: Vec<String> = args.iter().map(render_expr).collect();
            format!("{}({})", func, a.join(", "))
        }
        Expr::TableLookup { table, args, index } => {
            let a: Vec<String> = args.iter().map(render_expr).collect();
            format!("{}({})[{}]", table, a.join(", "), index)
        }
    }
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rules_flatvm::Binding;
    use std::collections::HashMap;

    /// 测试宿主：原子按标签查表；`now` 系列直接由外部注入。
    struct TestHost {
        pub truth: HashMap<String, bool>,
        pub windows: HashMap<String, i64>,
    }

    impl AtomHost for TestHost {
        fn eval_atom(&mut self, atom: &Atom) -> bool {
            self.truth.get(&atom.label).copied().unwrap_or(false)
        }
        fn window_secs(&mut self, e: &Expr) -> i64 {
            self.windows.get(&render_expr(e)).copied().unwrap_or(0)
        }
    }

    /// 把任意符号都绑到新槽位的绑定器（保证走快路径）。
    #[derive(Default)]
    struct GreedyBinder {
        next: u32,
        nums: HashMap<String, u32>,
    }
    impl SlotBinder for GreedyBinder {
        fn bind(&mut self, name: &str) -> Option<Binding> {
            let off = *self.nums.entry(name.to_string()).or_insert_with(|| {
                let v = self.next;
                self.next += 1;
                v
            });
            Some(Binding::Num(off))
        }
    }

    fn spec_with(invariant: &str) -> SpecDecl {
        let src = format!(
            r#"
            entity Company(key: code) {{ states: [NORMAL, BAD] initial: NORMAL }}
            spec S on c: Company {{
                invariant: {invariant}
                violation {{ severity: WARNING emit: "x" }}
            }}
            "#
        );
        rules_parser::parse(&src).unwrap().specs.remove(0)
    }

    fn compile_str(inv: &str) -> TemporalAutomaton {
        let spec = spec_with(inv);
        let mut b = GreedyBinder::default();
        let mut i = Interner::new();
        compile_spec(&spec, &mut b, &mut i)
    }

    #[test]
    fn nodes_are_emitted_in_post_order() {
        let aut = compile_str("(a > 1.0) implies always(b > 2.0)");
        // 根是 Implies，它的两个子节点索引必须小于根
        let root = aut.root as usize;
        assert_eq!(aut.nodes[root].kind(), "implies");
        for child in aut.nodes[root].children() {
            assert!((child as usize) < root, "post-order violated");
        }
    }

    #[test]
    fn always_latches_to_false_permanently() {
        let aut = compile_str("always(a > 1.0)");
        let mut st = aut.new_state();
        let mut host = TestHost { truth: HashMap::new(), windows: HashMap::new() };
        host.truth.insert("a > 1".into(), true);
        assert!(aut.step(&mut st, &mut host, 0));
        host.truth.insert("a > 1".into(), false);
        assert!(!aut.step(&mut st, &mut host, 1));
        // latch：即使恢复为真也不再成立
        host.truth.insert("a > 1".into(), true);
        assert!(!aut.step(&mut st, &mut host, 2));
    }

    #[test]
    fn historically_expires_after_window() {
        let aut = compile_str("historically(a > 1.0, within: 10s)");
        let mut st = aut.new_state();
        let mut host = TestHost { truth: HashMap::new(), windows: HashMap::new() };
        host.truth.insert("a > 1".into(), true);
        assert!(aut.step(&mut st, &mut host, 100));
        host.truth.insert("a > 1".into(), false);
        // 窗口内仍成立
        assert!(aut.step(&mut st, &mut host, 105));
        // 超窗后回落
        assert!(!aut.step(&mut st, &mut host, 111));
    }

    #[test]
    fn eventually_violates_when_deadline_passes() {
        let aut = compile_str("eventually(a > 1.0, within: 10s)");
        let mut st = aut.new_state();
        let mut host = TestHost { truth: HashMap::new(), windows: HashMap::new() };
        // 承诺窗口内未发生 → 仍视为成立（宽限）
        assert!(aut.step(&mut st, &mut host, 0));
        assert!(aut.step(&mut st, &mut host, 5));
        // 逾期未发生 → 违反
        assert!(!aut.step(&mut st, &mut host, 11));
    }

    #[test]
    fn eventually_satisfied_when_atom_fires() {
        let aut = compile_str("eventually(a > 1.0, within: 10s)");
        let mut st = aut.new_state();
        let mut host = TestHost { truth: HashMap::new(), windows: HashMap::new() };
        aut.step(&mut st, &mut host, 0);
        host.truth.insert("a > 1".into(), true);
        assert!(aut.step(&mut st, &mut host, 3));
        host.truth.insert("a > 1".into(), false);
        // 已兑现，后续不再违反
        assert!(aut.step(&mut st, &mut host, 100));
    }

    #[test]
    fn until_requires_p_until_q_holds() {
        let aut = compile_str("until(a > 1.0, b > 2.0)");
        let mut st = aut.new_state();
        let mut host = TestHost { truth: HashMap::new(), windows: HashMap::new() };
        host.truth.insert("a > 1".into(), true);
        assert!(aut.step(&mut st, &mut host, 0));
        host.truth.insert("a > 1".into(), false);
        assert!(!aut.step(&mut st, &mut host, 1));
        // q 出现后 latch，p 不再需要
        host.truth.insert("b > 2".into(), true);
        assert!(aut.step(&mut st, &mut host, 2));
        assert!(aut.step(&mut st, &mut host, 3));
    }

    #[test]
    fn dynamic_window_is_resolved_by_host() {
        let aut = compile_str("historically(a > 1.0, within: period_window)");
        let mut st = aut.new_state();
        let mut host = TestHost { truth: HashMap::new(), windows: HashMap::new() };
        host.windows.insert("period_window".into(), 10);
        host.truth.insert("a > 1".into(), true);
        assert!(aut.step(&mut st, &mut host, 100));
        host.truth.insert("a > 1".into(), false);
        assert!(!aut.step(&mut st, &mut host, 111));
    }

    #[test]
    fn numeric_predicates_compile_to_flat_bytecode() {
        let aut = compile_str("(a > 1.0) implies (b > 2.0)");
        assert!(aut.flat_atom_ratio() > 0.0, "numeric predicates must take the flat path");
        assert!(aut.atoms.iter().all(|a| a.kind.is_flat()));
    }

    #[test]
    fn explain_reports_implied_antecedent() {
        let aut = compile_str("(a > 1.0) implies (b > 2.0)");
        let mut st = aut.new_state();
        let mut host = TestHost { truth: HashMap::new(), windows: HashMap::new() };
        host.truth.insert("a > 1".into(), true);
        aut.step(&mut st, &mut host, 0);
        let text = aut.explain(&st);
        assert!(text.contains("antecedent true"), "{text}");
    }
}
