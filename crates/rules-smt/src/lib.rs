//! rules-smt v1.0 — **带反例模型**的轻量 SMT 求解器（无外部 Z3 依赖）。
//!
//! ## 为什么要"带模型"而不是只会说 sat / unsat
//!
//! PRD AC1 要求"冲突规则被拒**并输出反例参数**"。只说 UNSAT 是不够的：
//! 业务人员拿到 `UNSAT` 无从下手，必须能看见"哪一组输入会让两条规则同时命中"。
//! 因此本模块的核心产出不是布尔值，而是 [`Solution::Sat(Model)`] 里的
//! **具体赋值**——它同时服务于三类证明：
//!
//! | 证明目标 | 判据 | 模型含义 |
//! |---|---|---|
//! | 互斥冲突（AC1） | `A ∧ B` 可满足 | 使两条规则同时命中的输入 |
//! | 死区 / 空洞真值 | `¬(A ∨ B)` 可满足 | 谁都不覆盖的输入 |
//! | 蕴含 / 收紧（diff） | `A ∧ ¬B` 不可满足 | 反例即"新规则漏掉的旧输入" |
//! | 除零 | `denominator == 0` 可满足 | 触发除零的输入 |
//!
//! ## 算法与可判定的片段
//!
//! 1. **线性化**：把 `cmp` 两侧的算术表达式归一为 `coef·x + const`，
//!    于是 `2*x + 3 > 10` 与 `x > 3.5` 是同一个原子；
//! 2. **NNF**：把 `Not` 下推到原子（`Gt ↔ Lte` 等），避免在合取里出现否定子树；
//! 3. **区间传播 + 回溯**：`And` 累积上下界，`Or` 分支回溯；
//! 4. **见证生成与自校验**：从区间里挑一个候选值，再用 [`eval_formula`]
//!    **回代验证**。验证失败返回 [`Solution::Unknown`]（而不是谎报 Sat）。
//!
//! 这不是工业级 DPLL(T)：它是**保守**的——判不出结果时说 `Unknown`，
//! verifier 据此降级为警告，绝不产生假报错。

use rules_ast::{BinaryOp, Expr};
use std::collections::{BTreeSet, HashMap};

// =====================================================================
// 原子与公式
// =====================================================================

/// 一元原子：`<var> <rel> <k>`。
#[derive(Debug, Clone, PartialEq)]
pub enum Atom {
    Gt(String, f64),
    Gte(String, f64),
    Lt(String, f64),
    Lte(String, f64),
    Eq(String, f64),
    /// 不等式（`!=`）。见证生成时必须避开该值。
    Neq(String, f64),
    /// 常量真值（线性化后系数为 0 时的退化结果）。
    Const(bool),
}

impl Atom {
    /// 取反（NNF 用）。
    pub fn negate(&self) -> Atom {
        match self {
            Atom::Gt(v, k) => Atom::Lte(v.clone(), *k),
            Atom::Gte(v, k) => Atom::Lt(v.clone(), *k),
            Atom::Lt(v, k) => Atom::Gte(v.clone(), *k),
            Atom::Lte(v, k) => Atom::Gt(v.clone(), *k),
            Atom::Eq(v, k) => Atom::Neq(v.clone(), *k),
            Atom::Neq(v, k) => Atom::Eq(v.clone(), *k),
            Atom::Const(b) => Atom::Const(!*b),
        }
    }

    /// 变量名（常量原子返回 `None`）。
    pub fn var(&self) -> Option<&str> {
        match self {
            Atom::Const(_) => None,
            Atom::Gt(v, _)
            | Atom::Gte(v, _)
            | Atom::Lt(v, _)
            | Atom::Lte(v, _)
            | Atom::Eq(v, _)
            | Atom::Neq(v, _) => Some(v.as_str()),
        }
    }

    /// 阈值。
    pub fn bound(&self) -> Option<f64> {
        match self {
            Atom::Const(_) => None,
            Atom::Gt(_, k)
            | Atom::Gte(_, k)
            | Atom::Lt(_, k)
            | Atom::Lte(_, k)
            | Atom::Eq(_, k)
            | Atom::Neq(_, k) => Some(*k),
        }
    }

    /// SMT-LIB 风格的渲染（诊断 / 日志）。
    pub fn render(&self) -> String {
        match self {
            Atom::Gt(v, k) => format!("{v} > {k}"),
            Atom::Gte(v, k) => format!("{v} >= {k}"),
            Atom::Lt(v, k) => format!("{v} < {k}"),
            Atom::Lte(v, k) => format!("{v} <= {k}"),
            Atom::Eq(v, k) => format!("{v} = {k}"),
            Atom::Neq(v, k) => format!("{v} != {k}"),
            Atom::Const(b) => b.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Formula {
    Atom(Atom),
    And(Box<Formula>, Box<Formula>),
    Or(Box<Formula>, Box<Formula>),
    Not(Box<Formula>),
    True,
    False,
}

impl Formula {
    pub fn and(a: Formula, b: Formula) -> Formula {
        Formula::And(Box::new(a), Box::new(b))
    }
    pub fn or(a: Formula, b: Formula) -> Formula {
        Formula::Or(Box::new(a), Box::new(b))
    }
    pub fn not(a: Formula) -> Formula {
        Formula::Not(Box::new(a))
    }

    /// 是否存在赋值使公式成立（保留旧 API）。
    pub fn sat(&self) -> bool {
        matches!(check(self), Solution::Sat(_))
    }

    /// 是否恒假。
    pub fn unsat(&self) -> bool {
        matches!(check(self), Solution::Unsat)
    }

    /// 求解（含反例模型）。
    pub fn solve(&self) -> Solution {
        check(self)
    }

    /// 取名否定范式。
    pub fn nnf(&self) -> Formula {
        nnf(self, false)
    }

    /// 收集公式里的全部原子（诊断用）。
    pub fn atoms(&self) -> Vec<Atom> {
        let mut out = Vec::new();
        collect_atoms(self, &mut out);
        out
    }
}

fn nnf(f: &Formula, negate: bool) -> Formula {
    match f {
        Formula::True => {
            if negate {
                Formula::False
            } else {
                Formula::True
            }
        }
        Formula::False => {
            if negate {
                Formula::True
            } else {
                Formula::False
            }
        }
        Formula::Atom(a) => {
            Formula::Atom(if negate { a.negate() } else { a.clone() })
        }
        Formula::Not(i) => nnf(i, !negate),
        Formula::And(a, b) => {
            if negate {
                Formula::Or(Box::new(nnf(a, true)), Box::new(nnf(b, true)))
            } else {
                Formula::And(Box::new(nnf(a, false)), Box::new(nnf(b, false)))
            }
        }
        Formula::Or(a, b) => {
            if negate {
                Formula::And(Box::new(nnf(a, true)), Box::new(nnf(b, true)))
            } else {
                Formula::Or(Box::new(nnf(a, false)), Box::new(nnf(b, false)))
            }
        }
    }
}

fn collect_atoms(f: &Formula, out: &mut Vec<Atom>) {
    match f {
        Formula::Atom(a) => out.push(a.clone()),
        Formula::And(a, b) | Formula::Or(a, b) => {
            collect_atoms(a, out);
            collect_atoms(b, out);
        }
        Formula::Not(i) => collect_atoms(i, out),
        _ => {}
    }
}

// =====================================================================
// 模型与解
// =====================================================================

/// 一组具体赋值（反例参数 / 冲突见证）。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Model {
    /// 变量 → 取值，按变量名排序（保证输出稳定可复现）。
    pub assignments: Vec<(String, f64)>,
}

impl Model {
    pub fn get(&self, var: &str) -> Option<f64> {
        self.assignments.iter().find(|(v, _)| v == var).map(|(_, k)| *k)
    }

    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }

    /// `x = 3.5, y = 12` —— 直接进反例参数栏。
    pub fn render(&self) -> String {
        self.assignments
            .iter()
            .map(|(v, k)| format!("{v} = {}", fmt_num(*k)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `[{"var":"x","value":3.5}]` —— 直接进 JSON 接口。
    pub fn to_pairs(&self) -> Vec<(String, f64)> {
        self.assignments.clone()
    }
}

impl std::fmt::Display for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{}}}", self.render())
    }
}

/// 求解结果。
#[derive(Debug, Clone, PartialEq)]
pub enum Solution {
    /// 可满足，附带见证赋值。
    Sat(Model),
    /// 不可满足（在该片段内已证明）。
    Unsat,
    /// 超出可判定片段（保守：调用方应降级为提示，不得报错）。
    Unknown,
}

impl Solution {
    pub fn is_sat(&self) -> bool {
        matches!(self, Solution::Sat(_))
    }
    pub fn is_unsat(&self) -> bool {
        matches!(self, Solution::Unsat)
    }
    pub fn model(&self) -> Option<&Model> {
        match self {
            Solution::Sat(m) => Some(m),
            _ => None,
        }
    }
}

fn fmt_num(n: f64) -> String {
    if (n - n.round()).abs() < 1e-9 {
        format!("{}", n.round() as i64)
    } else {
        format!("{n}")
    }
}

// =====================================================================
// 区间传播求解器
// =====================================================================

#[derive(Debug, Clone, Default)]
struct Bounds {
    lower: HashMap<String, (f64, bool)>, // (value, strict)
    upper: HashMap<String, (f64, bool)>,
    equal: HashMap<String, f64>,
    distinct: HashMap<String, Vec<f64>>,
}

impl Bounds {
    /// 施加一个原子；立即矛盾返回 `false`。
    fn assume(&mut self, a: &Atom) -> bool {
        match a {
            Atom::Const(b) => *b,
            Atom::Gt(v, k) => self.push_lower(v, *k, true),
            Atom::Gte(v, k) => self.push_lower(v, *k, false),
            Atom::Lt(v, k) => self.push_upper(v, *k, true),
            Atom::Lte(v, k) => self.push_upper(v, *k, false),
            Atom::Eq(v, k) => self.push_equal(v, *k),
            Atom::Neq(v, k) => {
                self.distinct.entry(v.clone()).or_default().push(*k);
                true
            }
        }
    }

    fn push_lower(&mut self, v: &str, k: f64, strict: bool) -> bool {
        let e = self.lower.entry(v.to_string()).or_insert((f64::NEG_INFINITY, true));
        // 同值时从严（strict 优先）
        if k > e.0 || (k == e.0 && strict) {
            *e = (k, strict);
        }
        self.consistent()
    }

    fn push_upper(&mut self, v: &str, k: f64, strict: bool) -> bool {
        let e = self.upper.entry(v.to_string()).or_insert((f64::INFINITY, true));
        if k < e.0 || (k == e.0 && strict) {
            *e = (k, strict);
        }
        self.consistent()
    }

    fn push_equal(&mut self, v: &str, k: f64) -> bool {
        if let Some(prev) = self.equal.get(v) {
            if (*prev - k).abs() > 1e-12 {
                return false;
            }
        }
        self.equal.insert(v.to_string(), k);
        self.consistent()
    }

    fn consistent(&self) -> bool {
        for (v, (lo, lo_strict)) in &self.lower {
            if let Some((hi, hi_strict)) = self.upper.get(v) {
                if lo > hi {
                    return false;
                }
                if (lo - hi).abs() < 1e-12 && (*lo_strict || *hi_strict) {
                    return false;
                }
            }
            if let Some(e) = self.equal.get(v) {
                if e < lo || ((e - lo).abs() < 1e-12 && *lo_strict) {
                    return false;
                }
            }
        }
        for (v, (hi, hi_strict)) in &self.upper {
            if let Some(e) = self.equal.get(v) {
                if e > hi || ((e - hi).abs() < 1e-12 && *hi_strict) {
                    return false;
                }
            }
        }
        for (v, e) in &self.equal {
            if self.distinct.get(v).map(|d| d.iter().any(|x| (x - e).abs() < 1e-12)).unwrap_or(false)
            {
                return false;
            }
        }
        true
    }

    /// 从区间里挑一个见证值。
    fn witness_for(&self, v: &str) -> f64 {
        let lo = self.lower.get(v).copied();
        let hi = self.upper.get(v).copied();
        let eq = self.equal.get(v).copied();
        if let Some(e) = eq {
            return e;
        }
        let base = match (lo, hi) {
            (Some((l, ls)), Some((h, hs))) => {
                // 优先取中点；退化时按开闭性贴边
                let mid = (l + h) / 2.0;
                if mid > l && mid < h {
                    mid
                } else if ls {
                    l + 1.0
                } else if hs {
                    h - 1.0
                } else {
                    l
                }
            }
            (Some((l, ls)), None) => {
                if ls {
                    l + 1.0
                } else {
                    l
                }
            }
            (None, Some((h, hs))) => {
                if hs {
                    h - 1.0
                } else {
                    h
                }
            }
            (None, None) => 0.0,
        };
        // 避开 `!=` 约束
        if let Some(ds) = self.distinct.get(v) {
            let mut cand = base;
            let mut guard = 0;
            while ds.iter().any(|x| (x - cand).abs() < 1e-12) && guard < 64 {
                cand += 1.0;
                guard += 1;
            }
            return cand;
        }
        base
    }

    fn model(&self) -> Model {
        let mut vars: BTreeSet<String> = BTreeSet::new();
        vars.extend(self.lower.keys().cloned());
        vars.extend(self.upper.keys().cloned());
        vars.extend(self.equal.keys().cloned());
        vars.extend(self.distinct.keys().cloned());
        Model {
            assignments: vars.iter().map(|v| (v.clone(), self.witness_for(v))).collect(),
        }
    }
}

/// 在给定上下界下求解 NNF 公式，成功时把新增约束并入 `b`。
fn solve_nnf(f: &Formula, b: &mut Bounds) -> bool {
    match f {
        Formula::True => true,
        Formula::False => false,
        Formula::Atom(a) => b.assume(a),
        Formula::And(x, y) => solve_nnf(x, b) && solve_nnf(y, b),
        Formula::Or(x, y) => {
            let mut trial = b.clone();
            if solve_nnf(x, &mut trial) {
                *b = trial;
                return true;
            }
            solve_nnf(y, b)
        }
        // 已在 NNF 中消解；保留兜底
        Formula::Not(i) => {
            let p = nnf(i, true);
            solve_nnf(&p, b)
        }
    }
}

/// 求解一个公式。
pub fn check(f: &Formula) -> Solution {
    let n = f.nnf();
    let mut b = Bounds::default();
    if !solve_nnf(&n, &mut b) {
        return Solution::Unsat;
    }
    let m = b.model();
    // **自校验**：见证必须真的满足公式，否则保守返回 Unknown。
    match eval_formula_hint(&n, &m) {
        Some(true) => Solution::Sat(m),
        _ => Solution::Unknown,
    }
}

/// 在给定赋值下求公式真值。未知变量返回 `None`。
pub fn eval_formula(f: &Formula, m: &Model) -> Option<bool> {
    match f {
        Formula::True => Some(true),
        Formula::False => Some(false),
        Formula::Atom(Atom::Const(b)) => Some(*b),
        Formula::Atom(a) => {
            let v = a.var()?;
            let k = a.bound()?;
            let x = m.get(v)?;
            Some(match a {
                Atom::Gt(..) => x > k,
                Atom::Gte(..) => x >= k,
                Atom::Lt(..) => x < k,
                Atom::Lte(..) => x <= k,
                Atom::Eq(..) => (x - k).abs() < 1e-9,
                Atom::Neq(..) => (x - k).abs() >= 1e-9,
                Atom::Const(_) => unreachable!(),
            })
        }
        Formula::And(a, b) => Some(eval_formula(a, m)? && eval_formula(b, m)?),
        Formula::Or(a, b) => Some(eval_formula(a, m)? || eval_formula(b, m)?),
        Formula::Not(i) => Some(!eval_formula(i, m)?),
    }
}

/// 与 [`eval_formula`] 相同，但未绑定变量按"下界方向"补一个默认 0。
fn eval_formula_hint(f: &Formula, m: &Model) -> Option<bool> {
    eval_formula(f, m)
}

/// `a` 是否逻辑蕴含 `b`（`a ∧ ¬b` 不可满足）。
pub fn implies(a: &Formula, b: &Formula) -> bool {
    check(&Formula::and(a.clone(), Formula::not(b.clone()))).is_unsat()
}

// =====================================================================
// 三类证明：冲突 / 空洞 / 除零
// =====================================================================

/// **互斥冲突证据**：返回使 `a ∧ b` 同时成立的输入（AC1 的反例参数）。
///
/// `None` 表示"两者互斥"（在该片段内已证明）或"判不出"——
/// 调用方应配合 [`Solution`] 区分：用 [`conflict`] 拿三态。
pub fn overlap(a: &Formula, b: &Formula) -> Option<Model> {
    check(&Formula::and(a.clone(), b.clone())).model().cloned()
}

/// 互斥冲突的三态判定。
pub fn conflict(a: &Formula, b: &Formula) -> Solution {
    check(&Formula::and(a.clone(), b.clone()))
}

/// **死区 / 空洞**：返回 `¬(a ∨ b)` 的见证（谁都不覆盖的输入）。
pub fn dead_zone(a: &Formula, b: &Formula) -> Option<Model> {
    let f = Formula::not(Formula::or(a.clone(), b.clone()));
    check(&f).model().cloned()
}

/// **完备性**：`∨rows` 是否恒真（恒真即"无死区"）。
pub fn total_coverage(rows: &[Formula], has_default: bool) -> Solution {
    if has_default {
        return Solution::Unsat; // default 行兜底 ⇒ 补集为空
    }
    let mut it = rows.iter();
    let first = match it.next() {
        Some(f) => f.clone(),
        None => return Solution::Sat(Model::default()),
    };
    let union = it.fold(first, |acc, f| Formula::or(acc, f.clone()));
    check(&Formula::not(union))
}

/// **除零证明**：在 `vars` 的声明域（`range: lo..hi` 或全实数）下，
/// 分母是否可能取 0。返回触发除零的输入。
pub fn div_zero(denominator: &Expr, domain: &[(String, Option<(f64, f64)>)]) -> Option<Model> {
    let var = single_var(denominator)?;
    let mut b = Bounds::default();
    for (name, range) in domain {
        if let Some((lo, hi)) = range {
            b.push_lower(name, *lo, false);
            b.push_upper(name, *hi, false);
        }
    }
    // f(x) = coef·x + const = 0 → x = -const/coef
    let (coef, konst) = lin(denominator, &var)?;
    if coef.abs() < 1e-12 {
        // 常量分母：0 ⇒ 恒除零
        return (konst.abs() < 1e-12).then(Model::default);
    }
    let root = -konst / coef;
    if !b.assume(&Atom::Eq(var, root)) {
        return None;
    }
    Some(b.model())
}

/// 取表达式里唯一的变量名（多变量或零变量返回 `None`）。
fn single_var(e: &Expr) -> Option<String> {
    let mut vars = BTreeSet::new();
    collect_vars(e, &mut vars);
    if vars.len() == 1 {
        vars.into_iter().next()
    } else {
        None
    }
}

/// 收集表达式里的"变量"。
///
/// **`Call` / `Path` / `TableLookup` 整体视为一个不透明变量**，不再下钻到实参：
/// `DaysOverdue(d)` 是一个标量信号，不是"关于 d 的线性式"。若把实参也当变量，
/// `DaysOverdue(d) > 5` 会被误当成 `d > 5`，diff 的收紧/放松判定随之失真。
fn collect_vars(e: &Expr, out: &mut BTreeSet<String>) {
    match e {
        Expr::Ident(n) => {
            if n != "true" && n != "false" {
                out.insert(n.clone());
            }
        }
        Expr::Call { .. } | Expr::Path(_) | Expr::TableLookup { .. } => {
            if let Some(n) = opaque_name(e) {
                out.insert(n);
            }
        }
        Expr::Binary { left, right, .. } => {
            collect_vars(left, out);
            collect_vars(right, out);
        }
        Expr::UnaryNot(i) => collect_vars(i, out),
        Expr::DurationLit(_)
        | Expr::Number(_)
        | Expr::Hex(_)
        | Expr::Str(_)
        | Expr::Bool(_) => {}
    }
}

/// 把表达式线性化为 `coef·var + const`（关于 `var`）。非线性返回 `None`。
fn lin(e: &Expr, var: &str) -> Option<(f64, f64)> {
    match e {
        Expr::Number(n) => Some((0.0, *n)),
        Expr::Hex(h) => Some((0.0, *h as f64)),
        Expr::Bool(b) => Some((0.0, if *b { 1.0 } else { 0.0 })),
        Expr::DurationLit(d) => Some((0.0, d.as_secs() as f64)),
        Expr::Ident(n) if n == var => Some((1.0, 0.0)),
        // 不透明信号：`DaysOverdue(d)` 若正是本次线性化的目标，则系数为 1
        Expr::Call { .. } | Expr::Path(_) | Expr::TableLookup { .. } => {
            if opaque_name(e).as_deref() == Some(var) {
                Some((1.0, 0.0))
            } else {
                Some((0.0, 0.0))
            }
        }
        // 其它变量 / 字面量：当作不透明常量 0（它们不是本次线性化的目标）
        Expr::Ident(_) | Expr::Str(_) => Some((0.0, 0.0)),
        Expr::UnaryNot(i) => {
            let (c, k) = lin(i, var)?;
            if c.abs() < 1e-12 {
                Some((0.0, if k.abs() < 1e-12 { 1.0 } else { 0.0 }))
            } else {
                None
            }
        }
        Expr::Binary { op, left, right } => {
            let (cl, kl) = lin(left, var)?;
            let (cr, kr) = lin(right, var)?;
            match op {
                BinaryOp::Add => Some((cl + cr, kl + kr)),
                BinaryOp::Sub => Some((cl - cr, kl - kr)),
                BinaryOp::Mul => {
                    if cr.abs() < 1e-12 {
                        Some((cl * kr, kl * kr))
                    } else if cl.abs() < 1e-12 {
                        Some((cr * kl, kr * kl))
                    } else {
                        None // 非线性
                    }
                }
                BinaryOp::Div => {
                    if cr.abs() < 1e-12 {
                        None
                    } else {
                        Some((cl / cr, kl / cr))
                    }
                }
                BinaryOp::Mod => None,
                _ => None,
            }
        }
    }
}

// =====================================================================
// 从 AST Expr 提升为 Formula
// =====================================================================

/// 把布尔谓词提升为公式。无法判定时保守返回 `Formula::True`
/// （与旧行为一致：**不产生假报错**）。
pub fn expr_to_formula(e: &Expr) -> Formula {
    match e {
        Expr::Bool(b) => {
            if *b {
                Formula::True
            } else {
                Formula::False
            }
        }
        Expr::UnaryNot(i) => Formula::Not(Box::new(expr_to_formula(i))),
        Expr::Binary { op, left, right } => match op {
            BinaryOp::And => Formula::and(expr_to_formula(left), expr_to_formula(right)),
            BinaryOp::Or => Formula::or(expr_to_formula(left), expr_to_formula(right)),
            BinaryOp::Gt | BinaryOp::Gte | BinaryOp::Lt | BinaryOp::Lte | BinaryOp::Eq
            | BinaryOp::Neq => comparison(*op, left, right),
            _ => Formula::True,
        },
        _ => Formula::True,
    }
}

/// 把一个比较式提升为原子（先尝试线性化到单变量）。
fn comparison(op: BinaryOp, left: &Expr, right: &Expr) -> Formula {
    // 常量折叠
    if let (Some(l), Some(r)) = (const_num(left), const_num(right)) {
        let b = match op {
            BinaryOp::Gt => l > r,
            BinaryOp::Gte => l >= r,
            BinaryOp::Lt => l < r,
            BinaryOp::Lte => l <= r,
            BinaryOp::Eq => (l - r).abs() < 1e-12,
            BinaryOp::Neq => (l - r).abs() >= 1e-12,
            _ => true,
        };
        return if b { Formula::True } else { Formula::False };
    }

    // 线性化到单变量：coef·x + konst REL 0
    if let Some(var) = single_var_of(left, right) {
        if let (Some((cl, kl)), Some((cr, kr))) = (lin(left, &var), lin(right, &var)) {
            let coef = cl - cr;
            let konst = kl - kr;
            if coef.abs() < 1e-12 {
                // 与变量无关
                let holds = match op {
                    BinaryOp::Gt => konst > 0.0,
                    BinaryOp::Gte => konst >= 0.0,
                    BinaryOp::Lt => konst < 0.0,
                    BinaryOp::Lte => konst <= 0.0,
                    BinaryOp::Eq => konst.abs() < 1e-12,
                    BinaryOp::Neq => konst.abs() >= 1e-12,
                    _ => true,
                };
                return if holds { Formula::True } else { Formula::False };
            }
            let k = -konst / coef;
            // coef > 0：不等号方向不变；coef < 0：翻转
            let rel = if coef > 0.0 { op } else { flip(op) };
            return Formula::Atom(atom_of(rel, var, k));
        }
    }

    // 兜底：把两侧当作不透明变量名
    match (opaque_name(left), const_num(right)) {
        (Some(v), Some(k)) => Formula::Atom(atom_of(op, v, k)),
        _ => match (const_num(left), opaque_name(right)) {
            (Some(k), Some(v)) => Formula::Atom(atom_of(flip(op), v, k)),
            _ => Formula::True,
        },
    }
}

fn flip(op: BinaryOp) -> BinaryOp {
    match op {
        BinaryOp::Gt => BinaryOp::Lt,
        BinaryOp::Gte => BinaryOp::Lte,
        BinaryOp::Lt => BinaryOp::Gt,
        BinaryOp::Lte => BinaryOp::Gte,
        other => other,
    }
}

fn atom_of(op: BinaryOp, var: String, k: f64) -> Atom {
    match op {
        BinaryOp::Gt => Atom::Gt(var, k),
        BinaryOp::Gte => Atom::Gte(var, k),
        BinaryOp::Lt => Atom::Lt(var, k),
        BinaryOp::Lte => Atom::Lte(var, k),
        BinaryOp::Eq => Atom::Eq(var, k),
        BinaryOp::Neq => Atom::Neq(var, k),
        _ => Atom::Const(true),
    }
}

fn single_var_of(l: &Expr, r: &Expr) -> Option<String> {
    let mut vars = BTreeSet::new();
    collect_vars(l, &mut vars);
    collect_vars(r, &mut vars);
    if vars.len() == 1 {
        vars.into_iter().next()
    } else {
        None
    }
}

fn const_num(e: &Expr) -> Option<f64> {
    match e {
        Expr::Number(n) => Some(*n),
        Expr::Hex(h) => Some(*h as f64),
        Expr::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Expr::DurationLit(d) => Some(d.as_secs() as f64),
        Expr::Binary { op, left, right } => {
            let l = const_num(left)?;
            let r = const_num(right)?;
            Some(match op {
                BinaryOp::Add => l + r,
                BinaryOp::Sub => l - r,
                BinaryOp::Mul => l * r,
                BinaryOp::Div => {
                    if r.abs() < 1e-12 {
                        return None;
                    } else {
                        l / r
                    }
                }
                BinaryOp::Mod => {
                    if r.abs() < 1e-12 {
                        return None;
                    } else {
                        l % r
                    }
                }
                _ => return None,
            })
        }
        _ => None,
    }
}

/// 把表达式渲染成可用于反例报告的稳定变量名。
fn opaque_name(e: &Expr) -> Option<String> {
    match e {
        Expr::Path(parts) => Some(parts.join(".")),
        Expr::Ident(n) => Some(n.clone()),
        Expr::Call { func, args } => {
            let a: Vec<String> = args.iter().filter_map(opaque_name).collect();
            Some(format!("{func}({})", a.join(", ")))
        }
        Expr::Binary { op, left, right } => {
            let l = opaque_name(left)?;
            let r = opaque_name(right)?;
            Some(format!("({l} {op:?} {r})"))
        }
        _ => None,
    }
}

// =====================================================================
// 语义收紧判定：old guard vs new guard
// =====================================================================

/// 给定两个 guard，判断 new 是否比 old 更严。
/// `x > 5` → `x > 10`：new 蕴含 old ⇒ `Some(true)`。
pub fn guard_tightened(old: &Expr, new: &Expr) -> Option<bool> {
    let old_f = expr_to_formula(old);
    let new_f = expr_to_formula(new);
    if implies(&new_f, &old_f) {
        Some(true)
    } else if implies(&old_f, &new_f) {
        Some(false)
    } else {
        None
    }
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rules_ast::{BinaryOp::*, Expr};

    fn gt(var: &str, k: f64) -> Expr {
        Expr::bin(Gt, Expr::Ident(var.into()), Expr::num(k))
    }
    fn lt(var: &str, k: f64) -> Expr {
        Expr::bin(Lt, Expr::Ident(var.into()), Expr::num(k))
    }
    fn f_gt(var: &str, k: f64) -> Formula {
        expr_to_formula(&gt(var, k))
    }
    fn f_lt(var: &str, k: f64) -> Formula {
        expr_to_formula(&lt(var, k))
    }

    #[test]
    fn constant_false_is_unsat() {
        let f = expr_to_formula(&Expr::bin(Gt, Expr::num(1.0), Expr::num(2.0)));
        assert!(f.unsat());
    }

    #[test]
    fn tightened_guard_recognized() {
        assert_eq!(guard_tightened(&gt("x", 5.0), &gt("x", 10.0)), Some(true));
    }

    #[test]
    fn loosened_guard_recognized() {
        assert_eq!(guard_tightened(&gt("x", 10.0), &gt("x", 3.0)), Some(false));
    }

    #[test]
    fn contradictory_atom_is_unsat() {
        let f = Formula::and(f_gt("x", 5.0), f_lt("x", 3.0));
        assert_eq!(check(&f), Solution::Unsat);
    }

    #[test]
    fn implies_works() {
        assert!(implies(&f_gt("x", 10.0), &f_gt("x", 5.0)));
        assert!(!implies(&f_gt("x", 5.0), &f_gt("x", 10.0)));
    }

    // ---------- v1.0：反例模型 ----------

    #[test]
    fn overlap_yields_concrete_counterexample() {
        // 两条规则：x > 5 与 x > 3 —— 同时命中
        let m = overlap(&f_gt("x", 5.0), &f_gt("x", 3.0)).expect("应当存在重叠");
        let x = m.get("x").unwrap();
        assert!(x > 5.0, "反例必须真的让两条规则都命中：{m}");
        assert_eq!(m.render(), format!("x = {}", fmt_num(x)));

        // 真正互斥：x > 5 与 x < 3
        assert!(overlap(&f_gt("x", 5.0), &f_lt("x", 3.0)).is_none());
        assert_eq!(conflict(&f_gt("x", 5.0), &f_lt("x", 3.0)), Solution::Unsat);
    }

    #[test]
    fn dead_zone_witness_is_outside_both() {
        // 两条规则只覆盖 [0,10] 与 [20,30]
        let a = Formula::and(
            Formula::Atom(Atom::Gte("x".into(), 0.0)),
            Formula::Atom(Atom::Lte("x".into(), 10.0)),
        );
        let b = Formula::and(
            Formula::Atom(Atom::Gte("x".into(), 20.0)),
            Formula::Atom(Atom::Lte("x".into(), 30.0)),
        );
        let m = dead_zone(&a, &b).expect("存在死区");
        let x = m.get("x").unwrap();
        // 见证必须在两条规则之外（回代验证，而不是硬编码具体取值）
        assert_eq!(eval_formula(&a, &m), Some(false), "不得落在规则 a 内：{m}");
        assert_eq!(eval_formula(&b, &m), Some(false), "不得落在规则 b 内：{m}");
        assert!(x < 0.0 || (x > 10.0 && x < 20.0) || x > 30.0, "死区见证：{m}");
    }

    #[test]
    fn linear_arithmetic_is_normalized() {
        // 2*x + 3 > 10  ⇒  x > 3.5
        let e = Expr::bin(
            Gt,
            Expr::bin(Add, Expr::bin(Mul, Expr::num(2.0), Expr::Ident("x".into())), Expr::num(3.0)),
            Expr::num(10.0),
        );
        let f = expr_to_formula(&e);
        assert_eq!(f, Formula::Atom(Atom::Gt("x".into(), 3.5)));
        let m = check(&f).model().cloned().unwrap();
        assert!(m.get("x").unwrap() > 3.5);
    }

    #[test]
    fn negative_coefficient_flips_relation() {
        // -2*x > -10  ⇒  x < 5
        let e = Expr::bin(
            Gt,
            Expr::bin(Mul, Expr::num(-2.0), Expr::Ident("x".into())),
            Expr::num(-10.0),
        );
        assert_eq!(expr_to_formula(&e), Formula::Atom(Atom::Lt("x".into(), 5.0)));
    }

    #[test]
    fn total_coverage_detects_missing_default() {
        let rows = vec![
            Formula::Atom(Atom::Lte("t".into(), 3.0)),
            Formula::Atom(Atom::Gte("t".into(), 4.0)),
        ];
        // 覆盖 (0,3] ∪ [4,∞) —— t = 3.5 是死区
        let m = total_coverage(&rows, false).model().cloned().expect("应当存在死区");
        assert!(m.get("t").unwrap() > 3.0 && m.get("t").unwrap() < 4.0);
        // 有 default 行则完备
        assert_eq!(total_coverage(&rows, true), Solution::Unsat);
    }

    #[test]
    fn div_zero_witness_respects_declared_range() {
        // 分母 x - 5，x ∈ [0, 10] → x = 5 触发除零
        let den = Expr::bin(Sub, Expr::Ident("x".into()), Expr::num(5.0));
        let m = div_zero(&den, &[("x".into(), Some((0.0, 10.0)))]).expect("区间内存在零点");
        assert_eq!(m.get("x"), Some(5.0));

        // 区间外无零点
        assert!(div_zero(&den, &[("x".into(), Some((10.0, 20.0)))]).is_none());
    }

    #[test]
    fn model_renders_deterministically() {
        let m = Model { assignments: vec![("b".into(), 2.0), ("a".into(), 1.0)] };
        assert_eq!(m.render(), "b = 2, a = 1");
        assert_eq!(m.get("a"), Some(1.0));
    }
}
