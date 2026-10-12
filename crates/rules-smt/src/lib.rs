//! rules-smt — 轻量符号求解器（无外部 Z3 依赖）。
//!
//! 设计目标：在没有 libclang / Z3 原生库的环境下，仍能对规则 AST
//! 做**符号级**（而非常量折叠级）的可满足性与蕴含性判定。
//!
//! 能力：
//! - `sat(formula)`：是否存在变量赋值使公式成立；
//! - `unsat(formula)`：公式是否恒假（用于 vacuity 检测）；
//! - `implies(a, b)`：a 是否逻辑蕴含 b（用于 subsumption / 收紧判定）。
//!
//! 算法：对每个变量收集上下界（lower/upper），做区间传播；
//! 对 and/or 做递归。真非线性、跨变量乘法留给真 Z3 后端。

use rules_ast::{BinaryOp, Expr};

#[derive(Debug, Clone, PartialEq)]
pub enum Atom {
    Gt(String, f64),
    Gte(String, f64),
    Lt(String, f64),
    Lte(String, f64),
    Eq(String, f64),
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
    /// 是否存在赋值使公式成立。
    pub fn sat(&self) -> bool {
        match self {
            Formula::True => true,
            Formula::False => false,
            Formula::Atom(a) => atom_sat(a),
            Formula::And(a, b) => {
                // 收集合取中的所有原子，做区间传播。
                let mut atoms = Vec::new();
                collect_atoms(a, &mut atoms);
                collect_atoms(b, &mut atoms);
                conjunction_sat(&atoms)
            }
            Formula::Or(a, b) => a.sat() || b.sat(),
            Formula::Not(inner) => !inner.sat(),
        }
    }

    pub fn unsat(&self) -> bool {
        !self.sat()
    }
}

fn collect_atoms(f: &Formula, out: &mut Vec<Atom>) {
    match f {
        Formula::Atom(a) => out.push(a.clone()),
        Formula::And(a, b) => {
            collect_atoms(a, out);
            collect_atoms(b, out);
        }
        // Not(Atom) → 反向不等式，用于区间传播
        Formula::Not(inner) => {
            if let Formula::Atom(a) = &**inner {
                match a {
                    Atom::Gt(v, k) => out.push(Atom::Lte(v.clone(), *k)),
                    Atom::Gte(v, k) => out.push(Atom::Lt(v.clone(), *k)),
                    Atom::Lt(v, k) => out.push(Atom::Gte(v.clone(), *k)),
                    Atom::Lte(v, k) => out.push(Atom::Gt(v.clone(), *k)),
                    Atom::Eq(_, _) => {}
                }
            }
        }
        _ => {}
    }
}

/// 区间传播：对每个变量收集 lower / upper，检查是否冲突。
fn conjunction_sat(atoms: &[Atom]) -> bool {
    use std::collections::HashMap;
    let mut lower: HashMap<&str, f64> = HashMap::new();
    let mut upper: HashMap<&str, f64> = HashMap::new();
    let mut eq: HashMap<&str, f64> = HashMap::new();

    for a in atoms {
        match a {
            Atom::Gt(v, k) => {
                let e = lower.entry(v.as_str()).or_insert(f64::NEG_INFINITY);
                *e = e.max(*k);
            }
            Atom::Gte(v, k) => {
                let e = lower.entry(v.as_str()).or_insert(f64::NEG_INFINITY);
                *e = e.max(*k);
            }
            Atom::Lt(v, k) => {
                let e = upper.entry(v.as_str()).or_insert(f64::INFINITY);
                *e = e.min(*k);
            }
            Atom::Lte(v, k) => {
                let e = upper.entry(v.as_str()).or_insert(f64::INFINITY);
                *e = e.min(*k);
            }
            Atom::Eq(v, k) => {
                eq.insert(v.as_str(), *k);
            }
        }
    }

    // 检查上下界冲突
    for (v, lo) in &lower {
        if let Some(&hi) = upper.get(v) {
            // x > lo ∧ x < hi 要求 lo < hi（严格）
            if *lo >= hi {
                return false;
            }
        }
        if let Some(&e) = eq.get(v) {
            if e <= *lo {
                return false;
            }
        }
    }
    for (v, hi) in &upper {
        if let Some(&e) = eq.get(v) {
            if e >= *hi {
                return false;
            }
        }
    }
    true
}

/// 区间传播：对单个原子检查是否自洽。
fn atom_sat(a: &Atom) -> bool {
    match a {
        Atom::Gt(_, k) => *k < f64::INFINITY,
        Atom::Gte(_, k) => *k < f64::INFINITY,
        Atom::Lt(_, k) => *k > f64::NEG_INFINITY,
        Atom::Lte(_, k) => *k > f64::NEG_INFINITY,
        Atom::Eq(_, _) => true,
    }
}

/// a 是否逻辑蕴含 b：a => b 永真。
/// 判定方式：a ∧ ¬b 是否 unsat。
pub fn implies(a: &Formula, b: &Formula) -> bool {
    let counterexample = Formula::And(Box::new(a.clone()), Box::new(Formula::Not(Box::new(b.clone()))));
    counterexample.unsat()
}

// =====================================================================
// 从 AST Expr 提升为 Formula
// =====================================================================

pub fn expr_to_formula(e: &Expr) -> Formula {
    match e {
        Expr::Binary { op, left, right } => match (&**left, &**right) {
            (Expr::Ident(var), Expr::Number(k)) => atom_from_cmp(*op, var.clone(), *k),
            // Call 整体视为不透明变量：DaysOverdue(d) > K → Atom::Gt("DaysOverdue(d)", K)
            (call @ Expr::Call { .. }, Expr::Number(k)) => {
                let var = format!("{:?}", call);
                atom_from_cmp(*op, var, *k)
            }
            (Expr::Number(l), Expr::Number(r)) => {
                let b = match op {
                    BinaryOp::Gt => l > r,
                    BinaryOp::Gte => l >= r,
                    BinaryOp::Lt => l < r,
                    BinaryOp::Lte => l <= r,
                    BinaryOp::Eq => (l - r).abs() < f64::EPSILON,
                    BinaryOp::Neq => (l - r).abs() >= f64::EPSILON,
                    BinaryOp::And => *l > 0.0 && *r > 0.0,
                    BinaryOp::Or => *l > 0.0 || *r > 0.0,
                    _ => return Formula::True,
                };
                if b { Formula::True } else { Formula::False }
            }
            _ => Formula::True,
        },
        Expr::UnaryNot(inner) => Formula::Not(Box::new(expr_to_formula(inner))),
        _ => Formula::True,
    }
}

fn atom_from_cmp(op: BinaryOp, var: String, k: f64) -> Formula {
    match op {
        BinaryOp::Gt => Formula::Atom(Atom::Gt(var, k)),
        BinaryOp::Gte => Formula::Atom(Atom::Gte(var, k)),
        BinaryOp::Lt => Formula::Atom(Atom::Lt(var, k)),
        BinaryOp::Lte => Formula::Atom(Atom::Lte(var, k)),
        BinaryOp::Eq => Formula::Atom(Atom::Eq(var, k)),
        BinaryOp::Neq => Formula::Not(Box::new(Formula::Atom(Atom::Eq(var, k)))),
        BinaryOp::And => Formula::And(Box::new(Formula::True), Box::new(Formula::True)),
        BinaryOp::Or => Formula::Or(Box::new(Formula::False), Box::new(Formula::False)),
        _ => Formula::True,
    }
}

// =====================================================================
// 语义收紧判定：old guard vs new guard
// =====================================================================

/// 给定两个 guard（都是阈值比较式），判断 new 是否比 old 更严。
/// 例如 old: x > 5, new: x > 10 → new 蕴含 old → Tightened。
pub fn guard_tightened(old: &Expr, new: &Expr) -> Option<bool> {
    let old_f = expr_to_formula(old);
    let new_f = expr_to_formula(new);
    // Tightened iff new => old
    if implies(&new_f, &old_f) {
        Some(true)
    } else if implies(&old_f, &new_f) {
        Some(false)
    } else {
        None
    }
}

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

    #[test]
    fn constant_false_is_unsat() {
        // 1 > 2 → False → unsat
        let f = expr_to_formula(&Expr::bin(Gt, Expr::num(1.0), Expr::num(2.0)));
        assert!(f.unsat());
    }

    #[test]
    fn tightened_guard_recognized() {
        // old: x > 5, new: x > 10 → new implies old → tightened
        let old = gt("x", 5.0);
        let new = gt("x", 10.0);
        assert_eq!(guard_tightened(&old, &new), Some(true));
    }

    #[test]
    fn loosened_guard_recognized() {
        let old = gt("x", 10.0);
        let new = gt("x", 3.0);
        assert_eq!(guard_tightened(&old, &new), Some(false));
    }

    #[test]
    fn contradictory_atom_is_unsat() {
        // x > 5 ∧ x < 3 → unsat
        let f = Formula::And(
            Box::new(Formula::Atom(Atom::Gt("x".into(), 5.0))),
            Box::new(Formula::Atom(Atom::Lt("x".into(), 3.0))),
        );
        assert!(f.unsat());
    }

    #[test]
    fn implies_works() {
        // x > 10 蕴含 x > 5
        let a = Formula::Atom(Atom::Gt("x".into(), 10.0));
        let b = Formula::Atom(Atom::Gt("x".into(), 5.0));
        assert!(implies(&a, &b));
        // 反过来不成立
        assert!(!implies(&b, &a));
    }
}
