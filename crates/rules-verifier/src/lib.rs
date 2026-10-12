//! rules-verifier — 规则提交门禁的静态形式化校验。
//!
//! 三类核心检查（设计文档 §4）：
//! 1. **死规则**：vacuous antecedent（前提永假）/ tautology consequent（结论永真）；
//! 2. **动作冲突**：同实体同状态下，两条 contract 的 transition 互斥；
//! 3. **覆盖缺口**：声明的 stream 无人引用、实体死状态。
//!
//! v1 不直接链接 Z3（避免重型 C 依赖），而是实现一个"常量折叠 + 符号求值"的
//! 保守检查器：能静态判定的问题直接报错；不能判定的（依赖事件/var）标 Unknown。
//! 生产环境可将本模块替换为 z3 后端，接口保持不变。

use rules_ast::*;
use rules_dictionary::DataDictionary;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("entity '{entity}' references undeclared state '{state}' (at {file_line})")]
    UndefinedState {
        entity: String,
        state: String,
        file_line: u32,
    },
    #[error("dead rule: contract '{0}' antecedent is statically impossible (vacuous)")]
    VacuousAntecedent(String),
    #[error("dead rule: contract '{0}' consequent is statically true (tautology)")]
    TautologyConsequent(String),
    #[error("action conflict: contract '{a}' and '{b}' both transition entity '{entity}' out of state '{state}' to mutually exclusive targets ('{to_a}' vs '{to_b}')")]
    ActionConflict {
        a: String,
        b: String,
        entity: String,
        state: String,
        to_a: String,
        to_b: String,
    },
    #[error("coverage gap: stream '{0}' is declared but no contract references it")]
    UnreferencedStream(String),
    #[error("coverage gap: entity '{entity}' state '{state}' has no incoming transition (dead state)")]
    DeadState { entity: String, state: String },
    #[error("undefined reference: var '{0}' is not registered in the runtime data dictionary")]
    UndefinedVar(String),
}

pub struct Verifier;

impl Verifier {
    /// 对 spec 跑全套校验。`dict` 用于检查 var 是否已登记。
    pub fn verify(spec: &SpecFile, dict: &DataDictionary) -> Result<(), Vec<VerificationError>> {
        let mut errors = Vec::new();

        Self::check_states(spec, &mut errors);
        Self::check_dead_rules(spec, &mut errors);
        Self::check_action_conflicts(spec, &mut errors);
        Self::check_coverage_gaps(spec, &mut errors);
        Self::check_var_bindings(spec, dict, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    // ---------- (1) 状态合法性 ----------
    fn check_states(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for e in &spec.entities {
            let valid: HashSet<&str> = e.states.iter().map(|s| s.as_str()).collect();
            if !valid.contains(e.initial.as_str()) {
                errors.push(VerificationError::UndefinedState {
                    entity: e.name.clone(),
                    state: e.initial.clone(),
                    file_line: e.span.line,
                });
            }
            for c in &spec.contracts {
                if c.entity_name == e.name {
                    if let Some((from, to)) = &c.violation.transition {
                        if !valid.contains(from.as_str()) {
                            errors.push(VerificationError::UndefinedState {
                                entity: e.name.clone(),
                                state: from.clone(),
                                file_line: c.span.line,
                            });
                        }
                        if !valid.contains(to.as_str()) {
                            errors.push(VerificationError::UndefinedState {
                                entity: e.name.clone(),
                                state: to.clone(),
                                file_line: c.span.line,
                            });
                        }
                    }
                }
            }
        }
    }

    // ---------- (2) 死规则：vacuous / tautology ----------
    fn check_dead_rules(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for c in &spec.contracts {
            if let TemporalExpr::Implies(ant, cons) = &c.invariant {
                if eval_static(ant) == StaticBool::AlwaysFalse {
                    errors.push(VerificationError::VacuousAntecedent(c.name.clone()));
                }
                if eval_static(cons) == StaticBool::AlwaysTrue {
                    errors.push(VerificationError::TautologyConsequent(c.name.clone()));
                }
            }
        }
    }

    // ---------- (3) 动作冲突 ----------
    fn check_action_conflicts(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        // 按实体分组
        let mut by_entity: HashMap<&str, Vec<&ContractDecl>> = HashMap::new();
        for c in &spec.contracts {
            by_entity.entry(c.entity_name.as_str()).or_default().push(c);
        }

        for (_entity, cs) in by_entity {
            for i in 0..cs.len() {
                for j in (i + 1)..cs.len() {
                    let (a, b) = (cs[i], cs[j]);
                    if let (Some((fa, ta)), Some((fb, tb))) =
                        (&a.violation.transition, &b.violation.transition)
                    {
                        if fa == fb && ta != tb {
                            errors.push(VerificationError::ActionConflict {
                                a: a.name.clone(),
                                b: b.name.clone(),
                                entity: a.entity_name.clone(),
                                state: fa.clone(),
                                to_a: ta.clone(),
                                to_b: tb.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    // ---------- (4) 覆盖缺口 ----------
    fn check_coverage_gaps(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        // 4a. stream 未被任何 contract 引用
        let declared: HashSet<&str> = spec.streams.iter().map(|s| s.name.as_str()).collect();
        let mut referenced: HashSet<&str> = HashSet::new();
        for c in &spec.contracts {
            collect_stream_refs(&c.invariant, &mut referenced);
        }
        for s in declared.difference(&referenced) {
            errors.push(VerificationError::UnreferencedStream(s.to_string()));
        }

        // 4b. 死状态：非 initial 状态没有任何入边
        for e in &spec.entities {
            let mut incoming: HashSet<&str> = HashSet::new();
            incoming.insert(e.initial.as_str());
            for c in &spec.contracts {
                if c.entity_name == e.name {
                    if let Some((_, to)) = &c.violation.transition {
                        incoming.insert(to.as_str());
                    }
                }
            }
            for st in &e.states {
                // 终结态命名（TERMINATED / CLOSED / DONE / END）合法，无需入边。
                let upper = st.to_uppercase();
                let is_terminal = upper.contains("TERMINATED")
                    || upper.contains("CLOSED")
                    || upper == "DONE"
                    || upper == "END";
                if !incoming.contains(st.as_str()) && !is_terminal {
                    errors.push(VerificationError::DeadState {
                        entity: e.name.clone(),
                        state: st.clone(),
                    });
                }
            }
        }
    }

    // ---------- (5) var 必须在字典中登记 ----------
    fn check_var_bindings(
        spec: &SpecFile,
        dict: &DataDictionary,
        errors: &mut Vec<VerificationError>,
    ) {
        for v in &spec.vars {
            if !dict.has_var(&v.name) {
                errors.push(VerificationError::UndefinedVar(v.name.clone()));
            }
        }
    }
}

// =====================================================================
// 静态布尔求值（保守）
// =====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticBool {
    AlwaysTrue,
    AlwaysFalse,
    Unknown,
}

fn eval_static(t: &TemporalExpr) -> StaticBool {
    match t {
        TemporalExpr::Predicate(e) => eval_expr_static(e),
        TemporalExpr::Not(inner) => match eval_static(inner) {
            StaticBool::AlwaysTrue => StaticBool::AlwaysFalse,
            StaticBool::AlwaysFalse => StaticBool::AlwaysTrue,
            StaticBool::Unknown => StaticBool::Unknown,
        },
        TemporalExpr::And(a, b) => match (eval_static(a), eval_static(b)) {
            (StaticBool::AlwaysFalse, _) | (_, StaticBool::AlwaysFalse) => StaticBool::AlwaysFalse,
            (StaticBool::AlwaysTrue, StaticBool::AlwaysTrue) => StaticBool::AlwaysTrue,
            _ => StaticBool::Unknown,
        },
        TemporalExpr::Or(a, b) => match (eval_static(a), eval_static(b)) {
            (StaticBool::AlwaysTrue, _) | (_, StaticBool::AlwaysTrue) => StaticBool::AlwaysTrue,
            (StaticBool::AlwaysFalse, StaticBool::AlwaysFalse) => StaticBool::AlwaysFalse,
            _ => StaticBool::Unknown,
        },
        _ => StaticBool::Unknown,
    }
}

fn eval_expr_static(e: &Expr) -> StaticBool {
    match e {
        Expr::Binary { op, left, right } => {
            if let (Expr::Number(l), Expr::Number(r)) = (&**left, &**right) {
                let cmp = match op {
                    BinaryOp::Gt => l > r,
                    BinaryOp::Gte => l >= r,
                    BinaryOp::Lt => l < r,
                    BinaryOp::Lte => l <= r,
                    BinaryOp::Eq => (l - r).abs() < f64::EPSILON,
                    BinaryOp::Neq => (l - r).abs() >= f64::EPSILON,
                    _ => return StaticBool::Unknown,
                };
                if cmp {
                    StaticBool::AlwaysTrue
                } else {
                    StaticBool::AlwaysFalse
                }
            } else {
                StaticBool::Unknown
            }
        }
        _ => StaticBool::Unknown,
    }
}

fn collect_stream_refs<'a>(t: &'a TemporalExpr, out: &mut HashSet<&'a str>) {
    match t {
        TemporalExpr::Predicate(Expr::Call { func, args }) if func == "exists" => {
            if let Some(Expr::Ident(name)) = args.first() {
                out.insert(name.as_str());
            }
        }
        TemporalExpr::Predicate(_) => {}
        TemporalExpr::Historically { expr, .. } => collect_stream_refs(expr, out),
        TemporalExpr::Always(inner) | TemporalExpr::Eventually(inner)
        | TemporalExpr::WithinOp { inner, .. } | TemporalExpr::Not(inner) => {
            collect_stream_refs(inner, out)
        }
        TemporalExpr::Until { p, q } => {
            collect_stream_refs(p, out);
            collect_stream_refs(q, out);
        }
        TemporalExpr::Implies(a, b) | TemporalExpr::And(a, b) | TemporalExpr::Or(a, b) => {
            collect_stream_refs(a, out);
            collect_stream_refs(b, out);
        }
    }
}
