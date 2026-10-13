//! rules-verifier — 规则提交门禁的静态形式化校验。
//!
//! ## 为什么需要它（对比 Drools）
//!
//! Drools 这类产生式引擎的语言层面**没有时序维度**，因此无法回答：
//! - "跨时间维度的状态转移是否完备？"（是否存在永远走不到 / 进去出不来的状态）
//! - "时序事件是否可能产生因果死锁？"（`until` 的终止条件永假、`eventually`
//!   的承诺对象永假 —— 规则会一直挂起或永久违反）
//!
//! 本模块把这两类问题提升为**一等检查项**：
//!
//! | 类别 | 检查 | 级别 |
//! |---|---|---|
//! | 状态机完备性 | 不可达状态 / 无出边的非终态 / 终态有出边 / 未声明的迁移边 | warning / error |
//! | 因果死锁 | `until` 终止条件永假 / `eventually`·`within` 承诺对象永假 / 不变量恒假 | error |
//! | 既有检查 | 未声明实体 / 未声明状态 / 死规则 / 动作冲突 / 类型不匹配 / 未声明 metric | error |
//! | 覆盖缺口 | 流未被引用 / 未登记外部指标 / 冗余 spec | warning |
//!
//! v1 不链接 Z3，而是实现"常量折叠 + 结构可达性 + 时序形状分析"的保守检查器：
//! 能静态判定的直接报错；不能判定的标 Unknown 并放行。生产可整体替换为 z3 后端，
//! 接口（[`VerifyReport`] / [`VerifyIssue`]）保持不变。

use rules_ast::*;
use rules_dictionary::DataDictionary;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("undefined entity: spec '{spec}' targets undeclared entity '{entity}'")]
    UndefinedEntity { spec: String, entity: String },
    #[error("entity '{entity}' references undeclared state '{state}' (at line {file_line})")]
    UndefinedState { entity: String, state: String, file_line: u32 },
    #[error("dead rule: spec '{0}' antecedent is statically impossible (vacuous)")]
    VacuousAntecedent(String),
    #[error("dead rule: spec '{0}' consequent is statically true (tautology)")]
    TautologyConsequent(String),
    #[error("action conflict: spec '{a}' and '{b}' both transition entity '{entity}' out of state '{state}' to mutually exclusive targets ('{to_a}' vs '{to_b}')")]
    ActionConflict { a: String, b: String, entity: String, state: String, to_a: String, to_b: String },
    #[error("type mismatch: spec '{spec}' compares string literal with numeric expression in '{detail}'")]
    TypeMismatch { spec: String, detail: String },
    #[error("undefined reference: call to unknown function/metric '{0}'")]
    UndefinedMetric(String),
    #[error("coverage gap: stream '{0}' is declared but no spec or metric references it")]
    UnreferencedStream(String),
    #[error("coverage gap: entity '{entity}' state '{state}' has no incoming transition (dead state)")]
    DeadState { entity: String, state: String },
    #[error("undefined reference: external metric '{0}' is not registered in the runtime data dictionary")]
    UndefinedExternalMetric(String),
    #[error("redundant rule: spec '{a}' and spec '{b}' have identical invariant and violation")]
    RedundantSpec { a: String, b: String },

    // ---------- 时序模型检验：状态机完备性 ----------
    #[error("transition completeness: entity '{entity}' state '{state}' is unreachable from initial '{initial}'")]
    UnreachableState { entity: String, state: String, initial: String },
    #[error("transition completeness: entity '{entity}' state '{state}' is non-terminal but has no outgoing transition (stuck)")]
    StuckState { entity: String, state: String },
    #[error("transition completeness: entity '{entity}' terminal state '{state}' must not have outgoing transitions")]
    TerminalStateHasEdge { entity: String, state: String },
    #[error("transition completeness: transition '{transition}' of entity '{entity}' is driven by undeclared spec '{spec}'")]
    UndefinedTransitionDriver { entity: String, transition: String, spec: String },
    #[error("transition completeness: spec '{spec}' declares transition '{from} -> {to}' but entity '{entity}' has no such edge")]
    UndeclaredTransition { spec: String, entity: String, from: String, to: String },
    #[error("transition completeness: spec '{spec}' drives '{from} -> {to}' but entity '{entity}' binds that edge to spec '{bound}' (suggest adding `on: {spec}`)")]
    TransitionDriverMismatch { spec: String, entity: String, from: String, to: String, bound: String },

    // ---------- 时序模型检验：因果死锁 ----------
    #[error("causal deadlock: spec '{spec}' uses until(p, q) but q is statically impossible — the release condition can never fire")]
    DeadlockUntil { spec: String },
    #[error("causal deadlock: spec '{spec}' commits to eventually(p) but p is statically impossible — the obligation can never be discharged")]
    DeadlockEventually { spec: String },
    #[error("causal deadlock: spec '{spec}' invariant is statically unsatisfiable (always false)")]
    UnsatisfiableInvariant { spec: String },
    #[error("causal deadlock: spec '{spec}' implication consequent is statically impossible")]
    ImpossibleConsequent { spec: String },

    // ---------- v1.0：带反例参数的符号级证明（AC1 / FR2 / FR3） ----------
    #[error(
        "conflicting rules: spec '{a}' and spec '{b}' both apply to entity '{entity}' \
         but give contradictory verdicts (ALLOW vs DENY); counterexample: {witness}"
    )]
    ConflictingSpecs {
        a: String,
        b: String,
        entity: String,
        witness: String,
        params: Vec<(String, f64)>,
    },
    #[error(
        "decision table '{table}' rows #{row_a} and #{row_b} overlap under hit policy {policy} \
         (UNIQUE requires mutually exclusive rows); counterexample: {witness}"
    )]
    DmnOverlap {
        table: String,
        row_a: usize,
        row_b: usize,
        policy: String,
        witness: String,
        params: Vec<(String, f64)>,
    },
    #[error(
        "decision table '{table}' is incomplete: no rule matches input {witness} \
         and there is no `default` row — the table will miss at runtime"
    )]
    DmnGap { table: String, witness: String, params: Vec<(String, f64)> },
    #[error(
        "decision table '{table}' row #{row} yields {got} output value(s) but the table declares {want}"
    )]
    DmnArity { table: String, row: usize, got: usize, want: usize },
    #[error("var '{name}' declares an empty range [{lo} .. {hi}]")]
    VarRangeEmpty { name: String, lo: f64, hi: f64 },
    #[error(
        "var '{name}' declares range [{lo} .. {hi}] but spec '{spec}' guards on a value outside it \
         — inside the declared domain the rule can never fire (dead zone)"
    )]
    VarGuardOutOfRange { name: String, lo: f64, hi: f64, spec: String },
    #[error(
        "possible division by zero in spec '{spec}': denominator '{detail}' can be 0 when {witness}"
    )]
    DivisionByZero {
        spec: String,
        detail: String,
        witness: String,
        params: Vec<(String, f64)>,
    },
    #[error("cyclic stateful rules rejected at compile time: {detail}")]
    CyclicRules { detail: String, rules: Vec<String> },
    #[error(
        "undefined edge metric: spec '{spec}' uses crosses_above/crosses_below on undeclared metric '{metric}' \
         — the transition operator will silently never fire"
    )]
    UndefinedEdgeMetric { spec: String, metric: String },
}

impl VerificationError {
    /// 稳定机器可读标识，供 `/verify` 结构化报告消费。
    pub fn kind(&self) -> &'static str {
        match self {
            VerificationError::UndefinedEntity { .. } => "UNDEFINED_ENTITY",
            VerificationError::UndefinedState { .. } => "UNDEFINED_STATE",
            VerificationError::VacuousAntecedent(_) => "DEAD_RULE_VACUOUS",
            VerificationError::TautologyConsequent(_) => "DEAD_RULE_TAUTOLOGY",
            VerificationError::ActionConflict { .. } => "ACTION_CONFLICT",
            VerificationError::TypeMismatch { .. } => "TYPE_MISMATCH",
            VerificationError::UndefinedMetric(_) => "UNDEFINED_METRIC",
            VerificationError::UnreferencedStream(_) => "COVERAGE_GAP_STREAM",
            VerificationError::DeadState { .. } => "COVERAGE_GAP_DEAD_STATE",
            VerificationError::UndefinedExternalMetric(_) => "UNDEFINED_EXTERNAL_METRIC",
            VerificationError::RedundantSpec { .. } => "REDUNDANT_SPEC",
            VerificationError::UnreachableState { .. } => "UNREACHABLE_STATE",
            VerificationError::StuckState { .. } => "STUCK_STATE",
            VerificationError::TerminalStateHasEdge { .. } => "TERMINAL_STATE_HAS_EDGE",
            VerificationError::UndefinedTransitionDriver { .. } => "UNDEFINED_TRANSITION_DRIVER",
            VerificationError::UndeclaredTransition { .. } => "UNDECLARED_TRANSITION",
            VerificationError::TransitionDriverMismatch { .. } => "TRANSITION_DRIVER_MISMATCH",
            VerificationError::DeadlockUntil { .. } => "CAUSAL_DEADLOCK_UNTIL",
            VerificationError::DeadlockEventually { .. } => "CAUSAL_DEADLOCK_EVENTUALLY",
            VerificationError::UnsatisfiableInvariant { .. } => "UNSATISFIABLE_INVARIANT",
            VerificationError::ImpossibleConsequent { .. } => "IMPOSSIBLE_CONSEQUENT",
            // ---- v1.0 ----
            VerificationError::ConflictingSpecs { .. } => "CONFLICTING_SPECS",
            VerificationError::DmnOverlap { .. } => "DMN_ROW_OVERLAP",
            VerificationError::DmnGap { .. } => "DMN_COVERAGE_GAP",
            VerificationError::DmnArity { .. } => "DMN_ARITY_MISMATCH",
            VerificationError::VarRangeEmpty { .. } => "VAR_RANGE_EMPTY",
            VerificationError::VarGuardOutOfRange { .. } => "VAR_GUARD_OUT_OF_RANGE",
            VerificationError::DivisionByZero { .. } => "DIVISION_BY_ZERO",
            VerificationError::CyclicRules { .. } => "CYCLIC_RULES",
            VerificationError::UndefinedEdgeMetric { .. } => "UNDEFINED_EDGE_METRIC",
        }
    }

    /// 反例参数（`AC1`：冲突规则被拒并输出反例参数）。
    ///
    /// 只有符号级证明产生的条目带反例；其余返回空。
    pub fn counterexample(&self) -> Vec<(String, f64)> {
        match self {
            VerificationError::ConflictingSpecs { params, .. }
            | VerificationError::DmnOverlap { params, .. }
            | VerificationError::DmnGap { params, .. }
            | VerificationError::DivisionByZero { params, .. } => params.clone(),
            _ => Vec::new(),
        }
    }

    /// 是否只算提示（不阻断入库）。
    ///
    /// 覆盖缺口、未登记外部指标、冗余 spec、以及"模型可达性"类提示均不阻断提交。
    /// **因果死锁与未声明引用属于硬错误**——它们会让规则在运行期永久挂起或永久违反。
    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            VerificationError::UnreferencedStream(_)
                | VerificationError::DeadState { .. }
                | VerificationError::UndefinedExternalMetric(_)
                | VerificationError::RedundantSpec { .. }
                | VerificationError::UnreachableState { .. }
                | VerificationError::StuckState { .. }
                | VerificationError::TransitionDriverMismatch { .. }
                // `var range` 与守卫取值不重合：规则在声明域内永不触发。
                // 多数情况下是"守卫写宽了"，业务侧可能有意为之，故降级为提示。
                | VerificationError::VarGuardOutOfRange { .. }
        )
    }

    pub fn specs(&self) -> Vec<String> {
        match self {
            VerificationError::UndefinedEntity { spec, .. }
            | VerificationError::VacuousAntecedent(spec)
            | VerificationError::TautologyConsequent(spec)
            | VerificationError::ImpossibleConsequent { spec }
            | VerificationError::UnsatisfiableInvariant { spec }
            | VerificationError::DeadlockUntil { spec }
            | VerificationError::DeadlockEventually { spec }
            | VerificationError::UndeclaredTransition { spec, .. }
            | VerificationError::TransitionDriverMismatch { spec, .. } => vec![spec.clone()],
            VerificationError::TypeMismatch { spec, .. } => vec![spec.clone()],
            VerificationError::ActionConflict { a, b, .. }
            | VerificationError::RedundantSpec { a, b } => vec![a.clone(), b.clone()],
            VerificationError::ConflictingSpecs { a, b, .. } => vec![a.clone(), b.clone()],
            VerificationError::DmnOverlap { table, .. }
            | VerificationError::DmnGap { table, .. }
            | VerificationError::DmnArity { table, .. } => vec![table.clone()],
            VerificationError::DivisionByZero { spec, .. }
            | VerificationError::UndefinedEdgeMetric { spec, .. } => vec![spec.clone()],
            _ => vec![],
        }
    }
}

/// 结构化校验条目（`/verify` 与规则版本报告使用）。
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyIssue {
    pub kind: String,
    pub severity: &'static str, // "error" | "warning"
    pub message: String,
    pub specs: Vec<String>,
    /// 反例参数（`x = 21, y = 3` 形式），AC1 要求可直接展示。
    pub counterexample: Vec<(String, f64)>,
    /// 反例的一行渲染（便于直接进日志 / 前端）。
    pub counterexample_text: String,
}

impl VerifyIssue {
    fn from_error(e: &VerificationError) -> Self {
        let counterexample = e.counterexample();
        let counterexample_text = if counterexample.is_empty() {
            String::new()
        } else {
            counterexample
                .iter()
                .map(|(v, k)| {
                    if (k - k.round()).abs() < 1e-9 {
                        format!("{v} = {}", k.round() as i64)
                    } else {
                        format!("{v} = {k}")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        Self {
            kind: e.kind().to_string(),
            severity: if e.is_warning() { "warning" } else { "error" },
            message: e.to_string(),
            specs: e.specs(),
            counterexample,
            counterexample_text,
        }
    }
}

/// 分级校验报告。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VerifyReport {
    pub errors: Vec<VerifyIssue>,
    pub warnings: Vec<VerifyIssue>,
}

impl VerifyReport {
    /// 门禁判定：只有 `errors` 会阻断。
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

pub struct Verifier;

impl Verifier {
    /// 全量问题（含 warning），供 CLI 兼容旧行为。
    pub fn verify(spec: &SpecFile, dict: &DataDictionary) -> Result<(), Vec<VerificationError>> {
        let issues = Self::collect(spec, dict);
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    /// 分级报告：`errors` 阻断入库，`warnings` 仅提示。
    pub fn verify_report(spec: &SpecFile, dict: &DataDictionary) -> VerifyReport {
        let mut report = VerifyReport::default();
        for e in Self::collect(spec, dict) {
            let issue = VerifyIssue::from_error(&e);
            if e.is_warning() {
                report.warnings.push(issue);
            } else {
                report.errors.push(issue);
            }
        }
        report
    }

    fn collect(spec: &SpecFile, dict: &DataDictionary) -> Vec<VerificationError> {
        let mut out = Vec::new();
        Self::check_entities(spec, &mut out);
        Self::check_states(spec, &mut out);
        Self::check_metrics(spec, dict, &mut out);
        Self::check_types(spec, &mut out);
        Self::check_dead_rules(spec, &mut out);
        Self::check_action_conflicts(spec, &mut out);
        Self::check_redundant_specs(spec, &mut out);
        Self::check_coverage_gaps(spec, &mut out);
        // ---- 时序模型检验 ----
        Self::check_transition_completeness(spec, &mut out);
        Self::check_causal_deadlocks(spec, &mut out);
        // ---- v1.0：带反例参数的符号级证明 ----
        Self::check_conflicting_specs(spec, &mut out);
        Self::check_decision_tables(spec, &mut out);
        Self::check_var_ranges(spec, &mut out);
        Self::check_division_by_zero(spec, &mut out);
        Self::check_stateful_dag(spec, &mut out);
        Self::check_edge_metrics(spec, &mut out);
        out
    }

    // ---------- (0) 实体引用合法性 ----------
    fn check_entities(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        let declared: HashSet<&str> = spec.entities.iter().map(|e| e.name.as_str()).collect();
        for s in &spec.specs {
            if !declared.contains(s.entity_name.as_str()) {
                errors.push(VerificationError::UndefinedEntity {
                    spec: s.name.clone(),
                    entity: s.entity_name.clone(),
                });
            }
        }
    }

    // ---------- (1) 状态合法性 ----------
    fn check_states(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for e in &spec.entities {
            // §5 用例 1：`Seat` 是"纯作用域实体"——只声明 key + state var，
            // 没有 states 生命周期。此类实体跳过状态名合法性检查。
            if e.states.is_empty() && e.transitions.is_empty() {
                continue;
            }
            let valid: HashSet<&str> = e.states.iter().map(|s| s.as_str()).collect();
            // 省略 `initial:` 的位向量实体：初始状态即"全零掩码"，无需状态名。
            if !e.initial.is_empty() && !valid.contains(e.initial.as_str()) {
                errors.push(VerificationError::UndefinedState {
                    entity: e.name.clone(),
                    state: e.initial.clone(),
                    file_line: e.span.line,
                });
            }
            for t in &e.transitions {
                for st in [&t.from, &t.to] {
                    if !valid.contains(st.as_str()) {
                        errors.push(VerificationError::UndefinedState {
                            entity: e.name.clone(),
                            state: st.clone(),
                            file_line: t.span.line,
                        });
                    }
                }
            }
            for s in &spec.specs {
                if s.entity_name == e.name {
                    if let Some((from, to)) = &s.violation.transition {
                        for st in [from, to] {
                            if !valid.contains(st.as_str()) {
                                errors.push(VerificationError::UndefinedState {
                                    entity: e.name.clone(),
                                    state: st.clone(),
                                    file_line: s.span.line,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // ---------- (1b) metric / 函数引用合法性 ----------
    fn check_metrics(spec: &SpecFile, dict: &DataDictionary, errors: &mut Vec<VerificationError>) {
        let declared: HashSet<&str> = spec.metrics.iter().map(|m| m.name.as_str()).collect();
        let streams: HashSet<&str> = spec.streams.iter().map(|s| s.name.as_str()).collect();
        let mut seen = HashSet::new();
        let mut unknown = Vec::new();
        for name in collect_calls_in_spec(spec) {
            if is_builtin_call(&name) || declared.contains(name.as_str()) {
                continue;
            }
            // 流上的聚合调用 `<Stream>.<agg>()` 是合法的一阶流算子
            if let Some((stream, op)) = name.split_once('.') {
                if streams.contains(stream)
                    && matches!(op, "count" | "len" | "sum" | "avg" | "min" | "max")
                {
                    continue;
                }
            }
            if seen.insert(name.clone()) {
                unknown.push(name);
            }
        }
        for name in unknown {
            if dict.has_var(&name) {
                errors.push(VerificationError::UndefinedExternalMetric(name));
            } else {
                errors.push(VerificationError::UndefinedMetric(name));
            }
        }
    }

    // ---------- (1c) 类型不匹配 ----------
    fn check_types(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for s in &spec.specs {
            let mut found = Vec::new();
            for e in spec_exprs(s) {
                collect_type_mismatches(e, &mut found);
            }
            for mut detail in found {
                detail.truncate(80);
                errors.push(VerificationError::TypeMismatch { spec: s.name.clone(), detail });
            }
        }
    }

    // ---------- (2) 死规则 ----------
    fn check_dead_rules(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for s in &spec.specs {
            if let TemporalExpr::Implies(ant, cons) = &s.invariant {
                if is_unsat(ant) {
                    errors.push(VerificationError::VacuousAntecedent(s.name.clone()));
                }
                if is_taut(cons) {
                    errors.push(VerificationError::TautologyConsequent(s.name.clone()));
                }
            }
        }
    }

    // ---------- (3) 动作冲突 ----------
    fn check_action_conflicts(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        let mut by_entity: HashMap<&str, Vec<&SpecDecl>> = HashMap::new();
        for s in &spec.specs {
            by_entity.entry(s.entity_name.as_str()).or_default().push(s);
        }
        for (_entity, ss) in by_entity {
            for i in 0..ss.len() {
                for j in (i + 1)..ss.len() {
                    let (a, b) = (ss[i], ss[j]);
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

    // ---------- (3b) 冗余 spec ----------
    fn check_redundant_specs(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for i in 0..spec.specs.len() {
            for j in (i + 1)..spec.specs.len() {
                let (a, b) = (&spec.specs[i], &spec.specs[j]);
                if a.entity_name != b.entity_name {
                    continue;
                }
                let same = a.invariant == b.invariant
                    && a.violation.guard == b.violation.guard
                    && a.violation.transition == b.violation.transition
                    && a.violation.severity == b.violation.severity
                    && a.violation.message == b.violation.message;
                if same {
                    errors.push(VerificationError::RedundantSpec {
                        a: a.name.clone(),
                        b: b.name.clone(),
                    });
                }
            }
        }
    }

    // ---------- (4) 覆盖缺口 ----------
    fn check_coverage_gaps(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        let declared: HashSet<&str> = spec.streams.iter().map(|s| s.name.as_str()).collect();
        let mut referenced: HashSet<&str> = HashSet::new();
        for s in &spec.specs {
            collect_stream_refs(&s.invariant, &mut referenced);
        }
        for m in &spec.metrics {
            if let Some(s) = m.source_stream() {
                referenced.insert(s);
            }
        }
        // 流互相引用也算被使用
        for s in &spec.streams {
            if let StreamSource::Ref(r) = &s.source {
                referenced.insert(r.as_str());
            }
        }
        // 流上的聚合调用 `<Stream>.<agg>()` 也算对该流的引用
        for name in collect_calls_in_spec(spec) {
            if let Some((stream, _)) = name.split_once('.') {
                if let Some(hit) = spec.streams.iter().find(|s| s.name == stream) {
                    referenced.insert(hit.name.as_str());
                }
            }
        }
        for s in declared.difference(&referenced) {
            errors.push(VerificationError::UnreferencedStream(s.to_string()));
        }

        // 死状态（无入边且非 initial、非终态）
        for e in &spec.entities {
            // FR5：位向量实体的"状态"是单调格的位，不是 FSM 的互斥状态名：
            // 每一位都可以由 `state |= bit` 直接点亮，不存在"死状态"概念。
            if e.is_bitvec() {
                continue;
            }
            let mut incoming: HashSet<&str> = HashSet::new();
            incoming.insert(e.initial.as_str());
            for t in &e.transitions {
                incoming.insert(t.to.as_str());
            }
            for s in &spec.specs {
                if s.entity_name == e.name {
                    if let Some((_, to)) = &s.violation.transition {
                        incoming.insert(to.as_str());
                    }
                }
            }
            for st in &e.states {
                if !incoming.contains(st.as_str()) && !e.is_terminal(st.as_str()) {
                    errors.push(VerificationError::DeadState {
                        entity: e.name.clone(),
                        state: st.name.clone(),
                    });
                }
            }
        }
    }

    // =================================================================
    // 时序模型检验 1：跨时间维度的状态转移完备性
    // =================================================================
    fn check_transition_completeness(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        let spec_names: HashSet<&str> = spec.specs.iter().map(|s| s.name.as_str()).collect();

        for e in &spec.entities {
            // a) 迁移边引用的驱动 spec 必须存在，且目标实体一致
            for t in &e.transitions {
                if let Some(driver) = &t.on {
                    match spec.specs.iter().find(|s| s.name == *driver) {
                        None => errors.push(VerificationError::UndefinedTransitionDriver {
                            entity: e.name.clone(),
                            transition: t.name.clone(),
                            spec: driver.clone(),
                        }),
                        Some(d) if d.entity_name != e.name => {
                            errors.push(VerificationError::UndefinedTransitionDriver {
                                entity: e.name.clone(),
                                transition: t.name.clone(),
                                spec: driver.clone(),
                            })
                        }
                        _ => {}
                    }
                }
            }

            // b) 从 initial 出发的可达性
            // FR5：位向量实体的状态集合是"位"，单调格上任意位都可被点亮，
            // 因此不做 FSM 式可达性/停滞检查（否则会产生大量伪告警）。
            if e.is_bitvec() {
                continue;
            }
            let mut reachable: HashSet<&str> = HashSet::new();
            let mut frontier: Vec<&str> = vec![e.initial.as_str()];
            reachable.insert(e.initial.as_str());
            while let Some(cur) = frontier.pop() {
                for t in e.transitions.iter().filter(|t| t.from == cur) {
                    if reachable.insert(t.to.as_str()) {
                        frontier.push(t.to.as_str());
                    }
                }
            }
            for st in &e.states {
                if !reachable.contains(st.as_str()) {
                    errors.push(VerificationError::UnreachableState {
                        entity: e.name.clone(),
                        state: st.name.clone(),
                        initial: e.initial.clone(),
                    });
                }
            }

            // c) 非终态必须有出边；终态不得有出边
            for st in &e.states {
                let has_edge = e.transitions.iter().any(|t| t.from == st.name);
                if e.is_terminal(st.as_str()) {
                    if has_edge {
                        errors.push(VerificationError::TerminalStateHasEdge {
                            entity: e.name.clone(),
                            state: st.name.clone(),
                        });
                    }
                } else if !has_edge {
                    errors.push(VerificationError::StuckState {
                        entity: e.name.clone(),
                        state: st.name.clone(),
                    });
                }
            }

            // d) spec 声明的迁移必须与实体状态机一致
            let declares_edges = !e.transitions.is_empty();
            for s in spec.specs.iter().filter(|s| s.entity_name == e.name) {
                if let Some((from, to)) = &s.violation.transition {
                    let edge = e.transitions.iter().find(|t| t.from == *from && t.to == *to);
                    match edge {
                        None => {
                            // 实体完全没有声明迁移边 = 旧写法，降级为提示
                            if declares_edges {
                                errors.push(VerificationError::UndeclaredTransition {
                                    spec: s.name.clone(),
                                    entity: e.name.clone(),
                                    from: from.clone(),
                                    to: to.clone(),
                                });
                            }
                        }
                        Some(t) => {
                            if let Some(driver) = &t.on {
                                if *driver != s.name && spec_names.contains(driver.as_str()) {
                                    errors.push(VerificationError::TransitionDriverMismatch {
                                        spec: s.name.clone(),
                                        entity: e.name.clone(),
                                        from: from.clone(),
                                        to: to.clone(),
                                        bound: driver.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // =================================================================
    // 时序模型检验 2：因果死锁
    // =================================================================
    fn check_causal_deadlocks(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for s in &spec.specs {
            // 整体不变量恒假：规则一上线就永久违反
            if is_unsat(&s.invariant) {
                errors.push(VerificationError::UnsatisfiableInvariant { spec: s.name.clone() });
                continue;
            }
            let mut found = DeadlockScan::default();
            scan_deadlocks(&s.invariant, &mut found);
            if found.until_stuck {
                errors.push(VerificationError::DeadlockUntil { spec: s.name.clone() });
            }
            if found.eventually_stuck {
                errors.push(VerificationError::DeadlockEventually { spec: s.name.clone() });
            }
            if found.impossible_consequent {
                errors.push(VerificationError::ImpossibleConsequent { spec: s.name.clone() });
            }
        }
    }

    // =================================================================
    // v1.0 符号级证明（每条结论都带反例参数）
    // =================================================================

    /// **冲突规则**（AC1）。
    ///
    /// 两条策略作用于同一实体、事件集合可能同时到达，而裁决互斥
    /// （一条 `ALLOW`、一条 `DENY`）——运行期到底听谁的是不确定的。
    /// 判定方式：`trap_a ∧ trap_b` 的可满足性；SAT 时把模型作为反例参数输出。
    ///
    /// 注意：两条规则**都** `DENY`（只是错误码不同）不算冲突——那是分层防御
    /// （PEP 快筛 + 全量不变量），运行期由 `Adjudication` 携带各自的 code。
    fn check_conflicting_specs(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        let traps: Vec<(&SpecDecl, smt::Formula)> = spec
            .specs
            .iter()
            .filter_map(|s| violation_trap(s).map(|f| (s, f)))
            .collect();

        for i in 0..traps.len() {
            for j in (i + 1)..traps.len() {
                let (a, fa) = &traps[i];
                let (b, fb) = &traps[j];
                if a.entity_name != b.entity_name {
                    continue;
                }
                // 事件集合必须可能同时到达（空集 = 任意事件）
                if !a.events.is_empty()
                    && !b.events.is_empty()
                    && !a.events.iter().any(|x| b.events.contains(x))
                {
                    continue;
                }
                if a.verdict.is_deny() == b.verdict.is_deny() {
                    continue; // 同向裁决不冲突
                }
                if let smt::Solution::Sat(m) = smt::conflict(fa, fb) {
                    errors.push(VerificationError::ConflictingSpecs {
                        a: a.name.clone(),
                        b: b.name.clone(),
                        entity: a.entity_name.clone(),
                        witness: m.render(),
                        params: m.to_pairs(),
                    });
                }
            }
        }
    }

    /// **DMN 决策表**（FR3 / §4.4.2）。
    ///
    /// * 输出列数一致性；
    /// * `UNIQUE` 命中策略要求任意两行条件互斥 —— `row_i ∧ row_j` 必须 UNSAT；
    /// * 完备性：`¬(∨ rows)` 必须 UNSAT（或由 `default` 行兜底）。
    fn check_decision_tables(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for dt in &spec.decision_tables {
            for (ri, row) in dt.rows.iter().enumerate() {
                if !row.is_default && row.outputs.len() != dt.outputs.len() {
                    errors.push(VerificationError::DmnArity {
                        table: dt.name.clone(),
                        row: ri + 1,
                        got: row.outputs.len(),
                        want: dt.outputs.len(),
                    });
                }
            }

            let rows: Vec<(usize, smt::Formula)> = dt
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| !r.is_default)
                .map(|(i, r)| (i, dmn_row_formula(dt, r)))
                .collect();

            if dt.hit_policy == HitPolicy::Unique {
                for i in 0..rows.len() {
                    for j in (i + 1)..rows.len() {
                        let (ia, fa) = &rows[i];
                        let (ib, fb) = &rows[j];
                        if let smt::Solution::Sat(m) = smt::conflict(fa, fb) {
                            errors.push(VerificationError::DmnOverlap {
                                table: dt.name.clone(),
                                row_a: ia + 1,
                                row_b: ib + 1,
                                policy: "UNIQUE".to_string(),
                                witness: m.render(),
                                params: m.to_pairs(),
                            });
                        }
                    }
                }
            }

            let union: Vec<smt::Formula> = rows.iter().map(|(_, f)| f.clone()).collect();
            let has_default = dt.default_row().is_some();
            if let smt::Solution::Sat(m) = smt::total_coverage(&union, has_default) {
                errors.push(VerificationError::DmnGap {
                    table: dt.name.clone(),
                    witness: m.render(),
                    params: m.to_pairs(),
                });
            }
        }
    }

    /// **`var` 声明域一致性**（FR1/FR2）。
    ///
    /// `range: lo..hi` 是声明的定义域（送入 SMT 作为 DomainAxiom）。
    /// 空区间是硬错误；守卫取值落在域外则说明规则在域内永不触发（死区）。
    fn check_var_ranges(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        for v in all_var_decls(spec) {
            let (lo_e, hi_e) = match &v.range {
                Some(r) => r,
                None => continue,
            };
            let (lo, hi) = match (bound_num(lo_e), bound_num(hi_e)) {
                (Some(l), Some(h)) => (l, h),
                _ => continue,
            };
            if lo > hi {
                errors.push(VerificationError::VarRangeEmpty { name: v.name.clone(), lo, hi });
                continue;
            }
            let domain = smt::Formula::and(
                smt::Formula::Atom(smt::Atom::Gte(v.name.clone(), lo)),
                smt::Formula::Atom(smt::Atom::Lte(v.name.clone(), hi)),
            );
            for s in &spec.specs {
                let trap = match violation_trap(s) {
                    Some(t) => t,
                    None => continue,
                };
                for atom in trap.atoms() {
                    if atom.var() != Some(v.name.as_str()) {
                        continue;
                    }
                    let f = smt::Formula::Atom(atom.clone());
                    if smt::check(&smt::Formula::and(domain.clone(), f)).is_unsat() {
                        errors.push(VerificationError::VarGuardOutOfRange {
                            name: v.name.clone(),
                            lo,
                            hi,
                            spec: s.name.clone(),
                        });
                        break;
                    }
                }
            }
        }
    }

    /// **除零证明**（FR2）：分母在声明域内是否可能取 0。
    fn check_division_by_zero(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        let domain: Vec<(String, Option<(f64, f64)>)> = all_var_decls(spec)
            .into_iter()
            .map(|v| {
                let r = v
                    .range
                    .as_ref()
                    .and_then(|(l, h)| Some((bound_num(l)?, bound_num(h)?)));
                (v.name.clone(), r)
            })
            .collect();

        for s in &spec.specs {
            let mut dens: Vec<&Expr> = Vec::new();
            for e in spec_exprs(s) {
                collect_denominators(e, &mut dens);
            }
            for d in dens {
                if let Some(m) = smt::div_zero(d, &domain) {
                    errors.push(VerificationError::DivisionByZero {
                        spec: s.name.clone(),
                        detail: format!("{d:?}"),
                        witness: m.render(),
                        params: m.to_pairs(),
                    });
                    break; // 每个 spec 只报一次
                }
            }
        }
    }

    /// **模式 B 的编译期 DAG 无环检验**（FR7 / AC5）。
    fn check_stateful_dag(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        if spec.stateful_rules.is_empty() {
            return;
        }
        if let Err(c) = rules_ast::check_rule_dag(&spec.stateful_rules) {
            errors.push(VerificationError::CyclicRules {
                detail: c.message_en(),
                rules: c.rules,
            });
        }
    }

    /// **边缘跃迁算子引用的 metric 必须已声明**（FR6）。
    ///
    /// 未声明时运行期 `AtomHost::metric_value` 返回 `None`，算子恒定不触发——
    /// 这是最危险的一类静默失效，必须编译期拦下。
    fn check_edge_metrics(spec: &SpecFile, errors: &mut Vec<VerificationError>) {
        let declared: HashSet<&str> = spec.metrics.iter().map(|m| m.name.as_str()).collect();
        for s in &spec.specs {
            let mut found: Vec<String> = Vec::new();
            collect_edge_metrics(&s.invariant, &mut found);
            for m in found {
                if !declared.contains(m.as_str()) {
                    errors.push(VerificationError::UndefinedEdgeMetric {
                        spec: s.name.clone(),
                        metric: m,
                    });
                }
            }
        }
    }
}

// =====================================================================
// v1.0 证明辅助
// =====================================================================

use rules_smt as smt;

/// 从策略的不变量中取出"触发裁决的条件"（trap）。
///
/// 解析器的两套语义：
/// * 事件作用域：`Not(cond)` —— 本次事件构成违规的条件就是 `cond`；
/// * 连续不变量：`Always(Not(cond))`。
///
/// 其余形态（纯 MTL：`historically(…)`、`until(…)`）没有瞬时片段，返回 `None`
/// ——**判不出就不报**，避免假阳性。
fn violation_trap(s: &SpecDecl) -> Option<smt::Formula> {
    let inner: &TemporalExpr = match &s.invariant {
        TemporalExpr::Always(i) => i.as_ref(),
        other => other,
    };
    match inner {
        TemporalExpr::Not(p) => temporal_to_formula(p),
        _ => None,
    }
}

/// 把时序公式的"瞬时片段"提升为 SMT 公式；含时序算子时返回 `None`。
fn temporal_to_formula(t: &TemporalExpr) -> Option<smt::Formula> {
    Some(match t {
        TemporalExpr::Predicate(e) => smt::expr_to_formula(e),
        TemporalExpr::Not(i) => smt::Formula::not(temporal_to_formula(i)?),
        TemporalExpr::And(a, b) => {
            smt::Formula::and(temporal_to_formula(a)?, temporal_to_formula(b)?)
        }
        TemporalExpr::Or(a, b) => smt::Formula::or(temporal_to_formula(a)?, temporal_to_formula(b)?),
        TemporalExpr::Implies(a, b) => smt::Formula::or(
            smt::Formula::not(temporal_to_formula(a)?),
            temporal_to_formula(b)?,
        ),
        _ => return None,
    })
}

/// 决策表一行的输入子句提升为合取公式。
fn dmn_row_formula(dt: &DecisionTableDecl, row: &DecisionRow) -> smt::Formula {
    let mut acc: Option<smt::Formula> = None;
    for (i, entry) in row.inputs.iter().enumerate() {
        let var = dt
            .params
            .get(i)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| format!("in{i}"));
        let f = match entry {
            InputEntry::Any => smt::Formula::True,
            InputEntry::Range { lo, hi } => match (bound_num(lo), bound_num(hi)) {
                (Some(l), Some(h)) => smt::Formula::and(
                    smt::Formula::Atom(smt::Atom::Gte(var.clone(), l)),
                    smt::Formula::Atom(smt::Atom::Lte(var, h)),
                ),
                _ => smt::Formula::True,
            },
            InputEntry::Expr(e) => smt::expr_to_formula(e),
        };
        acc = Some(match acc {
            None => f,
            Some(a) => smt::Formula::and(a, f),
        });
    }
    acc.unwrap_or(smt::Formula::True)
}

/// 全量 `var` 声明：顶层 + 契约内（契约里的 `var` 会被 hoist 到实体上）。
fn all_var_decls(spec: &SpecFile) -> Vec<&VarDecl> {
    let mut out: Vec<&VarDecl> = spec.var_decls.iter().collect();
    for e in &spec.entities {
        out.extend(e.var_decls.iter());
    }
    out
}

/// 把绑定表达式折成数值：日期字面量 `"11-01"` 折成 `1101`（与运行期 MMDD 口径一致）。
fn bound_num(e: &Expr) -> Option<f64> {
    match e {
        Expr::Number(n) => Some(*n),
        Expr::Hex(h) => Some(*h as f64),
        Expr::DurationLit(d) => Some(d.as_secs() as f64),
        Expr::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Expr::Str(s) => {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() == 2 && parts[0].len() == 2 && parts[1].len() == 2 {
                let m: f64 = parts[0].parse().ok()?;
                let d: f64 = parts[1].parse().ok()?;
                if (1.0..=12.0).contains(&m) && (1.0..=31.0).contains(&d) {
                    return Some(m * 100.0 + d);
                }
            }
            None
        }
        _ => None,
    }
}

fn collect_denominators<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    if let Expr::Binary { op: BinaryOp::Div, right, .. } = e {
        out.push(right.as_ref());
    }
    match e {
        Expr::Binary { left, right, .. } => {
            collect_denominators(left, out);
            collect_denominators(right, out);
        }
        Expr::UnaryNot(i) => collect_denominators(i, out),
        Expr::Call { args, .. } | Expr::TableLookup { args, .. } => {
            for a in args {
                collect_denominators(a, out);
            }
        }
        _ => {}
    }
}

fn collect_edge_metrics(t: &TemporalExpr, out: &mut Vec<String>) {
    match t {
        TemporalExpr::CrossesAbove { metric, .. } | TemporalExpr::CrossesBelow { metric, .. } => {
            if !out.contains(metric) {
                out.push(metric.clone());
            }
        }
        TemporalExpr::Not(i) | TemporalExpr::Always(i) => collect_edge_metrics(i, out),
        TemporalExpr::Historically { expr, .. } | TemporalExpr::Eventually { expr, .. } => {
            collect_edge_metrics(expr, out)
        }
        TemporalExpr::Within { inner, .. } => collect_edge_metrics(inner, out),
        TemporalExpr::Until { p, q } | TemporalExpr::Since { p, q } => {
            collect_edge_metrics(p, out);
            collect_edge_metrics(q, out);
        }
        TemporalExpr::Implies(a, b) | TemporalExpr::And(a, b) | TemporalExpr::Or(a, b) => {
            collect_edge_metrics(a, out);
            collect_edge_metrics(b, out);
        }
        TemporalExpr::StreamQuant { .. } | TemporalExpr::Predicate(_) => {}
    }
}

#[derive(Default)]
struct DeadlockScan {
    until_stuck: bool,
    eventually_stuck: bool,
    impossible_consequent: bool,
}

fn scan_deadlocks(t: &TemporalExpr, out: &mut DeadlockScan) {
    match t {
        // FR6：边缘跃迁算子没有因果死锁语义（阈值比较恒可判定）
        TemporalExpr::CrossesAbove { .. } | TemporalExpr::CrossesBelow { .. } => {}
        TemporalExpr::Until { p, q } => {
            if is_unsat(q) {
                out.until_stuck = true;
            }
            scan_deadlocks(p, out);
            scan_deadlocks(q, out);
        }
        TemporalExpr::Eventually { expr, .. } => {
            if is_unsat(expr) {
                out.eventually_stuck = true;
            }
            scan_deadlocks(expr, out);
        }
        TemporalExpr::Within { inner, .. } => {
            if is_unsat(inner) {
                out.eventually_stuck = true;
            }
            scan_deadlocks(inner, out);
        }
        TemporalExpr::Implies(a, b) => {
            if is_taut(a) && is_unsat(b) {
                out.impossible_consequent = true;
            }
            scan_deadlocks(a, out);
            scan_deadlocks(b, out);
        }
        TemporalExpr::And(a, b) | TemporalExpr::Or(a, b) => {
            scan_deadlocks(a, out);
            scan_deadlocks(b, out);
        }
        TemporalExpr::Not(i)
        | TemporalExpr::Always(i)
        | TemporalExpr::Historically { expr: i, .. } => scan_deadlocks(i, out),
        TemporalExpr::Since { p, q } => {
            scan_deadlocks(p, out);
            scan_deadlocks(q, out);
        }
        TemporalExpr::Predicate(_) | TemporalExpr::StreamQuant { .. } => {}
    }
}

// =====================================================================
// 静态真假（保守）
// =====================================================================

enum StaticBool {
    True,
    False,
    Unknown,
}

/// 公式是否**恒假**。
pub fn is_unsat(t: &TemporalExpr) -> bool {
    matches!(eval_static(t), StaticBool::False)
}

/// 公式是否**恒真**。
pub fn is_taut(t: &TemporalExpr) -> bool {
    matches!(eval_static(t), StaticBool::True)
}

fn eval_static(t: &TemporalExpr) -> StaticBool {
    match t {
        TemporalExpr::Predicate(e) => eval_expr_static(e),
        TemporalExpr::Not(i) => match eval_static(i) {
            StaticBool::True => StaticBool::False,
            StaticBool::False => StaticBool::True,
            StaticBool::Unknown => StaticBool::Unknown,
        },
        TemporalExpr::And(a, b) => match (eval_static(a), eval_static(b)) {
            (StaticBool::False, _) | (_, StaticBool::False) => StaticBool::False,
            (StaticBool::True, StaticBool::True) => StaticBool::True,
            _ => StaticBool::Unknown,
        },
        TemporalExpr::Or(a, b) => match (eval_static(a), eval_static(b)) {
            (StaticBool::True, _) | (_, StaticBool::True) => StaticBool::True,
            (StaticBool::False, StaticBool::False) => StaticBool::False,
            _ => StaticBool::Unknown,
        },
        // always(p) 恒假当且仅当 p 恒假
        TemporalExpr::Always(i) => eval_static(i),
        TemporalExpr::Implies(a, b) => match (eval_static(a), eval_static(b)) {
            (StaticBool::False, _) | (_, StaticBool::True) => StaticBool::True,
            (StaticBool::True, StaticBool::False) => StaticBool::False,
            _ => StaticBool::Unknown,
        },
        _ => StaticBool::Unknown,
    }
}

fn eval_expr_static(e: &Expr) -> StaticBool {
    match e {
        Expr::Bool(true) => StaticBool::True,
        Expr::Bool(false) => StaticBool::False,
        Expr::Number(n) => {
            if *n > 0.0 {
                StaticBool::True
            } else {
                StaticBool::False
            }
        }
        Expr::UnaryNot(i) => match eval_expr_static(i) {
            StaticBool::True => StaticBool::False,
            StaticBool::False => StaticBool::True,
            StaticBool::Unknown => StaticBool::Unknown,
        },
        Expr::Binary { op, left, right } => {
            let (l, r) = (eval_expr_static(left), eval_expr_static(right));
            let lv = matches!(l, StaticBool::True);
            let rv = matches!(r, StaticBool::True);
            match op {
                BinaryOp::And => {
                    if !lv || !rv {
                        StaticBool::False
                    } else {
                        StaticBool::True
                    }
                }
                BinaryOp::Or => {
                    if lv || rv {
                        StaticBool::True
                    } else {
                        StaticBool::False
                    }
                }
                _ => {
                    if let (Expr::Number(a), Expr::Number(b)) = (&**left, &**right) {
                        let cmp = match op {
                            BinaryOp::Gt => a > b,
                            BinaryOp::Gte => a >= b,
                            BinaryOp::Lt => a < b,
                            BinaryOp::Lte => a <= b,
                            BinaryOp::Eq => (a - b).abs() < f64::EPSILON,
                            BinaryOp::Neq => (a - b).abs() >= f64::EPSILON,
                            _ => return StaticBool::Unknown,
                        };
                        if cmp {
                            StaticBool::True
                        } else {
                            StaticBool::False
                        }
                    } else {
                        StaticBool::Unknown
                    }
                }
            }
        }
        _ => StaticBool::Unknown,
    }
}

// =====================================================================
// 引用收集 / 类型检查辅助
// =====================================================================

/// DSL 内置函数白名单。
pub fn is_builtin_call(name: &str) -> bool {
    matches!(
        name,
        "now" | "today"
            | "days_between"
            | "len" | "count" | "sum" | "avg"
            | "max" | "min" | "abs" | "ratio"
            | "DaysOverdue" | "DaysSince"
            | "exists" | "forall"
    )
}

fn spec_exprs(s: &SpecDecl) -> Vec<&Expr> {
    let mut out: Vec<&Expr> = s.given.iter().map(|(_, e)| e).collect();
    if let Some(g) = &s.violation.guard {
        out.push(g);
    }
    collect_exprs_in_temporal(&s.invariant, &mut out);
    out
}

fn collect_exprs_in_temporal<'a>(t: &'a TemporalExpr, out: &mut Vec<&'a Expr>) {
    match t {
        TemporalExpr::Predicate(e) => out.push(e),
        TemporalExpr::Not(i) | TemporalExpr::Always(i) => collect_exprs_in_temporal(i, out),
        TemporalExpr::Historically { expr, .. } | TemporalExpr::Eventually { expr, .. } => {
            collect_exprs_in_temporal(expr, out)
        }
        TemporalExpr::Within { inner, .. } => collect_exprs_in_temporal(inner, out),
        TemporalExpr::CrossesAbove { threshold, .. }
        | TemporalExpr::CrossesBelow { threshold, .. } => out.push(threshold),
        TemporalExpr::Until { p, q } | TemporalExpr::Since { p, q } => {
            collect_exprs_in_temporal(p, out);
            collect_exprs_in_temporal(q, out);
        }
        TemporalExpr::Implies(a, b) | TemporalExpr::And(a, b) | TemporalExpr::Or(a, b) => {
            collect_exprs_in_temporal(a, out);
            collect_exprs_in_temporal(b, out);
        }
        TemporalExpr::StreamQuant { lambda, .. } => {
            if let Some(l) = lambda {
                out.push(&l.body);
            }
        }
    }
}

fn collect_stream_refs<'a>(t: &'a TemporalExpr, out: &mut HashSet<&'a str>) {
    match t {
        TemporalExpr::StreamQuant { stream, .. } => {
            out.insert(stream.as_str());
        }
        TemporalExpr::Predicate(_) => {}
        TemporalExpr::CrossesAbove { .. } | TemporalExpr::CrossesBelow { .. } => {}
        TemporalExpr::Not(i) | TemporalExpr::Always(i) => collect_stream_refs(i, out),
        TemporalExpr::Historically { expr, .. } | TemporalExpr::Eventually { expr, .. } => {
            collect_stream_refs(expr, out)
        }
        TemporalExpr::Within { inner, .. } => collect_stream_refs(inner, out),
        TemporalExpr::Until { p, q } | TemporalExpr::Since { p, q } => {
            collect_stream_refs(p, out);
            collect_stream_refs(q, out);
        }
        TemporalExpr::Implies(a, b) | TemporalExpr::And(a, b) | TemporalExpr::Or(a, b) => {
            collect_stream_refs(a, out);
            collect_stream_refs(b, out);
        }
    }
}

fn collect_calls_in_spec(spec: &SpecFile) -> Vec<String> {
    let mut names = Vec::new();
    // 流算子 lambda
    for s in &spec.streams {
        for l in s.lambdas() {
            collect_calls_in_expr(&l.body, &mut names);
        }
        for op in &s.ops {
            match op {
                StreamOp::Fold { init, body, .. } => {
                    collect_calls_in_expr(init, &mut names);
                    collect_calls_in_expr(body, &mut names);
                }
                StreamOp::Join { on, .. } | StreamOp::CoGroup { on, .. } => {
                    collect_calls_in_expr(on, &mut names)
                }
                StreamOp::Window(w) => collect_calls_in_expr(&w.size, &mut names),
                _ => {}
            }
        }
    }
    // metric
    for m in &spec.metrics {
        match &m.body {
            MetricBody::Scalar { expr, guard } => {
                collect_calls_in_expr(expr, &mut names);
                if let Some(g) = guard {
                    collect_calls_in_expr(g, &mut names);
                }
            }
            MetricBody::StreamFold { init, body, .. } => {
                collect_calls_in_expr(init, &mut names);
                collect_calls_in_expr(body, &mut names);
            }
            MetricBody::StreamAgg { .. } => {}
        }
    }
    // spec
    for s in &spec.specs {
        for e in spec_exprs(s) {
            collect_calls_in_expr(e, &mut names);
        }
    }
    names
}

fn collect_calls_in_expr(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Call { func, args } => {
            out.push(func.clone());
            for a in args {
                collect_calls_in_expr(a, out);
            }
        }
        Expr::Binary { left, right, .. } => {
            collect_calls_in_expr(left, out);
            collect_calls_in_expr(right, out);
        }
        Expr::UnaryNot(inner) => collect_calls_in_expr(inner, out),
        _ => {}
    }
}

fn collect_type_mismatches(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Binary { op, left, right } => {
            if op.is_comparison() {
                let l_str = matches!(&**left, Expr::Str(_));
                let r_str = matches!(&**right, Expr::Str(_));
                let l_num = matches!(&**left, Expr::Number(_) | Expr::DurationLit(_));
                let r_num = matches!(&**right, Expr::Number(_) | Expr::DurationLit(_));
                if (l_str && r_num) || (r_str && l_num) {
                    out.push(format!("{:?} {:?} {:?}", left, op, right));
                }
            }
            collect_type_mismatches(left, out);
            collect_type_mismatches(right, out);
        }
        Expr::UnaryNot(inner) => collect_type_mismatches(inner, out),
        Expr::Call { args, .. } => {
            for a in args {
                collect_type_mismatches(a, out);
            }
        }
        _ => {}
    }
}
