//! rules-parser —— 把四类一阶概念（Entity / Stream / Metric / Spec）× 四种执行模式的
//! 源码构建为 AST（v1.0 四模同构）。
//!
//! 解析器同时接受 **v1.0 语法**（契约块 + guard/invariant 块 + decision_table + stateful rule）
//! 与 **历史语法**（自动 desugar），以便既有规则文件平滑迁移：
//!
//! | 旧写法 | 等价新写法 |
//! |---|---|
//! | `contract X on E { ... }` | `spec X on E { ... }` |
//! | `signal f(x:T) -> T = expr` | `metric f(x: T) -> T := expr` |
//! | `var n = expr` | `metric n := expr` |
//! | `Stream[T]` | `Event[T]` |
//! | `stream X = ...` | `stream X := ...` |
//! | `rule X on E when P then {...}` | `spec X on E { invariant: always(not(P)) violation {...} }` |
//! | `exists(S)` | `S.exists()` |
//!
//! v1.0 的契约块（`contract N on Entity[E] pure { ... }`）是一个**语法容器**：
//! 解析后其成员被**提升（hoist）**到 [`SpecFile`] 的扁平四类概念向量上，
//! 因此下游（runtime / verifier / temporal / dmn）无需感知容器语法。

use rules_ast::*;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::time::Duration;
use thiserror::Error;

#[derive(Parser)]
#[grammar = "syntax.pest"]
pub struct DSLParser;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("syntax error: {0}")]
    Pest(#[from] Box<pest::error::Error<Rule>>),
    #[error("invalid number: {0}")]
    InvalidNumber(std::num::ParseFloatError),
    #[error("semantic error: {0}")]
    Semantic(String),
}

/// 解析一份规格文件（v1.0 四模同构）。
pub fn parse(input: &str) -> Result<SpecFile, ParseError> {
    let mut pairs = DSLParser::parse(Rule::spec_file, input).map_err(Box::new)?;
    let root = pairs.next().unwrap();

    let mut file = SpecFile::default();
    // `violation on <Spec>` 独立挂载：先收集，最后统一挂到对应 spec 上。
    let mut attaches: Vec<(String, ViolationHandler)> = Vec::new();

    for pair in root.into_inner() {
        match pair.as_rule() {
            Rule::contract_decl => parse_contract(pair, &mut file),
            Rule::entity_decl => file.entities.push(parse_entity(pair)),
            Rule::stream_decl => file.streams.push(parse_stream(pair)),
            Rule::metric_decl => file.metrics.push(parse_metric(pair)),
            Rule::decision_table_decl => file.decision_tables.push(parse_decision_table(pair)),
            Rule::stateful_rule => file.stateful_rules.push(parse_stateful_rule(pair)),
            Rule::legacy_signal => file.metrics.push(parse_legacy_signal(pair)),
            Rule::var_decl => match parse_var_decl(pair) {
                VarOutcome::Var(v) => file.var_decls.push(v),
                VarOutcome::Metric(m) => file.metrics.push(m),
            },
            Rule::legacy_rule => file.specs.push(parse_legacy_rule(pair)),
            Rule::violation_attach => {
                let (name, handler) = parse_violation_attach(pair);
                attaches.push((name, handler));
            }
            Rule::EOI => {}
            // event_decl / import_decl / type_decl：暂不入 AST
            _ => {}
        }
    }

    // 应用独立挂载的 violation
    for (spec_name, handler) in attaches {
        if let Some(s) = file.specs.iter_mut().find(|s| s.name == spec_name) {
            s.violation = handler;
        }
    }

    Ok(file)
}

fn span_of(p: &Pair<Rule>) -> Span {
    let s = p.as_span();
    let (line, col) = s.start_pos().line_col();
    Span { line: line as u32, col: col as u32 }
}

// =====================================================================
// 契约块（v1.0 语法容器）：contract N on <Target> <mode>? { ... }
// =====================================================================

/// 解析契约块并把成员提升到 [`SpecFile`]。
///
/// - 若出现 v1.0 实体成员（key / states / transition / state var / bind …），
///   则创建或合并 [`EntityDecl`]；
/// - `stream` / `metric` / `decision_table` 成员提升到对应顶层向量；
/// - `guard` / `invariant` 块提升为 [`SpecDecl`]（`kind` 分别 Guard / Invariant）；
/// - 经典 `given + invariant: + violation {}` 形态退化为一个经典 [`SpecDecl`]。
fn parse_contract(pair: Pair<Rule>, file: &mut SpecFile) {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let target = inner.next().unwrap(); // spec_target
    let (entity_var, entity_name) = parse_spec_target(target);

    let mut mode = Mode::Pure;
    let mut body: Option<Pair<Rule>> = None;
    for p in inner {
        match p.as_rule() {
            Rule::mode_modifier => {
                mode = Mode::parse(p.as_str()).unwrap_or(Mode::Pure);
            }
            Rule::contract_body => body = Some(p),
            _ => {}
        }
    }

    let body = match body {
        Some(b) => b,
        None => return,
    };

    // ---- 收集成员 ----
    let mut key = String::new();
    let mut has_entity_member = false;
    let mut states: Vec<StateConst> = Vec::new();
    let mut initial = String::new();
    let mut terminal: Vec<String> = Vec::new();
    let mut transitions: Vec<TransitionDecl> = Vec::new();
    let mut state_vars: Vec<StateVarDecl> = Vec::new();
    let mut binds: Vec<BindDecl> = Vec::new();
    let mut local_vars: Vec<VarDecl> = Vec::new();
    let mut given: Vec<(String, Expr)> = Vec::new();
    let mut invariants: Vec<TemporalExpr> = Vec::new();
    let mut violation: Option<ViolationHandler> = None;
    let mut policies: Vec<SpecDecl> = Vec::new();
    let mut has_classic_invariant = false;

    for p in body.into_inner() {
        match p.as_rule() {
            Rule::key_decl => {
                key = p.into_inner().next().unwrap().as_str().to_string();
                has_entity_member = true;
            }
            Rule::bind_decl => {
                binds.push(parse_bind(p));
                has_entity_member = true;
            }
            Rule::states_decl => {
                states = parse_states(p);
                has_entity_member = true;
            }
            Rule::initial_decl => {
                initial = p.into_inner().next().unwrap().as_str().to_string();
                has_entity_member = true;
            }
            Rule::terminal_decl => {
                terminal = p.into_inner().map(|x| x.as_str().to_string()).collect();
                has_entity_member = true;
            }
            Rule::state_var_decl => {
                state_vars.push(parse_state_var(p));
                has_entity_member = true;
            }
            Rule::transition_block => {
                transitions.push(parse_transition(p));
                has_entity_member = true;
            }
            Rule::stream_decl => file.streams.push(parse_stream(p)),
            Rule::metric_decl => file.metrics.push(parse_metric(p)),
            Rule::decision_table_decl => file.decision_tables.push(parse_decision_table(p)),
            Rule::policy_block => {
                let mut s = parse_policy_block(p, &entity_name, &entity_var);
                s.mode = mode;
                policies.push(s);
            }
            Rule::var_decl => match parse_var_decl(p) {
                VarOutcome::Var(v) => local_vars.push(v),
                VarOutcome::Metric(m) => file.metrics.push(m),
            },
            Rule::let_decl => given.extend(parse_let(p)),
            Rule::given_block => {
                for lp in p.into_inner() {
                    if lp.as_rule() == Rule::let_decl {
                        given.extend(parse_let(lp));
                    }
                }
            }
            Rule::invariant_clause => {
                invariants.push(parse_temporal(p.into_inner().next().unwrap()));
                has_classic_invariant = true;
            }
            Rule::violation_block => violation = Some(parse_violation_fields(p, sp)),
            _ => {}
        }
    }

    // ---- 经典形态：given + invariant: + violation {} ----
    if has_classic_invariant {
        let invariant = {
            let mut it = invariants.into_iter();
            let first = it.next().expect("invariant");
            it.fold(first, |acc, next| TemporalExpr::And(Box::new(acc), Box::new(next)))
        };
        let vh = violation.unwrap_or_default();
        file.specs.push(SpecDecl {
            name: name.clone(),
            entity_name: entity_name.clone(),
            entity_var: entity_var.clone(),
            mode,
            kind: PolicyKind::Invariant,
            events: Vec::new(),
            given,
            invariant,
            verdict: verdict_from_violation(&vh),
            effects: effects_from_violation(&vh),
            violation: vh,
            meta: NodeMeta::default(),
            span: sp,
        });
    }

    // ---- v1.0 实体成员：创建/合并 EntityDecl ----
    if has_entity_member {
        let decl = EntityDecl {
            name: entity_name.clone(),
            key,
            mode,
            states,
            initial,
            terminal,
            transitions,
            state_vars,
            binds,
            var_decls: local_vars,
            meta: NodeMeta::default(),
            span: sp,
        };
        merge_entity(file, decl);
    }

    file.specs.extend(policies);
    if mode != Mode::Pure && file.mode == Mode::Pure {
        file.mode = mode;
    }
}

/// 同名实体的合并（多个契约块可以分别贡献状态、迁移边、状态变量）。
fn merge_entity(file: &mut SpecFile, incoming: EntityDecl) {
    if let Some(existing) = file.entities.iter_mut().find(|e| e.name == incoming.name) {
        if existing.key.is_empty() {
            existing.key = incoming.key;
        }
        if existing.states.is_empty() {
            existing.states = incoming.states;
        }
        if existing.initial.is_empty() {
            existing.initial = incoming.initial;
        }
        for t in incoming.terminal {
            if !existing.terminal.contains(&t) {
                existing.terminal.push(t);
            }
        }
        for t in incoming.transitions {
            if !existing.transitions.iter().any(|x| x.name == t.name) {
                existing.transitions.push(t);
            }
        }
        for v in incoming.state_vars {
            if !existing.state_vars.iter().any(|x| x.name == v.name) {
                existing.state_vars.push(v);
            }
        }
        for b in incoming.binds {
            if !existing.binds.contains(&b) {
                existing.binds.push(b);
            }
        }
        existing.var_decls.extend(incoming.var_decls);
        if existing.mode == Mode::Pure {
            existing.mode = incoming.mode;
        }
    } else {
        file.entities.push(incoming);
    }
}

fn parse_spec_target(target: Pair<Rule>) -> (String, String) {
    let mut it = target.into_inner();
    let first = it.next().unwrap();
    if first.as_rule() == Rule::entity_target {
        let name = first.into_inner().next().unwrap().as_str().to_string();
        return (name.to_lowercase(), name);
    }
    let head = first.as_str().to_string();
    match it.next() {
        // `on c: Company`
        Some(e) => (head, e.as_str().to_string()),
        // `on Company`
        None => (head.to_lowercase(), head),
    }
}

// =====================================================================
// 概念 1a：Entity
// =====================================================================

fn parse_entity(pair: Pair<Rule>) -> EntityDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();

    let mut key = String::new();
    let mut mode = Mode::Pure;
    let mut states: Vec<StateConst> = Vec::new();
    let mut initial = String::new();
    let mut terminal: Vec<String> = Vec::new();
    let mut transitions: Vec<TransitionDecl> = Vec::new();
    let mut state_vars: Vec<StateVarDecl> = Vec::new();

    for p in inner {
        match p.as_rule() {
            Rule::entity_key_opt => key = parse_key(p.into_inner().next().unwrap()),
            Rule::key_decl => key = parse_key(p),
            Rule::mode_modifier => mode = Mode::parse(p.as_str()).unwrap_or(Mode::Pure),
            Rule::states_decl => states = parse_states(p),
            Rule::initial_decl => {
                initial = p.into_inner().next().unwrap().as_str().to_string()
            }
            Rule::terminal_decl => {
                terminal = p.into_inner().map(|x| x.as_str().to_string()).collect()
            }
            Rule::transition_block => transitions.push(parse_transition(p)),
            Rule::state_var_decl => state_vars.push(parse_state_var(p)),
            _ => {}
        }
    }

    EntityDecl {
        name,
        key,
        mode,
        states,
        initial,
        terminal,
        transitions,
        state_vars,
        binds: Vec::new(),
        var_decls: Vec::new(),
        meta: NodeMeta::default(),
        span: sp,
    }
}

fn parse_key(p: Pair<Rule>) -> String {
    p.into_inner().next().unwrap().as_str().to_string()
}

fn parse_states(p: Pair<Rule>) -> Vec<StateConst> {
    p.into_inner()
        .map(|sc| {
            let mut it = sc.into_inner();
            let name = it.next().unwrap().as_str().to_string();
            let mask = it.next().map(|m| parse_uint(m.as_str()));
            StateConst { name, mask }
        })
        .collect()
}

fn parse_uint(s: &str) -> u64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn parse_bind(p: Pair<Rule>) -> BindDecl {
    let sp = span_of(&p);
    let mut it = p.into_inner();
    let datasource = unescape_string(it.next().unwrap().into_inner().next().unwrap().as_str());
    let table = unescape_string(it.next().unwrap().into_inner().next().unwrap().as_str());
    BindDecl { datasource, table, meta: NodeMeta::default(), span: sp }
}

fn parse_state_var(p: Pair<Rule>) -> StateVarDecl {
    let sp = span_of(&p);
    let mut it = p.into_inner();
    let name = it.next().unwrap().as_str().to_string();
    let ty = parse_type(it.next().unwrap().as_str());
    let init = parse_expr(it.next().unwrap());
    StateVarDecl { name, ty, init, meta: NodeMeta::default(), span: sp }
}

fn parse_transition(pair: Pair<Rule>) -> TransitionDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    // `transition` ident? `{` ... `}` —— 名字可选
    let mut name = String::new();
    let mut from = String::new();
    let mut to = String::new();
    let mut on = None;
    let mut emit = None;

    for p in inner.by_ref() {
        if p.as_rule() == Rule::ident {
            name = p.as_str().to_string();
            break;
        }
    }
    for p in inner {
        match p.as_rule() {
            Rule::tf_from => from = p.into_inner().next().unwrap().as_str().to_string(),
            Rule::tf_to => to = p.into_inner().next().unwrap().as_str().to_string(),
            Rule::tf_on => on = Some(p.into_inner().next().unwrap().as_str().to_string()),
            Rule::tf_emit => emit = Some(unescape_string(p.into_inner().next().unwrap().as_str())),
            Rule::tf_when => { /* 条件边：预留，暂不入 AST */ }
            _ => {}
        }
    }
    if name.is_empty() {
        name = format!("{from}__{to}");
    }
    TransitionDecl {
        name,
        from,
        to,
        on,
        emit,
        bitwise: false,
        meta: NodeMeta::default(),
        span: sp,
    }
}

// =====================================================================
// 概念 2：Stream & Event
// =====================================================================

fn parse_stream(pair: Pair<Rule>) -> StreamDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let (source, ops) = parse_stream_expr(inner.next().unwrap());
    StreamDecl {
        name,
        source,
        ops,
        mode: Mode::Stream,
        meta: NodeMeta::default(),
        span: sp,
    }
}

fn parse_stream_expr(se: Pair<Rule>) -> (StreamSource, Vec<StreamOp>) {
    let mut inner = se.into_inner();
    // stream_expr 的 inner[0] 是 stream_source（非 silent），需再下钻一层。
    let src_wrap = inner.next().unwrap();
    let src_pair = match src_wrap.as_rule() {
        Rule::stream_source => src_wrap.into_inner().next().unwrap(),
        _ => src_wrap,
    };
    let source = match src_pair.as_rule() {
        Rule::stream_event_types => {
            let names: Vec<String> = src_pair
                .into_inner()
                .map(|p| p.as_str().to_string())
                .collect();
            if names.len() == 1 {
                StreamSource::Event(names.into_iter().next().unwrap())
            } else {
                StreamSource::Events(names)
            }
        }
        Rule::stream_ref => StreamSource::Ref(src_pair.into_inner().next().unwrap().as_str().to_string()),
        _ => StreamSource::Ref(src_pair.as_str().to_string()),
    };
    let ops = inner.map(parse_stream_op).collect();
    (source, ops)
}

fn parse_stream_op(op: Pair<Rule>) -> StreamOp {
    let mut inner = op.clone().into_inner();
    match op.as_rule() {
        Rule::filter_op => StreamOp::Filter(parse_lambda_or_formula(inner.next().unwrap())),
        Rule::map_op => StreamOp::Map(parse_lambda_or_formula(inner.next().unwrap())),
        Rule::window_op => StreamOp::Window(parse_window_spec(inner.next().unwrap())),
        Rule::fold_op => {
            let init = parse_expr(inner.next().unwrap());
            let (acc, item, body) = parse_lambda2(inner.next().unwrap());
            StreamOp::Fold { init, acc, item, body }
        }
        Rule::agg_op => {
            let kind_pair = inner.next().unwrap(); // agg_kind
            let kind = AggKind::parse(kind_pair.as_str()).unwrap_or(AggKind::Count);
            let lambda = inner.next().map(parse_lambda);
            StreamOp::Aggregate { kind, lambda }
        }
        Rule::join_op | Rule::cogroup_op => {
            let other = inner.next().unwrap().as_str().to_string();
            let (left, right, on) = parse_lambda2(inner.next().unwrap());
            if op.as_rule() == Rule::join_op {
                StreamOp::Join { other, left, right, on }
            } else {
                StreamOp::CoGroup { other, left, right, on }
            }
        }
        Rule::distinct_op => StreamOp::Distinct(inner.next().map(parse_lambda)),
        Rule::union_op => StreamOp::Union(inner.next().unwrap().as_str().to_string()),
        other => panic!("unexpected stream op: {:?}", other),
    }
}

/// `.window(60d)` 或 `.window(sliding(5s))`。
fn parse_window_spec(pair: Pair<Rule>) -> WindowSpec {
    let mut it = pair.into_inner();
    let first = it.next().unwrap();
    match first.as_rule() {
        Rule::window_mode => {
            let kind = if first.as_str() == "tumbling" {
                WindowKind::Tumbling
            } else {
                WindowKind::Sliding
            };
            WindowSpec { kind, size: parse_expr(it.next().unwrap()) }
        }
        _ => WindowSpec::sliding(parse_expr(first)),
    }
}

/// `.filter(e => P)` 或旧写法 `.filter(P)`（隐式绑定 `event`）。
fn parse_lambda_or_formula(pair: Pair<Rule>) -> Lambda {
    debug_assert_eq!(pair.as_rule(), Rule::lambda_or_formula);
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::lambda => parse_lambda(inner),
        Rule::formula => {
            let body = match parse_temporal(inner) {
                TemporalExpr::Predicate(e) => e,
                _ => Expr::always_true(),
            };
            Lambda::implicit(body)
        }
        _ => unreachable!(),
    }
}

fn parse_lambda(pair: Pair<Rule>) -> Lambda {
    let mut inner = pair.into_inner();
    let params = inner
        .next()
        .unwrap()
        .into_inner()
        .map(|x| x.as_str().to_string())
        .collect();
    let body = parse_expr(inner.next().unwrap());
    Lambda { params, body }
}

fn parse_lambda2(pair: Pair<Rule>) -> (String, String, Expr) {
    let mut inner = pair.into_inner();
    let a = inner.next().unwrap().as_str().to_string();
    let b = inner.next().unwrap().as_str().to_string();
    let body = parse_expr(inner.next().unwrap());
    (a, b, body)
}

// =====================================================================
// 概念 1b：Metric
// =====================================================================

fn parse_metric(pair: Pair<Rule>) -> MetricDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();

    let mut params: Vec<Param> = Vec::new();
    let mut ret = DataType::Float;
    let mut body: Option<MetricBody> = None;

    for p in inner {
        match p.as_rule() {
            Rule::metric_params => params = p.into_inner().map(parse_param).collect(),
            Rule::type_expr => ret = parse_type(p.as_str()),
            Rule::metric_body => body = Some(parse_metric_body(p)),
            _ => {}
        }
    }

    MetricDecl {
        name,
        params,
        ret,
        body: body.expect("metric body"),
        meta: NodeMeta::default(),
        span: sp,
    }
}

fn parse_param(pair: Pair<Rule>) -> Param {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let ty = parse_type(inner.next().unwrap().as_str());
    Param { name, ty }
}

fn parse_metric_body(pair: Pair<Rule>) -> MetricBody {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::metric_scalar => {
            let mut it = inner.into_inner();
            let expr = parse_expr(it.next().unwrap());
            let guard = it.next().map(parse_expr);
            MetricBody::Scalar { expr, guard }
        }
        Rule::derived_from => {
            let (source, ops) = parse_stream_expr(inner.into_inner().next().unwrap());
            let stream = match source {
                StreamSource::Ref(r) => r,
                StreamSource::Event(t) => t,
                StreamSource::Events(v) => v.into_iter().next().unwrap_or_default(),
                StreamSource::None => String::new(),
            };
            for op in ops {
                match op {
                    StreamOp::Fold { init, acc, item, body } => {
                        return MetricBody::StreamFold { stream, init, acc, item, body }
                    }
                    StreamOp::Aggregate { kind, .. } => {
                        return MetricBody::StreamAgg { stream, kind }
                    }
                    _ => {}
                }
            }
            MetricBody::StreamAgg { stream, kind: AggKind::Count }
        }
        _ => unreachable!(),
    }
}

/// 旧写法 `signal f(x: T) -> T = expr` → 带形参的标量 metric。
fn parse_legacy_signal(pair: Pair<Rule>) -> MetricDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let param = parse_param(inner.next().unwrap());
    let ret = parse_type(inner.next().unwrap().as_str());
    let expr = parse_expr(inner.next().unwrap());
    MetricDecl {
        name,
        params: vec![param],
        ret,
        body: MetricBody::Scalar { expr, guard: None },
        meta: NodeMeta::default(),
        span: sp,
    }
}

/// `var` 声明结果：带类型/range 的进 [`VarDecl`]，否则退化零元 metric（兼容旧 `var n = e`）。
enum VarOutcome {
    Var(VarDecl),
    Metric(MetricDecl),
}

fn parse_var_decl(pair: Pair<Rule>) -> VarOutcome {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut ty: Option<DataType> = None;
    let mut range: Option<(Expr, Expr)> = None;
    let mut init: Option<Expr> = None;
    for p in inner {
        match p.as_rule() {
            Rule::type_expr => ty = Some(parse_type(p.as_str())),
            Rule::range_clause => {
                let mut ri = p.into_inner();
                let lo = parse_expr(ri.next().unwrap());
                let hi = parse_expr(ri.next().unwrap());
                range = Some((lo, hi));
            }
            Rule::expr => init = Some(parse_expr(p)),
            _ => {}
        }
    }
    if ty.is_some() || range.is_some() {
        VarOutcome::Var(VarDecl {
            name,
            ty: ty.unwrap_or(DataType::Float),
            range,
            init,
            meta: NodeMeta::default(),
            span: sp,
        })
    } else {
        VarOutcome::Metric(MetricDecl {
            name,
            params: Vec::new(),
            ret: DataType::Bool,
            body: MetricBody::Scalar {
                expr: init.unwrap_or(Expr::Bool(false)),
                guard: None,
            },
            meta: NodeMeta::default(),
            span: sp,
        })
    }
}

fn parse_type(s: &str) -> DataType {
    DataType::parse(s).unwrap_or(DataType::Float)
}

// =====================================================================
// 概念 3/4：策略块（guard / invariant，v1.0 用例语法）
// =====================================================================

/// ```text
/// guard IsNotFrozen on Event[OrderIntent, CancelIntent] {
///     when:    now() < frozen_until
///     verdict: DENY(code: "...", reason: "..."), LeaseUpdate(frozen_until = now() + 60s)
/// }
/// ```
fn parse_policy_block(
    pair: Pair<Rule>,
    entity_name: &str,
    entity_var: &str,
) -> SpecDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let kw = inner.next().unwrap().as_str().to_string();
    let kind = if kw == "guard" { PolicyKind::Guard } else { PolicyKind::Invariant };
    let name = inner.next().unwrap().as_str().to_string();
    let mut events: Vec<String> = Vec::new();
    let mut cond: Option<TemporalExpr> = None;
    let mut temporal: Option<TemporalExpr> = None;
    let mut verdict = Verdict::Allow;
    let mut effects: Vec<Effect> = Vec::new();
    let mut severity: Option<Severity> = None;
    let mut message = String::new();
    let mut transition: Option<(String, String)> = None;
    let mut given: Vec<(String, Expr)> = Vec::new();

    for p in inner {
        match p.as_rule() {
            Rule::event_list => {
                events = p.into_inner().map(|e| e.as_str().to_string()).collect();
            }
            Rule::when_field | Rule::guard_field => {
                cond = Some(parse_temporal(p.into_inner().next().unwrap()));
            }
            Rule::temporal_field => {
                temporal = Some(parse_temporal(p.into_inner().next().unwrap()));
            }
            Rule::verdict_field | Rule::on_violation_field => {
                let (v, effs) = parse_verdict_effects(p.into_inner().next().unwrap());
                verdict = v;
                effects.extend(effs);
            }
            Rule::severity_field => {
                severity = Severity::parse(p.into_inner().next().unwrap().as_str());
            }
            Rule::emit_field => message = unescape_string(p.into_inner().next().unwrap().as_str()),
            Rule::transition_field => transition = Some(parse_transition_field(p)),
            Rule::let_decl => given.extend(parse_let(p)),
            _ => {}
        }
    }

    // 违规条件 = when/guard ∧ temporal；语义：两者同时成立即触发裁决。
    let combined = match (cond, temporal) {
        (None, None) => TemporalExpr::Predicate(Expr::Bool(false)),
        (Some(c), None) => c,
        (None, Some(t)) => t,
        (Some(c), Some(t)) => TemporalExpr::And(Box::new(c), Box::new(t)),
    };
    // 两种时序语义，取决于该策略是否**事件作用域**：
    //
    // * `invariant P on Event[E] { when: … }` —— 事件作用域的准入策略。
    //   它在"类型为 E 的事件到达"的那一拍求值一次，判据是本次事件是否构成违规，
    //   **不做跨时间的 latch**。因此编译为 `Not(combined)`：
    //   本次事件不构成违规 ⇔ `Not(combined)` 成立。
    // * `guard P { when: … }`（无事件列表）—— 连续不变量，编译为
    //   `Always(Not(combined))`，一旦打破保持违反（MTL 的 always 语义）。
    //
    // 若统一用 `Always(Not(…))`，则 AC3 里"批文过期 → 拒绝"一旦触发，实体之后
    // 即便进入 ISSUING 阶段（`!(state & ISSUING)` 令判据为假）也会被永久 latch
    // 拦住——那正是把准入策略误当成了安全性质。
    let event_scoped = !events.is_empty();
    let invariant = if event_scoped {
        TemporalExpr::Not(Box::new(combined))
    } else {
        TemporalExpr::Always(Box::new(TemporalExpr::Not(Box::new(combined))))
    };

    let severity = severity.unwrap_or(if verdict.is_deny() {
        Severity::Critical
    } else {
        Severity::Info
    });
    if message.is_empty() {
        if let Some(r) = verdict.reason() {
            message = r.to_string();
        }
    }
    if let Some((f, t)) = &transition {
        effects.push(Effect::Transition { from: f.clone(), to: t.clone() });
    }

    SpecDecl {
        name,
        entity_name: entity_name.to_string(),
        entity_var: entity_var.to_string(),
        mode: Mode::Pure,
        kind,
        events,
        given,
        invariant,
        violation: ViolationHandler {
            severity,
            guard: None,
            transition,
            message,
            meta: NodeMeta::default(),
            span: sp,
        },
        verdict,
        effects,
        meta: NodeMeta::default(),
        span: sp,
    }
}

fn parse_transition_field(p: Pair<Rule>) -> (String, String) {
    let mut ti = p.into_inner();
    let from_raw = ti.next().unwrap().as_str();
    let from = from_raw.rsplit('.').next().unwrap_or(from_raw).to_string();
    let to = ti.next().unwrap().as_str().to_string();
    (from, to)
}

fn parse_verdict_effects(pair: Pair<Rule>) -> (Verdict, Vec<Effect>) {
    let mut it = pair.into_inner();
    let verdict = parse_verdict_expr(it.next().unwrap());
    let mut effects = Vec::new();
    for p in it {
        let e = p.into_inner().next().unwrap();
        match e.as_rule() {
            Rule::lease_update => {
                let mut li = e.into_inner();
                let target = li.next().unwrap().as_str().to_string();
                let expr = parse_expr(li.next().unwrap());
                effects.push(Effect::LeaseUpdate { target, expr });
            }
            Rule::emit_effect => {
                effects.push(Effect::Emit {
                    message: unescape_string(e.into_inner().next().unwrap().as_str()),
                });
            }
            _ => {}
        }
    }
    (verdict, effects)
}

fn parse_verdict_expr(pair: Pair<Rule>) -> Verdict {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::allow_expr => Verdict::Allow,
        Rule::deny_expr => {
            let mut it = inner.into_inner();
            let code = unescape_string(it.next().unwrap().as_str());
            let reason = unescape_string(it.next().unwrap().as_str());
            Verdict::Deny { code, reason }
        }
        _ => Verdict::Allow,
    }
}

fn verdict_from_violation(v: &ViolationHandler) -> Verdict {
    if v.message.is_empty() && v.severity == Severity::Info {
        Verdict::Allow
    } else {
        Verdict::Deny { code: String::new(), reason: v.message.clone() }
    }
}

fn effects_from_violation(v: &ViolationHandler) -> Vec<Effect> {
    let mut out = Vec::new();
    if let Some((f, t)) = &v.transition {
        out.push(Effect::Transition { from: f.clone(), to: t.clone() });
    }
    if !v.message.is_empty() {
        out.push(Effect::Emit { message: v.message.clone() });
    }
    out
}

// =====================================================================
// 模式 D：DMN 决策表
// =====================================================================

fn parse_decision_table(pair: Pair<Rule>) -> DecisionTableDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();

    let mut params: Vec<Param> = Vec::new();
    let mut outputs: Vec<Param> = Vec::new();
    let mut hit_policy = HitPolicy::Unique;
    let mut rows: Vec<DecisionRow> = Vec::new();

    for p in inner {
        match p.as_rule() {
            Rule::param => {
                if params.is_empty() && outputs.is_empty() {
                    params.push(parse_param(p));
                }
            }
            Rule::dt_outputs => outputs = p.into_inner().map(parse_param).collect(),
            Rule::dt_hit_policy => {
                let s = p.into_inner().next().unwrap().as_str();
                hit_policy = HitPolicy::parse(s).unwrap_or(HitPolicy::Unique);
            }
            Rule::dt_rules => {
                for row in p.into_inner() {
                    rows.push(parse_decision_row(row));
                }
            }
            _ => {}
        }
    }

    DecisionTableDecl {
        name,
        params,
        outputs,
        hit_policy,
        rows,
        meta: NodeMeta::default(),
        span: sp,
    }
}

fn parse_decision_row(row: Pair<Rule>) -> DecisionRow {
    let sp = span_of(&row);
    let inner = row.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::dt_default_row => {
            let outputs = parse_dt_tuple(inner.into_inner().next().unwrap());
            DecisionRow {
                inputs: Vec::new(),
                outputs,
                is_default: true,
                meta: NodeMeta::default(),
                span: sp,
            }
        }
        Rule::dt_input_row => {
            let mut it = inner.into_inner();
            let entry = it.next().unwrap();
            let input = match entry.as_rule() {
                Rule::dt_range_entry => {
                    let mut ri = entry.into_inner();
                    let lo = parse_dt_bound(ri.next().unwrap());
                    let hi = parse_dt_bound(ri.next().unwrap());
                    InputEntry::Range { lo, hi }
                }
                _ => InputEntry::Expr(parse_expr(entry.into_inner().next().unwrap())),
            };
            let outputs = parse_dt_tuple(it.next().unwrap());
            DecisionRow {
                inputs: vec![input],
                outputs,
                is_default: false,
                meta: NodeMeta::default(),
                span: sp,
            }
        }
        _ => unreachable!(),
    }
}

fn parse_dt_bound(p: Pair<Rule>) -> Expr {
    let inner = p.into_inner().next().unwrap();
    match inner.as_rule() {
        // `11-01` 视为 MM-DD 文本字面量（决策表按日历口径解释）
        Rule::date_lit => Expr::Str(inner.as_str().to_string()),
        _ => parse_expr(inner),
    }
}

fn parse_dt_tuple(p: Pair<Rule>) -> Vec<Expr> {
    p.into_inner().map(parse_expr).collect()
}

// =====================================================================
// 模式 B：受限工作内存规则（Drools 兼容）
// =====================================================================

fn parse_stateful_rule(pair: Pair<Rule>) -> StatefulRuleDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = unescape_string(inner.next().unwrap().as_str());

    let mut patterns: Vec<Pattern> = Vec::new();
    let mut negatives: Vec<Pattern> = Vec::new();
    let mut actions: Vec<RuleAction> = Vec::new();

    for p in inner {
        match p.as_rule() {
            Rule::rule_when => {
                for item in p.into_inner() {
                    let inner_item = item.into_inner().next().unwrap();
                    match inner_item.as_rule() {
                        Rule::negative_pattern => {
                            negatives.push(parse_pattern(inner_item.into_inner().next().unwrap()));
                        }
                        Rule::positive_pattern => {
                            patterns.push(parse_pattern(inner_item.into_inner().next().unwrap()));
                        }
                        _ => {}
                    }
                }
            }
            Rule::rule_then => {
                for a in p.into_inner() {
                    let act = a.into_inner().next().unwrap();
                    match act.as_rule() {
                        Rule::insert_action => {
                            let asp = span_of(&act);
                            let mut ai = act.into_inner();
                            let type_name = ai.next().unwrap().as_str().to_string();
                            let mut fields = Vec::new();
                            if let Some(fs) = ai.next() {
                                for fa in fs.into_inner() {
                                    let mut fi = fa.into_inner();
                                    let fname = fi.next().unwrap().as_str().to_string();
                                    let fexpr = parse_expr(fi.next().unwrap());
                                    fields.push((fname, fexpr));
                                }
                            }
                            actions.push(RuleAction::Insert { type_name, fields, span: asp });
                        }
                        Rule::retract_action => {
                            let asp = span_of(&act);
                            let binding = act.into_inner().next().unwrap().as_str().to_string();
                            actions.push(RuleAction::Retract { binding, span: asp });
                        }
                        Rule::yield_action => {
                            let asp = span_of(&act);
                            let v = parse_verdict_expr(act.into_inner().next().unwrap());
                            actions.push(RuleAction::Yield { verdict: v, span: asp });
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    StatefulRuleDecl {
        name,
        patterns,
        negatives,
        actions,
        meta: NodeMeta::default(),
        span: sp,
    }
}

fn parse_pattern(core: Pair<Rule>) -> Pattern {
    let sp = span_of(&core);
    let mut binding = None;
    let mut type_name = String::new();
    let mut constraints = Vec::new();
    for p in core.into_inner() {
        match p.as_rule() {
            Rule::pattern_binding => {
                binding = Some(p.into_inner().next().unwrap().as_str().to_string());
            }
            Rule::ident => type_name = p.as_str().to_string(),
            Rule::pattern_constraint => {
                constraints = p.into_inner().map(parse_expr).collect();
            }
            _ => {}
        }
    }
    Pattern {
        binding,
        type_name,
        constraints,
        meta: NodeMeta::default(),
        span: sp,
    }
}

/// Desugar：`rule X on E when P then { ... }` → `spec X on E { invariant: always(not(P)) ... }`
fn parse_legacy_rule(pair: Pair<Rule>) -> SpecDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let entity_name = inner.next().unwrap().as_str().to_string();
    let when = parse_temporal(inner.next().unwrap());
    let violation = parse_violation_fields(inner.next().unwrap(), sp);

    SpecDecl {
        entity_var: entity_name.to_lowercase(),
        name,
        entity_name,
        mode: Mode::Pure,
        kind: PolicyKind::Invariant,
        events: Vec::new(),
        given: vec![],
        invariant: TemporalExpr::Always(Box::new(TemporalExpr::Not(Box::new(when)))),
        verdict: verdict_from_violation(&violation),
        effects: effects_from_violation(&violation),
        violation,
        meta: NodeMeta::default(),
        span: sp,
    }
}

fn parse_violation_attach(pair: Pair<Rule>) -> (String, ViolationHandler) {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    // violation_attach 没有 block wrapper：名字之后直接是 violation_field 序列。
    (name, build_violation(inner, sp))
}

fn parse_violation_fields(block: Pair<Rule>, sp: Span) -> ViolationHandler {
    build_violation(block.into_inner(), sp)
}

fn build_violation<'a>(fields: impl Iterator<Item = Pair<'a, Rule>>, sp: Span) -> ViolationHandler {
    let mut severity = Severity::Warning;
    let mut guard = None;
    let mut transition = None;
    let mut message = String::new();

    for p in fields {
        match p.as_rule() {
            Rule::severity_field => {
                let s = p.into_inner().next().unwrap().as_str();
                severity = Severity::parse(s).unwrap_or(Severity::Warning);
            }
            Rule::guard_field => {
                let te = parse_temporal(p.into_inner().next().unwrap());
                // guard 通常是纯布尔组合，折叠回标量表达式；含时序算子时保守降级为恒真
                guard = Some(temporal_to_expr(&te).unwrap_or(Expr::Bool(true)));
            }
            Rule::transition_field => transition = Some(parse_transition_field(p)),
            Rule::emit_field => {
                message = unescape_string(p.into_inner().next().unwrap().as_str());
            }
            _ => {}
        }
    }

    ViolationHandler {
        severity,
        guard,
        transition,
        message,
        meta: NodeMeta::default(),
        span: sp,
    }
}

fn parse_let(pair: Pair<Rule>) -> Vec<(String, Expr)> {
    let mut it = pair.into_inner();
    let target = it.next().unwrap();
    let mut expr = None;
    for p in it {
        if p.as_rule() == Rule::expr {
            expr = Some(parse_expr(p));
        }
    }
    let expr = expr.expect("let binding requires an expression");

    let mut names: Vec<String> = Vec::new();
    for t in target.into_inner() {
        match t.as_rule() {
            Rule::ident => names.push(t.as_str().to_string()),
            // 元组解构：`let (a, b) = F(x)`
            _ => {}
        }
    }
    if names.len() <= 1 {
        return vec![(names.into_iter().next().unwrap_or_default(), expr)];
    }
    // 多返回值解构 → 每列一条 TableLookup 绑定
    let (table, args) = match &expr {
        Expr::Call { func, args } => (func.clone(), args.clone()),
        _ => (String::new(), vec![expr.clone()]),
    };
    names
        .into_iter()
        .enumerate()
        .map(|(i, n)| {
            (
                n,
                Expr::TableLookup { table: table.clone(), args: args.clone(), index: i },
            )
        })
        .collect()
}

// =====================================================================
// 时序表达式
// =====================================================================

fn parse_temporal(pair: Pair<Rule>) -> TemporalExpr {
    match pair.as_rule() {
        Rule::formula => parse_temporal(pair.into_inner().next().unwrap()),

        Rule::f_implies => {
            let mut it = pair.into_inner();
            let left = parse_temporal(it.next().unwrap());
            match it.next() {
                Some(r) => TemporalExpr::Implies(Box::new(left), Box::new(parse_temporal(r))),
                None => left,
            }
        }
        Rule::f_or => fold_binary(pair, |a, b| TemporalExpr::Or(Box::new(a), Box::new(b))),
        Rule::f_and => fold_binary(pair, |a, b| TemporalExpr::And(Box::new(a), Box::new(b))),
        Rule::f_not => {
            // `f_not = { (kw_not ~ f_not) | ("!" ~ f_not) | f_atom }`
            // `kw_not` 是具名原子规则，会出现在 `into_inner()` 里——必须跳过它，
            // 否则 `not (state == TERMINATED)` 会把 `kw_not` 当成子公式塞进 `parse_expr`。
            let inner = pair
                .into_inner()
                .find(|p| p.as_rule() != Rule::kw_not)
                .expect("f_not 缺少子公式");
            if inner.as_rule() == Rule::f_not {
                TemporalExpr::Not(Box::new(parse_temporal(inner)))
            } else {
                parse_temporal(inner)
            }
        }
        Rule::f_atom => parse_temporal(pair.into_inner().next().unwrap()),

        Rule::always_op => {
            TemporalExpr::Always(Box::new(parse_temporal(pair.into_inner().next().unwrap())))
        }
        Rule::eventually_op => {
            let mut it = pair.into_inner();
            let e = parse_temporal(it.next().unwrap());
            let w = it.next().map(parse_expr);
            TemporalExpr::Eventually { expr: Box::new(e), within: w }
        }
        Rule::historically_op | Rule::once_op => {
            let mut it = pair.into_inner();
            let e = parse_temporal(it.next().unwrap());
            let w = it.next().map(parse_expr);
            TemporalExpr::Historically { expr: Box::new(e), within: w }
        }
        Rule::until_op => {
            let mut it = pair.into_inner();
            let p = parse_temporal(it.next().unwrap());
            let q = parse_temporal(it.next().unwrap());
            TemporalExpr::Until { p: Box::new(p), q: Box::new(q) }
        }
        Rule::since_op => {
            let mut it = pair.into_inner();
            let p = parse_temporal(it.next().unwrap());
            let q = parse_temporal(it.next().unwrap());
            TemporalExpr::Since { p: Box::new(p), q: Box::new(q) }
        }
        Rule::within_op => {
            let mut it = pair.into_inner();
            let w = parse_expr(it.next().unwrap());
            let e = parse_temporal(it.next().unwrap());
            TemporalExpr::Within { window: w, inner: Box::new(e) }
        }
        Rule::reaches_op => {
            let op = pair.into_inner().next().unwrap();
            let mut it = op.clone().into_inner();
            let metric = it.next().unwrap().as_str().to_string();
            let threshold = parse_expr(it.next().unwrap());
            match op.as_rule() {
                Rule::crosses_above_op => TemporalExpr::CrossesAbove { metric, threshold },
                _ => TemporalExpr::CrossesBelow { metric, threshold },
            }
        }

        Rule::stream_quant => {
            let mut it = pair.into_inner();
            let stream = it.next().unwrap().as_str().to_string();
            let q = it.next().unwrap().into_inner().next().unwrap();
            let (quant, lambda) = match q.as_rule() {
                Rule::quant_exists => (Quant::Exists, q.into_inner().next().map(parse_lambda)),
                Rule::quant_forall => (Quant::Forall, q.into_inner().next().map(parse_lambda)),
                _ => (Quant::Count, q.into_inner().next().map(parse_lambda)),
            };
            TemporalExpr::StreamQuant { stream, quant, lambda }
        }

        Rule::predicate => predicate_to_temporal(parse_expr(pair.into_inner().next().unwrap())),
        _ => predicate_to_temporal(parse_expr(pair)),
    }
}

fn fold_binary(
    pair: Pair<Rule>,
    f: impl Fn(TemporalExpr, TemporalExpr) -> TemporalExpr,
) -> TemporalExpr {
    let mut it = pair.into_inner();
    let mut acc = parse_temporal(it.next().unwrap());
    for next in it {
        acc = f(acc, parse_temporal(next));
    }
    acc
}

/// 旧写法 `exists(S)` / `forall(S)` 提升为流量化节点。
fn predicate_to_temporal(e: Expr) -> TemporalExpr {
    if let Expr::Call { func, args } = &e {
        if (func == "exists" || func == "forall") && args.len() == 1 {
            if let Expr::Ident(stream) = &args[0] {
                return TemporalExpr::StreamQuant {
                    stream: stream.clone(),
                    quant: if func == "exists" { Quant::Exists } else { Quant::Forall },
                    lambda: None,
                };
            }
        }
        // `crosses_above(metric, k)` 直接作为表达式书写时同样提升为一等时序算子（FR6）
        if func == "crosses_above" && args.len() == 2 {
            if let Expr::Ident(metric) = &args[0] {
                return TemporalExpr::CrossesAbove {
                    metric: metric.clone(),
                    threshold: args[1].clone(),
                };
            }
        }
        if func == "crosses_below" && args.len() == 2 {
            if let Expr::Ident(metric) = &args[0] {
                return TemporalExpr::CrossesBelow {
                    metric: metric.clone(),
                    threshold: args[1].clone(),
                };
            }
        }
    }
    TemporalExpr::Predicate(e)
}

/// 把"纯布尔组合的时序表达式"折回标量表达式（用于 `guard:` 这类标量位置）。
/// 含 `historically/eventually/until/...` 时返回 `None`。
fn temporal_to_expr(t: &TemporalExpr) -> Option<Expr> {
    match t {
        TemporalExpr::Predicate(e) => Some(e.clone()),
        TemporalExpr::Not(i) => Some(Expr::UnaryNot(Box::new(temporal_to_expr(i)?))),
        TemporalExpr::And(a, b) => {
            Some(Expr::bin(BinaryOp::And, temporal_to_expr(a)?, temporal_to_expr(b)?))
        }
        TemporalExpr::Or(a, b) => {
            Some(Expr::bin(BinaryOp::Or, temporal_to_expr(a)?, temporal_to_expr(b)?))
        }
        TemporalExpr::Implies(a, b) => Some(Expr::bin(
            BinaryOp::Or,
            Expr::UnaryNot(Box::new(temporal_to_expr(a)?)),
            temporal_to_expr(b)?,
        )),
        // 流量化 / 时序算子无法折叠成标量
        _ => None,
    }
}

// =====================================================================
// 标量表达式
// =====================================================================

fn parse_expr(pair: Pair<Rule>) -> Expr {
    match pair.as_rule() {
        Rule::expr => parse_expr(pair.into_inner().next().unwrap()),
        Rule::or_bits_expr | Rule::and_bits_expr | Rule::shift_expr | Rule::cmp_expr
        | Rule::add_expr | Rule::mul_expr => fold_ops(pair),
        Rule::unary_expr => {
            let mut it = pair.into_inner();
            let first = it.next().unwrap();
            match first.as_rule() {
                Rule::unary_op => {
                    let inner = parse_expr(it.next().unwrap());
                    match first.as_str() {
                        "!" => Expr::UnaryNot(Box::new(inner)),
                        "-" => Expr::bin(BinaryOp::Sub, Expr::Number(0.0), inner),
                        _ => inner,
                    }
                }
                _ => parse_expr(first),
            }
        }
        Rule::primary => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::expr => parse_expr(inner),
                Rule::duration => Expr::DurationLit(parse_duration(inner.as_str())),
                Rule::hex => Expr::Hex(parse_uint(inner.as_str())),
                Rule::number => Expr::Number(
                    inner.as_str().parse().map_err(ParseError::InvalidNumber).unwrap(),
                ),
                Rule::string_lit => Expr::Str(unescape_string(inner.as_str())),
                Rule::bool_lit => Expr::Bool(inner.as_str() == "true"),
                Rule::call_expr => {
                    let mut ci = inner.into_inner();
                    let func = ci.next().unwrap().as_str().to_string();
                    let args = ci.map(parse_expr).collect();
                    Expr::Call { func, args }
                }
                Rule::path_call_expr => {
                    // `Trades.count()` -> Call { func: "Trades.count" }
                    let mut ci = inner.into_inner();
                    let func = ci.next().unwrap().as_str().to_string();
                    let args = ci.map(parse_expr).collect();
                    Expr::Call { func, args }
                }
                Rule::stream_agg_expr => {
                    // `SeatActions[OrderIntent].count` ->
                    // Call { func: "SeatActions.count", args: [Str("OrderIntent")] }
                    let mut ci = inner.into_inner();
                    let stream = ci.next().unwrap().as_str();
                    let event = ci.next().unwrap().as_str();
                    let kind = AggKind::parse(ci.next().unwrap().as_str()).unwrap_or(AggKind::Count);
                    Expr::Call {
                        func: format!("{stream}.{}", kind.as_str()),
                        args: vec![Expr::Str(event.to_string())],
                    }
                }
                Rule::path_ident => {
                    Expr::Path(inner.as_str().split('.').map(|s| s.to_string()).collect())
                }
                Rule::ident => Expr::Ident(inner.as_str().to_string()),
                _ => unreachable!(),
            }
        }
        other => panic!("parse_expr unexpected rule {other:?} on {:?}", pair.as_str()),
    }
}

/// 统一处理所有左结合二元层（bit-or / bit-and / shift / cmp / add / mul）。
fn fold_ops(pair: Pair<Rule>) -> Expr {
    let mut it = pair.into_inner();
    let mut left = parse_expr(it.next().unwrap());
    while let Some(op_pair) = it.next() {
        let op = BinaryOp::parse(op_pair.as_str()).expect("binary operator");
        let right = parse_expr(it.next().unwrap());
        left = Expr::bin(op, left, right);
    }
    left
}

fn parse_duration(s: &str) -> Duration {
    let (num, unit) = s.split_at(s.len() - 1);
    let val: u64 = num.parse().unwrap_or(0);
    match unit {
        "s" => Duration::from_secs(val),
        "m" => Duration::from_secs(val * 60),
        "h" => Duration::from_secs(val * 3600),
        "d" => Duration::from_secs(val * 86400),
        "w" => Duration::from_secs(val * 7 * 86400),
        "y" => Duration::from_secs(val * 365 * 86400),
        _ => Duration::from_secs(val),
    }
}

fn unescape_string(literal: &str) -> String {
    let body = if literal.starts_with('"') && literal.len() >= 2 {
        &literal[1..literal.len() - 1]
    } else {
        literal
    };
    let mut chars = body.chars();
    let mut value = String::new();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            value.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => value.push('\n'),
            Some('r') => value.push('\r'),
            Some('t') => value.push('\t'),
            Some('"') => value.push('"'),
            Some('\\') => value.push('\\'),
            Some(other) => value.push(other),
            None => value.push('\\'),
        }
    }
    value
}

// =====================================================================
// 测试：新旧语法覆盖
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const NEW_SYNTAX: &str = r#"
        entity Company(key: code) {
            states: [NORMAL, SUSPENDED, TERMINATED]
            initial: NORMAL
            terminal: [TERMINATED]

            transition Suspend {
                from: NORMAL
                to: SUSPENDED
                on: SemiAnnualDeadline
                emit: "trading suspended"
            }
        }

        stream PeriodicReports := Event[DisclosureEvent]
            .filter(e => e.report_type == "SEMI_ANNUAL")
            .window(60d)

        stream Approved := PeriodicReports.filter(r => r.status == "APPROVED")

        metric DaysOverdue(c: Company, deadline: Timestamp) -> int :=
            days_between(now(), deadline) where now() > deadline

        metric ApprovedCount := from Approved.count()

        spec SemiAnnualDeadline on c: Company {
            given:
                let period_deadline = 100000.0
                let period_window = 60d

            invariant:
                (now() > period_deadline) implies
                    historically(Approved.exists(r => r.status == "APPROVED"), within: period_window)

            violation {
                severity: CRITICAL
                guard: DaysOverdue(c, period_deadline) > 5
                transition: NORMAL -> SUSPENDED
                emit: "Semi-annual report overdue > 5 days"
            }
        }
    "#;

    const V1_SYNTAX: &str = r#"
        contract SeatFloodProtection on Entity[Seat] pure {
          key: seat_id
          state var frozen_until: Timestamp = 0

          guard IsNotFrozen on Event[OrderIntent, CancelIntent] {
              when:
                  now() < frozen_until
              verdict:
                  DENY(code: "ERR_SEAT_FROZEN", reason: "席位处于熔断冻结期，禁止报单！")
          }

          stream SeatActions = Stream[OrderIntent, CancelIntent]
              .filter(e => e.seat_id == seat_id)
              .window(sliding(5s))

          metric window_order_count  = sum(SeatActions[OrderIntent].count)
          metric window_cancel_count = sum(SeatActions[CancelIntent].count)

          invariant MaxFrequencyLimit on Event[OrderIntent, CancelIntent] {
              when:
                  window_order_count > 20 or window_cancel_count > 10
              verdict:
                  DENY(code: "ERR_RATE_LIMIT_EXCEEDED", reason: "5秒内报撤单频率超限，触发席位冻结1分钟"),
                  LeaseUpdate(frozen_until = now() + 60s)
          }
        }

        contract EcommerceCouponPolicy on Entity[User] pure {
          key: user_id
          states: [ PHASE_1 = 0x01, PHASE_2 = 0x02, PHASE_3 = 0x04 ]

          decision_table DetermineAmount(req_time: Timestamp) -> (amount: Int, phase: Int) {
              hit_policy: UNIQUE
              rules: [
                  in [11-01 .. 11-03] => (10, PHASE_1),
                  in [11-04 .. 11-05] => (20, PHASE_2),
                  in [11-06 .. 11-06] => (5,  PHASE_3),
                  default             => (0,  0x00)
              ]
          }

          invariant PreventFraud on Event[IssueCouponIntent] {
              let (legal_amount, phase_mask) = DetermineAmount(event.timestamp)
              when:
                  event.requested_amount != legal_amount or (state & phase_mask != 0)
              verdict:
                  DENY(code: "ERR_COUPON_REJECT", reason: "金额与活动阶段不符或当前阶段已领取！")
          }
        }

        rule "Derive_Suspicious_Account" stateful {
            when:
                $acc: Account(trade_frequency_5s > 10)
                not exists SuspiciousTag(account_id == $acc.id)
            then:
                insert(SuspiciousTag { account_id: $acc.id, reason: "HighFrequency" });
        }

        rule "Action_On_Suspicious" stateful {
            when:
                $tag: SuspiciousTag(reason == "HighFrequency")
                $order: InFlightOrder(account_id == $tag.account_id, amount > 500000)
            then:
                yield DENY(code: "ERR_SUSPICIOUS_BLOCK", reason: "嫌疑账户大额报单阻断");
        }
    "#;

    #[test]
    fn parses_four_first_class_concepts() {
        let f = parse(NEW_SYNTAX).unwrap();

        // 概念 1a：Entity 生命周期 + 状态机迁移边
        assert_eq!(f.entities.len(), 1);
        let e = &f.entities[0];
        assert_eq!(e.name, "Company");
        assert_eq!(e.key, "code");
        assert_eq!(e.initial, "NORMAL");
        assert!(e.is_terminal("TERMINATED"));
        assert_eq!(e.transitions.len(), 1);
        assert_eq!(e.transitions[0].on.as_deref(), Some("SemiAnnualDeadline"));
        assert_eq!(e.edges_from("NORMAL").count(), 1);

        // 概念 2：Stream + lambda + window
        assert_eq!(f.streams.len(), 2);
        assert_eq!(f.streams[0].source, StreamSource::Event("DisclosureEvent".into()));
        assert_eq!(f.streams[0].window_secs(), Some(60 * 86400));
        assert!(matches!(f.streams[0].ops[0], StreamOp::Filter(_)));
        assert_eq!(f.streams[1].source, StreamSource::Ref("PeriodicReports".into()));

        // 概念 1b：Metric 派生信号
        assert_eq!(f.metrics.len(), 2);
        let m = &f.metrics[0];
        assert_eq!(m.name, "DaysOverdue");
        assert_eq!(m.params.len(), 2);
        match &m.body {
            MetricBody::Scalar { guard: Some(_), .. } => {}
            other => panic!("expected guarded scalar metric, got {other:?}"),
        }
        assert!(matches!(f.metrics[1].body, MetricBody::StreamAgg { .. }));

        // 概念 3 + 4：Spec 时序不变量 + 违规处置
        assert_eq!(f.specs.len(), 1);
        let s = &f.specs[0];
        assert_eq!(s.entity_var, "c");
        assert_eq!(s.entity_name, "Company");
        assert_eq!(s.given.len(), 2);
        assert!(matches!(s.invariant, TemporalExpr::Implies(_, _)));
        assert_eq!(s.violation.severity, Severity::Critical);
        assert_eq!(s.violation.transition, Some(("NORMAL".into(), "SUSPENDED".into())));
    }

    #[test]
    fn v1_contract_hoists_entity_streams_metrics_policies() {
        let f = parse(V1_SYNTAX).unwrap();

        // 两个契约块 → 两个实体（Seat / User）
        assert_eq!(f.entities.len(), 2);
        let seat = f.entity("Seat").unwrap();
        assert_eq!(seat.key, "seat_id");
        assert_eq!(seat.state_vars.len(), 1);
        assert_eq!(seat.state_vars[0].name, "frozen_until");
        assert_eq!(seat.state_vars[0].ty, DataType::Timestamp);

        // 位掩码状态（FR5）
        let user = f.entity("User").unwrap();
        assert!(user.is_bitvec());
        assert_eq!(user.mask_of("PHASE_2"), Some(0x02));

        // 流：多事件源 + sliding window
        assert_eq!(f.streams.len(), 1);
        assert_eq!(
            f.streams[0].source,
            StreamSource::Events(vec!["OrderIntent".into(), "CancelIntent".into()])
        );
        assert_eq!(f.streams[0].window_kind(), Some(WindowKind::Sliding));
        assert_eq!(f.streams[0].window_secs(), Some(5));

        // metric：sum(Stream[Type].count)
        assert_eq!(f.metrics.len(), 2);
        match &f.metrics[0].body {
            MetricBody::Scalar { expr, .. } => {
                let rendered = format!("{expr:?}");
                assert!(rendered.contains("SeatActions.count"), "{rendered}");
                assert!(rendered.contains("OrderIntent"), "{rendered}");
            }
            other => panic!("expected scalar metric, got {other:?}"),
        }

        // guard / invariant 块 → SpecDecl
        assert_eq!(f.specs.len(), 3);
        let guard = f.specs.iter().find(|s| s.name == "IsNotFrozen").unwrap();
        assert!(guard.is_guard());
        assert_eq!(guard.events, vec!["OrderIntent", "CancelIntent"]);
        assert_eq!(guard.verdict.code(), Some("ERR_SEAT_FROZEN"));

        let freq = f.specs.iter().find(|s| s.name == "MaxFrequencyLimit").unwrap();
        assert!(!freq.is_guard());
        assert!(freq.lease_update().is_some());
        let (target, _) = freq.lease_update().unwrap();
        assert_eq!(target, "frozen_until");

        let fraud = f.specs.iter().find(|s| s.name == "PreventFraud").unwrap();
        assert_eq!(fraud.given.len(), 2);
        assert_eq!(fraud.given[0].0, "legal_amount");
        assert!(matches!(fraud.given[0].1, Expr::TableLookup { index: 0, .. }));
        assert!(matches!(fraud.given[1].1, Expr::TableLookup { index: 1, .. }));
    }

    #[test]
    fn v1_decision_table_parses_ranges_and_default() {
        let f = parse(V1_SYNTAX).unwrap();
        assert_eq!(f.decision_tables.len(), 1);
        let dt = &f.decision_tables[0];
        assert_eq!(dt.name, "DetermineAmount");
        assert_eq!(dt.hit_policy, HitPolicy::Unique);
        assert_eq!(dt.params.len(), 1);
        assert_eq!(dt.outputs.len(), 2);
        assert_eq!(dt.rows.len(), 4);
        assert_eq!(dt.rule_rows().count(), 3);
        assert!(dt.default_row().is_some());
        match &dt.rows[0].inputs[0] {
            InputEntry::Range { lo, hi } => {
                assert_eq!(lo, &Expr::Str("11-01".into()));
                assert_eq!(hi, &Expr::Str("11-03".into()));
            }
            other => panic!("expected range entry, got {other:?}"),
        }
        assert_eq!(dt.rows[0].outputs[0], Expr::Number(10.0));
    }

    #[test]
    fn v1_stateful_rules_parse_patterns_and_actions() {
        let f = parse(V1_SYNTAX).unwrap();
        assert_eq!(f.stateful_rules.len(), 2);
        let derive = &f.stateful_rules[0];
        assert_eq!(derive.name, "Derive_Suspicious_Account");
        assert_eq!(derive.patterns.len(), 1);
        assert_eq!(derive.patterns[0].binding.as_deref(), Some("$acc"));
        assert_eq!(derive.patterns[0].type_name, "Account");
        assert_eq!(derive.negatives.len(), 1);
        assert_eq!(derive.negatives[0].type_name, "SuspiciousTag");
        assert_eq!(derive.writes(), vec!["SuspiciousTag"]);

        let action = &f.stateful_rules[1];
        assert!(action.verdict().unwrap().is_deny());
        assert_eq!(action.reads(), vec!["SuspiciousTag", "InFlightOrder"]);
    }

    #[test]
    fn stream_ops_cover_projection_join_fold() {
        let src = r#"
            entity Account(key: account_id) { states: [ACTIVE] initial: ACTIVE }
            stream Trades := Event[TradeEvent].filter(t => t.kind == "CANCEL")
            stream Enriched := Trades.map(t => t.amount * 2.0).window(1h)
            stream Joined := Trades.join(Enriched, (l, r) => l.amount == r.amount)
            stream Folded := Trades.fold(0.0, (acc, t) => acc + t.amount)
            stream Dedup := Trades.distinct(t => t.account_id)
            metric Exposure := from Folded.count()
        "#;
        let f = parse(src).unwrap();
        assert_eq!(f.streams.len(), 5);
        assert!(matches!(f.streams[1].ops[0], StreamOp::Map(_)));
        assert!(matches!(f.streams[2].ops[0], StreamOp::Join { .. }));
        assert!(matches!(f.streams[3].ops[0], StreamOp::Fold { .. }));
        assert!(matches!(f.streams[4].ops[0], StreamOp::Distinct(Some(_))));
    }

    #[test]
    fn violation_on_attaches_to_named_spec() {
        let src = r#"
            entity Company(key: code) { states: [NORMAL, SUSPENDED] initial: NORMAL }
            stream R := Event[E].filter(e => e.t == "R")
            spec Overdue on c: Company {
                invariant: historically(R.exists(), within: 30d) implies always(true)
                violation { severity: INFO emit: "placeholder" }
            }
            violation on Overdue {
                severity: CRITICAL
                guard: now() > 100.0
                transition: NORMAL -> SUSPENDED
                emit: "attached async"
            }
        "#;
        let f = parse(src).unwrap();
        assert_eq!(f.specs[0].violation.severity, Severity::Critical);
        assert_eq!(f.specs[0].violation.message, "attached async");
    }

    #[test]
    fn legacy_syntax_still_parses_and_desugars() {
        let src = r#"
            entity Company { key: code states: [NORMAL, SUSPENDED, TERMINATED] initial: NORMAL }
            stream ValidSemiReports = Stream[DisclosureEvent].filter(event.type == "SEMI_ANNUAL")
            signal Doubled(x: float) -> float = x * 2.0
            var audit_clean = DisclosureEvent.audit_opinion == "UNQUALIFIED"
            contract SemiAnnualCompliance on Company {
                let deadline = 100000.0
                invariant:
                    (now() > deadline) implies historically(exists(ValidSemiReports), within: 60d)
                violation {
                    severity: CRITICAL
                    guard: DaysOverdue(deadline) > 5.0
                    transition: NORMAL -> SUSPENDED
                    emit: "Overdue"
                }
            }
            rule ImmediateStop on Company when DaysOverdue(1.0) > 0.0 then {
                severity: WARNING
                emit: "stop"
            }
            var threshold: int range: 0 .. 100 = 5
        "#;
        let f = parse(src).unwrap();
        assert_eq!(f.entities[0].key, "code");
        assert_eq!(f.streams[0].source, StreamSource::Event("DisclosureEvent".into()));
        // signal / var 一律提升为 metric
        assert_eq!(f.metrics.len(), 2);
        assert_eq!(f.metrics[1].params.len(), 0);
        // var x: int range: 0..100 → VarDecl
        assert_eq!(f.var_decls.len(), 1);
        assert_eq!(f.var_decls[0].name, "threshold");
        assert!(f.var_decls[0].range.is_some());
        // exists(X) → StreamQuant
        let inv = &f.specs[0].invariant;
        assert!(
            format!("{inv:?}").contains("StreamQuant"),
            "expected legacy exists() to lift into StreamQuant: {inv:?}"
        );
        // rule ... when ... then → spec with always(not(P))
        assert_eq!(f.specs.len(), 2);
        assert!(matches!(&f.specs[1].invariant, TemporalExpr::Always(_)));
        assert_eq!(f.specs[1].entity_var, "company");
    }

    #[test]
    fn bitwise_and_hex_expressions_parse() {
        let src = r#"
            contract C on Entity[Company] pure {
                key: code
                states: [ A = 0x01, B = 0x02, C = 0x04 ]
                guard G on Event[E] {
                    when: (state & 0x04) != 0 and !(state & 0x08)
                    verdict: DENY(code: "E1", reason: "r1")
                }
            }
        "#;
        let f = parse(src).unwrap();
        assert_eq!(f.entities[0].mask_of("C"), Some(0x04));
        assert_eq!(f.specs.len(), 1);
        assert!(f.specs[0].events == vec!["E".to_string()]);
    }

    #[test]
    fn crosses_above_lifts_into_temporal_node() {
        let src = r#"
            entity Account(key: account_id) { states: [ACTIVE] initial: ACTIVE }
            spec Flood on a: Account {
                invariant: always(crosses_above(cancel_ratio, 0.85))
                violation { severity: WARNING emit: "flood" }
            }
        "#;
        let f = parse(src).unwrap();
        assert!(format!("{:?}", f.specs[0].invariant).contains("CrossesAbove"));
    }
}
