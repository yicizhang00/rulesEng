//! rules-parser — pest 文法驱动的 AST 构建器。

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
}

pub fn parse(input: &str) -> Result<SpecFile, ParseError> {
    let mut pairs = DSLParser::parse(Rule::spec_file, input).map_err(|e| Box::new(e))?;
    let root = pairs.next().unwrap();

    let mut entities = Vec::new();
    let mut streams = Vec::new();
    let mut signals = Vec::new();
    let mut vars = Vec::new();
    let mut contracts = Vec::new();

    for pair in root.into_inner() {
        match pair.as_rule() {
            Rule::entity_decl => entities.push(parse_entity(pair)),
            Rule::stream_decl => streams.push(parse_stream(pair)),
            Rule::signal_decl => signals.push(parse_signal(pair)),
            Rule::var_decl => vars.push(parse_var(pair)),
            Rule::contract_decl => contracts.push(parse_contract(pair)),
            Rule::rule_decl => contracts.push(parse_rule_sugar(pair)),
            Rule::EOI => {}
            // import_decl / type_decl / event_decl 暂不入 AST，忽略
            _ => {}
        }
    }

    Ok(SpecFile {
        entities,
        streams,
        signals,
        vars,
        contracts,
        span: Span::default(),
    })
}

fn span_of(p: &Pair<Rule>) -> Span {
    let s = p.as_span();
    Span { line: s.start_pos().line_col().0 as u32, col: s.start_pos().line_col().1 as u32 }
}

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------
fn parse_entity(pair: Pair<Rule>) -> EntityDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();

    let mut key = String::new();
    let mut states: Vec<String> = Vec::new();
    let mut initial = String::new();

    // entity_member 是 silent rule，其内部 key_decl / states_decl / initial_decl
    // 直接展开为 entity_decl 的 inner pairs
    for p in inner {
        match p.as_rule() {
            Rule::key_decl => {
                key = p.into_inner().next().unwrap().as_str().to_string();
            }
            Rule::states_decl => {
                states = p.into_inner().map(|x| x.as_str().to_string()).collect();
            }
            Rule::initial_decl => {
                initial = p.into_inner().next().unwrap().as_str().to_string();
            }
            // transition_decl / entity_invariant 暂不入 AST
            _ => {}
        }
    }

    EntityDecl { name, key, states, initial, span: sp }
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------
fn parse_stream(pair: Pair<Rule>) -> StreamDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let se = inner.next().unwrap(); // stream_expr

    let mut se_inner = se.into_inner();
    let primary = se_inner.next().unwrap(); // stream_primary

    let event_type = match primary.as_rule() {
        Rule::stream_source => {
            // stream_source = "Stream" "[" ident "]"
            primary.into_inner().next().unwrap().as_str().to_string()
        }
        Rule::stream_ref => primary.as_str().to_string(),
        _ => String::new(),
    };

    // stream_op 是 silent，filter_op / window_op 等直接展开
    // 默认恒真：1 == 1
    let mut filter = Expr::bin(
        BinaryOp::Eq,
        Expr::Number(1.0),
        Expr::Number(1.0),
    );
    let mut hint_window_secs = None;
    for op in se_inner {
        match op.as_rule() {
            Rule::filter_op => {
                let formula_pair = op.into_inner().next().unwrap();
                let te = parse_temporal_expr(formula_pair);
                if let TemporalExpr::Predicate(e) = te {
                    filter = e;
                }
            }
            Rule::window_op => {
                let dur = parse_duration(op.into_inner().next().unwrap().as_str());
                hint_window_secs = Some(dur.as_secs());
            }
            _ => {}
        }
    }

    StreamDecl { name, event_type, filter, hint_window_secs, span: sp }
}

// ---------------------------------------------------------------------------
// Signal / Var
// ---------------------------------------------------------------------------
fn parse_signal(pair: Pair<Rule>) -> SignalDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let param_name = inner.next().unwrap().as_str().to_string();
    let _param_type = inner.next().unwrap(); // type_expr — 暂不使用
    let return_type_pair = inner.next().unwrap(); // type_expr
    let return_type = match return_type_pair.as_str() {
        "int" => DataType::Int,
        "float" => DataType::Float,
        "bool" => DataType::Bool,
        "string" => DataType::String,
        "timestamp" => DataType::Timestamp,
        _ => DataType::Float,
    };
    let formula_pair = inner.next().unwrap();
    let expr = formula_to_expr(formula_pair);

    SignalDecl { name, param_name, entity_name: String::new(), return_type, expr, span: sp }
}

fn parse_var(pair: Pair<Rule>) -> VarDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    // var_decl = "var" ident (":" type_expr)? "=" formula
    let first = inner.next().unwrap();
    let formula_pair = if first.as_rule() == Rule::type_expr {
        inner.next().unwrap()
    } else {
        first
    };
    let expr = formula_to_expr(formula_pair);
    VarDecl { name, expr, span: sp }
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------
fn parse_contract(pair: Pair<Rule>) -> ContractDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let entity_name = inner.next().unwrap().as_str().to_string();
    let body = inner.next().unwrap(); // contract_body

    let mut bindings = Vec::new();
    let mut invariants: Vec<TemporalExpr> = Vec::new();
    let mut violation: Option<ViolationHandler> = None;

    for p in body.into_inner() {
        match p.as_rule() {
            Rule::let_decl => {
                let mut b = p.into_inner();
                let var_name = b.next().unwrap().as_str().to_string();
                // let_decl = "let" ident (":" type_expr)? "=" formula
                let formula_pair = if b.len() == 1 {
                    b.next().unwrap()
                } else {
                    b.next(); // type_expr
                    b.next().unwrap()
                };
                bindings.push((var_name, formula_to_expr(formula_pair)));
            }
            Rule::formula => {
                // assume / invariant / guarantee 的 formula 在语法中都直接暴露，
                // 无法从语法上区分；这里按 invariant 收集（示例中 invariant 至少一个）。
                invariants.push(parse_temporal_expr(p));
            }
            Rule::violation_block => {
                violation = Some(parse_violation(p));
            }
            _ => {}
        }
    }

    let invariant = invariants.remove(0);
    ContractDecl {
        name,
        entity_name,
        bindings,
        invariant,
        violation: violation.expect("contract requires a violation block"),
        span: sp,
    }
}

/// Desugar: `rule X on E when P then { ... }`
/// → `contract X on E { invariant: always(not(P)) violation { ... } }`
fn parse_rule_sugar(pair: Pair<Rule>) -> ContractDecl {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let entity_name = inner.next().unwrap().as_str().to_string();
    let when = parse_temporal_expr(inner.next().unwrap());
    let action = parse_action_block(inner.next().unwrap());

    // when P 成立即违规 → invariant 要求 always(not(P))
    let invariant = TemporalExpr::Always(Box::new(TemporalExpr::Not(Box::new(when))));

    ContractDecl {
        name,
        entity_name,
        bindings: vec![],
        invariant,
        violation: action,
        span: sp,
    }
}

fn parse_action_block(pair: Pair<Rule>) -> ViolationHandler {
    let sp = span_of(&pair);
    let mut severity = Severity::Warning;
    let mut from_state = None;
    let mut to_state = None;
    let mut message = String::new();

    // action_field 是 silent，severity_field / transition_field / emit_field 直接展开
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::severity_field => {
                let sev = p.into_inner().next().unwrap();
                severity = match sev.as_str() {
                    "INFO" => Severity::Info,
                    "WARNING" => Severity::Warning,
                    "CRITICAL" => Severity::Critical,
                    _ => unreachable!(),
                };
            }
            Rule::transition_field => {
                let mut ti = p.into_inner();
                from_state = Some(ti.next().unwrap().as_str().to_string());
                to_state = Some(ti.next().unwrap().as_str().to_string());
            }
            Rule::emit_field => {
                let s = p.into_inner().next().unwrap().as_str();
                message = s[1..s.len() - 1].to_string();
            }
            _ => {}
        }
    }

    ViolationHandler {
        severity,
        guard: None,
        transition: from_state.zip(to_state),
        message,
        span: sp,
    }
}

fn parse_violation(pair: Pair<Rule>) -> ViolationHandler {
    let sp = span_of(&pair);
    let mut severity = Severity::Warning;
    let mut guard = None;
    let mut from_state = None;
    let mut to_state = None;
    let mut message = String::new();

    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::severity_field => {
                let sev = p.into_inner().next().unwrap();
                severity = match sev.as_str() {
                    "INFO" => Severity::Info,
                    "WARNING" => Severity::Warning,
                    "CRITICAL" => Severity::Critical,
                    _ => unreachable!(),
                };
            }
            Rule::guard_field => {
                let formula_pair = p.into_inner().next().unwrap();
                let te = parse_temporal_expr(formula_pair);
                if let TemporalExpr::Predicate(e) = te {
                    guard = Some(e);
                }
            }
            Rule::transition_field => {
                let mut ti = p.into_inner();
                from_state = Some(ti.next().unwrap().as_str().to_string());
                to_state = Some(ti.next().unwrap().as_str().to_string());
            }
            Rule::emit_field => {
                let s = p.into_inner().next().unwrap().as_str();
                message = s[1..s.len() - 1].to_string();
            }
            _ => {}
        }
    }

    let transition = match (from_state, to_state) {
        (Some(f), Some(t)) => Some((f, t)),
        _ => None,
    };

    ViolationHandler { severity, guard, transition, message, span: sp }
}

// ---------------------------------------------------------------------------
// Temporal expressions
// ---------------------------------------------------------------------------

/// 把 formula pair 解包到底层 predicate，返回一个标量 Expr。
/// 用于 stream filter / var / let 等只接受标量表达式的位置。
fn formula_to_expr(pair: Pair<Rule>) -> Expr {
    match parse_temporal_expr(pair) {
        TemporalExpr::Predicate(e) => e,
        other => {
            // 兜底：非谓词的时序表达式出现在标量位置，用一个 Call 占位
            Expr::Call { func: format!("<temporal:{:?}>", other), args: vec![] }
        }
    }
}

fn parse_temporal_expr(pair: Pair<Rule>) -> TemporalExpr {
    match pair.as_rule() {
        // formula = f_implies
        Rule::formula => parse_temporal_expr(pair.into_inner().next().unwrap()),
        // f_implies = f_or ~ ("implies" ~ f_implies)?
        Rule::f_implies => {
            let mut inner = pair.into_inner();
            let left = parse_temporal_expr(inner.next().unwrap());
            if let Some(right) = inner.next() {
                TemporalExpr::Implies(
                    Box::new(left),
                    Box::new(parse_temporal_expr(right)),
                )
            } else {
                left
            }
        }
        // f_or = f_and ~ ("or" ~ f_and)*
        Rule::f_or => {
            let mut inner = pair.into_inner();
            let mut left = parse_temporal_expr(inner.next().unwrap());
            while let Some(right) = inner.next() {
                left = TemporalExpr::Or(
                    Box::new(left),
                    Box::new(parse_temporal_expr(right)),
                );
            }
            left
        }
        // f_and = f_not ~ ("and" ~ f_not)*
        Rule::f_and => {
            let mut inner = pair.into_inner();
            let mut left = parse_temporal_expr(inner.next().unwrap());
            while let Some(right) = inner.next() {
                left = TemporalExpr::And(
                    Box::new(left),
                    Box::new(parse_temporal_expr(right)),
                );
            }
            left
        }
        // f_not = ("not" ~ f_not) | f_atom
        Rule::f_not => {
            let inner = pair.into_inner().next().unwrap();
            if inner.as_rule() == Rule::f_not {
                TemporalExpr::Not(Box::new(parse_temporal_expr(inner)))
            } else {
                parse_temporal_expr(inner)
            }
        }
        // f_atom = temporal_op | quantifier_op | predicate | "(" formula ")"
        Rule::f_atom => parse_temporal_expr(pair.into_inner().next().unwrap()),

        // ----- temporal operators -----
        Rule::historically_op => {
            let mut inner = pair.into_inner();
            let sub = parse_temporal_expr(inner.next().unwrap());
            let within = inner.next().map(|p| parse_duration(p.as_str()));
            TemporalExpr::Historically { expr: Box::new(sub), within }
        }
        Rule::always_op => {
            TemporalExpr::Always(Box::new(parse_temporal_expr(
                pair.into_inner().next().unwrap(),
            )))
        }
        Rule::eventually_op => TemporalExpr::Eventually(Box::new(parse_temporal_expr(
            pair.into_inner().next().unwrap(),
        ))),
        Rule::once_op => TemporalExpr::Eventually(Box::new(parse_temporal_expr(
            pair.into_inner().next().unwrap(),
        ))),
        Rule::next_op => TemporalExpr::Eventually(Box::new(parse_temporal_expr(
            pair.into_inner().next().unwrap(),
        ))),
        Rule::until_op => {
            let mut inner = pair.into_inner();
            let p = parse_temporal_expr(inner.next().unwrap());
            let q = parse_temporal_expr(inner.next().unwrap());
            TemporalExpr::Until { p: Box::new(p), q: Box::new(q) }
        }
        Rule::since_op => {
            let mut inner = pair.into_inner();
            let p = parse_temporal_expr(inner.next().unwrap());
            let q = parse_temporal_expr(inner.next().unwrap());
            TemporalExpr::Until { p: Box::new(p), q: Box::new(q) }
        }
        Rule::within_op => {
            let mut inner = pair.into_inner();
            let dur = parse_duration(inner.next().unwrap().as_str());
            let inner_expr = parse_temporal_expr(inner.next().unwrap());
            TemporalExpr::WithinOp { window: dur, inner: Box::new(inner_expr) }
        }

        // ----- quantifiers -----
        Rule::exists_op => {
            let mut inner = pair.into_inner();
            let stream_ref = inner.next().unwrap().as_str().to_string();
            TemporalExpr::Predicate(Expr::Call {
                func: "exists".to_string(),
                args: vec![Expr::Ident(stream_ref)],
            })
        }
        Rule::forall_op => {
            let mut inner = pair.into_inner();
            let stream_ref = inner.next().unwrap().as_str().to_string();
            TemporalExpr::Predicate(Expr::Call {
                func: "forall".to_string(),
                args: vec![Expr::Ident(stream_ref)],
            })
        }

        // predicate = expr
        Rule::predicate => {
            TemporalExpr::Predicate(parse_expr(pair.into_inner().next().unwrap()))
        }

        _ => TemporalExpr::Predicate(parse_expr(pair)),
    }
}

// ---------------------------------------------------------------------------
// Scalar expressions
// ---------------------------------------------------------------------------
fn parse_expr(pair: Pair<Rule>) -> Expr {
    match pair.as_rule() {
        Rule::expr => parse_expr(pair.into_inner().next().unwrap()),
        Rule::cmp_expr => {
            let mut inner = pair.into_inner();
            let mut left = parse_expr(inner.next().unwrap());
            if let Some(op_pair) = inner.next() {
                let op = match op_pair.as_str() {
                    ">" => BinaryOp::Gt,
                    ">=" => BinaryOp::Gte,
                    "<" => BinaryOp::Lt,
                    "<=" => BinaryOp::Lte,
                    "==" => BinaryOp::Eq,
                    "!=" => BinaryOp::Neq,
                    _ => unreachable!(),
                };
                let right = parse_expr(inner.next().unwrap());
                left = Expr::bin(op, left, right);
            }
            left
        }
        Rule::add_expr => {
            let mut inner = pair.into_inner();
            let mut left = parse_expr(inner.next().unwrap());
            while let Some(op_pair) = inner.next() {
                let op = match op_pair.as_str() {
                    "+" => BinaryOp::Add,
                    "-" => BinaryOp::Sub,
                    _ => unreachable!(),
                };
                let right = parse_expr(inner.next().unwrap());
                left = Expr::bin(op, left, right);
            }
            left
        }
        Rule::mul_expr => {
            let mut inner = pair.into_inner();
            let mut left = parse_expr(inner.next().unwrap());
            while let Some(op_pair) = inner.next() {
                let op = match op_pair.as_str() {
                    "*" => BinaryOp::Mul,
                    "/" => BinaryOp::Div,
                    _ => unreachable!(),
                };
                let right = parse_expr(inner.next().unwrap());
                left = Expr::bin(op, left, right);
            }
            left
        }
        Rule::primary => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::expr => parse_expr(inner),
                Rule::duration => Expr::DurationLit(parse_duration(inner.as_str())),
                Rule::number => Expr::Number(
                    inner.as_str().parse().map_err(ParseError::InvalidNumber).unwrap(),
                ),
                Rule::string_lit => {
                    let s = inner.as_str();
                    Expr::Str(s[1..s.len() - 1].to_string())
                }
                Rule::bool_lit => Expr::Ident(inner.as_str().to_string()),
                Rule::call_expr => {
                    let mut ci = inner.into_inner();
                    let func = ci.next().unwrap().as_str().to_string();
                    let args = ci.map(parse_expr).collect();
                    Expr::Call { func, args }
                }
                Rule::path_ident => {
                    Expr::Path(inner.as_str().split('.').map(|s| s.to_string()).collect())
                }
                Rule::ident => Expr::Ident(inner.as_str().to_string()),
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}

fn parse_duration(s: &str) -> Duration {
    let (num, unit) = s.split_at(s.len() - 1);
    let val: u64 = num.parse().unwrap();
    match unit {
        "s" => Duration::from_secs(val),
        "m" => Duration::from_secs(val * 60),
        "h" => Duration::from_secs(val * 3600),
        "d" => Duration::from_secs(val * 86400),
        "w" => Duration::from_secs(val * 7 * 86400),
        _ => Duration::from_secs(val),
    }
}
