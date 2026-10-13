//! 模式 D：DMN 决策表执行器（FR3 / 用例 3）。
//!
//! 决策表被当作**纯函数代数查表**：输入子句 → 命中策略 → 输出子句。
//! 与 `rules-verifier` 的 SMT 侧共享同一份 [`InputEntry`] 语义，
//! 因此"编译期证明无重叠/无死区"与"运行期查表"是同一模型的两个视图。
//!
//! 支持四种 OMG DMN 1.3 命中策略：
//!
//! | 策略 | 语义 |
//! |---|---|
//! | `UNIQUE` | 唯一命中（要求行互斥，由 SMT 证明） |
//! | `FIRST` | 按书写序首条命中即返回 |
//! | `PRIORITY` | 命中行中取第一输出列最小（优先级最高）者 |
//! | `COLLECT` | 收集全部命中行 |

use crate::Value;
use rules_ast::{DecisionRow, DecisionTableDecl, Expr, HitPolicy, InputEntry};

/// 决策表求值所需的宿主环境（把参数绑定注入表达式求值）。
pub trait DecisionEnv {
    /// 在 `params` 绑定下求值表达式。
    fn eval_bound(&mut self, e: &Expr, params: &[(String, Value)]) -> Value;
}

/// 一次决策表求值结果。
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionOutcome {
    /// 命中行的输出（`COLLECT` 时按行序拼接）。
    pub outputs: Vec<Value>,
    /// 非 default 命中行的下标（`None` 表示落到 default 或未命中）。
    pub row: Option<usize>,
    /// 全部命中的非 default 行下标（用于 `COLLECT` 与冲突观测）。
    pub hits: Vec<usize>,
    /// 是否由 default 行兜底。
    pub default: bool,
}

impl DecisionOutcome {
    fn miss() -> Self {
        DecisionOutcome { outputs: Vec::new(), row: None, hits: Vec::new(), default: false }
    }
    /// 命中行数（不含 default）。
    pub fn hit_count(&self) -> usize {
        self.hits.len()
    }
}

/// 求值一张决策表。
pub fn evaluate(
    decl: &DecisionTableDecl,
    args: &[Value],
    env: &mut dyn DecisionEnv,
) -> DecisionOutcome {
    let params: Vec<(String, Value)> = decl
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| (p.name.clone(), args.get(i).cloned().unwrap_or(Value::Num(0.0))))
        .collect();

    let mut hits: Vec<(usize, Vec<Value>)> = Vec::new();
    for (ri, row) in decl.rows.iter().enumerate() {
        if row.is_default {
            continue;
        }
        if row_matches(row, &params, env) {
            let outs = row.outputs.iter().map(|o| env.eval_bound(o, &params)).collect();
            hits.push((ri, outs));
        }
    }

    let mut default_outs = || -> Vec<Value> {
        decl.default_row()
            .map(|r| r.outputs.iter().map(|o| env.eval_bound(o, &params)).collect())
            .unwrap_or_default()
    };

    if hits.is_empty() {
        let outs = default_outs();
        if outs.is_empty() {
            return DecisionOutcome::miss();
        }
        return DecisionOutcome {
            outputs: outs,
            row: None,
            hits: Vec::new(),
            default: true,
        };
    }

    match decl.hit_policy {
        HitPolicy::Unique | HitPolicy::First => {
            let (ri, outs) = hits.remove(0);
            DecisionOutcome {
                outputs: outs,
                row: Some(ri),
                hits: vec![ri],
                default: false,
            }
        }
        HitPolicy::Priority => {
            // 第一输出列越小优先级越高（DMN Priority 的“优先级序表”的等价实现）
            let best = hits
                .iter()
                .min_by(|a, b| {
                    let ka = a.1.first().map(|v| v.as_num()).unwrap_or(f64::MAX);
                    let kb = b.1.first().map(|v| v.as_num()).unwrap_or(f64::MAX);
                    ka.partial_cmp(&kb).unwrap_or(std::cmp::Ordering::Equal)
                })
                .cloned()
                .unwrap();
            DecisionOutcome {
                outputs: best.1,
                row: Some(best.0),
                hits: hits.iter().map(|(i, _)| *i).collect(),
                default: false,
            }
        }
        HitPolicy::Collect => {
            let mut merged = Vec::new();
            for (_, outs) in &hits {
                merged.extend(outs.iter().cloned());
            }
            DecisionOutcome {
                outputs: merged,
                row: hits.first().map(|(i, _)| *i),
                hits: hits.iter().map(|(i, _)| *i).collect(),
                default: false,
            }
        }
    }
}

/// 一行是否命中（所有输入子句的合取）。
pub fn row_matches(row: &DecisionRow, params: &[(String, Value)], env: &mut dyn DecisionEnv) -> bool {
    row.inputs.iter().enumerate().all(|(i, entry)| {
        let v = params.get(i).map(|(_, v)| v.clone()).unwrap_or(Value::Num(0.0));
        entry_matches(entry, &v, params, env)
    })
}

fn entry_matches(
    entry: &InputEntry,
    input: &Value,
    params: &[(String, Value)],
    env: &mut dyn DecisionEnv,
) -> bool {
    match entry {
        InputEntry::Any => true,
        InputEntry::Range { lo, hi } => {
            // FR3 / 用例 3：`in [11-01 .. 11-03]` 这类 MM-DD 边界按"日历口径"比较——
            // 输入时间戳被折算成 MMDD 整数后落在闭区间内即命中。
            match (mmdd_literal(lo), mmdd_literal(hi)) {
                (Some(a), Some(b)) => {
                    let v = mmdd_of_timestamp(input.as_num());
                    v >= a && v <= b
                }
                _ => {
                    let l = env.eval_bound(lo, params).as_num();
                    let h = env.eval_bound(hi, params).as_num();
                    let v = input.as_num();
                    v >= l && v <= h
                }
            }
        }
        // S-FEEL 自由谓词：参数已注入，直接求真值；若与参数无关则退化为等值比较
        InputEntry::Expr(e) => {
            let got = env.eval_bound(e, params);
            if references_params(e, params) {
                got.truthy()
            } else {
                value_loose_eq(&got, input)
            }
        }
    }
}

fn references_params(e: &Expr, params: &[(String, Value)]) -> bool {
    match e {
        Expr::Ident(n) => params.iter().any(|(p, _)| p == n),
        Expr::Path(parts) => params.iter().any(|(p, _)| p == &parts[0]),
        Expr::Binary { left, right, .. } => {
            references_params(left, params) || references_params(right, params)
        }
        Expr::UnaryNot(i) => references_params(i, params),
        Expr::Call { args, .. } | Expr::TableLookup { args, .. } => {
            args.iter().any(|a| references_params(a, params))
        }
        _ => false,
    }
}

fn value_loose_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Text(x), Value::Text(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        _ => (a.as_num() - b.as_num()).abs() < f64::EPSILON,
    }
}

/// `"11-01"` → `Some(1101)`。
fn mmdd_literal(e: &Expr) -> Option<u32> {
    if let Expr::Str(s) = e {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 && parts[0].len() == 2 && parts[1].len() == 2 {
            let m: u32 = parts[0].parse().ok()?;
            let d: u32 = parts[1].parse().ok()?;
            if (1..=12).contains(&m) && (1..=31).contains(&d) {
                return Some(m * 100 + d);
            }
        }
    }
    None
}

/// Unix 秒 → MMDD（Howard Hinnant 的 civil_from_days）。
fn mmdd_of_timestamp(ts: f64) -> u32 {
    let days = (ts / 86_400.0).floor() as i64;
    let (_, m, d) = civil_from_days(days);
    (m as u32) * 100 + d as u32
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules_ast::{DataType, NodeMeta, Param, Span};

    struct NoEnv;
    impl DecisionEnv for NoEnv {
        fn eval_bound(&mut self, e: &Expr, _params: &[(String, Value)]) -> Value {
            match e {
                Expr::Number(n) => Value::Num(*n),
                Expr::Str(s) => Value::Text(s.clone()),
                _ => Value::Num(0.0),
            }
        }
    }

    fn table(hit: HitPolicy) -> DecisionTableDecl {
        let p = |n: &str| Param { name: n.into(), ty: DataType::Timestamp };
        let row = |lo: &str, hi: &str, out: f64| DecisionRow {
            inputs: vec![InputEntry::Range {
                lo: Expr::Str(lo.into()),
                hi: Expr::Str(hi.into()),
            }],
            outputs: vec![Expr::Number(out)],
            is_default: false,
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        DecisionTableDecl {
            name: "D".into(),
            params: vec![p("req_time")],
            outputs: vec![p("amount")],
            hit_policy: hit,
            rows: vec![
                row("11-01", "11-03", 10.0),
                row("11-04", "11-05", 20.0),
                row("11-06", "11-06", 5.0),
                DecisionRow {
                    inputs: vec![],
                    outputs: vec![Expr::Number(0.0)],
                    is_default: true,
                    meta: NodeMeta::default(),
                    span: Span::default(),
                },
            ],
            meta: NodeMeta::default(),
            span: Span::default(),
        }
    }

    /// 2026-11-02 00:00:00 UTC 的 Unix 秒。
    fn ts(y: i64, mo: i64, d: i64) -> f64 {
        let days = days_from_civil(y, mo, d);
        (days * 86_400) as f64
    }

    fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as i64;
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    #[test]
    fn unique_hit_policy_picks_first_match() {
        let dt = table(HitPolicy::Unique);
        let out = evaluate(&dt, &[Value::Num(ts(2026, 11, 2))], &mut NoEnv);
        assert_eq!(out.outputs, vec![Value::Num(10.0)]);
        assert_eq!(out.row, Some(0));
        assert!(!out.default);
    }

    #[test]
    fn default_row_handles_non_promotion_period() {
        let dt = table(HitPolicy::Unique);
        let out = evaluate(&dt, &[Value::Num(ts(2026, 12, 1))], &mut NoEnv);
        assert!(out.default);
        assert_eq!(out.outputs, vec![Value::Num(0.0)]);
    }

    #[test]
    fn collect_returns_all_matches() {
        let mut dt = table(HitPolicy::Collect);
        // 让两行同时命中
        dt.rows[1].inputs = vec![InputEntry::Range {
            lo: Expr::Str("11-01".into()),
            hi: Expr::Str("11-05".into()),
        }];
        let out = evaluate(&dt, &[Value::Num(ts(2026, 11, 2))], &mut NoEnv);
        assert_eq!(out.hit_count(), 2);
        assert_eq!(out.outputs, vec![Value::Num(10.0), Value::Num(20.0)]);
    }

    #[test]
    fn mmdd_calendar_window_is_inclusive() {
        assert_eq!(mmdd_of_timestamp(ts(2026, 11, 3)), 1103);
        assert_eq!(mmdd_of_timestamp(ts(2026, 11, 4)), 1104);
        let dt = table(HitPolicy::First);
        let out = evaluate(&dt, &[Value::Num(ts(2026, 11, 5))], &mut NoEnv);
        assert_eq!(out.outputs, vec![Value::Num(20.0)]);
    }
}
