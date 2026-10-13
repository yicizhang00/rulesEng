//! rules-diff — 规则版本语义级对比（Semantic Diff & Subsumption）。
//!
//! 传统 Git 文本 diff 看不出规则"收紧了"还是"放宽了"。本模块在 AST 层
//! 对两条 contract 做逻辑包含关系判定：
//!
//! - **Equivalent**：新旧规则逻辑等价，无实质变化；
//! - **Tightened**：新规则比旧规则更严（误报减少、漏报风险下降）；
//! - **Loosened**：新规则比旧规则更松（**潜在漏报漏洞**，需要合规复核）；
//! - **ChangedActionOnly**：触发条件未变，只改了告警级别/处置动作；
//! - **Incomparable**：结构差异过大，无法自动判定，需人工 review。
//!
//! v1 用保守的符号求值（阈值提取 + 结构相似度），后续可替换为 Z3
//! 后端：证明 `(P_old => Q_old) => (P_new => Q_new)` 永真即 Tightened。

use rules_ast::*;
use rules_smt::guard_tightened;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffVerdict {
    Equivalent,
    Tightened,
    Loosened,
    ChangedActionOnly,
    Incomparable,
}

#[derive(Debug, Clone)]
pub struct ContractDiff {
    pub spec: String,
    pub verdict: DiffVerdict,
    pub details: Vec<String>,
}

/// 对整份 spec 的两个版本做逐 contract 对比。
pub fn diff_specs(old: &SpecFile, new: &SpecFile) -> Vec<ContractDiff> {
    let mut out = Vec::new();
    for nc in &new.specs {
        match old.specs.iter().find(|c| c.name == nc.name) {
            Some(oc) => out.push(diff_contract(oc, nc)),
            None => out.push(ContractDiff {
                spec: nc.name.clone(),
                verdict: DiffVerdict::Incomparable,
                details: vec!["new spec, no old version to compare".into()],
            }),
        }
    }
    out
}

pub fn diff_contract(old: &SpecDecl, new: &SpecDecl) -> ContractDiff {
    let mut details = Vec::new();

    // 1. 比较 guard 阈值（符号级判定，不仅看数字）
    let guard_verdict = match (&old.violation.guard, &new.violation.guard) {
        (Some(og), Some(ng)) => match guard_tightened(og, ng) {
            Some(true) => {
                details.push("guard is logically tighter (new => old)".into());
                Some(DiffVerdict::Tightened)
            }
            Some(false) => {
                details.push("guard is logically looser (old => new) — potential regression".into());
                Some(DiffVerdict::Loosened)
            }
            None => None,
        },
        _ => None,
    };

    // 2. 比较 transition
    if old.violation.transition != new.violation.transition {
        details.push(format!(
            "transition: {:?} -> {:?}",
            old.violation.transition, new.violation.transition
        ));
    }

    // 3. 比较 severity
    if std::mem::discriminant(&old.violation.severity) != std::mem::discriminant(&new.violation.severity)
    {
        details.push(format!(
            "severity changed: {:?} -> {:?}",
            old.violation.severity, new.violation.severity
        ));
    }

    // 4. 综合判定
    let verdict = if old.invariant == new.invariant && old.violation.guard == new.violation.guard {
        if old.violation.transition == new.violation.transition
            && std::mem::discriminant(&old.violation.severity)
                == std::mem::discriminant(&new.violation.severity)
        {
            DiffVerdict::Equivalent
        } else {
            DiffVerdict::ChangedActionOnly
        }
    } else if let Some(v) = guard_verdict {
        v
    } else {
        DiffVerdict::Incomparable
    };

    ContractDiff {
        spec: old.name.clone(),
        verdict,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules_parser::parse;

    fn src(guard: &str) -> String {
        format!(
            r#"
            entity Company {{ key: code states: [NORMAL, X] initial: NORMAL }}
            stream S = Stream[E].filter(event.t == "S")
            contract C on Company {{
                invariant: historically(exists(S), within: 1d) implies always(true)
                violation {{
                    severity: CRITICAL
                    guard: {guard}
                    emit: "x"
                }}
            }}
            "#
        )
    }

    #[test]
    fn detects_tightening_when_threshold_increases() {
        let old = parse(&src("DaysOverdue(d) > 5.0")).unwrap();
        let new = parse(&src("DaysOverdue(d) > 10.0")).unwrap();
        let d = diff_contract(&old.specs[0], &new.specs[0]);
        assert_eq!(d.verdict, DiffVerdict::Tightened);
    }

    #[test]
    fn detects_loosening_regression_hole() {
        let old = parse(&src("DaysOverdue(d) > 10.0")).unwrap();
        let new = parse(&src("DaysOverdue(d) > 3.0")).unwrap();
        let d = diff_contract(&old.specs[0], &new.specs[0]);
        assert_eq!(d.verdict, DiffVerdict::Loosened);
    }

    #[test]
    fn detects_equivalent() {
        let old = parse(&src("DaysOverdue(d) > 5.0")).unwrap();
        let new = parse(&src("DaysOverdue(d) > 5.0")).unwrap();
        let d = diff_contract(&old.specs[0], &new.specs[0]);
        assert_eq!(d.verdict, DiffVerdict::Equivalent);
    }

    #[test]
    fn action_only_change() {
        let old = parse(&src("DaysOverdue(d) > 5.0")).unwrap();
        let mut new = parse(&src("DaysOverdue(d) > 5.0")).unwrap();
        new.specs[0].violation.severity = Severity::Warning;
        let d = diff_contract(&old.specs[0], &new.specs[0]);
        assert_eq!(d.verdict, DiffVerdict::ChangedActionOnly);
    }
}
