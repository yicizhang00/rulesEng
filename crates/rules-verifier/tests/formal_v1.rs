//! v1.0 形式化验证验收测试（PRD §8 · AC1，以及 FR1–FR3 / FR6 / FR7 的编译期证明）。
//!
//! 每条断言都要求**结论 + 反例参数**同时正确：只说"有冲突"不算通过，
//! 必须能给出让冲突发生的具体输入。

use rules_dictionary::DataDictionary;
use rules_verifier::{Verifier, VerifyReport};

fn report(src: &str) -> VerifyReport {
    let spec = rules_parser::parse(src).unwrap_or_else(|e| panic!("解析失败: {e}\n{src}"));
    Verifier::verify_report(&spec, &DataDictionary::default())
}

fn find<'a>(r: &'a VerifyReport, kind: &str) -> Option<&'a rules_verifier::VerifyIssue> {
    r.errors.iter().chain(r.warnings.iter()).find(|i| i.kind == kind)
}

// =====================================================================
// AC1 —— 冲突规则被拒 + 输出反例参数
// =====================================================================

#[test]
fn ac1_contradictory_verdicts_are_rejected_with_counterexample() {
    // 同一实体、同一事件：一条硬性拒绝，一条显式放行且条件重叠
    let src = r#"
        contract Gate on Entity[Account] pure {
            key: account_id
            states: [NORMAL, BLOCKED]
            initial: NORMAL

            guard BlockRisky on Event[TradeIntent] {
                when: risk_score > 70
                verdict: DENY(code: "ERR_RISKY", reason: "风险分过高")
            }
            guard AllowTrusted on Event[TradeIntent] {
                when: risk_score > 50
                verdict: ALLOW()
            }
        }
    "#;
    let r = report(src);
    assert!(!r.is_ok(), "互斥裁决的规则必须被拒绝");

    let issue = find(&r, "CONFLICTING_SPECS").expect("应当报 CONFLICTING_SPECS");
    assert_eq!(issue.severity, "error");
    // 反例参数：risk_score 必须同时 > 70 与 > 50
    let score = issue
        .counterexample
        .iter()
        .find(|(v, _)| v == "risk_score")
        .map(|(_, k)| *k)
        .expect("反例必须给出 risk_score");
    assert!(score > 70.0, "反例必须让两条规则同时命中：{}", issue.counterexample_text);
    assert!(issue.message.contains("counterexample"), "{}", issue.message);
}

#[test]
fn ac1_non_overlapping_rules_are_accepted() {
    // 条件互斥：risk_score > 70 与 risk_score < 30 不可能同时成立 → 不报冲突
    let src = r#"
        contract Gate on Entity[Account] pure {
            key: account_id
            guard BlockRisky on Event[TradeIntent] {
                when: risk_score > 70
                verdict: DENY(code: "ERR_RISKY", reason: "高风险")
            }
            guard AllowSafe on Event[TradeIntent] {
                when: risk_score < 30
                verdict: ALLOW()
            }
        }
    "#;
    let r = report(src);
    assert!(find(&r, "CONFLICTING_SPECS").is_none(), "互斥条件不应报冲突：{:?}", r.errors);
}

#[test]
fn ac1_same_direction_double_deny_is_not_a_conflict() {
    // 分层防御：`guard` 快筛 + `invariant` 全量，两者都 DENY 但错误码不同 —— 合法
    let src = r#"
        contract Gate on Entity[Account] pure {
            key: account_id
            state var frozen_until: Timestamp = 0
            guard IsNotFrozen on Event[TradeIntent] {
                when: now() < frozen_until
                verdict: DENY(code: "ERR_FROZEN", reason: "冻结期")
            }
            invariant RiskLimit on Event[TradeIntent] {
                when: risk_score > 70
                verdict: DENY(code: "ERR_RISKY", reason: "高风险")
            }
        }
    "#;
    let r = report(src);
    assert!(find(&r, "CONFLICTING_SPECS").is_none(), "同向 DENY 不应判为冲突：{:?}", r.errors);
}

// =====================================================================
// FR3 —— DMN 决策表互斥 / 完备（§4.4.2）
// =====================================================================

#[test]
fn dmn_unique_policy_requires_mutually_exclusive_rows() {
    let src = r#"
        contract Coupon on Entity[User] decision_table {
            key: user_id
            decision_table Pick(req_time: Timestamp) -> (amount: Int, phase: Int) {
                hit_policy: UNIQUE
                rules: [
                    in [11-01 .. 11-05] => (10, 0x01),
                    in [11-03 .. 11-08] => (20, 0x02),
                    default             => (0, 0x00)
                ]
            }
            invariant Guard on Event[IssueIntent] {
                let (amount, phase) = Pick(event.timestamp)
                when: event.amount != amount
                verdict: DENY(code: "ERR_AMOUNT", reason: "额度不符")
            }
        }
    "#;
    let r = report(src);
    let issue = find(&r, "DMN_ROW_OVERLAP").expect("11-01..11-05 与 11-03..11-08 必须报重叠");
    assert_eq!(issue.severity, "error");
    // 反例落在 11-03 ~ 11-05 之间（MMDD 口径：1103..1105）
    let t = issue.counterexample.iter().find(|(v, _)| v == "req_time").unwrap().1;
    assert!((1103.0..=1105.0).contains(&t), "反例必须落在重叠区：{t}");
}

#[test]
fn dmn_missing_default_is_reported_as_gap_with_witness() {
    let src = r#"
        contract Coupon on Entity[User] decision_table {
            key: user_id
            decision_table Pick(req_time: Timestamp) -> (amount: Int) {
                hit_policy: UNIQUE
                rules: [
                    in [11-01 .. 11-03] => (10),
                    in [11-04 .. 11-05] => (20)
                ]
            }
            invariant Guard on Event[IssueIntent] {
                when: event.requested != 10
                verdict: DENY(code: "ERR_AMOUNT", reason: "额度不符")
            }
        }
    "#;
    let r = report(src);
    let issue = find(&r, "DMN_COVERAGE_GAP").expect("缺少 default 且存在未覆盖区间必须报缺口");
    let t = issue.counterexample.iter().find(|(v, _)| v == "req_time").unwrap().1;
    assert!(t > 1105.0 || t < 1101.0, "反例必须落在覆盖之外：{t}");
}

#[test]
fn dmn_complete_table_with_default_passes() {
    let src = r#"
        contract Coupon on Entity[User] decision_table {
            key: user_id
            decision_table Pick(req_time: Timestamp) -> (amount: Int) {
                hit_policy: UNIQUE
                rules: [
                    in [11-01 .. 11-03] => (10),
                    in [11-04 .. 11-05] => (20),
                    default             => (0)
                ]
            }
            invariant Guard on Event[IssueIntent] {
                when: event.requested != 10
                verdict: DENY(code: "ERR_AMOUNT", reason: "额度不符")
            }
        }
    "#;
    let r = report(src);
    assert!(find(&r, "DMN_ROW_OVERLAP").is_none(), "{:?}", r.errors);
    assert!(find(&r, "DMN_COVERAGE_GAP").is_none(), "{:?}", r.errors);
}

#[test]
fn dmn_output_arity_mismatch_is_an_error() {
    let src = r#"
        contract Coupon on Entity[User] decision_table {
            key: user_id
            decision_table Pick(t: Timestamp) -> (amount: Int, phase: Int) {
                hit_policy: FIRST
                rules: [
                    in [11-01 .. 11-03] => (10),
                    default             => (0, 0x00)
                ]
            }
            invariant Guard on Event[IssueIntent] {
                when: event.requested != 10
                verdict: DENY(code: "ERR_AMOUNT", reason: "额度不符")
            }
        }
    "#;
    let r = report(src);
    let issue = find(&r, "DMN_ARITY_MISMATCH").expect("输出列数不匹配必须报错");
    assert!(issue.message.contains("1 output"), "{}", issue.message);
}

// =====================================================================
// FR1 —— var range 作为 DomainAxiom
// =====================================================================

#[test]
fn var_range_empty_is_rejected() {
    let src = r#"
        contract C on Entity[Account] pure {
            key: account_id
            var quota: int range: 100 .. 10 = 50
            invariant Guard on Event[E] {
                when: quota > 200
                verdict: DENY(code: "E", reason: "x")
            }
        }
    "#;
    let r = report(src);
    assert!(find(&r, "VAR_RANGE_EMPTY").is_some(), "{:?}", r.errors);
}

#[test]
fn var_range_dead_zone_is_a_warning() {
    // quota ∈ [0, 100]，但守卫要求 quota > 200 → 域内永不触发
    let src = r#"
        contract C on Entity[Account] pure {
            key: account_id
            var quota: int range: 0 .. 100 = 50
            invariant Guard on Event[E] {
                when: quota > 200
                verdict: DENY(code: "E", reason: "x")
            }
        }
    "#;
    let r = report(src);
    let issue = find(&r, "VAR_GUARD_OUT_OF_RANGE").expect("域外守卫必须被指出");
    assert_eq!(issue.severity, "warning");
}

// =====================================================================
// FR2 —— 除零证明
// =====================================================================

#[test]
fn division_by_zero_is_proved_with_witness() {
    // avg_days = total_days / successful_days，且 successful_days ∈ [0, 30]
    let src = r#"
        contract C on Entity[Account] pure {
            key: account_id
            var successful_days: int range: 0 .. 30 = 10
            invariant Guard on Event[E] {
                when: total_days / successful_days > 5
                verdict: DENY(code: "ERR_RATIO", reason: "日均过高")
            }
        }
    "#;
    let r = report(src);
    let issue = find(&r, "DIVISION_BY_ZERO").expect("分母可取 0 必须报除零");
    let v = issue
        .counterexample
        .iter()
        .find(|(n, _)| n == "successful_days")
        .map(|(_, k)| *k)
        .expect("反例必须给出分母变量");
    assert_eq!(v, 0.0, "除零反例的分母必须为 0");
}

#[test]
fn division_by_constant_is_not_reported() {
    let src = r#"
        contract C on Entity[Account] pure {
            key: account_id
            invariant Guard on Event[E] {
                when: total / 86400.0 > 365
                verdict: DENY(code: "E", reason: "x")
            }
        }
    "#;
    let r = report(src);
    assert!(find(&r, "DIVISION_BY_ZERO").is_none(), "{:?}", r.errors);
}

// =====================================================================
// FR7 —— 模式 B 的 DAG 环检测
// =====================================================================

#[test]
fn cyclic_stateful_rules_are_rejected_at_compile_time() {
    let src = r#"
        rule "A" stateful {
            when: $x: X()
            then: insert(Y { v: $x.v });
        }
        rule "B" stateful {
            when: $y: Y()
            then: insert(X { v: $y.v });
        }
    "#;
    let r = report(src);
    let issue = find(&r, "CYCLIC_RULES").expect("环依赖必须被静态驳回");
    assert_eq!(issue.severity, "error");
    assert!(issue.message.contains("Y") && issue.message.contains("X"), "{}", issue.message);
}

#[test]
fn acyclic_stateful_rules_pass() {
    let src = r#"
        rule "Derive" stateful {
            when: $a: Account(trade_frequency_5s > 10)
                  not exists Tag(account_id == $a.id)
            then: insert(Tag { account_id: $a.id });
        }
        rule "Act" stateful {
            when: $t: Tag()
                  $o: Order(account_id == $t.account_id)
            then: yield DENY(code: "ERR", reason: "x")
        }
    "#;
    let r = report(src);
    assert!(find(&r, "CYCLIC_RULES").is_none(), "{:?}", r.errors);
}

// =====================================================================
// FR6 —— 边缘跃迁算子的 metric 必须已声明
// =====================================================================

#[test]
fn undefined_edge_metric_is_an_error() {
    let src = r#"
        contract C on Entity[Account] pure {
            key: account_id
            invariant Edge on Event[E] {
                when: crosses_above(not_declared, 10)
                verdict: DENY(code: "E", reason: "x")
            }
        }
    "#;
    let r = report(src);
    let issue = find(&r, "UNDEFINED_EDGE_METRIC").expect("未声明的边缘指标必须报错");
    assert!(issue.message.contains("not_declared"), "{}", issue.message);
}

#[test]
fn declared_edge_metric_passes() {
    let src = r#"
        contract C on Entity[Account] pure {
            key: account_id
            metric pressure := 0
            invariant Edge on Event[Tick] {
                when: crosses_above(pressure, 10)
                verdict: DENY(code: "E", reason: "x")
            }
        }
    "#;
    let r = report(src);
    assert!(find(&r, "UNDEFINED_EDGE_METRIC").is_none(), "{:?}", r.errors);
}

// =====================================================================
// 回归：PRD §5 的四个用例必须全部通过门禁
// =====================================================================

#[test]
fn all_prd_examples_pass_the_gate() {
    for name in [
        "seat_flood_protection.rules",
        "additional_issuance.rules",
        "ecommerce_coupon.rules",
        "suspicious_account.rules",
    ] {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(name);
        let src = std::fs::read_to_string(&p).unwrap();
        let r = report(&src);
        assert!(r.is_ok(), "{name} 必须通过门禁，实际错误：{:?}", r.errors);
    }
}
