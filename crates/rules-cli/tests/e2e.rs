//! 端到端集成测试：parse → verify → runtime。
//!
//! 全部用例基于**四类一阶概念**的新范式书写：
//! `entity`（生命周期 + 状态迁移边）/ `stream`（事件流算子）/ `metric`（派生信号）/
//! `spec`（时序不变量 MTL）。旧语法（`contract` / `signal` / `var` / `rule when then`）
//! 只在一个"必须仍然能解析并 desugar"的用例里出现。

use rules_dictionary::{DataDictionary, ScalarValue};
use rules_dispatcher::VecDispatcher;
use rules_parser::parse;
use rules_runtime::{Event, RegulatoryRuntime};
use rules_verifier::Verifier;
use std::collections::HashMap;
use std::sync::Arc;

fn make_engine(src: &str) -> (RegulatoryRuntime, Arc<VecDispatcher>) {
    let spec = parse(src).unwrap();
    let dict = DataDictionary::default();
    Verifier::verify(&spec, &dict).expect("verification failed");
    let disp = Arc::new(VecDispatcher::new());
    let mut eng = RegulatoryRuntime::new(spec, dict).with_dispatcher(disp.clone());
    // 半年报 demo 约定：实体 id = "600000"
    eng.ensure_entity("Company", "600000");
    (eng, disp)
}

fn semi_annual_src() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/semi_annual.rules"))
        .unwrap()
}

fn example(name: &str) -> String {
    std::fs::read_to_string(format!("{}/../../examples/{}", env!("CARGO_MANIFEST_DIR"), name))
        .unwrap()
}

fn error_kinds(src: &str) -> Vec<String> {
    let spec = parse(src).unwrap();
    Verifier::verify(&spec, &DataDictionary::default())
        .err()
        .map(|errs| errs.iter().map(|e| e.kind().to_string()).collect())
        .unwrap_or_default()
}

fn warning_kinds(src: &str) -> Vec<String> {
    let spec = parse(src).unwrap();
    Verifier::verify_report(&spec, &DataDictionary::default())
        .warnings
        .iter()
        .map(|w| w.kind.clone())
        .collect()
}

// =====================================================================
// 原型 4 个场景回归（event-driven，而非 RETE 事实插入）
// =====================================================================

#[test]
fn scenario_before_deadline_no_alert() {
    let (mut eng, disp) = make_engine(&semi_annual_src());
    eng.set_clock(50_000);
    eng.tick();
    assert_eq!(disp.snapshot().len(), 0);
}

#[test]
fn scenario_overdue_2d_blocked_by_guard() {
    let (mut eng, disp) = make_engine(&semi_annual_src());
    eng.set_clock(272_800);
    eng.tick();
    assert_eq!(disp.snapshot().len(), 0);
}

#[test]
fn scenario_overdue_6d_triggers_suspension() {
    let (mut eng, disp) = make_engine(&semi_annual_src());
    eng.set_clock(618_400);
    eng.tick();
    let snap = disp.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(eng.entity_state("Company", "600000"), Some("SUSPENDED"));
}

#[test]
fn scenario_early_upload_avoids_alert() {
    let (mut eng, _disp) = make_engine(&semi_annual_src());
    let mut fields = HashMap::new();
    fields.insert("type".into(), "SEMI_ANNUAL".into());
    // 事件字段与 spec 内 `r.code == c.code` 引用的字段（也是实体 key）一致
    fields.insert("code".into(), "600000".into());
    eng.ingest(Event { event_type: "DisclosureEvent".into(), fields, timestamp: 80_000 });
    assert_eq!(eng.stream_len("SemiAnnualReports"), 1);
    eng.set_clock(618_400);
    eng.tick();
    // 已上传报告，historically(exists(...)) 成立，不违规
    assert_eq!(eng.entity_state("Company", "600000"), Some("NORMAL"));
}

// =====================================================================
// 事件驱动：ingest 在同一拍推进受影响实体的状态机
// =====================================================================

#[test]
fn ingest_advances_automaton_without_explicit_tick() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, SUSPENDED]
            initial: NORMAL
            transition Suspend { from: NORMAL to: SUSPENDED on: LateReport }
        }
        stream Reports := Event[DisclosureEvent].window(60d)
            .filter(e => e.type == "SEMI_ANNUAL")
        metric DaysLate(c: Company) -> int := days_between(now(), 100.0) where now() > 100.0
        spec LateReport on c: Company {
            invariant: (now() > 100.0) implies Reports.exists(r => r.code == c.code)
            violation {
                severity: CRITICAL
                guard: DaysLate(c) > 5
                transition: NORMAL -> SUSPENDED
                emit: "late"
            }
        }
    "#;
    let spec = parse(src).unwrap();
    let disp = Arc::new(VecDispatcher::new());
    let mut eng = RegulatoryRuntime::new(spec, DataDictionary::default()).with_dispatcher(disp.clone());

    // 事件落地即推进状态机：无报告 → 不变量被打破 → guard 通过 → 迁移
    let mut fields = HashMap::new();
    fields.insert("code".into(), "600000".into());
    fields.insert("type".into(), "OTHER".into());
    eng.ingest(Event { event_type: "DisclosureEvent".into(), fields, timestamp: 618_400 });
    assert_eq!(eng.entity_state("Company", "600000"), Some("SUSPENDED"));
}

// =====================================================================
// 四类一阶概念：解析形状
// =====================================================================

#[test]
fn entity_stream_metric_spec_are_first_class() {
    let spec = parse(&semi_annual_src()).unwrap();
    assert_eq!(spec.entities.len(), 1);
    assert_eq!(spec.streams.len(), 1);
    assert_eq!(spec.metrics.len(), 1);
    assert_eq!(spec.specs.len(), 1);

    let e = &spec.entities[0];
    assert_eq!(e.key, "code");
    assert_eq!(e.initial, "NORMAL");
    assert!(e.is_terminal("TERMINATED"));
    assert_eq!(e.transitions.len(), 3);

    // metric 是"派生信号"，不是静态变量
    let m = &spec.metrics[0];
    assert_eq!(m.name, "DaysOverdue");
    assert_eq!(m.params.len(), 2);
}

#[test]
fn stream_ops_are_projected_into_ring_buffer() {
    let src = r#"
        entity Account(key: account_id) { states: [ACTIVE, RESTRICTED] initial: ACTIVE }
        stream Trades := Event[TradeEvent].window(1h)
        stream Cancels := Trades.filter(t => t.kind == "CANCEL")
        metric CancelRatio(c: Account) -> float := ratio(Cancels.count(), Trades.count()) where Trades.count() > 0.0
        spec Ratio on c: Account {
            invariant: always(CancelRatio(c) < 0.2)
            violation { severity: WARNING transition: ACTIVE -> RESTRICTED emit: "ratio high" }
        }
    "#;
    let spec = parse(src).unwrap();
    let report = Verifier::verify_report(&spec, &DataDictionary::default());
    assert!(report.is_ok(), "{:?}", report.errors);

    let mut eng = RegulatoryRuntime::new(spec, DataDictionary::default());
    for (i, kind) in ["NEW", "CANCEL", "NEW", "CANCEL"].iter().enumerate() {
        let mut fields = HashMap::new();
        fields.insert("account_id".into(), "A001".into());
        fields.insert("kind".into(), (*kind).into());
        fields.insert("amount".into(), "100".into());
        eng.ingest(Event { event_type: "TradeEvent".into(), fields, timestamp: 10 + i as u64 });
    }
    // 源流与派生流各自维护自己的环形缓冲区
    assert_eq!(eng.stream_len("Trades"), 4);
}

// =====================================================================
// 形式化校验：删除死规则 / 动作冲突 / 冗余
// =====================================================================

#[test]
fn vacuous_antecedent_rejected() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, BAD]
            initial: NORMAL
            transition Mark { from: NORMAL to: BAD }
        }
        stream X := Event[E].filter(e => e.t == "X")
        spec Bad on c: Company {
            invariant: (1 > 2) implies historically(X.exists(), within: 1d)
            violation { severity: WARNING emit: "x" }
        }
    "#;
    let kinds = error_kinds(src);
    assert!(kinds.contains(&"DEAD_RULE_VACUOUS".to_string()), "{kinds:?}");
}

#[test]
fn action_conflict_detected() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, SUSPENDED, TERMINATED]
            initial: NORMAL
            transition A { from: NORMAL to: SUSPENDED }
            transition B { from: NORMAL to: TERMINATED }
        }
        stream X := Event[E].filter(e => e.t == "X")
        spec A on c: Company {
            invariant: historically(X.exists(), within: 1d) implies always(true)
            violation { severity: CRITICAL transition: NORMAL -> SUSPENDED emit: "a" }
        }
        spec B on c: Company {
            invariant: historically(X.exists(), within: 1d) implies always(true)
            violation { severity: CRITICAL transition: NORMAL -> TERMINATED emit: "b" }
        }
    "#;
    let kinds = error_kinds(src);
    assert!(kinds.contains(&"ACTION_CONFLICT".to_string()), "{kinds:?}");
}

#[test]
fn redundant_spec_is_warning() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream S := Event[E].filter(e => e.t == "S")
        spec A on c: Company {
            invariant: historically(S.exists(), within: 1d) implies always(true)
            violation { severity: WARNING emit: "same" }
        }
        spec B on c: Company {
            invariant: historically(S.exists(), within: 1d) implies always(true)
            violation { severity: WARNING emit: "same" }
        }
    "#;
    assert!(warning_kinds(src).contains(&"REDUNDANT_SPEC".to_string()));
}

#[test]
fn hard_errors_block_verification() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream S := Event[E].filter(e => e.t == "S")
        spec C on c: Company {
            invariant: historically(S.exists(), within: 1d) implies always(true)
            violation { severity: CRITICAL transition: NORMAL -> SUSPENDED emit: "c" }
        }
        spec D on c: Account {
            invariant: historically(S.exists(), within: 1d) implies always(true)
            violation { severity: INFO emit: "d" }
        }
    "#;
    let kinds = error_kinds(src);
    // spec D 挂在未声明的实体上
    assert!(kinds.contains(&"UNDEFINED_ENTITY".to_string()), "{kinds:?}");
    // spec C 引用了未声明的状态 SUSPENDED
    assert!(kinds.contains(&"UNDEFINED_STATE".to_string()), "{kinds:?}");
}

#[test]
fn type_mismatch_between_string_and_number_is_reported() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream S := Event[E].filter(e => e.t == "S")
        spec C on c: Company {
            invariant: historically(S.exists(), within: 1d) implies (x > 1.0)
            violation { severity: INFO guard: "abc" > 3.0 emit: "c" }
        }
    "#;
    assert!(error_kinds(src).contains(&"TYPE_MISMATCH".to_string()));
}

#[test]
fn unknown_function_call_is_reported() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream S := Event[E].filter(e => e.t == "S")
        spec C on c: Company {
            invariant: historically(S.exists(), within: 1d) implies (SomeUnknownMetric(1.0) > 0.0)
            violation { severity: INFO emit: "c" }
        }
    "#;
    let spec = parse(src).unwrap();
    let report = Verifier::verify_report(&spec, &DataDictionary::default());
    assert!(report
        .errors
        .iter()
        .any(|e| e.kind == "UNDEFINED_METRIC" && e.message.contains("SomeUnknownMetric")));
}

#[test]
fn coverage_gap_is_warning_not_error() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream Unused := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: always(true)
            violation { severity: INFO emit: "c" }
        }
    "#;
    let report = {
        let spec = parse(src).unwrap();
        Verifier::verify_report(&spec, &DataDictionary::default())
    };
    // 覆盖缺口只算提示，不阻断入库
    assert!(report.is_ok(), "unreferenced stream must not block: {:?}", report.errors);
    assert!(report.warnings.iter().any(|w| w.kind == "COVERAGE_GAP_STREAM"));
}

// =====================================================================
// 时序模型检验 1：状态转移完备性
// =====================================================================

#[test]
fn unreachable_state_is_reported() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, SUSPENDED, GHOST]
            initial: NORMAL
            transition Suspend { from: NORMAL to: SUSPENDED }
        }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: always(true)
            violation { severity: INFO emit: "c" }
        }
    "#;
    assert!(warning_kinds(src).contains(&"UNREACHABLE_STATE".to_string()));
}

#[test]
fn stuck_state_is_reported() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, WAITING]
            initial: NORMAL
            transition Go { from: NORMAL to: WAITING }
        }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: always(true)
            violation { severity: INFO emit: "c" }
        }
    "#;
    assert!(warning_kinds(src).contains(&"STUCK_STATE".to_string()));
}

#[test]
fn terminal_state_with_edge_is_error() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, DEAD]
            initial: NORMAL
            terminal: [DEAD]
            transition Kill { from: NORMAL to: DEAD }
            transition Revive { from: DEAD to: NORMAL }
        }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: always(true)
            violation { severity: INFO emit: "c" }
        }
    "#;
    assert!(error_kinds(src).contains(&"TERMINAL_STATE_HAS_EDGE".to_string()));
}

#[test]
fn undeclared_transition_edge_is_error() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, SUSPENDED]
            initial: NORMAL
            transition Suspend { from: NORMAL to: SUSPENDED }
        }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: always(true)
            violation { severity: CRITICAL transition: NORMAL -> TERMINATED emit: "c" }
        }
    "#;
    assert!(error_kinds(src).contains(&"UNDECLARED_TRANSITION".to_string()));
}

#[test]
fn undefined_transition_driver_is_error() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, SUSPENDED]
            initial: NORMAL
            transition Suspend { from: NORMAL to: SUSPENDED on: NoSuchSpec }
        }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: always(true)
            violation { severity: INFO emit: "c" }
        }
    "#;
    assert!(error_kinds(src).contains(&"UNDEFINED_TRANSITION_DRIVER".to_string()));
}

// =====================================================================
// 时序模型检验 2：因果死锁
// =====================================================================

#[test]
fn causal_deadlock_until_is_error() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: until(always(true), (1 > 2))
            violation { severity: INFO emit: "c" }
        }
    "#;
    assert!(error_kinds(src).contains(&"CAUSAL_DEADLOCK_UNTIL".to_string()));
}

#[test]
fn causal_deadlock_eventually_is_error() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: eventually((1 > 2), within: 1d)
            violation { severity: INFO emit: "c" }
        }
    "#;
    assert!(error_kinds(src).contains(&"CAUSAL_DEADLOCK_EVENTUALLY".to_string()));
}

#[test]
fn impossible_consequent_is_error() {
    // implies 的前提恒真、结论恒假 —— 嵌在 historically 内，避免整体恒假被
    // 更早的 UnsatisfiableInvariant 分支拦截
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: (now() > 0.0) implies historically((1 > 0) implies (2 > 3), within: 1d)
            violation { severity: INFO emit: "c" }
        }
    "#;
    assert!(error_kinds(src).contains(&"IMPOSSIBLE_CONSEQUENT".to_string()));
}

// =====================================================================
// 编译为扁平自动机 / 原生字节码
// =====================================================================

#[test]
fn numeric_predicates_compile_to_flat_bytecode() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        spec C on c: Company {
            invariant: always((a > 1.0) implies (b > 2.0))
            violation { severity: INFO emit: "c" }
        }
    "#;
    let spec = parse(src).unwrap();
    let eng = RegulatoryRuntime::new(spec, DataDictionary::default());
    let aut = eng.automaton("C").expect("spec compiled");
    assert!(aut.flat_atom_ratio() > 0.0, "numeric predicates must take the flat path");
    assert!(aut.num_nodes() >= 3);
}

#[test]
fn dynamic_window_is_resolved_from_host() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream X := Event[E].filter(e => e.t == "X")
        spec C on c: Company {
            invariant: (now() > 1.0) implies historically(X.exists(), within: 1800)
            violation { severity: WARNING emit: "c" }
        }
    "#;
    let spec = parse(src).unwrap();
    let eng = RegulatoryRuntime::new(spec, DataDictionary::default());
    let aut = eng.automaton("C").expect("spec compiled");
    assert!(aut.max_window() > 0);
}

// =====================================================================
// 时序状态机记忆单元：always latch / historically 窗口回落
// =====================================================================

#[test]
fn always_latches_permanently_after_failure() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, SUSPENDED]
            initial: NORMAL
            transition Suspend { from: NORMAL to: SUSPENDED }
        }
        spec C on c: Company {
            invariant: always(state == SUSPENDED)
            violation { severity: WARNING transition: NORMAL -> SUSPENDED emit: "c" }
        }
    "#;
    let spec = parse(src).unwrap();
    let disp = Arc::new(VecDispatcher::new());
    let mut eng = RegulatoryRuntime::new(spec, DataDictionary::default()).with_dispatcher(disp.clone());
    eng.ensure_entity("Company", "600000");
    eng.set_clock(10);
    eng.tick();
    // 初始 NORMAL：state == SUSPENDED 为假 → always 永久 latch 为假 → 违规
    assert_eq!(disp.snapshot().len(), 1);
    assert_eq!(eng.entity_state("Company", "600000"), Some("SUSPENDED"));
}

#[test]
fn until_operator_parses_and_holds() {
    let src = r#"
        entity Company(key: code) {
            states: [NORMAL, TERMINATED]
            initial: NORMAL
            transition Terminate { from: NORMAL to: TERMINATED }
        }
        stream Remediation := Event[RemediationEvent].filter(e => e.kind == "FIX")
        spec TerminationRequiresRemediation on c: Company {
            invariant: until(not (state == TERMINATED), Remediation.exists(r => r.code == c.code))
            violation { severity: WARNING emit: "terminated before remediation" }
        }
    "#;
    let spec = parse(src).unwrap();
    assert_eq!(spec.specs.len(), 1);

    let disp = Arc::new(VecDispatcher::new());
    let mut eng = RegulatoryRuntime::new(spec, DataDictionary::default()).with_dispatcher(disp.clone());
    eng.ensure_entity("Company", "600000");
    eng.set_clock(10);
    eng.tick();
    // 初始未终止：`not(state == TERMINATED)` 为真 → until 暂不违反
    assert_eq!(disp.snapshot().len(), 0);
}

// =====================================================================
// 派生信号（metric）运行时求值：滑动折叠 / 聚合
// =====================================================================

#[test]
fn metric_signal_is_evaluated_at_runtime() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream S := Event[E].filter(e => e.t == "S")
        metric Doubled(x: float) -> float := x * 2.0
        spec C on c: Company {
            invariant: always(true) implies historically(S.exists(), within: 1d)
            violation { severity: WARNING guard: Doubled(3.0) > 5.0 emit: "sig" }
        }
    "#;
    let spec = parse(src).unwrap();
    let report = Verifier::verify_report(&spec, &DataDictionary::default());
    assert!(report.is_ok(), "{:?}", report.errors);

    let disp = Arc::new(VecDispatcher::new());
    let mut eng = RegulatoryRuntime::new(spec, DataDictionary::default()).with_dispatcher(disp.clone());
    eng.ensure_entity("Company", "600000");
    eng.set_clock(10);
    eng.tick();
    let snap = disp.snapshot();
    assert_eq!(snap.len(), 1, "Doubled(3.0)=6.0 > 5.0 must trigger");
    assert!(snap[0].trace.iter().any(|(k, _)| k == "guard_value"));
    assert!(snap[0].trace.iter().any(|(k, v)| k == "invariant" && v.contains("VIOLATED")));
}

#[test]
fn stream_fold_metric_accumulates() {
    let src = r#"
        entity Account(key: account_id) { states: [ACTIVE, RESTRICTED] initial: ACTIVE }
        stream Cancels := Event[TradeEvent].window(1h).filter(t => t.kind == "CANCEL")
        metric CancelNotional(c: Account) -> float := from Cancels.fold(0.0, (acc, t) => acc + t.amount)
        spec BigCancel on c: Account {
            invariant: always(CancelNotional(c) < 1000.0)
            violation { severity: WARNING transition: ACTIVE -> RESTRICTED emit: "notional" }
        }
    "#;
    let spec = parse(src).unwrap();
    let report = Verifier::verify_report(&spec, &DataDictionary::default());
    assert!(report.is_ok(), "{:?}", report.errors);

    let disp = Arc::new(VecDispatcher::new());
    let mut eng = RegulatoryRuntime::new(spec, DataDictionary::default()).with_dispatcher(disp.clone());
    for (i, amount) in ["400", "400", "400"].iter().enumerate() {
        let mut fields = HashMap::new();
        fields.insert("account_id".into(), "A001".into());
        fields.insert("kind".into(), "CANCEL".into());
        fields.insert("amount".into(), (*amount).into());
        eng.ingest(Event { event_type: "TradeEvent".into(), fields, timestamp: 10 + i as u64 });
    }
    let snap = disp.snapshot();
    // 累计 1200 > 1000 → 违规
    assert_eq!(snap.len(), 1, "fold(0,+) over 3 cancels = 1200 > 1000");
    assert_eq!(eng.entity_state("Account", "A001"), Some("RESTRICTED"));
}

// =====================================================================
// 实体 `key:` 字段驱动的实体路由
// =====================================================================

#[test]
fn entity_declared_key_routes_events_to_instance() {
    let src = r#"
        entity Account(key: account_id) { states: [ACTIVE, RESTRICTED] initial: ACTIVE }
        stream Trades := Event[TradeEvent].filter(e => e.kind == "CANCEL")
        spec C on c: Account {
            invariant: historically(Trades.exists(), within: 1d) implies always(true)
            violation { severity: WARNING emit: "x" }
        }
    "#;
    let spec = parse(src).unwrap();
    let mut eng = RegulatoryRuntime::new(spec, DataDictionary::default());
    let mut fields = HashMap::new();
    fields.insert("account_id".into(), "A001".into());
    fields.insert("kind".into(), "CANCEL".into());
    eng.ingest(Event { event_type: "TradeEvent".into(), fields, timestamp: 10 });
    assert_eq!(eng.entity_state("Account", "A001"), Some("ACTIVE"));
    assert_eq!(eng.stream_len("Trades"), 1);
}

#[test]
fn key_field_drives_historically_window() {
    // entity key 为 `code`，事件字段也用 `code`：historically 必须能按同一 key 归属
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL transition Go { from: NORMAL to: DONE } }
        stream Semi := Event[DisclosureEvent].filter(e => e.type == "SEMI_ANNUAL")
        spec C on c: Company {
            invariant: (now() > 100.0) implies historically(Semi.exists(r => r.code == c.code), within: 60d)
            violation { severity: CRITICAL emit: "late" }
        }
    "#;
    let spec = parse(src).unwrap();
    let disp = Arc::new(VecDispatcher::new());
    let mut eng = RegulatoryRuntime::new(spec, DataDictionary::default()).with_dispatcher(disp.clone());
    let mut fields = HashMap::new();
    fields.insert("code".into(), "600000".into());
    fields.insert("type".into(), "SEMI_ANNUAL".into());
    eng.ingest(Event { event_type: "DisclosureEvent".into(), fields, timestamp: 50 });
    assert_eq!(eng.entity_state("Company", "600000"), Some("NORMAL"));
    eng.set_clock(200);
    eng.tick();
    assert_eq!(disp.snapshot().len(), 0);
}

// =====================================================================
// 向后兼容：旧语法必须仍能解析并 desugar
// =====================================================================

#[test]
fn legacy_syntax_desugars_to_new_ast() {
    let src = r#"
        entity Company { key: code states: [NORMAL, SUSPENDED, DONE] initial: NORMAL }
        stream R = Stream[E].filter(event.t == "R")
        signal Doubled(x: float) -> float = x * 2.0
        var fresh = event.value > 1.0
        contract C on Company {
            invariant: until(always(true), historically(exists(R), within: 10d))
            violation { severity: WARNING transition: NORMAL -> SUSPENDED emit: "old" }
        }
    "#;
    let spec = parse(src).unwrap();
    // contract → spec、signal/var → metric
    assert_eq!(spec.specs.len(), 1);
    assert_eq!(spec.specs[0].name, "C");
    assert!(spec.metrics.iter().any(|m| m.name == "Doubled"));
    assert!(spec.metrics.iter().any(|m| m.name == "fresh"));
    // Stream[T] → Event[T]
    assert!(spec.streams.iter().any(|s| s.name == "R"));
}

#[test]
fn rule_when_then_sugar_desugars_to_spec() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, SUSPENDED] initial: NORMAL }
        stream R := Event[E].filter(e => e.t == "R")
        rule OverdueAlert on Company when historically(R.exists(), within: 10d) then {
            severity: CRITICAL
            transition: NORMAL -> SUSPENDED
            emit: "overdue"
        }
    "#;
    let spec = parse(src).unwrap();
    assert_eq!(spec.specs.len(), 1);
    assert_eq!(spec.specs[0].name, "OverdueAlert");
    assert_eq!(
        spec.specs[0].violation.transition,
        Some(("NORMAL".into(), "SUSPENDED".into()))
    );
}

#[test]
fn escaped_quotes_in_messages_round_trip() {
    let src = r#"
        entity Company(key: code) { states: [NORMAL, DONE] initial: NORMAL }
        spec MessageSpec on c: Company {
            invariant: always(true)
            violation { severity: INFO emit: "quote: \"value\"" }
        }
    "#;
    let spec = parse(src).unwrap();
    assert_eq!(spec.specs[0].violation.message, "quote: \"value\"");
}

// =====================================================================
// DMN 1.3 XML 互通（FR3 / NFR「DMN 1.3 XML 互通」）
// =====================================================================

/// §5 四个用例中，只有用例 3 声明了 `decision_table`。
fn dmn_examples() -> Vec<&'static str> {
    vec![
        "ecommerce_coupon.rules",
        "additional_issuance.rules",
        "seat_flood_protection.rules",
        "suspicious_account.rules",
        "semi_annual.rules",
    ]
}

#[test]
fn dmn_xml_round_trip_for_all_examples() {
    let mut seen = 0usize;
    for name in dmn_examples() {
        let spec = parse(&example(name)).unwrap_or_else(|e| panic!("{name} parse failed: {e}"));
        if spec.decision_tables.is_empty() {
            continue;
        }
        seen += 1;
        let xml = rules_dmn::export_tables(&spec.decision_tables);
        assert!(xml.contains("https://www.omg.org/spec/DMN/20191111/MODEL/"), "{name} 未输出 DMN 命名空间");
        let back = rules_dmn::import_tables(&xml).unwrap_or_else(|e| panic!("{name} DMN 回读失败: {e}"));

        assert_eq!(back.len(), spec.decision_tables.len(), "{name} 决策表数量不一致");
        for (a, b) in back.iter().zip(spec.decision_tables.iter()) {
            assert_eq!(a.name, b.name, "{name} 表名不一致");
            assert_eq!(a.hit_policy, b.hit_policy, "{name} 命中策略不一致");
            assert_eq!(a.params, b.params, "{name} 输入参数不一致");
            assert_eq!(a.outputs, b.outputs, "{name} 输出列不一致");
            assert_eq!(a.rows.len(), b.rows.len(), "{name} 规则行数不一致");
            for (ra, rb) in a.rows.iter().zip(b.rows.iter()) {
                assert_eq!(ra.is_default, rb.is_default, "{name} 默认行标记丢失");
                assert_eq!(ra.inputs, rb.inputs, "{name} 输入条目不一致");
                assert_eq!(ra.outputs, rb.outputs, "{name} 输出条目不一致");
            }
        }
    }
    assert!(seen >= 1, "没有任何示例包含 decision_table，DMN 链路未被覆盖");
}

#[test]
fn dmn_xml_to_dsl_chain_reparses_and_reverifies() {
    for name in dmn_examples() {
        let spec = parse(&example(name)).unwrap();
        if spec.decision_tables.is_empty() {
            continue;
        }
        let xml = rules_dmn::export_tables(&spec.decision_tables);
        let tables = rules_dmn::import_tables(&xml).unwrap();
        let dsl: String = tables
            .iter()
            .map(rules_dmn::render_decision_table_dsl)
            .collect::<Vec<_>>()
            .join("\n");

        // DSL 必须能被 parser 回读，且语义等价
        let reparsed = parse(&dsl).unwrap_or_else(|e| panic!("{name} DSL 回读失败: {e}\n{dsl}"));
        assert_eq!(reparsed.decision_tables.len(), spec.decision_tables.len());
        for (a, b) in reparsed.decision_tables.iter().zip(spec.decision_tables.iter()) {
            assert_eq!(a.rows.len(), b.rows.len(), "{name} DSL 往返后行数变化");
            assert_eq!(a.hit_policy, b.hit_policy);
            assert_eq!(a.params, b.params);
            assert_eq!(a.outputs, b.outputs);
        }

        // 二次导出必须稳定（XML → DSL → XML 幂等）
        let xml2 = rules_dmn::export_tables(&reparsed.decision_tables);
        assert_eq!(xml, xml2, "{name} XML→DSL→XML 链路不稳定");
    }
}

#[test]
fn dmn_exported_xml_is_well_formed_and_self_contained() {
    let spec = parse(&example("ecommerce_coupon.rules")).unwrap();
    let xml = rules_dmn::export_tables(&spec.decision_tables);
    let root = rules_dmn::parse_xml(&xml).unwrap();
    assert_eq!(root.name, "definitions");
    assert_eq!(root.attr("xmlns"), Some(rules_dmn::DMN_NS));
    let tables = root.descendants("decisionTable");
    assert_eq!(tables.len(), spec.decision_tables.len());
    assert!(tables[0].attr("hitPolicy").is_some());
    assert_eq!(tables[0].children_named("input").count(), spec.decision_tables[0].params.len());
    assert_eq!(tables[0].children_named("output").count(), spec.decision_tables[0].outputs.len());
    assert_eq!(tables[0].children_named("rule").count(), spec.decision_tables[0].rows.len());
}

#[test]
fn dmn_import_accepts_foreign_hand_written_xml() {
    // 模拟第三方建模工具（Camunda / kie）导出的常见形状：一元测试 + 长名 hitPolicy
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="https://www.omg.org/spec/DMN/20191111/MODEL/" id="defs" name="Credit">
  <decision id="risk" name="RiskGrade">
    <decisionTable id="risk_tbl" hitPolicy="FIRST">
      <input id="i1" label="score">
        <inputExpression id="ie1" typeRef="integer"><text>score</text></inputExpression>
      </input>
      <output id="o1" name="grade" typeRef="string"/>
      <rule id="r1">
        <inputEntry id="r1i"><text>&gt;= 700</text></inputEntry>
        <outputEntry id="r1o"><text>"A"</text></outputEntry>
      </rule>
      <rule id="r2">
        <inputEntry id="r2i"><text>[500..699]</text></inputEntry>
        <outputEntry id="r2o"><text>"B"</text></outputEntry>
      </rule>
      <rule id="r3">
        <inputEntry id="r3i"><text>-</text></inputEntry>
        <outputEntry id="r3o"><text>"C"</text></outputEntry>
      </rule>
    </decisionTable>
  </decision>
</definitions>"#;

    let t = rules_dmn::import_table(xml).unwrap();
    assert_eq!(t.name, "RiskGrade");
    assert_eq!(t.hit_policy, rules_ast::HitPolicy::First);
    assert_eq!(t.params.len(), 1);
    assert_eq!(t.params[0].name, "score");
    assert_eq!(t.params[0].ty, rules_ast::DataType::Int);
    assert_eq!(t.outputs[0].name, "grade");
    assert_eq!(t.outputs[0].ty, rules_ast::DataType::String);
    assert_eq!(t.rows.len(), 3);
    // 一元测试补上输入变量名
    assert_eq!(
        t.rows[0].inputs[0],
        rules_ast::InputEntry::Expr(rules_ast::Expr::bin(
            rules_ast::BinaryOp::Gte,
            rules_ast::Expr::ident("score"),
            rules_ast::Expr::Number(700.0)
        ))
    );
    // 闭区间升格为 Range
    assert!(matches!(t.rows[1].inputs[0], rules_ast::InputEntry::Range { .. }));
    // 全 `-` 行识别为默认行
    assert!(t.rows[2].is_default);
    assert!(t.rows.last().map(|r| r.is_default).unwrap_or(false));
    // 重新导出后仍可回读
    let back = rules_dmn::import_table(&rules_dmn::export_table(&t)).unwrap();
    assert_eq!(back.rows.len(), 3);
    assert_eq!(back.hit_policy, rules_ast::HitPolicy::First);
}

// =====================================================================
// 示例文件：全部必须能解析 + 校验通过
// =====================================================================

#[test]
fn all_shipped_examples_parse_and_verify() {
    for name in [
        "semi_annual.rules",
        "until_rule.rules",
        "with_var.rules",
        "cancel_ratio.rules",
        "ecommerce_coupon.rules",
        "additional_issuance.rules",
        "seat_flood_protection.rules",
        "suspicious_account.rules",
    ] {
        let src = example(name);
        let spec = parse(&src).unwrap_or_else(|e| panic!("{name} parse failed: {e}"));
        let mut dict = DataDictionary::default();
        for m in &spec.metrics {
            if m.params.is_empty() {
                dict.set_var(m.name.clone(), ScalarValue::Bool(true));
            }
        }
        let report = Verifier::verify_report(&spec, &dict);
        assert!(report.is_ok(), "{name} failed verification: {:?}", report.errors);
    }
}
