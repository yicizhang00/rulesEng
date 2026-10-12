//! 端到端集成测试：parse -> verify -> runtime。

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

// ---------- 原型 4 个场景回归 ----------

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
    fields.insert("company_id".into(), "600000".into());
    eng.ingest(Event { event_type: "DisclosureEvent".into(), fields, timestamp: 80_000 });
    eng.set_clock(618_400);
    eng.tick();
    // 已上传报告，historically(exists(...)) 成立，不违规
    assert_eq!(eng.entity_state("Company", "600000"), Some("NORMAL"));
}

// ---------- 形式化校验 ----------

#[test]
fn dead_rule_vacuous_antecedent_rejected() {
    let src = r#"
        entity Company { key: code states: [NORMAL, BAD] initial: NORMAL }
        stream X = Stream[E].filter(event.t == "X")
        contract Bad on Company {
            invariant: (1 > 2) implies historically(exists(X), within: 1d)
            violation { severity: WARNING emit: "x" }
        }
    "#;
    let spec = parse(src).unwrap();
    let res = Verifier::verify(&spec, &DataDictionary::default());
    assert!(res.is_err());
    let msgs: Vec<String> = res.unwrap_err().iter().map(|e| e.to_string()).collect();
    assert!(msgs.iter().any(|m| m.contains("vacuous")));
}

#[test]
fn action_conflict_detected() {
    let src = r#"
        entity Company { key: code states: [NORMAL, SUSPENDED, TERMINATED] initial: NORMAL }
        stream X = Stream[E].filter(event.t == "X")
        contract A on Company {
            invariant: historically(exists(X), within: 1d) implies always(true)
            violation { severity: CRITICAL transition: NORMAL -> SUSPENDED emit: "a" }
        }
        contract B on Company {
            invariant: historically(exists(X), within: 1d) implies always(true)
            violation { severity: CRITICAL transition: NORMAL -> TERMINATED emit: "b" }
        }
    "#;
    let spec = parse(src).unwrap();
    let res = Verifier::verify(&spec, &DataDictionary::default());
    assert!(res.is_err());
    let msgs: Vec<String> = res.unwrap_err().iter().map(|e| e.to_string()).collect();
    assert!(msgs.iter().any(|m| m.contains("conflict")));
}

#[test]
fn unreferenced_stream_reported() {
    let src = r#"
        entity Company { key: code states: [NORMAL, X] initial: NORMAL }
        stream Unused = Stream[E].filter(event.t == "X")
        contract C on Company {
            invariant: always(true)
            violation { severity: INFO emit: "c" }
        }
    "#;
    let spec = parse(src).unwrap();
    let res = Verifier::verify(&spec, &DataDictionary::default());
    assert!(res.is_err());
    let msgs: Vec<String> = res.unwrap_err().iter().map(|e| e.to_string()).collect();
    assert!(msgs.iter().any(|m| m.contains("UnreferencedStream") || m.contains("coverage gap")));
}

#[test]
fn undeclared_var_rejected() {
    let src = r#"
        entity Company { key: code states: [NORMAL, X] initial: NORMAL }
        stream S = Stream[E].filter(event.t == "S")
        var fresh_metric = event.value > 1.0
        contract C on Company {
            invariant: historically(exists(S), within: 1d) implies always(true)
            violation { severity: INFO emit: "c" }
        }
    "#;
    let spec = parse(src).unwrap();
    // 字典里没登记 fresh_metric
    let res = Verifier::verify(&spec, &DataDictionary::default());
    assert!(res.is_err());
}

#[test]
fn registered_var_passes() {
    let src = r#"
        entity Company { key: code states: [NORMAL, DONE] initial: NORMAL }
        stream S = Stream[E].filter(event.t == "S")
        var fresh_metric = event.value > 1.0
        contract C on Company {
            invariant: historically(exists(S), within: 1d) implies always(true)
            violation { severity: INFO emit: "c" }
        }
    "#;
    let spec = parse(src).unwrap();
    let mut dict = DataDictionary::default();
    dict.set_var("fresh_metric", ScalarValue::Bool(true));
    let res = Verifier::verify(&spec, &dict);
    // 不应再因为 var 未登记报错
    assert!(res.is_ok(), "{:?}", res.err());
}

// ---------- until 算子解析 ----------

#[test]
fn rule_when_then_sugar_desugars_to_contract() {
    let src = r#"
        entity Company { key: code states: [NORMAL, SUSPENDED, DONE] initial: NORMAL }
        stream R = Stream[E].filter(event.t == "R")
        rule OverdueAlert on Company when historically(exists(R), within: 10d) then {
            severity: CRITICAL
            transition: NORMAL -> SUSPENDED
            emit: "overdue"
        }
    "#;
    let spec = parse(src).unwrap();
    assert_eq!(spec.contracts.len(), 1);
    assert_eq!(spec.contracts[0].name, "OverdueAlert");
    assert_eq!(spec.contracts[0].violation.transition, Some(("NORMAL".into(), "SUSPENDED".into())));
}

#[test]
fn until_operator_parses() {
    let src = r#"
        entity Company { key: code states: [NORMAL, SUSPENDED, DONE] initial: NORMAL }
        stream R = Stream[E].filter(event.t == "R")
        contract C on Company {
            invariant: until(always(true), historically(exists(R), within: 10d))
            violation { severity: WARNING emit: "until broken" }
        }
    "#;
    let spec = parse(src).unwrap();
    assert_eq!(spec.contracts.len(), 1);
}
