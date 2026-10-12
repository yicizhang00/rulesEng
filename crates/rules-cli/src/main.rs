//! rules-cli — 命令行入口。
//!
//! 用法：
//!   rules-cli verify <file.rules>   # 只做 parse + 静态校验
//!   rules-cli run    <file.rules>   # parse + verify + 跑内置演示场景
//!   rules-cli demo                  # 跑内置半年报披露 demo

use rules_dictionary::DataDictionary;
use rules_dispatcher::VecDispatcher;
use rules_parser::parse;
use rules_runtime::{Event, RegulatoryRuntime};
use rules_verifier::Verifier;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: rules-cli <verify|run|demo> [file.rules]");
        std::process::exit(1);
    }
    match args[1].as_str() {
        "verify" => {
            let path = &args[2];
            let src = fs::read_to_string(path).expect("read rules file");
            match run_verify(&src) {
                Ok(_) => println!("OK: verification passed."),
                Err(errs) => {
                    for e in &errs {
                        eprintln!("ERROR: {}", e);
                    }
                    std::process::exit(2);
                }
            }
        }
        "run" => {
            let path = &args[2];
            let src = fs::read_to_string(path).expect("read rules file");
            if let Err(errs) = run_verify(&src) {
                for e in &errs {
                    eprintln!("ERROR: {}", e);
                }
                std::process::exit(2);
            }
            run_demo(&src);
        }
        "demo" => run_demo(include_str!("../../../examples/semi_annual.rules")),
        _ => eprintln!("unknown subcommand"),
    }
}

fn run_verify(src: &str) -> Result<(), Vec<rules_verifier::VerificationError>> {
    let spec = parse(src).expect("parse failed");
    // 演示字典：把所有 var 登记为空占位（demo 里没有 var）。
    let dict = DataDictionary::default();
    Verifier::verify(&spec, &dict)
}

fn run_demo(src: &str) {
    println!("=== Parsing ===");
    let spec = parse(src).expect("parse failed");
    println!(
        "entities={} streams={} signals={} vars={} contracts={}",
        spec.entities.len(),
        spec.streams.len(),
        spec.signals.len(),
        spec.vars.len(),
        spec.contracts.len()
    );

    println!("\n=== Verifying ===");
    let dict = DataDictionary::default();
    Verifier::verify(&spec, &dict).expect("verification failed");
    println!("verification passed.");

    let disp = Arc::new(VecDispatcher::new());
    let mut engine = RegulatoryRuntime::new(spec, dict).with_dispatcher(disp.clone());
    engine.ensure_entity("Company", "600000");

    // 场景 A：截止期前
    engine.set_clock(50_000);
    engine.tick();
    println!("\n[A] t=50000 (before deadline): alerts={}", disp.snapshot().len());

    // 场景 B：逾期 2 天，guard 拦截
    engine.set_clock(272_800);
    engine.tick();
    println!("[B] t=272800 (+2d, guard blocked): alerts={}", disp.snapshot().len());

    // 场景 C：逾期 6 天，触发 CRITICAL + 停牌
    engine.set_clock(618_400);
    engine.tick();
    let snap = disp.snapshot();
    println!("[C] t=618400 (+6d, no report): alerts={}", snap.len());
    for a in &snap {
        println!("    -> {}", a.message);
    }
    println!(
        "    company 600000 state = {:?}",
        engine.entity_state("Company", "600000")
    );

    // 场景 D：新引擎，t=80000 已上传报告
    println!("\n[D] re-run with early report upload:");
    let spec2 = parse(src).expect("parse failed");
    let mut engine2 = RegulatoryRuntime::new(spec2, DataDictionary::default())
        .with_dispatcher(Arc::new(VecDispatcher::new()));
    engine2.ensure_entity("Company", "600000");
    let mut fields = HashMap::new();
    fields.insert("type".into(), "SEMI_ANNUAL".into());
    fields.insert("company_id".into(), "600000".into());
    engine2.ingest(Event {
        event_type: "DisclosureEvent".into(),
        fields,
        timestamp: 80_000,
    });
    engine2.set_clock(618_400);
    engine2.tick();
    println!(
        "    t=618400 after early upload: state = {:?}",
        engine2.entity_state("Company", "600000")
    );
}
