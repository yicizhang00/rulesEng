//! rules-cli — 命令行入口。
//!
//! 用法：
//!   rules-cli verify <file.rules>            # 只做 parse + 静态校验（错误阻断，警告提示）
//!   rules-cli run    <file.rules>            # parse + verify + 跑内置演示场景
//!   rules-cli demo                           # 跑内置半年报披露 demo
//!   rules-cli dmn-export <in.rules> [out.xml]  # 决策表 → DMN 1.3 XML
//!   rules-cli dmn-import <in.xml>   [out.rules]# DMN 1.3 XML → 决策表 DSL

use rules_dictionary::{DataDictionary, ScalarValue};
use rules_dispatcher::VecDispatcher;
use rules_dmn::{export_tables, import_tables, render_decision_table_dsl};
use rules_parser::parse;
use rules_runtime::{Event, RegulatoryRuntime};
use rules_verifier::{Verifier, VerifyReport};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: rules-cli <verify|run|demo|dmn-export|dmn-import> [args...]"
        );
        std::process::exit(1);
    }
    match args[1].as_str() {
        "verify" => {
            let path = &args[2];
            let src = fs::read_to_string(path).expect("read rules file");
            match run_verify(&src) {
                Ok(report) => {
                    print_report(&report);
                    if report.is_ok() {
                        println!("OK: verification passed.");
                    } else {
                        std::process::exit(2);
                    }
                }
                Err(e) => {
                    eprintln!("ERROR: parse failed: {e}");
                    std::process::exit(2);
                }
            }
        }
        "run" => {
            let path = &args[2];
            let src = fs::read_to_string(path).expect("read rules file");
            match run_verify(&src) {
                Ok(report) => {
                    print_report(&report);
                    if !report.is_ok() {
                        std::process::exit(2);
                    }
                }
                Err(e) => {
                    eprintln!("ERROR: parse failed: {e}");
                    std::process::exit(2);
                }
            }
            run_demo(&src);
        }
        "demo" => run_demo(include_str!("../../../examples/semi_annual.rules")),
        "dmn-export" => {
            let path = &args[2];
            let src = fs::read_to_string(path).expect("read rules file");
            let spec = match parse(&src) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ERROR: parse failed: {e}");
                    std::process::exit(2);
                }
            };
            if spec.decision_tables.is_empty() {
                eprintln!("ERROR: 文件 {path} 中没有任何 decision_table");
                std::process::exit(2);
            }
            let xml = export_tables(&spec.decision_tables);
            match args.get(3) {
                Some(out) => {
                    fs::write(out, &xml).expect("write dmn xml");
                    println!(
                        "OK: 已导出 {} 张决策表 → {out}",
                        spec.decision_tables.len()
                    );
                }
                None => print!("{xml}"),
            }
        }
        "dmn-import" => {
            let path = &args[2];
            let xml = fs::read_to_string(path).expect("read dmn xml");
            let tables = match import_tables(&xml) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("ERROR: DMN 解析失败: {e}");
                    std::process::exit(2);
                }
            };
            let dsl: String = tables
                .iter()
                .map(render_decision_table_dsl)
                .collect::<Vec<_>>()
                .join("\n");
            // 自检：渲染出的 DSL 必须能被 parser 回读
            if let Err(e) = parse(&dsl) {
                eprintln!("ERROR: 生成的 DSL 无法被 parser 回读: {e}");
                std::process::exit(2);
            }
            match args.get(3) {
                Some(out) => {
                    fs::write(out, &dsl).expect("write dsl");
                    println!("OK: 已导入 {} 张决策表 → {out}", tables.len());
                }
                None => print!("{dsl}"),
            }
        }
        other => eprintln!("unknown subcommand: {other}"),
    }
}

/// 校验并返回分级报告。
///
/// 设计文档 FR5 / §7.3：校验器对 `var` 采取**保守策略**（假设其任意取值），
/// 因此这里把所有 `var` 以占位值登记进字典后再校验——未登记的 `var` 只会
/// 产生 warning，不会阻断；真正的运行期取值由 DataDictionary 注入。
fn run_verify(src: &str) -> Result<VerifyReport, String> {
    let spec = parse(src).map_err(|e| e.to_string())?;
    let mut dict = DataDictionary::default();
    // 零元 metric 在运行期是"派生信号"，但在校验期可能externally 注入；
    // 这里按保守策略用占位值登记，未绑定的只会产生 warning。
    for m in &spec.metrics {
        if m.params.is_empty() {
            dict.set_var(m.name.clone(), ScalarValue::Bool(true));
        }
    }
    Ok(Verifier::verify_report(&spec, &dict))
}

fn print_report(report: &VerifyReport) {
    for issue in &report.warnings {
        println!("WARN  [{}] {}", issue.kind, issue.message);
    }
    for issue in &report.errors {
        eprintln!("ERROR [{}] {}", issue.kind, issue.message);
    }
}

fn run_demo(src: &str) {
    println!("=== Parsing (four first-class concepts) ===");
    let spec = parse(src).expect("parse failed");
    println!(
        "entities={} streams={} metrics={} specs={}",
        spec.entities.len(),
        spec.streams.len(),
        spec.metrics.len(),
        spec.specs.len()
    );
    for e in &spec.entities {
        println!(
            "  entity {} (key: {}) states={:?} initial={} terminal={:?} edges={}",
            e.name,
            e.key,
            e.states,
            e.initial,
            e.terminal,
            e.transitions.len()
        );
    }
    for m in &spec.metrics {
        println!(
            "  metric {} params={} ret={:?} source_stream={:?}",
            m.name,
            m.params.len(),
            m.ret,
            m.source_stream()
        );
    }

    println!("\n=== Verifying (MTL temporal model checking) ===");
    let dict = DataDictionary::default();
    let report = Verifier::verify_report(&spec, &dict);
    for issue in &report.warnings {
        println!("WARN  [{}] {}", issue.kind, issue.message);
    }
    if !report.is_ok() {
        for issue in &report.errors {
            eprintln!("ERROR [{}] {}", issue.kind, issue.message);
        }
        panic!("verification failed");
    }
    println!("verification passed ({} warning(s)).", report.warnings.len());

    let disp = Arc::new(VecDispatcher::new());
    let mut engine = RegulatoryRuntime::new(spec.clone(), dict).with_dispatcher(disp.clone());
    engine.ensure_entity("Company", "600000");

    // 展示：时序不变量被编译为扁平自动机（单向扫描，零递归），
    // 且数值谓词落到原生字节码快路径。
    println!("\n=== Compiled temporal automata ===");
    for s in &spec.specs {
        if let Some(aut) = engine.automaton(&s.name) {
            println!(
                "  spec {} -> {} nodes, flat_atom_ratio={:.2}, window={}s",
                s.name,
                aut.num_nodes(),
                aut.flat_atom_ratio(),
                aut.max_window()
            );
        }
    }

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
        for (k, v) in &a.trace {
            println!("       trace {k} = {v}");
        }
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
    // 事件字段名必须与 spec 内 `r.code == c.code` 引用的字段一致（同时是实体 key）
    fields.insert("code".into(), "600000".into());
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
