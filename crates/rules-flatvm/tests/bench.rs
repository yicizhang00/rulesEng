//! 性能基准：递归 AST eval vs FlatVM 栈式字节码。
//!
//! 运行：cargo test -p rules-flatvm --release --test bench -- --nocapture

use rules_ast::{BinaryOp, Expr};
use rules_flatvm::{compile, FlatVm};
use std::collections::HashMap;
use std::time::Instant;

/// 递归 AST 求值（对照基线）。
fn eval_rec(e: &Expr, x: f64, y: f64) -> f64 {
    match e {
        Expr::Number(n) => *n,
        Expr::Ident(name) => match name.as_str() {
            "x" => x,
            "y" => y,
            _ => 0.0,
        },
        Expr::Binary { op, left, right } => {
            let l = eval_rec(left, x, y);
            let r = eval_rec(right, x, y);
            match op {
                BinaryOp::Add => l + r,
                BinaryOp::Mul => l * r,
                BinaryOp::Gt => {
                    if l > r {
                        1.0
                    } else {
                        0.0
                    }
                }
                _ => 0.0,
            }
        }
        _ => 0.0,
    }
}

fn build_expr() -> Expr {
    // ((x + y) * (x - y)) > 100
    Expr::bin(
        BinaryOp::Gt,
        Expr::bin(
            BinaryOp::Mul,
            Expr::bin(BinaryOp::Add, Expr::Ident("x".into()), Expr::Ident("y".into())),
            Expr::bin(BinaryOp::Add, Expr::Ident("x".into()), Expr::Ident("y".into())),
        ),
        Expr::num(100.0),
    )
}

#[test]
fn bench_throughput() {
    let expr = build_expr();
    let mut offs = HashMap::new();
    offs.insert("x".to_string(), 0);
    offs.insert("y".to_string(), 1);
    let prog = compile(&expr, &offs);

    const N: u32 = 1_000_000;

    // 递归 AST
    let t0 = Instant::now();
    let mut sink = 0.0;
    for i in 0..N {
        sink += eval_rec(&expr, i as f64 % 100.0, (i * 7) as f64 % 100.0);
    }
    let t_rec = t0.elapsed();

    // FlatVM
    let mut vm = FlatVm::new(prog.num_slots);
    let t0 = Instant::now();
    for i in 0..N {
        vm.set(0, i as f64 % 100.0);
        vm.set(1, (i * 7) as f64 % 100.0);
        sink += vm.run(&prog);
    }
    let t_flat = t0.elapsed();

    println!("\n=== FlatVM 性能基准 ({} iterations) ===", N);
    println!("  recursive AST : {:?}  ({:.0} ns/iter)", t_rec, t_rec.as_nanos() as f64 / N as f64);
    println!("  flat VM       : {:?}  ({:.0} ns/iter)", t_flat, t_flat.as_nanos() as f64 / N as f64);
    println!("  speedup       : {:.2}x", t_rec.as_nanos() as f64 / t_flat.as_nanos().max(1) as f64);
    println!("  sink (防优化) : {}", sink);
}
