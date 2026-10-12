//! rules-flatvm — 栈式字节码 VM，把 AST 编译为扁平操作序列。
//!
//! 设计目标（性能下沉，PRD §四）：
//! - 抛弃对象引用链，上下文变量映射为 `Vec<f64>` 固定偏移（SoA flat layout）；
//! - 栈式 VM 每条 op 一次 CPU 基本指令，cache-friendly；
//! - 本模块是 WASM / Cranelift 后端的"中间 IR"：后续只需把 FlatOp 翻译成
//!   WASM opcodes 即可跑在 wasmtime 沙箱里。
//!
//! v1 支持：算术 + 比较 + 逻辑。不支持 Call（留给生产后端）。

use rules_ast::{BinaryOp, Expr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlatOp {
    Push(f64),
    Load(u32),
    Add,
    Sub,
    Mul,
    Div,
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Neq,
    And,
    Or,
}

#[derive(Debug, Clone)]
pub struct FlatProgram {
    pub ops: Vec<FlatOp>,
    pub num_slots: usize,
}

/// 编译：把 AST Expr 翻译成栈式 op 序列。
/// `var_offset` 把变量名映射到 slots 偏移。
pub fn compile(expr: &Expr, var_offset: &std::collections::HashMap<String, u32>) -> FlatProgram {
    let mut ops = Vec::new();
    let mut max_slot = 0u32;
    compile_into(expr, var_offset, &mut ops, &mut max_slot);
    FlatProgram { ops, num_slots: (max_slot + 1) as usize }
}

fn compile_into(
    e: &Expr,
    var_offset: &std::collections::HashMap<String, u32>,
    ops: &mut Vec<FlatOp>,
    max_slot: &mut u32,
) {
    match e {
        Expr::Number(n) => ops.push(FlatOp::Push(*n)),
        Expr::Ident(name) => {
            if let Some(off) = var_offset.get(name) {
                *max_slot = (*max_slot).max(*off);
                ops.push(FlatOp::Load(*off));
            } else {
                ops.push(FlatOp::Push(0.0));
            }
        }
        Expr::Binary { op, left, right } => {
            compile_into(left, var_offset, ops, max_slot);
            compile_into(right, var_offset, ops, max_slot);
            let o = match op {
                BinaryOp::Add => FlatOp::Add,
                BinaryOp::Sub => FlatOp::Sub,
                BinaryOp::Mul => FlatOp::Mul,
                BinaryOp::Div => FlatOp::Div,
                BinaryOp::Gt => FlatOp::Gt,
                BinaryOp::Gte => FlatOp::Gte,
                BinaryOp::Lt => FlatOp::Lt,
                BinaryOp::Lte => FlatOp::Lte,
                BinaryOp::Eq => FlatOp::Eq,
                BinaryOp::Neq => FlatOp::Neq,
                BinaryOp::And => FlatOp::And,
                BinaryOp::Or => FlatOp::Or,
            };
            ops.push(o);
        }
        _ => ops.push(FlatOp::Push(0.0)),
    }
}

/// 栈式 VM。执行时只接触连续 f64 数组，零 GC 压力。
pub struct FlatVm {
    pub slots: Vec<f64>,
    stack: Vec<f64>,
}

impl FlatVm {
    pub fn new(num_slots: usize) -> Self {
        Self { slots: vec![0.0; num_slots], stack: Vec::with_capacity(64) }
    }

    pub fn set(&mut self, slot: usize, v: f64) {
        self.slots[slot] = v;
    }

    pub fn run(&mut self, prog: &FlatProgram) -> f64 {
        self.stack.clear();
        for op in &prog.ops {
            match *op {
                FlatOp::Push(v) => self.stack.push(v),
                FlatOp::Load(off) => self.stack.push(self.slots[off as usize]),
                FlatOp::Add => bin(&mut self.stack, |a, b| a + b),
                FlatOp::Sub => bin(&mut self.stack, |a, b| a - b),
                FlatOp::Mul => bin(&mut self.stack, |a, b| a * b),
                FlatOp::Div => bin(&mut self.stack, |a, b| if b == 0.0 { 0.0 } else { a / b }),
                FlatOp::Gt => cmp(&mut self.stack, |a, b| a > b),
                FlatOp::Gte => cmp(&mut self.stack, |a, b| a >= b),
                FlatOp::Lt => cmp(&mut self.stack, |a, b| a < b),
                FlatOp::Lte => cmp(&mut self.stack, |a, b| a <= b),
                FlatOp::Eq => cmp(&mut self.stack, |a, b| (a - b).abs() < f64::EPSILON),
                FlatOp::Neq => cmp(&mut self.stack, |a, b| (a - b).abs() >= f64::EPSILON),
                FlatOp::And => logic(&mut self.stack, |a, b| a > 0.0 && b > 0.0),
                FlatOp::Or => logic(&mut self.stack, |a, b| a > 0.0 || b > 0.0),
            }
        }
        self.stack.pop().unwrap_or(0.0)
    }
}

#[inline]
fn bin(stack: &mut Vec<f64>, f: impl FnOnce(f64, f64) -> f64) {
    let b = stack.pop().unwrap();
    let a = stack.pop().unwrap();
    stack.push(f(a, b));
}

#[inline]
fn cmp(stack: &mut Vec<f64>, f: impl FnOnce(f64, f64) -> bool) {
    let b = stack.pop().unwrap();
    let a = stack.pop().unwrap();
    stack.push(if f(a, b) { 1.0 } else { 0.0 });
}

#[inline]
fn logic(stack: &mut Vec<f64>, f: impl FnOnce(f64, f64) -> bool) {
    let b = stack.pop().unwrap();
    let a = stack.pop().unwrap();
    stack.push(if f(a, b) { 1.0 } else { 0.0 });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules_ast::Expr;
    use std::collections::HashMap;

    #[test]
    fn compiles_and_runs_arithmetic() {
        // (x + y) * 2
        let e = Expr::bin(
            BinaryOp::Mul,
            Expr::bin(BinaryOp::Add, Expr::Ident("x".into()), Expr::Ident("y".into())),
            Expr::num(2.0),
        );
        let mut offs = HashMap::new();
        offs.insert("x".into(), 0);
        offs.insert("y".into(), 1);
        let prog = compile(&e, &offs);
        let mut vm = FlatVm::new(prog.num_slots);
        vm.set(0, 3.0);
        vm.set(1, 4.0);
        let r = vm.run(&prog);
        assert_eq!(r, 14.0);
    }

    #[test]
    fn comparison_returns_0_or_1() {
        // x > 5
        let e = Expr::bin(BinaryOp::Gt, Expr::Ident("x".into()), Expr::num(5.0));
        let mut offs = HashMap::new();
        offs.insert("x".into(), 0);
        let prog = compile(&e, &offs);
        let mut vm = FlatVm::new(prog.num_slots);
        vm.set(0, 10.0);
        assert_eq!(vm.run(&prog), 1.0);
        vm.set(0, 1.0);
        assert_eq!(vm.run(&prog), 0.0);
    }
}
