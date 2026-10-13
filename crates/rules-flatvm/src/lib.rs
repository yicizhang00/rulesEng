//! rules-flatvm — 扁平编译层：槽位偏移 + 栈式字节码 + 环形缓冲区。
//!
//! 这一层承担 PRD「性能下沉」的三件事，也是"脱离 Drools/RETE"的落点：
//!
//! 1. **零反射、零 AST 遍历**：`Expr` 在装载时编译为线性 `Vec<FlatOp>`，
//!    运行期只做连续数组索引，不再递归下降 AST；
//! 2. **扁平内存布局（SoA）**：所有动态指标（metric）编译为固定槽位偏移，
//!    数值走 `nums: Vec<f64>`，文本走 `texts: Vec<u32>`（**字符串驻留为整数 id**，
//!    于是字符串相等退化为 `u32` 比较，无指针追逐、无 GC 压力）；
//! 3. **环形缓冲区**：事件流窗口是定长环形缓冲，push/evict 均为 O(1)，
//!    窗口扫描为顺序内存遍历（cache-friendly），替代 `VecDeque` 的搬移与堆碎片。

use rules_ast::{BinaryOp, Expr};
use std::collections::HashMap;

// =====================================================================
// 字符串驻留：文本 → u32
// =====================================================================

/// 字符串驻留表。id 0 保留给空串，因此 `text == 0` 可表示"该操作数是数值"。
#[derive(Debug, Clone, Default)]
pub struct Interner {
    strings: Vec<String>,
    index: HashMap<String, u32>,
}

impl Interner {
    pub fn new() -> Self {
        Self { strings: vec![String::new()], index: HashMap::new() }
    }

    /// 驻留一个字符串，返回其整数 id。
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(id) = self.index.get(s) {
            return *id;
        }
        let id = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.index.insert(s.to_string(), id);
        id
    }

    pub fn resolve(&self, id: u32) -> &str {
        self.strings.get(id as usize).map(|s| s.as_str()).unwrap_or("")
    }

    /// 已驻留字符串的 id（不新增；未驻留返回 0）。
    pub fn id_of(&self, s: &str) -> u32 {
        self.index.get(s).copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.strings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.len() <= 1
    }
}

// =====================================================================
// 槽位绑定
// =====================================================================

/// 一个符号在扁平内存中落到哪个槽。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// 数值槽（`nums[offset]`）。
    Num(u32),
    /// 文本槽（`texts[offset]`，存驻留 id）。
    Text(u32),
    /// **配对槽**（`fields[offset]`）：同时携带数值投影与驻留文本 id。
    /// 这是 DSL 里"动态指标 / 事件字段"的落地形态——一个槽位同时支持
    /// `x > 5`（走数值）与 `x == "OK"`（走驻留 id 比较），无需类型标注。
    Field(u32),
}

/// 符号 → 槽位 的绑定策略。由 runtime 实现（它才知道 metric / 事件字段 / 实体状态各占哪个槽）。
pub trait SlotBinder {
    fn bind(&mut self, name: &str) -> Option<Binding>;
}

/// 简易数值绑定器（测试 / 基准用）。
#[derive(Debug, Default, Clone)]
pub struct MapBinder {
    pub offsets: HashMap<String, u32>,
    pub next: u32,
}

impl MapBinder {
    pub fn from_map(offsets: HashMap<String, u32>) -> Self {
        let next = offsets.values().copied().max().map(|m| m + 1).unwrap_or(0);
        Self { offsets, next }
    }
}

impl SlotBinder for MapBinder {
    fn bind(&mut self, name: &str) -> Option<Binding> {
        if let Some(off) = self.offsets.get(name) {
            return Some(Binding::Num(*off));
        }
        let off = self.next;
        self.next += 1;
        self.offsets.insert(name.to_string(), off);
        Some(Binding::Num(off))
    }
}

// =====================================================================
// 字节码
// =====================================================================

/// 扁平操作码。`Call` 通过索引引用 `FlatProgram::funcs`，保持 `Copy`。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlatOp {
    /// 压入数值常量。
    Push(f64),
    /// 压入驻留文本 id。
    PushText(u32),
    /// 读数值槽。
    Load(u32),
    /// 读文本槽。
    LoadText(u32),
    /// 读**配对槽**（同时取数值投影与驻留文本 id）。
    LoadField(u32),
    /// 内置函数 / 信号调用（参数个数由 `argc` 决定）。
    Call(u16),
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Neq,
    And,
    Or,
    Not,
    /// 取负。
    Neg,
    /// FR5：位运算（单调状态格 `state & MASK` / `state |= next`）。
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

/// 编译产物：线性操作序列 + 调用的函数名表。
#[derive(Debug, Clone, PartialEq)]
pub struct FlatProgram {
    pub ops: Vec<FlatOp>,
    /// `Call(i)` 对应的函数 / 信号名。
    pub funcs: Vec<String>,
    /// `Call(i)` 的参数个数。
    pub argc: Vec<u8>,
    pub num_slots: usize,
    pub text_slots: usize,
    /// 配对槽数量。
    pub field_slots: usize,
}

impl FlatProgram {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    /// 该程序引用的所有函数名（供 verifier 做"未定义指标"检查）。
    pub fn called_funcs(&self) -> impl Iterator<Item = &str> {
        self.funcs.iter().map(|s| s.as_str())
    }
}

/// 编译期：把 `Expr` 折叠为线性字节码。
pub struct Compiler<'a> {
    binder: &'a mut dyn SlotBinder,
    interner: &'a mut Interner,
    ops: Vec<FlatOp>,
    funcs: Vec<String>,
    argc: Vec<u8>,
    max_num: u32,
    max_text: u32,
    max_field: u32,
}

impl<'a> Compiler<'a> {
    pub fn new(binder: &'a mut dyn SlotBinder, interner: &'a mut Interner) -> Self {
        Self {
            binder,
            interner,
            ops: Vec::new(),
            funcs: Vec::new(),
            argc: Vec::new(),
            max_num: 0,
            max_text: 0,
            max_field: 0,
        }
    }

    /// 编译一个表达式。
    pub fn compile(&mut self, e: &Expr) {
        match e {
            Expr::Number(n) => self.ops.push(FlatOp::Push(*n)),
            Expr::Hex(h) => self.ops.push(FlatOp::Push(*h as f64)),
            Expr::Bool(b) => self.ops.push(FlatOp::Push(if *b { 1.0 } else { 0.0 })),
            Expr::DurationLit(d) => self.ops.push(FlatOp::Push(d.as_secs() as f64)),
            // 决策表查询无法在扁平字节码里表达 → 交由标量路径（temporal 会把它判为 non-flat）
            Expr::TableLookup { .. } => self.ops.push(FlatOp::Push(0.0)),
            Expr::Str(s) => {
                let id = self.interner.intern(s);
                self.ops.push(FlatOp::PushText(id));
            }
            Expr::Ident(name) => self.compile_binding(name),
            Expr::Path(parts) => self.compile_binding(&parts.join(".")),
            Expr::UnaryNot(inner) => {
                self.compile(inner);
                self.ops.push(FlatOp::Not);
            }
            Expr::Binary { op, left, right } => {
                self.compile(left);
                self.compile(right);
                self.ops.push(opcode(*op));
            }
            Expr::Call { func, args } => {
                for a in args {
                    self.compile(a);
                }
                let idx = self.funcs.len() as u16;
                self.funcs.push(func.clone());
                self.argc.push(args.len() as u8);
                self.ops.push(FlatOp::Call(idx));
            }
        }
    }

    fn compile_binding(&mut self, name: &str) {
        match self.binder.bind(name) {
            Some(Binding::Num(off)) => {
                self.max_num = self.max_num.max(off);
                self.ops.push(FlatOp::Load(off));
            }
            Some(Binding::Text(off)) => {
                self.max_text = self.max_text.max(off);
                self.ops.push(FlatOp::LoadText(off));
            }
            Some(Binding::Field(off)) => {
                self.max_field = self.max_field.max(off);
                self.ops.push(FlatOp::LoadField(off));
            }
            // 未绑定符号：编译为 0（verifier 会在装载期给出 warning）
            None => {
                if let Some(b) = name.strip_prefix('"') {
                    let id = self.interner.intern(b.trim_matches('"'));
                    self.ops.push(FlatOp::PushText(id));
                } else {
                    self.ops.push(FlatOp::Push(0.0));
                }
            }
        }
    }

    pub fn finish(self) -> FlatProgram {
        FlatProgram {
            ops: self.ops,
            funcs: self.funcs,
            argc: self.argc,
            num_slots: (self.max_num + 1) as usize,
            text_slots: (self.max_text + 1) as usize,
            field_slots: (self.max_field + 1) as usize,
        }
    }
}

fn opcode(op: BinaryOp) -> FlatOp {
    match op {
        BinaryOp::Add => FlatOp::Add,
        BinaryOp::Sub => FlatOp::Sub,
        BinaryOp::Mul => FlatOp::Mul,
        BinaryOp::Div => FlatOp::Div,
        BinaryOp::Mod => FlatOp::Mod,
        BinaryOp::Gt => FlatOp::Gt,
        BinaryOp::Gte => FlatOp::Gte,
        BinaryOp::Lt => FlatOp::Lt,
        BinaryOp::Lte => FlatOp::Lte,
        BinaryOp::Eq => FlatOp::Eq,
        BinaryOp::Neq => FlatOp::Neq,
        BinaryOp::And => FlatOp::And,
        BinaryOp::Or => FlatOp::Or,
        BinaryOp::BitAnd => FlatOp::BitAnd,
        BinaryOp::BitOr => FlatOp::BitOr,
        BinaryOp::BitXor => FlatOp::BitXor,
        BinaryOp::Shl => FlatOp::Shl,
        BinaryOp::Shr => FlatOp::Shr,
    }
}

/// 便捷入口：用 `MapBinder` 编译纯数值表达式（基准 / 单测）。
pub fn compile(expr: &Expr, binder: &mut MapBinder, interner: &mut Interner) -> FlatProgram {
    let mut c = Compiler::new(binder, interner);
    c.compile(expr);
    c.finish()
}

// =====================================================================
// 执行
// =====================================================================

/// 栈上的操作数。数值与文本共用一个 `f64`+`u32` 定长结构，
/// 因此栈是**连续内存**且每次求值零分配。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Operand {
    pub num: f64,
    /// 0 = 无文本（纯数值操作数）。
    pub text: u32,
}

impl Operand {
    pub const ZERO_INIT: Operand = Operand { num: 0.0, text: 0 };
    pub fn num(n: f64) -> Self {
        Operand { num: n, text: 0 }
    }
    pub fn text(id: u32, reified: f64) -> Self {
        Operand { num: reified, text: id }
    }
    pub fn as_bool(&self) -> bool {
        self.num > 0.0
    }
}

/// 外部环境：为 `Call` 提供实现（内置函数 / metric / 事件字段等）。
pub trait Env {
    /// 求值一个函数调用。`args` 是已经求好的操作数。
    fn call(&mut self, func: &str, args: &[Operand]) -> Operand;
    /// 常量折叠：`PushText` 的数值化表示（用于 `PushText` 后参与数值运算）。
    fn reify(&self, text_id: u32) -> f64 {
        text_id as f64
    }
}

/// 栈式 VM。执行期只接触 `nums` / `texts` / `fields_*` / `stack` 四块连续数组。
pub struct FlatVm {
    pub nums: Vec<f64>,
    pub texts: Vec<u32>,
    /// 配对槽数组（数值投影）。
    pub fields_num: Vec<f64>,
    /// 配对槽数组（驻留文本 id）。
    pub fields_text: Vec<u32>,
    stack: Vec<Operand>,
}

impl FlatVm {
    pub fn new(num_slots: usize, text_slots: usize) -> Self {
        Self {
            nums: vec![0.0; num_slots.max(1)],
            texts: vec![0; text_slots.max(1)],
            fields_num: Vec::new(),
            fields_text: Vec::new(),
            stack: Vec::with_capacity(64),
        }
    }

    /// O(1) 换入当前事件的配对槽数组（`mem::swap`，零拷贝）。
    pub fn swap_fields(&mut self, nums: &mut Vec<f64>, texts: &mut Vec<u32>) {
        std::mem::swap(&mut self.fields_num, nums);
        std::mem::swap(&mut self.fields_text, texts);
    }

    pub fn set(&mut self, slot: usize, v: f64) {
        if slot < self.nums.len() {
            self.nums[slot] = v;
        }
    }

    pub fn set_text(&mut self, slot: usize, id: u32) {
        if slot < self.texts.len() {
            self.texts[slot] = id;
        }
    }

    pub fn get(&self, slot: usize) -> f64 {
        self.nums.get(slot).copied().unwrap_or(0.0)
    }

    /// 执行一段字节码，返回栈顶操作数。
    pub fn run(&mut self, prog: &FlatProgram, env: &mut dyn Env) -> Operand {
        self.stack.clear();
        for op in &prog.ops {
            match *op {
                FlatOp::Push(v) => self.stack.push(Operand::num(v)),
                FlatOp::PushText(id) => {
                    let reified = env.reify(id);
                    self.stack.push(Operand::text(id, reified));
                }
                FlatOp::Load(off) => {
                    let v = self.nums.get(off as usize).copied().unwrap_or(0.0);
                    self.stack.push(Operand::num(v));
                }
                FlatOp::LoadText(off) => {
                    let id = self.texts.get(off as usize).copied().unwrap_or(0);
                    let reified = env.reify(id);
                    self.stack.push(Operand::text(id, reified));
                }
                FlatOp::LoadField(off) => {
                    let o = off as usize;
                    let num = self.fields_num.get(o).copied().unwrap_or(0.0);
                    let text = self.fields_text.get(o).copied().unwrap_or(0);
                    self.stack.push(Operand { num, text });
                }
                FlatOp::Call(i) => {
                    let idx = i as usize;
                    let argc = prog.argc.get(idx).copied().unwrap_or(0) as usize;
                    let start = self.stack.len().saturating_sub(argc);
                    let args: Vec<Operand> = self.stack.split_off(start);
                    let func = prog.funcs.get(idx).cloned().unwrap_or_default();
                    let out = env.call(&func, &args);
                    self.stack.push(out);
                }
                FlatOp::Add => bin(&mut self.stack, |a, b| a + b),
                FlatOp::Sub => bin(&mut self.stack, |a, b| a - b),
                FlatOp::Mul => bin(&mut self.stack, |a, b| a * b),
                FlatOp::Div => bin(&mut self.stack, |a, b| if b == 0.0 { 0.0 } else { a / b }),
                FlatOp::Mod => bin(&mut self.stack, |a, b| if b == 0.0 { 0.0 } else { a % b }),
                FlatOp::Gt => cmp(&mut self.stack, |a, b| a > b),
                FlatOp::Gte => cmp(&mut self.stack, |a, b| a >= b),
                FlatOp::Lt => cmp(&mut self.stack, |a, b| a < b),
                FlatOp::Lte => cmp(&mut self.stack, |a, b| a <= b),
                FlatOp::Eq => eq_op(&mut self.stack, false),
                FlatOp::Neq => eq_op(&mut self.stack, true),
                FlatOp::And => logic(&mut self.stack, |a, b| a && b),
                FlatOp::Or => logic(&mut self.stack, |a, b| a || b),
                FlatOp::Not => {
                    let v = self.stack.pop().unwrap_or(Operand::ZERO_INIT);
                    self.stack.push(Operand::num(if v.as_bool() { 0.0 } else { 1.0 }));
                }
                FlatOp::Neg => {
                    let v = self.stack.pop().unwrap_or(Operand::ZERO_INIT);
                    self.stack.push(Operand::num(-v.num));
                }
                // ---- FR5：位运算（数值投影转 u64 运算后回写 f64） ----
                FlatOp::BitAnd => bit(&mut self.stack, |a, b| a & b),
                FlatOp::BitOr => bit(&mut self.stack, |a, b| a | b),
                FlatOp::BitXor => bit(&mut self.stack, |a, b| a ^ b),
                FlatOp::Shl => bit(&mut self.stack, |a, b| a.wrapping_shl(b.min(63) as u32)),
                FlatOp::Shr => bit(&mut self.stack, |a, b| a.wrapping_shr(b.min(63) as u32)),
            }
        }
        self.stack.pop().unwrap_or(Operand::ZERO_INIT)
    }
}

#[inline]
fn bin(stack: &mut Vec<Operand>, f: impl FnOnce(f64, f64) -> f64) {
    let b = stack.pop().unwrap_or(Operand::ZERO_INIT);
    let a = stack.pop().unwrap_or(Operand::ZERO_INIT);
    stack.push(Operand::num(f(a.num, b.num)));
}

#[inline]
fn cmp(stack: &mut Vec<Operand>, f: impl FnOnce(f64, f64) -> bool) {
    let b = stack.pop().unwrap_or(Operand::ZERO_INIT);
    let a = stack.pop().unwrap_or(Operand::ZERO_INIT);
    // 有序比较统一走数值投影（驻留 id 无字典序语义）
    stack.push(Operand::num(if f(a.num, b.num) { 1.0 } else { 0.0 }));
}

/// FR5：位运算辅助——数值投影转 `u64` 运算后回写。
#[inline]
fn bit(stack: &mut Vec<Operand>, f: impl FnOnce(u64, u64) -> u64) {
    let b = stack.pop().unwrap_or(Operand::ZERO_INIT);
    let a = stack.pop().unwrap_or(Operand::ZERO_INIT);
    stack.push(Operand::num(f(a.num as u64, b.num as u64) as f64));
}

/// 相等：**两侧都携带驻留文本**时比较整数 id；否则比较数值投影。
///
/// 这条规则让同一个配对槽同时支持 `x == "APPROVED"`（走驻留）与 `x == 3`（走数值），
/// 不需要在 DSL 里写类型标注。
#[inline]
fn eq_op(stack: &mut Vec<Operand>, negate: bool) {
    let b = stack.pop().unwrap_or(Operand::ZERO_INIT);
    let a = stack.pop().unwrap_or(Operand::ZERO_INIT);
    let equal = if a.text != 0 && b.text != 0 {
        a.text == b.text
    } else {
        (a.num - b.num).abs() < f64::EPSILON
    };
    let v = if negate { !equal } else { equal };
    stack.push(Operand::num(if v { 1.0 } else { 0.0 }));
}

#[inline]
fn logic(stack: &mut Vec<Operand>, f: impl FnOnce(bool, bool) -> bool) {
    let b = stack.pop().unwrap_or(Operand::ZERO_INIT);
    let a = stack.pop().unwrap_or(Operand::ZERO_INIT);
    stack.push(Operand::num(if f(a.as_bool(), b.as_bool()) { 1.0 } else { 0.0 }));
}

// =====================================================================
// 环形缓冲区
// =====================================================================

/// 流窗口中的一条扁平事件记录。
///
/// `nums` / `texts` 是该流投影后的定长视图（字段 → 偏移在装载期固定），
/// 因此窗口扫描没有 HashMap 查找、没有指针追逐。
#[derive(Debug, Clone, PartialEq)]
pub struct RingEntry {
    pub ts: u64,
    /// 实体实例键（驻留 id）。
    pub key: u32,
    /// 来源事件类型（驻留 id；0 = 未标注）。
    ///
    /// 多事件源流（`Stream[OrderIntent, CancelIntent]`）共用一条环，
    /// 但 `SeatActions[OrderIntent].count` 这类**切片聚合**必须能按事件类型分流，
    /// 因此每格记录来源事件类型（FR6 / 用例 1）。
    pub evt: u32,
    pub nums: Vec<f64>,
    pub texts: Vec<u32>,
}

impl RingEntry {
    pub fn new(ts: u64, key: u32, nums: Vec<f64>, texts: Vec<u32>) -> Self {
        Self { ts, key, evt: 0, nums, texts }
    }
    /// 带来源事件类型的入队构造。
    pub fn tagged(ts: u64, key: u32, evt: u32, nums: Vec<f64>, texts: Vec<u32>) -> Self {
        Self { ts, key, evt, nums, texts }
    }
    pub fn num(&self, off: usize) -> f64 {
        self.nums.get(off).copied().unwrap_or(0.0)
    }
    pub fn text(&self, off: usize) -> u32 {
        self.texts.get(off).copied().unwrap_or(0)
    }
}

/// 定长环形缓冲区。push / evict 都是 O(1)，不搬移元素。
#[derive(Debug)]
pub struct RingBuffer {
    buf: Vec<Option<RingEntry>>,
    /// 下一次写入位置。
    head: usize,
    len: usize,
    /// 已写入的总条数（单调递增，用于诊断）。
    total: u64,
}

impl RingBuffer {
    pub fn with_capacity(cap: usize) -> Self {
        let cap = cap.max(1);
        Self { buf: (0..cap).map(|_| None).collect(), head: 0, len: 0, total: 0 }
    }
    /// 以时长（秒）估算容量：按平均每秒事件数上取整。
    pub fn for_window(window_secs: u64, events_per_sec: u64) -> Self {
        let cap = window_secs.saturating_mul(events_per_sec.max(1)).max(64) as usize;
        Self::with_capacity(cap.min(1 << 22))
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn total_seen(&self) -> u64 {
        self.total
    }

    /// O(1) 入队。缓冲满时覆盖最旧元素（滑动窗口语义）。
    pub fn push(&mut self, entry: RingEntry) {
        self.buf[self.head] = Some(entry);
        self.head = (self.head + 1) % self.buf.len();
        if self.len < self.buf.len() {
            self.len += 1;
        }
        self.total += 1;
    }

    /// 淘汰时间戳早于 `cutoff` 的条目（必须在队首，单调时间戳前提下 O(k)）。
    pub fn evict_before(&mut self, cutoff: u64) {
        while self.len > 0 {
            let oldest = (self.head + self.buf.len() - self.len) % self.buf.len();
            match &self.buf[oldest] {
                Some(e) if e.ts < cutoff => {
                    self.buf[oldest] = None;
                    self.len -= 1;
                }
                _ => break,
            }
        }
    }

    /// 按时间顺序遍历（旧 → 新）。零拷贝。
    pub fn iter(&self) -> RingIter<'_> {
        RingIter { ring: self, idx: 0 }
    }

    /// 逆序遍历（新 → 旧），用于"最近一次"语义。
    pub fn iter_rev(&self) -> impl Iterator<Item = &RingEntry> {
        let n = self.len;
        (0..n).filter_map(move |i| {
            let pos = (self.head + self.buf.len() - 1 - i) % self.buf.len();
            self.buf[pos].as_ref()
        })
    }

    pub fn clear(&mut self) {
        for slot in self.buf.iter_mut() {
            *slot = None;
        }
        self.head = 0;
        self.len = 0;
    }

    /// 撤回最近一次 push。
    ///
    /// PEP 物理阻断（PRD §4.2 AC2）需要"第 21 笔不进窗口"的语义：
    /// 先把事件投影入环、再判定是否违规，若违规则立即撤回，
    /// 使被拒事件不占用滑动窗口配额（否则一次拒绝会永久抬高基线）。
    pub fn pop_last(&mut self) -> Option<RingEntry> {
        if self.len == 0 {
            return None;
        }
        let pos = (self.head + self.buf.len() - 1) % self.buf.len();
        let taken = self.buf[pos].take();
        self.head = pos;
        self.len -= 1;
        self.total = self.total.saturating_sub(1);
        taken
    }
}

pub struct RingIter<'a> {
    ring: &'a RingBuffer,
    idx: usize,
}

impl<'a> Iterator for RingIter<'a> {
    type Item = &'a RingEntry;
    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.ring.len {
            let pos = (self.ring.head + self.ring.buf.len() - self.ring.len + self.idx) % self.ring.buf.len();
            self.idx += 1;
            if let Some(e) = self.ring.buf[pos].as_ref() {
                return Some(e);
            }
        }
        None
    }
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rules_ast::{BinaryOp, Expr};

    /// 求值环境：只实现 `now`，其余返回 0。
    struct SimpleEnv;
    impl Env for SimpleEnv {
        fn call(&mut self, func: &str, args: &[Operand]) -> Operand {
            match func {
                "now" => Operand::num(1_000.0),
                "max" => Operand::num(args.iter().map(|a| a.num).fold(f64::MIN, f64::max)),
                _ => Operand::ZERO_INIT,
            }
        }
    }

    fn vm_run(e: &Expr) -> f64 {
        let mut binder = MapBinder::default();
        let mut interner = Interner::new();
        let prog = compile(e, &mut binder, &mut interner);
        let mut vm = FlatVm::new(prog.num_slots, prog.text_slots);
        let mut env = SimpleEnv;
        vm.run(&prog, &mut env).num
    }

    #[test]
    fn arithmetic_and_comparison() {
        let e = Expr::bin(
            BinaryOp::Gt,
            Expr::bin(BinaryOp::Mul, Expr::num(3.0), Expr::num(4.0)),
            Expr::num(10.0),
        );
        assert_eq!(vm_run(&e), 1.0);
    }

    #[test]
    fn text_equality_uses_interned_ids() {
        // "SEMI_ANNUAL" == "SEMI_ANNUAL" → 1
        let e = Expr::bin(BinaryOp::Eq, Expr::text("SEMI_ANNUAL"), Expr::text("SEMI_ANNUAL"));
        assert_eq!(vm_run(&e), 1.0);
        // "SEMI_ANNUAL" == "ANNUAL" → 0
        let e2 = Expr::bin(BinaryOp::Eq, Expr::text("SEMI_ANNUAL"), Expr::text("ANNUAL"));
        assert_eq!(vm_run(&e2), 0.0);
    }

    #[test]
    fn calls_resolve_through_env() {
        let e = Expr::bin(BinaryOp::Eq, Expr::call("now", vec![]), Expr::num(1000.0));
        assert_eq!(vm_run(&e), 1.0);
    }

    #[test]
    fn ring_buffer_is_fifo_and_bounded() {
        let mut rb = RingBuffer::with_capacity(3);
        for i in 0..5u64 {
            rb.push(RingEntry::new(i * 10, 0, vec![i as f64], vec![]));
        }
        // 容量 3，保留最新 3 条（ts = 20,30,40）
        assert_eq!(rb.len(), 3);
        let ts: Vec<u64> = rb.iter().map(|e| e.ts).collect();
        assert_eq!(ts, vec![20, 30, 40]);

        // 淘汰 ts < 35
        rb.evict_before(35);
        let ts: Vec<u64> = rb.iter().map(|e| e.ts).collect();
        assert_eq!(ts, vec![40]);
    }

    #[test]
    fn ring_buffer_rev_is_newest_first() {
        let mut rb = RingBuffer::with_capacity(4);
        for i in 0..4u64 {
            rb.push(RingEntry::new(i, 0, vec![], vec![]));
        }
        let ts: Vec<u64> = rb.iter_rev().map(|e| e.ts).collect();
        assert_eq!(ts, vec![3, 2, 1, 0]);
    }
}
