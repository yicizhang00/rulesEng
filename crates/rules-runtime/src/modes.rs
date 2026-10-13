//! v1.0 四模执行（PRD §4）的公共骨架：模式路由、PEP 裁决结果、惩罚租约账本。
//!
//! 四种执行模式共享同一份 AST（`SpecFile`），运行期的差异被收敛到三个横切设施：
//!
//! ```text
//!   ┌──────────────┐   ┌───────────────┐   ┌──────────────────┐
//!   │ ModeRouter   │   │ Adjudication  │   │ LeaseLedger      │
//!   │ 名字 → 模式   │   │ ALLOW / DENY  │   │ frozen_until 账本 │
//!   └──────────────┘   └───────────────┘   └──────────────────┘
//! ```
//!
//! * **模式 A（PURE）**：`Adjudication` 就是 `Verdict`，无状态、纯函数。
//! * **模式 B（STATEFUL）**：由 [`crate::memory`] 的受限工作内存承担，
//!   本模块只负责"规则 ∈ 模式 B"的路由与 DAG 合法性门禁。
//! * **模式 C（STREAM）**：滑动窗口 + [`LeaseLedger`] 的惩罚租约；
//!   租约只增不减（单调 `max`），由 `tick()` 驱动的到期回收负责放行，
//!   **不引入任何后台定时器**（PRD §4.3.2 消除 1 秒漏单）。
//! * **模式 D（DMN）**：由 [`crate::decision`] 的决策表执行器承担。

use crate::ViolationRecord;
use rules_ast::*;
use std::collections::HashMap;

/// 一次 PEP 裁决的完整结果。
///
/// PEP 只需要读 [`Adjudication::verdict`]：`Allow` 放行，`Deny` 物理阻断。
/// 其余字段是可观测性负载（`explain` / `effects` 会进入告警 trace）。
#[derive(Debug, Clone, PartialEq)]
pub struct Adjudication {
    /// 裁决结论。
    pub verdict: Verdict,
    /// 触发裁决的规则名（`Allow` 时为快筛通过且无违规时命中的最后一条 guard，或空串）。
    pub spec_name: String,
    /// 实体类型。
    pub entity_name: String,
    /// 实体实例键。
    pub entity_id: String,
    /// 触发裁决的事件类型。
    pub event_type: String,
    /// 人类可读的冲突/违规解释。
    pub explain: String,
    /// 裁决附带的确定性副作用（`LeaseUpdate` / `Transition` / `Emit`）。
    pub effects: Vec<Effect>,
    /// 裁决时刻。
    pub timestamp: u64,
    /// 是否由 PEP 前置快筛（`guard`）产生（真）还是全量不变量产生（假）。
    pub from_guard: bool,
}

impl Adjudication {
    /// 放行。
    pub fn allow(event_type: impl Into<String>, timestamp: u64) -> Self {
        Adjudication {
            verdict: Verdict::Allow,
            spec_name: String::new(),
            entity_name: String::new(),
            entity_id: String::new(),
            event_type: event_type.into(),
            explain: "no policy violated".to_string(),
            effects: Vec::new(),
            timestamp,
            from_guard: false,
        }
    }

    /// 阻断。
    pub fn deny(spec: &SpecDecl, entity_name: &str, entity_id: &str, explain: impl Into<String>, timestamp: u64, from_guard: bool) -> Self {
        Adjudication {
            verdict: spec.verdict.clone(),
            spec_name: spec.name.clone(),
            entity_name: entity_name.to_string(),
            entity_id: entity_id.to_string(),
            event_type: String::new(),
            explain: explain.into(),
            effects: spec.effects.clone(),
            timestamp,
            from_guard,
        }
    }

    /// 由运行期违规记录构造。
    pub fn from_record(r: &ViolationRecord, from_guard: bool) -> Self {
        Adjudication {
            verdict: r.verdict.clone(),
            spec_name: r.spec_name.clone(),
            entity_name: r.entity_name.clone(),
            entity_id: r.entity_id.clone(),
            event_type: String::new(),
            explain: r.explain.clone(),
            effects: r.effects.clone(),
            timestamp: r.timestamp,
            from_guard,
        }
    }

    /// 是否拒绝。
    pub fn is_deny(&self) -> bool {
        self.verdict.is_deny()
    }

    /// 拒绝码（`ALLOW` 时为 `None`）。
    pub fn code(&self) -> Option<&str> {
        self.verdict.code()
    }

    /// 单行协议串：`ALLOW` 或 `DENY:ERR_CODE`（PEP 共享内存原子位图写这个值）。
    pub fn as_protocol(&self) -> String {
        self.verdict.as_str()
    }

    /// 该裁决要求冻结到的时间点（若带 `LeaseUpdate`）。
    pub fn lease_until(&self, now: u64) -> Option<(String, u64)> {
        self.effects.iter().find_map(|e| match e {
            Effect::LeaseUpdate { target, expr } => {
                Some((target.clone(), apply_lease_expr(expr, now)))
            }
            _ => None,
        })
    }
}

/// 求值租约表达式（`now() + 60s`）→ 绝对到期时间戳。
///
/// 只接受 `now()` / `now() + <duration>` / 裸 `<duration>` / 数值字面量
/// ——**刻意不支持任意表达式**：租约到期时间必须是可静态求界的，
/// 否则"无后台定时器"的回收语义会被图灵完备的副作用破坏。
pub fn apply_lease_expr(e: &Expr, now: u64) -> u64 {
    fn dur_secs(e: &Expr) -> Option<i64> {
        match e {
            Expr::DurationLit(d) => Some(d.as_secs() as i64),
            Expr::Number(n) => Some(*n as i64),
            _ => None,
        }
    }
    match e {
        Expr::Call { func, args } if func == "now" || func == "today" => {
            let extra = args.first().and_then(dur_secs).unwrap_or(0);
            now.saturating_add(extra.max(0) as u64)
        }
        Expr::Binary { op: BinaryOp::Add, left, right } => {
            let base = match left.as_ref() {
                Expr::Call { func, .. } if func == "now" || func == "today" => now,
                other => dur_secs(other).unwrap_or(0).max(0) as u64,
            };
            let extra = dur_secs(right).unwrap_or(0).max(0) as u64;
            base.saturating_add(extra)
        }
        other => dur_secs(other).unwrap_or(0).max(0) as u64,
    }
}

/// 惩罚租约账本（PRD §4.3.1 特性三）。
///
/// 两条铁律：
/// 1. **单调**：`apply` 只延长、不缩短。同一实体被重复命中时取 `max`，
///    避免"用一笔小额违规把大额冻结刷掉"的博弈。
/// 2. **无后台定时器**：到期回收发生在 `tick()`（时钟推进）或下一次
///    `is_frozen` 查询上，回收成本 O(活跃租约数)。
#[derive(Debug, Clone, Default)]
pub struct LeaseLedger {
    frozen: HashMap<(String, String), u64>,
}

impl LeaseLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// 单调推进租约，返回推进后的到期时间。
    pub fn apply(&mut self, entity: &str, id: &str, until: u64) -> u64 {
        let slot = self.frozen.entry((entity.to_string(), id.to_string())).or_insert(0);
        *slot = (*slot).max(until);
        *slot
    }

    /// 到期时间（未冻结为 0）。
    pub fn frozen_until(&self, entity: &str, id: &str) -> u64 {
        self.frozen.get(&(entity.to_string(), id.to_string())).copied().unwrap_or(0)
    }

    /// 当前是否处于冻结期。
    pub fn is_frozen(&self, entity: &str, id: &str, now: u64) -> bool {
        self.frozen_until(entity, id) > now
    }

    /// 到期回收，返回本次放行的实体数。由 `tick()` 调用（无后台定时器）。
    pub fn release_expired(&mut self, now: u64) -> usize {
        let before = self.frozen.len();
        self.frozen.retain(|_, until| *until > now);
        before - self.frozen.len()
    }

    pub fn len(&self) -> usize {
        self.frozen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frozen.is_empty()
    }

    /// 活跃租约快照（可观测性）。
    pub fn snapshot(&self) -> Vec<((String, String), u64)> {
        let mut v: Vec<_> = self.frozen.iter().map(|(k, t)| (k.clone(), *t)).collect();
        v.sort();
        v
    }
}

/// 模式路由：`SpecFile` 内的每个可执行单元归属哪个模式。
#[derive(Debug, Clone, Default)]
pub struct ModeRouter {
    entries: Vec<(String, Mode)>,
}

impl ModeRouter {
    /// 从 AST 构建路由表（顺序即声明序）。
    pub fn build(spec: &SpecFile) -> Self {
        let mut entries: Vec<(String, Mode)> = Vec::new();
        for s in &spec.specs {
            entries.push((s.name.clone(), s.mode));
        }
        for d in &spec.decision_tables {
            entries.push((d.name.clone(), Mode::DecisionTable));
        }
        for r in &spec.stateful_rules {
            entries.push((r.name.clone(), Mode::Stateful));
        }
        for st in &spec.streams {
            entries.push((st.name.clone(), Mode::Stream));
        }
        ModeRouter { entries }
    }

    /// 按名字查模式。
    pub fn mode_of(&self, name: &str) -> Option<Mode> {
        self.entries.iter().find(|(n, _)| n == name).map(|(_, m)| *m)
    }

    /// 某模式下的全部名字。
    pub fn names(&self, mode: Mode) -> Vec<&str> {
        self.entries.iter().filter(|(_, m)| *m == mode).map(|(n, _)| n.as_str()).collect()
    }

    /// 各模式的单元计数，按 PURE / STATEFUL / STREAM / DMN 顺序。
    pub fn census(&self) -> [(Mode, usize); 4] {
        [
            (Mode::Pure, self.names(Mode::Pure).len()),
            (Mode::Stateful, self.names(Mode::Stateful).len()),
            (Mode::Stream, self.names(Mode::Stream).len()),
            (Mode::DecisionTable, self.names(Mode::DecisionTable).len()),
        ]
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 位向量状态的可读渲染：`0x0A` → `CSRC_APPROVED|ISSUING`。
///
/// 用于 AC1/AC4 的"反例参数"与运行期 trace——PRD 要求裁决必须能说清
/// 是**哪几位**同时成立，而不是丢一个裸整数给运维。
pub fn render_bits(entity: Option<&EntityDecl>, mask: u64) -> String {
    let mut names: Vec<&str> = Vec::new();
    if let Some(e) = entity {
        for st in &e.states {
            if let Some(b) = st.mask {
                if b != 0 && (mask & b) == b {
                    names.push(st.name.as_str());
                }
            }
        }
    }
    if names.is_empty() {
        return format!("0x{mask:02X}");
    }
    format!("0x{mask:02X}({})", names.join("|"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn lease_is_monotonic_and_releases_on_tick() {
        let mut l = LeaseLedger::new();
        assert_eq!(l.apply("Seat", "A1", 100), 100);
        // 更短的租约不能把已冻结的实体提前放行
        assert_eq!(l.apply("Seat", "A1", 40), 100);
        assert!(l.is_frozen("Seat", "A1", 99));
        assert!(!l.is_frozen("Seat", "A1", 100));
        assert_eq!(l.release_expired(100), 1);
        assert_eq!(l.frozen_until("Seat", "A1"), 0);
        assert!(l.is_empty());
    }

    #[test]
    fn lease_expr_now_plus_60s() {
        let e = Expr::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expr::Call { func: "now".into(), args: vec![] }),
            right: Box::new(Expr::DurationLit(Duration::from_secs(60))),
        };
        assert_eq!(apply_lease_expr(&e, 1_000), 1_060);
    }

    #[test]
    fn mode_router_census() {
        let spec = SpecFile {
            entities: vec![],
            streams: vec![],
            metrics: vec![],
            specs: vec![],
            decision_tables: vec![],
            stateful_rules: vec![],
            var_decls: vec![],
            binds: vec![],
            mode: Mode::Pure,
        };
        let r = ModeRouter::build(&spec);
        assert!(r.is_empty());
        assert_eq!(r.census()[0], (Mode::Pure, 0));
    }

    #[test]
    fn render_bits_names_each_bit() {
        let e = EntityDecl {
            name: "Company".into(),
            key: "company_code".into(),
            mode: Mode::Pure,
            states: vec![
                StateConst::masked("BOARD_RESOLVED", 0x01),
                StateConst::masked("SHAREHOLDER_APPROVED", 0x02),
                StateConst::masked("CSRC_APPROVED", 0x04),
                StateConst::masked("ISSUING", 0x08),
            ],
            ..Default::default()
        };
        assert_eq!(render_bits(Some(&e), 0x05), "0x05(BOARD_RESOLVED|CSRC_APPROVED)");
        assert_eq!(render_bits(Some(&e), 0x10), "0x10");
    }

    #[test]
    fn adjudication_protocol_string() {
        let spec = SpecDecl {
            name: "MaxFrequencyLimit".into(),
            entity_name: "Seat".into(),
            entity_var: "s".into(),
            mode: Mode::Stream,
            kind: PolicyKind::Invariant,
            events: vec!["OrderIntent".into()],
            given: vec![],
            invariant: TemporalExpr::Predicate(Expr::Bool(true)),
            violation: ViolationHandler::default(),
            verdict: Verdict::Deny { code: "ERR_X".into(), reason: "boom".into() },
            effects: vec![],
            meta: NodeMeta::default(),
            span: Span::default(),
        };
        let a = Adjudication::deny(&spec, "Seat", "A1", "21st order", 10, false);
        assert!(a.is_deny());
        assert_eq!(a.code(), Some("ERR_X"));
        assert_eq!(a.as_protocol(), "DENY:ERR_X");
        assert_eq!(Adjudication::allow("OrderIntent", 5).as_protocol(), "ALLOW");
    }
}
