//! # rules-pep —— 策略执行点（PEP）代理层（PRD §3 / FR4）
//!
//! PEP 层是"**无侵入意图-裁决架构**"的落地点：原业务微服务**不写任何合规业务代码**，
//! 由本层在三个物理位置把 In-Flight 数据截下来送 PDP 裁决，并在 `DENY` 时
//! 就地阻断：
//!
//! | 位置 | 适配器 | 阻断手段 |
//! |---|---|---|
//! | 报单网关 | [`ffi`]（C-ABI / WASM 内联过滤器） | 同线程返回 `DENY`，报单不出网关 |
//! | 消息代理 | [`kafka::RuleKafkaProducerInterceptor`] | `on_send` 抛拦截异常，消息不落 Broker |
//! | 数据库 | [`db::TxGuard`] / [`db::Outbox`] | `COMMIT` 前送审，`DENY` 强制回滚 |
//!
//! ## 双轨延迟模型（NFR：内联 P99 < 1μs / 平均 < 200ns）
//!
//! * **极速域**（[`PepCore::fast_gate`]）：只做一次共享内存原子读（[`latch::FrozenLatch`]），
//!   零分配、零哈希表、零规则求值——这是"超限后 60 秒内所有后续报单被瞬间拦截"的物理实现。
//! * **旁路域**（[`PepCore::admit`]）：完整 PDP 裁决（四模执行 + 租约广播 + 窗口撤回）。
//!
//! 两轨共用同一份 [`latch::FrozenLatch`]：引擎（PDP 进程）写入冻结租约，
//! 网关（PEP 进程）只读命中——这正是 PRD §4.1 中 `shm_open` / `mmap` 广播
//! 的语义模型；[`latch::FrozenLatch::attach`] 允许宿主持有真实共享内存后原位构造。
//!
//! ## 协议
//!
//! PEP 与 PDP 之间只交换一句话：[`Protocol`] —— `ALLOW` 或 `DENY:<ERR_CODE>`。
//! 该串同时是共享内存位图、C-ABI 返回值与审计日志的公共载体。
//!
//! ```text
//! 业务代码 ──► PEP(fast_gate / admit) ──► PDP(四模执行引擎) ──► Protocol
//!                    │                                          │
//!                    └──────────── 共享内存 frozen_until ◄────────┘
//! ```
//!
//! # 契约与语义
//!
//! * **fail-closed**：协议串无法解析时一律视为 `DENY:ERR_PEP_MALFORMED_PROTOCOL`；
//!   C-ABI 层任何 panic 都被 `catch_unwind` 捕获并返回 [`ffi::PEP_ERR`]。
//! * **单调租约**：共享内存写入用 `fetch_max`，重复命中只延长、不缩短，
//!   杜绝"用一笔小额违规把大额冻结刷掉"的博弈。

pub mod db;
pub mod ffi;
pub mod kafka;
pub mod latch;

use rules_ast::Effect;
use rules_runtime::{Adjudication, Event, RegulatoryRuntime};
use std::collections::HashMap;
use std::sync::Arc;

pub use db::{CommitOutcome, Outbox, OutboxEntry, RelayReport, RowMutation, RowOp, TableIntentMapper, TxGuard, TxIntentMapper};
pub use kafka::{HeaderIntentMapper, InterceptionDenied, KafkaIntentMapper, ProducerRecord, RuleKafkaProducerInterceptor};
pub use latch::{key_hash, FrozenLatch};

// =====================================================================
// 协议
// =====================================================================

/// 放行标记。
pub const ALLOW: &str = "ALLOW";
/// 拒绝前缀（`DENY:<ERR_CODE>`）。
pub const DENY_PREFIX: &str = "DENY:";

/// 冻结租约命中（极速域唯一的拒绝码，PRD AC2）。
pub const ERR_FROZEN: &str = "ERR_PEP_FROZEN";
/// 协议串无法解析（fail-closed 兜底）。
pub const ERR_MALFORMED: &str = "ERR_PEP_MALFORMED_PROTOCOL";
/// C-ABI 边界内部错误（panic / 空指针）。
pub const ERR_FFI: &str = "ERR_PEP_FFI";
/// 契约文本解析失败。
pub const ERR_BAD_SPEC: &str = "ERR_PEP_BAD_SPEC";

/// PEP ⇄ PDP 之间的单行裁决协议。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// 放行。
    Allow,
    /// 阻断，携带业务可读的拒绝码。
    Deny { code: String },
}

impl Protocol {
    pub fn allow() -> Self {
        Protocol::Allow
    }

    pub fn deny(code: impl Into<String>) -> Self {
        Protocol::Deny { code: code.into() }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Protocol::Allow)
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Protocol::Deny { .. })
    }

    /// 拒绝码（`ALLOW` 时 `None`）。
    pub fn code(&self) -> Option<&str> {
        match self {
            Protocol::Allow => None,
            Protocol::Deny { code } => Some(code),
        }
    }

    /// 线格式：`ALLOW` / `DENY:ERR_CODE`。
    pub fn to_wire(&self) -> String {
        match self {
            Protocol::Allow => ALLOW.to_string(),
            Protocol::Deny { code } => format!("{DENY_PREFIX}{code}"),
        }
    }

    /// 解析线格式。**fail-closed**：任何无法识别的串都判为拒绝。
    pub fn parse(s: &str) -> Protocol {
        let s = s.trim();
        if s.eq_ignore_ascii_case(ALLOW) {
            return Protocol::Allow;
        }
        if let Some(code) = s.strip_prefix(DENY_PREFIX).or_else(|| s.strip_prefix("deny:")) {
            let code = code.trim();
            return if code.is_empty() {
                Protocol::deny(ERR_MALFORMED)
            } else {
                Protocol::deny(code)
            };
        }
        Protocol::deny(ERR_MALFORMED)
    }

    /// 由运行期裁决结果转换。
    pub fn from_adjudication(adj: &Adjudication) -> Protocol {
        if adj.is_deny() {
            Protocol::deny(adj.code().unwrap_or(ERR_MALFORMED))
        } else {
            Protocol::Allow
        }
    }

    /// C-ABI 返回值：`0` 放行，`1` 阻断。
    pub fn to_code(&self) -> i32 {
        if self.is_allow() {
            ffi::PEP_ALLOW
        } else {
            ffi::PEP_DENY
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

// =====================================================================
// 送审意图
// =====================================================================

/// 意图来源（用于审计与差异化处置策略）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// 报单网关内联过滤器（C-ABI / WASM）。
    Gateway { venue: String },
    /// Kafka 生产者拦截器。
    Kafka { topic: String, partition: i32 },
    /// 数据库事务拦截 / Outbox。
    Database { table: String, op: RowOp },
    /// 直接调用（控制台试算 / 测试）。
    Direct,
}

impl Origin {
    /// 是否属于"必须同线程物理阻断"的极速域来源（FR4）。
    pub fn is_hot_path(&self) -> bool {
        matches!(self, Origin::Gateway { .. } | Origin::Kafka { .. })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Origin::Gateway { .. } => "gateway",
            Origin::Kafka { .. } => "kafka",
            Origin::Database { .. } => "database",
            Origin::Direct => "direct",
        }
    }
}

/// 一笔待送审的意图（与 `rules_runtime::Event` 同构，但**携带实体归属**）。
///
/// `entity` / `entity_id` 是 PEP 侧独有的信息：事件流本身只带字段，
/// 而网关/Kafka/DB 三个接入点都知道"这笔数据属于谁"。
#[derive(Debug, Clone, PartialEq)]
pub struct Intent {
    pub event_type: String,
    pub entity: String,
    pub entity_id: String,
    /// 共享内存租约位图键，构造时一次性算出，热路径零分配。
    pub latch_key: String,
    pub fields: HashMap<String, String>,
    pub timestamp: u64,
    pub origin: Origin,
}

impl Intent {
    pub fn new(
        event_type: impl Into<String>,
        entity: impl Into<String>,
        entity_id: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        let entity = entity.into();
        let entity_id = entity_id.into();
        Intent {
            event_type: event_type.into(),
            latch_key: latch_key_of(&entity, &entity_id),
            entity,
            entity_id,
            fields: HashMap::new(),
            timestamp,
            origin: Origin::Direct,
        }
    }

    /// 报单网关来源（交易前风控，NFR 内联 < 1μs）。
    pub fn gateway(
        event_type: impl Into<String>,
        venue: impl Into<String>,
        entity: impl Into<String>,
        entity_id: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        let mut i = Intent::new(event_type, entity, entity_id, timestamp);
        i.origin = Origin::Gateway { venue: venue.into() };
        i
    }

    /// Kafka 来源（生产者拦截器）。
    pub fn kafka(
        event_type: impl Into<String>,
        topic: impl Into<String>,
        partition: i32,
        entity: impl Into<String>,
        entity_id: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        let mut i = Intent::new(event_type, entity, entity_id, timestamp);
        i.origin = Origin::Kafka { topic: topic.into(), partition };
        i
    }

    /// 数据库来源（事务拦截 / Outbox）。
    pub fn database(
        event_type: impl Into<String>,
        table: impl Into<String>,
        op: RowOp,
        entity: impl Into<String>,
        entity_id: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        let mut i = Intent::new(event_type, entity, entity_id, timestamp);
        i.origin = Origin::Database { table: table.into(), op };
        i
    }

    pub fn with_field(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.fields.insert(k.into(), v.into());
        self
    }

    pub fn with_fields<I, K, V>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in it {
            self.fields.insert(k.into(), v.into());
        }
        self
    }

    /// 转成运行期事件（字段原样透传）。
    pub fn to_event(&self) -> Event {
        Event {
            event_type: self.event_type.clone(),
            fields: self.fields.clone(),
            timestamp: self.timestamp,
        }
    }
}

/// 共享内存租约键：`<Entity>#<id>`。
pub fn latch_key_of(entity: &str, entity_id: &str) -> String {
    let mut s = String::with_capacity(entity.len() + entity_id.len() + 1);
    s.push_str(entity);
    s.push('#');
    s.push_str(entity_id);
    s
}

// =====================================================================
// PDP 抽象
// =====================================================================

/// 策略决策点抽象。
///
/// 抽出这一层有两个目的：
/// 1. PEP 不必依赖 `rules-runtime` 的具体实现（可用 mock 做超低延迟验证）；
/// 2. 真实 PDP 可以是本进程内的引擎，也可以是远端集群（实现同一 trait 即可）。
pub trait DecisionPoint: Send {
    /// 当前逻辑时钟（秒）。
    fn now(&self) -> u64;
    /// 送审一笔意图，返回裁决。
    fn admit(&mut self, intent: &Intent) -> Adjudication;
    /// 查询实体冻结到期时间（`0` = 未冻结）。
    fn frozen_until(&self, entity: &str, entity_id: &str) -> u64;

    /// 是否处于冻结期。
    fn is_frozen(&self, entity: &str, entity_id: &str) -> bool {
        self.frozen_until(entity, entity_id) > self.now()
    }
}

impl DecisionPoint for RegulatoryRuntime {
    fn now(&self) -> u64 {
        self.now
    }

    /// 全量准入：补齐实体键字段 → 走运行时的 `admit`（含窗口撤回与租约推进）。
    ///
    /// 实体键字段的补齐放在这里而不是调用方：PEP 接入点（网关 / Kafka / JDBC）
    /// 天然知道实体归属，但**不该知道 DSL 里键字段叫什么名字**。
    fn admit(&mut self, intent: &Intent) -> Adjudication {
        let mut ev = intent.to_event();
        if let Some(key) = self.spec.entity(&intent.entity).map(|e| e.key.clone()) {
            if !key.is_empty() {
                ev.fields.entry(key).or_insert_with(|| intent.entity_id.clone());
            }
        }
        ev.timestamp = intent.timestamp;
        RegulatoryRuntime::admit(self, ev)
    }

    fn frozen_until(&self, entity: &str, entity_id: &str) -> u64 {
        self.leases.frozen_until(entity, entity_id)
    }
}

// =====================================================================
// PEP 统计与结果
// =====================================================================

/// PEP 侧可观测性计数（无锁累加在单线程 PEP 上无竞争）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PepStats {
    /// 送审总笔数。
    pub reviewed: u64,
    /// 放行笔数。
    pub allowed: u64,
    /// 阻断笔数（含极速域命中）。
    pub denied: u64,
    /// 极速域命中次数（未进入 PDP）。
    pub latch_hits: u64,
    /// 由租约广播写出的冻结数。
    pub leases_broadcast: u64,
    /// 共享内存位图容量不足导致广播失败的次数（容量规划告警）。
    pub latch_overflow: u64,
}

impl PepStats {
    /// 阻断率。
    pub fn deny_rate(&self) -> f64 {
        if self.reviewed == 0 {
            0.0
        } else {
            self.denied as f64 / self.reviewed as f64
        }
    }
}

/// 一次完整准入的结果。
#[derive(Debug, Clone, PartialEq)]
pub struct PepOutcome {
    /// 单行协议。
    pub protocol: Protocol,
    /// 完整裁决（极速域命中时为 `None`）。
    pub adjudication: Option<Adjudication>,
    /// 是否走的是极速域（未求值任何规则）。
    pub fast_path: bool,
    /// 该实体当前冻结到期时间（`0` = 未冻结）。
    pub frozen_until: u64,
}

impl PepOutcome {
    pub fn is_allowed(&self) -> bool {
        self.protocol.is_allow()
    }
    pub fn is_denied(&self) -> bool {
        self.protocol.is_deny()
    }
    /// 被阻断的规则名（极速域命中或未阻断时为空）。
    pub fn rule(&self) -> &str {
        self.adjudication.as_ref().map(|a| a.spec_name.as_str()).unwrap_or("")
    }
    /// 人类可读解释。
    pub fn explain(&self) -> &str {
        self.adjudication.as_ref().map(|a| a.explain.as_str()).unwrap_or("frozen by shared-memory lease")
    }
}

// =====================================================================
// PEP 核心
// =====================================================================

/// PEP 核心：把"极速域"与"旁路域"粘合在一起。
///
/// 泛型参数让同一套 PEP 逻辑既能挂真实引擎（`RegulatoryRuntime`），
/// 也能挂测试替身（衡量纯 PEP 开销）。
pub struct PepCore<D: DecisionPoint = RegulatoryRuntime> {
    pdp: D,
    latch: Arc<FrozenLatch>,
    stats: PepStats,
    last: Option<PepOutcome>,
}

impl<D: DecisionPoint> PepCore<D> {
    /// 用默认共享内存位图（4096 槽）构造。
    pub fn new(pdp: D) -> Self {
        PepCore::with_latch(pdp, Arc::new(FrozenLatch::new(4096)))
    }

    /// 挂到宿主提供的共享内存位图上（跨进程广播）。
    pub fn with_latch(pdp: D, latch: Arc<FrozenLatch>) -> Self {
        PepCore { pdp, latch, stats: PepStats::default(), last: None }
    }

    pub fn pdp(&self) -> &D {
        &self.pdp
    }
    pub fn pdp_mut(&mut self) -> &mut D {
        &mut self.pdp
    }
    pub fn latch(&self) -> &FrozenLatch {
        &self.latch
    }
    pub fn stats(&self) -> &PepStats {
        &self.stats
    }
    pub fn last_outcome(&self) -> Option<&PepOutcome> {
        self.last.as_ref()
    }
    /// 逻辑时钟（租约到期的唯一依据，无后台定时器）。
    pub fn now(&self) -> u64 {
        self.pdp.now()
    }

    /// **极速域**：一次共享内存原子读。
    ///
    /// 复杂度 O(1)、无分配、无锁、无规则求值——报单网关内联过滤器的
    /// 唯一入口（NFR：P99 < 1μs）。
    pub fn fast_gate(&self, latch_key: &str) -> Protocol {
        self.fast_gate_at(latch_key, 0)
    }

    /// 极速域（显式时钟）。`now == 0` 表示沿用 PDP 内部时钟。
    ///
    /// 取二者的 `max`：网关的单调时钟与引擎时钟可能因跨进程部署而略有偏差，
    /// 取大值可保证"引擎刚刚广播的冻结"不会被网关的落后时钟判为已过期。
    pub fn fast_gate_at(&self, latch_key: &str, now: u64) -> Protocol {
        let effective = now.max(self.pdp.now());
        let until = self.latch.frozen_until(latch_key);
        if until > effective {
            Protocol::deny(ERR_FROZEN)
        } else {
            Protocol::Allow
        }
    }

    /// **完整准入**：极速域 → 旁路域（PDP）→ 租约广播。
    pub fn admit(&mut self, intent: &Intent) -> PepOutcome {
        let now = intent.timestamp.max(self.pdp.now());
        self.stats.reviewed += 1;

        // ① 极速域：共享内存位图命中即阻断，绝不进入规则求值。
        let until = self.latch.frozen_until(&intent.latch_key);
        if until > now {
            self.stats.denied += 1;
            self.stats.latch_hits += 1;
            let out = PepOutcome {
                protocol: Protocol::deny(ERR_FROZEN),
                adjudication: None,
                fast_path: true,
                frozen_until: until,
            };
            self.last = Some(out.clone());
            return out;
        }

        // ② 旁路域：完整 PDP 裁决。
        let adj = self.pdp.admit(intent);
        let protocol = Protocol::from_adjudication(&adj);

        // ③ 租约广播：DENY 携带的 `LeaseUpdate` 写进共享内存（单调 max），
        //    此后 60 秒内的所有后续意图都被极速域拦下（AC2）。
        let mut broadcast = 0u64;
        if let Some((_, new_until)) = adj.lease_until(now) {
            if new_until > 0 {
                match self.latch.put(&intent.latch_key, new_until) {
                    Some(_) => self.stats.leases_broadcast += 1,
                    None => self.stats.latch_overflow += 1,
                }
                broadcast = new_until;
            }
        }

        let frozen_until = if broadcast > 0 {
            broadcast
        } else {
            self.pdp.frozen_until(&intent.entity, &intent.entity_id)
        };

        if protocol.is_allow() {
            self.stats.allowed += 1;
        } else {
            self.stats.denied += 1;
        }

        let out = PepOutcome {
            protocol,
            adjudication: Some(adj),
            fast_path: false,
            frozen_until,
        };
        self.last = Some(out.clone());
        out
    }

    /// 审计视角：与 [`PepCore::admit`] 的区别是**不做极速域短路、不做租约广播**，
    /// 事件照常落地，只报告它打破了哪些不变量（回放 / 对账用）。
    pub fn adjudicate(&mut self, intent: &Intent) -> Vec<Adjudication> {
        self.stats.reviewed += 1;
        let adj = self.pdp.admit(intent);
        if adj.is_deny() {
            self.stats.denied += 1;
        } else {
            self.stats.allowed += 1;
        }
        vec![adj]
    }

    /// 推进逻辑时钟并回收到期租约（无后台定时器，PRD §4.3.1）。
    pub fn release_expired_leases(&mut self, now: u64) -> usize {
        self.latch.clear_expired(now)
    }

    /// 已广播出去的活跃冻结数。
    pub fn active_leases(&self) -> usize {
        self.latch.active()
    }

    /// 所有活跃冻结的快照（`(键哈希, 到期时间)`）。
    pub fn lease_snapshot(&self) -> Vec<(u64, u64)> {
        self.latch.entries()
    }

    /// 清空统计（压测用）。
    pub fn reset_stats(&mut self) {
        self.stats = PepStats::default();
    }
}

impl PepCore<RegulatoryRuntime> {
    /// 推进引擎逻辑时钟，并回收到期租约（返回回收数）。
    ///
    /// 无后台定时器：时钟推进是租约唯一的回收时机。滑动窗口的淘汰同样挂在
    /// 引擎时钟上，因此**跨时间窗的重放必须先 `tick`**——否则旧事件仍留在
    /// 窗口里，会得到偏保守（误拒）的结论。
    pub fn tick(&mut self, now: u64) -> usize {
        self.pdp_mut().now = now;
        self.release_expired_leases(now)
    }
}

// =====================================================================
// 便捷构造
// =====================================================================

/// 契约源码 → PEP 核心（控制台 / CLI / FFI 共用入口）。
pub fn open(spec_src: &str) -> Result<PepCore<RegulatoryRuntime>, String> {
    let spec = rules_parser::parse(spec_src).map_err(|e| format!("{ERR_BAD_SPEC}: {e}"))?;
    let dict = rules_dictionary::DataDictionary::default();
    let rt = RegulatoryRuntime::new(spec, dict);
    Ok(PepCore::new(rt))
}

/// 契约源码 → 挂接共享内存位图的 PEP 核心。
pub fn open_with_latch(
    spec_src: &str,
    latch: Arc<FrozenLatch>,
) -> Result<PepCore<RegulatoryRuntime>, String> {
    let spec = rules_parser::parse(spec_src).map_err(|e| format!("{ERR_BAD_SPEC}: {e}"))?;
    let dict = rules_dictionary::DataDictionary::default();
    let rt = RegulatoryRuntime::new(spec, dict);
    Ok(PepCore::with_latch(rt, latch))
}

/// 该实体实例当前生效的 `LeaseUpdate` 目标名（审计用）。
pub fn lease_target(adj: &Adjudication) -> Option<&str> {
    adj.effects.iter().find_map(|e| match e {
        Effect::LeaseUpdate { target, .. } => Some(target.as_str()),
        _ => None,
    })
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rules_ast::Verdict;

    // ---------- 协议 ----------

    #[test]
    fn protocol_wire_format_round_trips() {
        assert_eq!(Protocol::allow().to_wire(), "ALLOW");
        assert_eq!(Protocol::deny("ERR_X").to_wire(), "DENY:ERR_X");
        assert_eq!(Protocol::parse("ALLOW"), Protocol::Allow);
        assert_eq!(Protocol::parse(" allow "), Protocol::Allow);
        assert_eq!(Protocol::parse("DENY:ERR_A").code(), Some("ERR_A"));
    }

    #[test]
    fn malformed_protocol_is_fail_closed() {
        assert_eq!(Protocol::parse("garbage").code(), Some(ERR_MALFORMED));
        assert_eq!(Protocol::parse("DENY:").code(), Some(ERR_MALFORMED));
        assert_eq!(Protocol::parse("").code(), Some(ERR_MALFORMED));
        assert!(Protocol::parse("yeet").is_deny());
    }

    #[test]
    fn protocol_codes_are_stable() {
        assert_eq!(Protocol::allow().to_code(), 0);
        assert_eq!(Protocol::deny("X").to_code(), 1);
        assert_eq!(Protocol::deny("X").to_string(), "DENY:X");
    }

    #[test]
    fn protocol_from_adjudication_mirrors_verdict() {
        let allow = Adjudication {
            verdict: Verdict::Allow,
            spec_name: String::new(),
            entity_name: "Seat".into(),
            entity_id: "PBU1".into(),
            event_type: "OrderIntent".into(),
            explain: String::new(),
            effects: Vec::new(),
            timestamp: 1,
            from_guard: false,
        };
        assert_eq!(Protocol::from_adjudication(&allow), Protocol::Allow);

        let mut deny = allow.clone();
        deny.verdict = Verdict::Deny { code: "ERR_SEAT_FROZEN".into(), reason: "r".into() };
        assert_eq!(Protocol::from_adjudication(&deny), Protocol::deny("ERR_SEAT_FROZEN"));
    }

    // ---------- 意图 ----------

    #[test]
    fn intent_latch_key_is_entity_scoped() {
        let i = Intent::new("OrderIntent", "Seat", "PBU001", 10);
        assert_eq!(i.latch_key, "Seat#PBU001");
        assert_eq!(i.to_event().event_type, "OrderIntent");
        assert_eq!(i.to_event().timestamp, 10);
        assert!(!i.origin.is_hot_path());

        let g = Intent::gateway("OrderIntent", "SSE", "Seat", "PBU001", 10);
        assert!(g.origin.is_hot_path());
        assert_eq!(g.origin.as_str(), "gateway");

        let k = Intent::kafka("E", "orders", 3, "Seat", "PBU001", 10);
        assert!(k.origin.is_hot_path());
        assert_eq!(k.origin.as_str(), "kafka");

        let d = Intent::database("Row", "coupon", RowOp::Insert, "User", "U1", 10);
        assert!(!d.origin.is_hot_path());
        assert_eq!(d.origin.as_str(), "database");
    }

    #[test]
    fn intent_fields_accumulate() {
        let i = Intent::new("E", "Seat", "S1", 0)
            .with_field("a", "1")
            .with_fields(vec![("b", "2"), ("c", "3")]);
        assert_eq!(i.fields.get("a").map(String::as_str), Some("1"));
        assert_eq!(i.fields.get("b").map(String::as_str), Some("2"));
        assert_eq!(i.fields.get("c").map(String::as_str), Some("3"));
    }

    // ---------- 测试替身 PDP ----------

    /// 记录送审次序的假 PDP，用于隔离测量 PEP 自身开销。
    struct MockPdp {
        now: u64,
        frozen: HashMap<String, u64>,
        calls: Vec<String>,
        always_deny: Option<String>,
    }

    impl MockPdp {
        fn new(now: u64) -> Self {
            MockPdp { now, frozen: HashMap::new(), calls: Vec::new(), always_deny: None }
        }
    }

    impl DecisionPoint for MockPdp {
        fn now(&self) -> u64 {
            self.now
        }
        fn admit(&mut self, intent: &Intent) -> Adjudication {
            self.calls.push(intent.latch_key.clone());
            match &self.always_deny {
                Some(code) => Adjudication {
                    verdict: Verdict::Deny { code: code.clone(), reason: "mock".into() },
                    spec_name: "MockRule".into(),
                    entity_name: intent.entity.clone(),
                    entity_id: intent.entity_id.clone(),
                    event_type: intent.event_type.clone(),
                    explain: "mock deny".into(),
                    effects: Vec::new(),
                    timestamp: intent.timestamp,
                    from_guard: false,
                },
                None => Adjudication::allow(intent.event_type.clone(), intent.timestamp),
            }
        }
        fn frozen_until(&self, entity: &str, id: &str) -> u64 {
            self.frozen.get(&latch_key_of(entity, id)).copied().unwrap_or(0)
        }
    }

    #[test]
    fn fast_gate_short_circuits_pdp() {
        let mut core = PepCore::new(MockPdp::new(1000));
        let intent = Intent::new("OrderIntent", "Seat", "PBU001", 1000);

        // 首次放行 → 进入 PDP
        let out = core.admit(&intent);
        assert!(out.is_allowed());
        assert!(!out.fast_path);
        assert_eq!(core.pdp().calls.len(), 1);

        // 手工广播一笔冻结 → 后续不再进入 PDP
        core.latch().put(&intent.latch_key, 1060);
        let out2 = core.admit(&intent);
        assert!(out2.is_denied());
        assert!(out2.fast_path);
        assert_eq!(out2.protocol.code(), Some(ERR_FROZEN));
        assert_eq!(core.pdp().calls.len(), 1, "极速域命中后不得再调用 PDP");
        assert_eq!(out2.frozen_until, 1060);
    }

    #[test]
    fn fast_gate_releases_after_lease_expiry() {
        let mut core = PepCore::new(MockPdp::new(1000));
        let intent = Intent::new("OrderIntent", "Seat", "PBU001", 1000);
        core.latch().put(&intent.latch_key, 1060);
        assert!(core.admit(&intent).is_denied());

        // 时钟推过 1060：无需任何后台定时器，租约自然失效
        core.pdp_mut().now = 1061;
        let out = core.admit(&intent);
        assert!(out.is_allowed(), "租约到期后必须自动放行");
        assert!(!out.fast_path);
    }

    #[test]
    fn fast_gate_uses_max_of_pdp_and_intent_clock() {
        // PDP 时钟领先于意图时间戳时，必须用 PDP 时钟判断冻结
        let core = PepCore::new(MockPdp::new(5000));
        let stale = Intent::new("E", "Seat", "S1", 10);
        core.latch().put(&stale.latch_key, 100);
        // 租约 100 相对 PDP 时钟 5000 已过期
        assert!(core.fast_gate(&stale.latch_key).is_allow());

        core.latch().put(&stale.latch_key, 9000);
        assert!(core.fast_gate(&stale.latch_key).is_deny());
    }

    #[test]
    fn stats_track_allow_deny_and_latch_hits() {
        let mut core = PepCore::new(MockPdp::new(100));
        let i = Intent::new("E", "Seat", "S1", 100);
        core.admit(&i);
        core.latch().put(&i.latch_key, 160);
        core.admit(&i);
        core.admit(&i);

        let s = core.stats();
        assert_eq!(s.reviewed, 3);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.denied, 2);
        assert_eq!(s.latch_hits, 2);
        assert!((s.deny_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn deny_broadcasts_lease_to_shared_memory() {
        // 假 PDP：返回带 LeaseUpdate 的拒绝
        struct LeaseDenying { now: u64 }
        impl DecisionPoint for LeaseDenying {
            fn now(&self) -> u64 {
                self.now
            }
            fn admit(&mut self, intent: &Intent) -> Adjudication {
                Adjudication {
                    verdict: Verdict::Deny { code: "ERR_SEAT_FLOOD".into(), reason: "flood".into() },
                    spec_name: "SeatFloodProtection".into(),
                    entity_name: intent.entity.clone(),
                    entity_id: intent.entity_id.clone(),
                    event_type: intent.event_type.clone(),
                    explain: ">20 in 5s".into(),
                    effects: vec![Effect::LeaseUpdate {
                        target: "frozen_until".into(),
                        expr: rules_ast::Expr::call("now", vec![rules_ast::Expr::Number(60.0)]),
                    }],
                    timestamp: intent.timestamp,
                    from_guard: false,
                }
            }
            fn frozen_until(&self, _e: &str, _i: &str) -> u64 {
                0
            }
        }

        let mut core = PepCore::new(LeaseDenying { now: 1000 });
        let i = Intent::new("OrderIntent", "Seat", "PBU001", 1000);
        let out = core.admit(&i);
        assert!(out.is_denied());
        assert_eq!(out.frozen_until, 1060, "租约必须广播到共享内存");
        assert_eq!(core.stats().leases_broadcast, 1);

        // 下一笔走极速域
        let out2 = core.admit(&Intent::new("OrderIntent", "Seat", "PBU001", 1001));
        assert!(out2.fast_path);
        assert_eq!(out2.frozen_until, 1060);

        // 到期回收
        let released = core.release_expired_leases(1061);
        assert_eq!(released, 1);
        assert_eq!(core.active_leases(), 0);
    }

    #[test]
    fn pep_open_parses_real_contract_and_reviews() {
        let src = r#"
            contract CouponGate on Entity[User] pure {
                key: user_id
                guard AmountMatches on Event[IssueCouponIntent] {
                    when: event.requested_amount > 10
                    verdict: DENY(code: "ERR_COUPON_AMOUNT_FRAUD", reason: "amount mismatch")
                }
            }
        "#;
        let mut core = open(src).expect("契约解析失败");
        let ok = core.admit(&Intent::new("IssueCouponIntent", "User", "U1", 100).with_field("requested_amount", "5"));
        assert!(ok.is_allowed(), "{:?}", ok.adjudication);
        let bad = core.admit(&Intent::new("IssueCouponIntent", "User", "U1", 101).with_field("requested_amount", "20"));
        assert!(bad.is_denied());
        assert_eq!(bad.protocol.code(), Some("ERR_COUPON_AMOUNT_FRAUD"));
    }

    #[test]
    fn open_rejects_garbage_spec() {
        let err = match open("this is not a contract at all !!!") {
            Ok(_) => panic!("非法契约必须被拒绝"),
            Err(e) => e,
        };
        assert!(err.starts_with(ERR_BAD_SPEC), "{err}");
    }

    #[test]
    fn outcome_exposes_rule_and_explain() {
        let mut core = PepCore::new(MockPdp { always_deny: Some("ERR_X".into()), ..MockPdp::new(1) });
        let out = core.admit(&Intent::new("E", "Seat", "S1", 1));
        assert_eq!(out.rule(), "MockRule");
        assert_eq!(out.explain(), "mock deny");
    }

    #[test]
    fn lease_target_is_extracted() {
        let adj = Adjudication {
            verdict: Verdict::Deny { code: "X".into(), reason: "y".into() },
            spec_name: "S".into(),
            entity_name: "Seat".into(),
            entity_id: "S1".into(),
            event_type: "E".into(),
            explain: String::new(),
            effects: vec![Effect::LeaseUpdate {
                target: "frozen_until".into(),
                expr: rules_ast::Expr::Number(60.0),
            }],
            timestamp: 0,
            from_guard: false,
        };
        assert_eq!(lease_target(&adj), Some("frozen_until"));
        assert_eq!(lease_target(&Adjudication::allow("E", 0)), None);
    }
}
