//! # `kafka` —— Kafka ProducerInterceptor（FR4）
//!
//! PRD FR4 原文：
//!
//! > **Kafka 消息拦截**：提供 `RuleKafkaProducerInterceptor`，在消息发出前调用
//! > PDP，返回 `DENY` 时抛出拦截异常，物理阻止消息到达 Broker。
//!
//! ## 为什么必须是"拦截器"而不是"消费者"
//!
//! 消费端改写（consume-then-compensate）本质是**事后**补偿：消息已经进了
//! Broker，其他消费者可能已经读到了。PEP 必须在 `KafkaProducer.send()` 的
//! **同一次调用栈里**阻断，让 `send()` 直接失败——这才是"禁止进入 Broker"。
//!
//! ## Java 侧接入形态
//!
//! 本 crate 提供的是一份**语义完整、可测试**的模型（[`ProducerRecord`] +
//! [`RuleKafkaProducerInterceptor::on_send`]），以及一条 C-ABI 通道
//! （[`crate::ffi`]）。真实 Kafka 客户端（`org.apache.kafka.clients.producer
//! .ProducerInterceptor`）的适配只需要三行：
//!
//! ```text
//! public ProducerRecord<K,V> onSend(ProducerRecord<K,V> rec) {
//!     int rc = RulesPep.rules_pep_admit(h, headers);
//!     if (rc != 0) throw new InterceptionDeniedException(RulesPep.lastProtocol(h));
//!     return rec;
//! }
//! ```
//!
//! 抛出的异常会沿 `send()` 调用栈浮出，Kafka 把这次 produce 记为失败且**不写
//! 入日志段**——这正是"物理阻止消息到达 Broker"。
//!
//! ## 字段从哪里来
//!
//! 生产实践里，路由元数据（事件类型 / 实体 / 主键）放 Kafka **header**，
//! 业务载荷留在 `value` 由业务侧异步保存——这样拦截器不需要反序列化业务体，
//! 也就不会在热路径上引入 schema 依赖。[`HeaderIntentMapper`] 实现了这一约定。

use crate::{DecisionPoint, Intent, PepCore, Protocol, RegulatoryRuntime};
use rules_runtime::Adjudication;
use std::collections::HashMap;
use std::fmt;

/// 一条待发送的 Kafka 记录（`ProducerRecord<K,V>` 的字节化投影）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProducerRecord {
    pub topic: String,
    pub partition: i32,
    /// `None` 表示由分区器决定。
    pub key: Option<Vec<u8>>,
    pub value: Vec<u8>,
    pub headers: Vec<(String, String)>,
    /// 生产者时间戳（毫秒）；`0` 表示由 Broker 赋时间戳。
    pub timestamp: u64,
}

impl ProducerRecord {
    pub fn new(topic: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        ProducerRecord {
            topic: topic.into(),
            partition: -1,
            key: None,
            value: value.into(),
            headers: Vec::new(),
            timestamp: 0,
        }
    }

    pub fn with_partition(mut self, p: i32) -> Self {
        self.partition = p;
        self
    }

    pub fn with_key(mut self, k: impl Into<Vec<u8>>) -> Self {
        self.key = Some(k.into());
        self
    }

    pub fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp = ts;
        self
    }

    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    /// 取 header 值（同名取第一个）。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

// =====================================================================
// 意图映射
// =====================================================================

/// 把 Kafka 记录映射为送审意图。
///
/// 抽象这一层是因为"哪条消息属于哪个实体"是**业务拓扑**，不是引擎能猜的。
pub trait KafkaIntentMapper: Send {
    fn map(&self, rec: &ProducerRecord) -> Intent;
}

/// 从 Kafka header 提取路由元数据的默认映射器。
///
/// 约定的保留 header：
///
/// | header | 含义 |
/// |---|---|
/// | `rules.event_type` | 事件类型（必填） |
/// | `rules.entity`     | 实体类型（必填） |
/// | `rules.entity_id`  | 实体实例键（必填；缺省回落到记录 key 的 UTF-8） |
///
/// 其余 header 一律成为意图字段（值原样透传）。
#[derive(Debug, Clone)]
pub struct HeaderIntentMapper {
    pub event_type_header: String,
    pub entity_header: String,
    pub entity_id_header: String,
}

impl Default for HeaderIntentMapper {
    fn default() -> Self {
        HeaderIntentMapper {
            event_type_header: "rules.event_type".into(),
            entity_header: "rules.entity".into(),
            entity_id_header: "rules.entity_id".into(),
        }
    }
}

impl HeaderIntentMapper {
    pub fn new() -> Self {
        Self::default()
    }

    fn reserved(&self, name: &str) -> bool {
        name == self.event_type_header || name == self.entity_header || name == self.entity_id_header
    }
}

impl KafkaIntentMapper for HeaderIntentMapper {
    fn map(&self, rec: &ProducerRecord) -> Intent {
        let event_type = rec.header(&self.event_type_header).unwrap_or("KafkaMessage").to_string();
        let entity = rec.header(&self.entity_header).unwrap_or("Message").to_string();
        let entity_id = rec
            .header(&self.entity_id_header)
            .map(str::to_string)
            .or_else(|| rec.key.as_ref().map(|k| String::from_utf8_lossy(k).into_owned()))
            .unwrap_or_default();

        let mut intent = Intent::kafka(event_type, rec.topic.clone(), rec.partition, entity, entity_id, rec.timestamp);
        for (k, v) in &rec.headers {
            if !self.reserved(k) {
                intent.fields.insert(k.clone(), v.clone());
            }
        }
        intent
    }
}

// =====================================================================
// 拦截异常
// =====================================================================

/// 拦截异常 —— 对应 Java 侧抛出的 `InterceptionDeniedException`。
///
/// 实现 [`std::error::Error`]，因此在 Rust 适配层也能用 `?` 向上传播；
/// 在跨语言边界上，[`InterceptionDenied::protocol`] 就是抛给客户端的消息体。
#[derive(Debug, Clone, PartialEq)]
pub struct InterceptionDenied {
    /// 单行协议（`DENY:<ERR_CODE>`）。
    pub protocol: Protocol,
    /// 拒绝码（冗余字段，便于日志）。
    pub code: String,
    /// 触发的规则名。
    pub rule: String,
    /// 人类可读解释。
    pub reason: String,
    pub topic: String,
    pub partition: i32,
    pub entity: String,
    pub entity_id: String,
    pub timestamp: u64,
    /// 是否由共享内存极速域（而非规则求值）拦下。
    pub fast_path: bool,
}

impl InterceptionDenied {
    pub fn from_adjudication(rec: &ProducerRecord, adj: &Adjudication) -> Self {
        InterceptionDenied {
            protocol: Protocol::from_adjudication(adj),
            code: adj.code().unwrap_or(crate::ERR_MALFORMED).to_string(),
            rule: adj.spec_name.clone(),
            reason: adj.explain.clone(),
            topic: rec.topic.clone(),
            partition: rec.partition,
            entity: adj.entity_name.clone(),
            entity_id: adj.entity_id.clone(),
            timestamp: adj.timestamp,
            fast_path: false,
        }
    }

    fn frozen(rec: &ProducerRecord, intent: &Intent, until: u64) -> Self {
        InterceptionDenied {
            protocol: Protocol::deny(crate::ERR_FROZEN),
            code: crate::ERR_FROZEN.to_string(),
            rule: String::new(),
            reason: format!(
                "实体 {}#{} 处于惩罚租约冻结期（frozen_until={until}）",
                intent.entity, intent.entity_id
            ),
            topic: rec.topic.clone(),
            partition: rec.partition,
            entity: intent.entity.clone(),
            entity_id: intent.entity_id.clone(),
            timestamp: intent.timestamp,
            fast_path: true,
        }
    }

    pub fn is_deny(&self) -> bool {
        self.protocol.is_deny()
    }
}

impl fmt::Display for InterceptionDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} topic={} partition={} entity={}#{} rule={} reason={}",
            self.protocol.to_wire(),
            self.topic,
            self.partition,
            self.entity,
            self.entity_id,
            if self.rule.is_empty() { "<shared-memory-latch>" } else { &self.rule },
            self.reason
        )
    }
}

impl std::error::Error for InterceptionDenied {}

/// 拦截器错误：只有两类——配置错误与拦截。
///
/// 刻意不把"送审过程出错"建模成第三类：PEP 的 `admit` 是**不可失败**的
/// （要么改判 `ALLOW`，要么改判 `DENY`），不存在"送审失败所以放行"的灰区。
#[derive(Debug, Clone, PartialEq)]
pub enum KafkaInterceptError {
    /// 载荷缺少必需的路由元数据。
    MissingRouting {
        topic: String,
        header: String,
    },
    /// 被 PDP / 极速域阻断。
    Denied(Box<InterceptionDenied>),
}

impl fmt::Display for KafkaInterceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KafkaInterceptError::MissingRouting { topic, header } => {
                write!(f, "记录缺少必需 header {header:?}（topic={topic}）")
            }
            KafkaInterceptError::Denied(d) => write!(f, "{d}"),
        }
    }
}

impl std::error::Error for KafkaInterceptError {}

impl From<InterceptionDenied> for KafkaInterceptError {
    fn from(d: InterceptionDenied) -> Self {
        KafkaInterceptError::Denied(Box::new(d))
    }
}

// =====================================================================
// 拦截器
// =====================================================================

/// `RuleKafkaProducerInterceptor` —— 消息发出前的同步准入闸门。
pub struct RuleKafkaProducerInterceptor<D: DecisionPoint = RegulatoryRuntime> {
    core: PepCore<D>,
    mapper: Box<dyn KafkaIntentMapper>,
    /// 是否强制要求 `rules.event_type` / `rules.entity` 存在；
    /// 关掉后缺省回落为 `KafkaMessage` / `Message`（宽松模式，便于灰度）。
    strict: bool,
    /// 被拦截的记录计数（按 topic）。
    denied_by_topic: HashMap<String, u64>,
}

impl<D: DecisionPoint> RuleKafkaProducerInterceptor<D> {
    /// 用指定映射器构造。
    pub fn new(core: PepCore<D>, mapper: Box<dyn KafkaIntentMapper>) -> Self {
        RuleKafkaProducerInterceptor { core, mapper, strict: true, denied_by_topic: HashMap::new() }
    }

    /// 用默认 header 映射器构造。
    pub fn with_header_mapper(core: PepCore<D>) -> Self {
        Self::new(core, Box::new(HeaderIntentMapper::default()))
    }

    /// 关闭严格路由校验。
    pub fn lenient(mut self) -> Self {
        self.strict = false;
        self
    }

    pub fn core(&self) -> &PepCore<D> {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut PepCore<D> {
        &mut self.core
    }

    pub fn mapper(&self) -> &dyn KafkaIntentMapper {
        self.mapper.as_ref()
    }

    /// 各 topic 的拦截计数。
    pub fn denied_by_topic(&self) -> &HashMap<String, u64> {
        &self.denied_by_topic
    }

    /// 记录不送审直接放行的次数（`on_acknowledgement` / 非阻塞路径）。
    pub fn record<'a>(&self, rec: &'a ProducerRecord) -> Intent {
        self.mapper.map(rec)
    }

    /// **`ProducerInterceptor.onSend` 的语义等价实现**。
    ///
    /// * `Ok(())` —— 放行，消息进入 RecordAccumulator，随后写入 Broker；
    /// * `Err(Denied)` —— 拦截，适配层必须抛出异常让 `send()` 失败。
    ///
    /// 拦截路径**不分配除异常对象以外的东西**：`DENY` 由共享内存极速域命中时
    /// 连规则求值都不发生（见 [`PepCore::fast_gate`]）。
    pub fn on_send(&mut self, rec: &ProducerRecord) -> Result<(), KafkaInterceptError> {
        let intent = self.mapper.map(rec);

        if self.strict {
            if rec.header("rules.event_type").is_none() && intent.event_type == "KafkaMessage" {
                return Err(KafkaInterceptError::MissingRouting {
                    topic: rec.topic.clone(),
                    header: "rules.event_type".into(),
                });
            }
            if rec.header("rules.entity").is_none() && intent.entity == "Message" {
                return Err(KafkaInterceptError::MissingRouting {
                    topic: rec.topic.clone(),
                    header: "rules.entity".into(),
                });
            }
        }

        // 极速域（共享内存位图）与旁路域（完整 PDP）都由 `PepCore::admit` 承担——
        // 这里刻意**不**另写一份前置判断：重复实现会让统计口径分叉
        // （`latch_hits` 漏记），而 `admit` 在极速域命中时本就不会求值任何规则。
        let out = self.core.admit(&intent);
        if out.is_denied() {
            let d = match &out.adjudication {
                Some(adj) => InterceptionDenied::from_adjudication(rec, adj),
                None => InterceptionDenied::frozen(rec, &intent, out.frozen_until),
            };
            *self.denied_by_topic.entry(rec.topic.clone()).or_insert(0) += 1;
            return Err(d.into());
        }
        Ok(())
    }

    /// **`ProducerInterceptor.onAcknowledgement`**：Broker 确认回调。
    ///
    /// 默认实现是空操作——PEP 的裁决在 `on_send` 阶段已经终结，
    /// 确认阶段只用于可观测性（延迟 / 失败统计）。
    pub fn on_acknowledgement(&mut self, _rec: &ProducerRecord) {}

    /// **`ProducerInterceptor.configure` / `close`** 对应物。
    pub fn close(&mut self) -> usize {
        let n = self.denied_by_topic.values().sum::<u64>() as usize;
        self.denied_by_topic.clear();
        n
    }
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PepCore;

    /// 凡送审即拒绝并广播 30 秒租约的假 PDP。
    struct DenyPdp {
        now: u64,
    }

    impl DecisionPoint for DenyPdp {
        fn now(&self) -> u64 {
            self.now
        }
        fn admit(&mut self, intent: &Intent) -> Adjudication {
            Adjudication {
                verdict: rules_ast::Verdict::Deny {
                    code: "ERR_MSG_FORBIDDEN".into(),
                    reason: "blocked".into(),
                },
                spec_name: "MessageGate".into(),
                entity_name: intent.entity.clone(),
                entity_id: intent.entity_id.clone(),
                event_type: intent.event_type.clone(),
                explain: "消息体命中禁区".into(),
                effects: vec![rules_ast::Effect::LeaseUpdate {
                    target: "frozen_until".into(),
                    expr: rules_ast::Expr::call("now", vec![rules_ast::Expr::Number(30.0)]),
                }],
                timestamp: intent.timestamp,
                from_guard: false,
            }
        }
        fn frozen_until(&self, _e: &str, _i: &str) -> u64 {
            0
        }
    }

    /// 凡送审即放行的假 PDP。
    struct AllowPdp {
        now: u64,
    }

    impl DecisionPoint for AllowPdp {
        fn now(&self) -> u64 {
            self.now
        }
        fn admit(&mut self, intent: &Intent) -> Adjudication {
            Adjudication::allow(intent.event_type.clone(), intent.timestamp)
        }
        fn frozen_until(&self, _e: &str, _i: &str) -> u64 {
            0
        }
    }

    fn gate_deny(now: u64) -> RuleKafkaProducerInterceptor<DenyPdp> {
        RuleKafkaProducerInterceptor::with_header_mapper(PepCore::new(DenyPdp { now }))
    }

    fn allow_gate(now: u64) -> RuleKafkaProducerInterceptor<AllowPdp> {
        RuleKafkaProducerInterceptor::with_header_mapper(PepCore::new(AllowPdp { now }))
    }

    fn record(topic: &str, id: &str) -> ProducerRecord {
        ProducerRecord::new(topic, b"payload".to_vec())
            .with_key("PBU001")
            .with_timestamp(100)
            .with_header("rules.event_type", "OrderIntent")
            .with_header("rules.entity", "Seat")
            .with_header("rules.entity_id", id)
            .with_header("amount", "500")
    }

    // ---------- 记录 ----------

    #[test]
    fn producer_record_builders_and_header_lookup() {
        let r = record("orders", "PBU001");
        assert_eq!(r.header("rules.event_type"), Some("OrderIntent"));
        assert_eq!(r.header("amount"), Some("500"));
        assert_eq!(r.header("missing"), None);
        assert_eq!(r.header("rules.entity_id"), Some("PBU001"));
        assert_eq!(r.timestamp, 100);
    }

    // ---------- 映射 ----------

    #[test]
    fn header_mapper_extracts_routing_and_fields() {
        let m = HeaderIntentMapper::default();
        let i = m.map(&record("orders", "PBU001"));
        assert_eq!(i.event_type, "OrderIntent");
        assert_eq!(i.entity, "Seat");
        assert_eq!(i.entity_id, "PBU001");
        assert_eq!(i.latch_key, "Seat#PBU001");
        assert_eq!(i.fields.get("amount").map(String::as_str), Some("500"));
        // 保留 header 不得成为业务字段
        assert!(!i.fields.contains_key("rules.event_type"));
        assert!(!i.fields.contains_key("rules.entity"));
        assert!(!i.fields.contains_key("rules.entity_id"));
    }

    #[test]
    fn header_mapper_falls_back_to_record_key() {
        let m = HeaderIntentMapper::default();
        let r = ProducerRecord::new("orders", b"x".to_vec())
            .with_key("SEAT-9")
            .with_header("rules.event_type", "E")
            .with_header("rules.entity", "Seat");
        assert_eq!(m.map(&r).entity_id, "SEAT-9");
    }

    #[test]
    fn header_mapper_uses_lossy_utf8_for_binary_key() {
        let m = HeaderIntentMapper::default();
        let r = ProducerRecord::new("t", b"x".to_vec())
            .with_key(vec![0x50, 0x42, 0xff])
            .with_header("rules.event_type", "E")
            .with_header("rules.entity", "Seat");
        let i = m.map(&r);
        assert!(i.entity_id.starts_with("PB"));
        assert!(i.entity_id.contains('\u{fffd}'));
    }

    // ---------- 拦截 ----------

    #[test]
    fn allowed_record_passes_through() {
        let mut ic = allow_gate(100);
        assert!(ic.on_send(&record("orders", "P1")).is_ok());
        assert!(ic.denied_by_topic().is_empty());
        assert_eq!(ic.core().stats().allowed, 1);
    }

    #[test]
    fn denied_record_yields_interception_error_with_protocol() {
        let mut ic = gate_deny(100);
        let err = ic.on_send(&record("orders", "P1")).unwrap_err();
        match &err {
            KafkaInterceptError::Denied(d) => {
                assert_eq!(d.protocol.to_wire(), "DENY:ERR_MSG_FORBIDDEN");
                assert_eq!(d.rule, "MessageGate");
                assert_eq!(d.topic, "orders");
                assert_eq!(d.entity_id, "P1");
                assert!(!d.fast_path);
                assert!(d.reason.contains("禁区"));
            }
            other => panic!("期望 Denied，实际 {other:?}"),
        }
        assert!(err.to_string().contains("DENY:ERR_MSG_FORBIDDEN"));
        assert_eq!(ic.denied_by_topic().get("orders"), Some(&1));
    }

    #[test]
    fn denial_broadcasts_lease_so_next_record_hits_fast_path() {
        let mut ic = gate_deny(100);
        let _ = ic.on_send(&record("orders", "P1"));
        assert_eq!(ic.core().active_leases(), 1);

        let err = ic.on_send(&record("orders", "P1")).unwrap_err();
        match err {
            KafkaInterceptError::Denied(d) => {
                assert!(d.fast_path, "第二笔必须走极速域");
                assert_eq!(d.code, crate::ERR_FROZEN);
                assert!(d.reason.contains("frozen_until"));
            }
            other => panic!("期望 Denied，实际 {other:?}"),
        }
        assert_eq!(ic.core().stats().latch_hits, 1);
        assert_eq!(ic.core().stats().leases_broadcast, 1);
    }

    #[test]
    fn strict_mode_rejects_missing_routing_headers() {
        let mut ic = allow_gate(100);
        let bare = ProducerRecord::new("orders", b"x".to_vec());
        let err = ic.on_send(&bare).unwrap_err();
        assert!(matches!(err, KafkaInterceptError::MissingRouting { .. }));
        assert!(err.to_string().contains("rules.event_type"));
    }

    #[test]
    fn lenient_mode_accepts_bare_records() {
        let mut ic = allow_gate(100).lenient();
        let bare = ProducerRecord::new("orders", b"x".to_vec());
        assert!(ic.on_send(&bare).is_ok());
        assert_eq!(ic.core().stats().allowed, 1);
    }

    #[test]
    fn missing_entity_header_alone_is_rejected_in_strict_mode() {
        let mut ic = allow_gate(100);
        let r = ProducerRecord::new("orders", b"x".to_vec()).with_header("rules.event_type", "E");
        let err = ic.on_send(&r).unwrap_err();
        assert!(matches!(err, KafkaInterceptError::MissingRouting { ref header, .. } if header == "rules.entity"));
    }

    #[test]
    fn acknowledgement_and_close_are_safe() {
        let mut ic = gate_deny(100);
        let r = record("orders", "P1");
        let _ = ic.on_send(&r);
        ic.on_acknowledgement(&r);
        assert_eq!(ic.close(), 1);
        assert!(ic.denied_by_topic().is_empty());
    }

    #[test]
    fn custom_mapper_is_honoured() {
        struct AlwaysSeat;
        impl KafkaIntentMapper for AlwaysSeat {
            fn map(&self, rec: &ProducerRecord) -> Intent {
                Intent::kafka("OrderIntent", rec.topic.clone(), rec.partition, "Seat", "FIXED", rec.timestamp)
            }
        }
        let mut ic = RuleKafkaProducerInterceptor::new(
            PepCore::new(AllowPdp { now: 100 }),
            Box::new(AlwaysSeat),
        );
        let bare = ProducerRecord::new("t", b"x".to_vec());
        assert!(ic.on_send(&bare).is_ok());
        assert_eq!(ic.record(&bare).entity_id, "FIXED");
    }
}
