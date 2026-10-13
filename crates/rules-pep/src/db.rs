//! # `db` —— 数据库事务拦截与 Transactional Outbox（FR4）
//!
//! PRD FR4 原文：
//!
//! > **数据库事务拦截**：提供 MyBatis / JDBC / MySQL Proxy 拦截插件，在 SQL
//! > `COMMIT` 前提取行数据送审，返回 `DENY` 时强制触发事务回滚。
//!
//! ## 两种落库形态
//!
//! ### ① 同步拦截（[`TxGuard`]）—— "物理禁止落库"
//!
//! ```text
//!   SQL 预编译            DB 事务                引擎
//!  ┌───────────┐        ┌──────────┐          ┌──────────┐
//!  │ execute() ├──登记──►│ COMMIT   ├──送审───►│  PDP     │
//!  └───────────┘        │          │◄─ALLOW───┤          │
//!                       │          │          └──────────┘
//!                       │          │◄─DENY────────────────┘
//!                       └────┬─────┘
//!                    ROLLBACK（无一行写入磁盘）
//! ```
//!
//! 关键点：拦截点必须在 **`execute()` 之后、`COMMIT` 之前**——这时行数据已在
//! 事务的未提交缓冲里（MySQL 的 undo log / 内存页），可以完整送审，而 `DENY`
//! 触发的 `ROLLBACK` 保证这些行**永远不落到磁盘**。若在 `execute()` 之前拦截，
//! 引擎看不到最终行值（例如 `UPDATE ... SET amount = amount + ?`）；若在
//! `COMMIT` 之后拦截，已经来不及了。
//!
//! ### ② Transactional Outbox（[`Outbox`]）—— 最终一致版
//!
//! 适用于跨服务、无法在同一事务里回调引擎的场景：
//!
//! 1. 业务事务内**只写** `outbox` 暂存表（同一事务，原子）；
//! 2. 事务提交后由 [`Outbox::relay`] 逐条送审；
//! 3. `ALLOW` 的行投递到业务表，`DENY` 的行标记为丢弃并告警。
//!
//! 相比 ①，它把"阻断"从**物理**降级为**最终一致**——但换来的是业务侧零侵入
//! （不需要 JDBC 插件、不需要 MySQL Proxy）。两者的选择是延迟与耦合的取舍。

use crate::{DecisionPoint, Intent, PepCore, Protocol, RegulatoryRuntime};
use std::collections::HashMap;
use std::fmt;

/// 行级 DML 操作类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowOp {
    Insert,
    Update,
    Delete,
}

impl RowOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            RowOp::Insert => "INSERT",
            RowOp::Update => "UPDATE",
            RowOp::Delete => "DELETE",
        }
    }
}

impl fmt::Display for RowOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一行待落库的变更（`execute()` 之后从 PreparedStatement 参数/返回行提取）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowMutation {
    pub table: String,
    pub op: RowOp,
    /// 列名 → 值的字符串投影（与 `rules_runtime::Event.fields` 同构）。
    pub row: HashMap<String, String>,
    /// 该行业务生效时间（Unix 秒）。
    ///
    /// 不是可选项：模式 D 的 DMN 决策表按**日历口径**取值（`in [11-01 .. 11-03]`），
    /// 引擎必须知道这行数据"属于哪一天"。缺省 `0` 会让日历类规则全部落进 default 行。
    pub at: u64,
}

impl RowMutation {
    pub fn new(table: impl Into<String>, op: RowOp, row: HashMap<String, String>) -> Self {
        RowMutation { table: table.into(), op, row, at: 0 }
    }

    pub fn insert(table: impl Into<String>, row: HashMap<String, String>) -> Self {
        Self::new(table, RowOp::Insert, row)
    }

    pub fn update(table: impl Into<String>, row: HashMap<String, String>) -> Self {
        Self::new(table, RowOp::Update, row)
    }

    pub fn delete(table: impl Into<String>, row: HashMap<String, String>) -> Self {
        Self::new(table, RowOp::Delete, row)
    }

    /// 设置行业务生效时间。
    pub fn at(mut self, ts: u64) -> Self {
        self.at = ts;
        self
    }

    pub fn get(&self, col: &str) -> Option<&str> {
        self.row.get(col).map(String::as_str)
    }
}

impl fmt::Display for RowMutation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.op, self.table)
    }
}

// =====================================================================
// 行 → 意图映射
// =====================================================================

/// 把一行变更映射为送审意图。
///
/// 返回 `None` 表示**该表不纳管**（直接放行、不产生审计噪声）。
/// "哪些表需要合规拦截"是业务拓扑，必须由接入方显式声明，
/// 引擎不能也不该去猜（否则 `DENY` 漫无边界）。
pub trait TxIntentMapper: Send {
    fn map(&self, m: &RowMutation) -> Option<Intent>;
}

/// 一张纳管表的单条路由规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRoute {
    /// 送审时使用的事件类型（如 `"CouponIssueRow"`）。
    pub event_type: String,
    /// 归属的实体类型（如 `"User"`）。
    pub entity: String,
    /// 主键所在列名（如 `"user_id"`）。
    pub id_column: String,
}

impl TableRoute {
    pub fn new(
        event_type: impl Into<String>,
        entity: impl Into<String>,
        id_column: impl Into<String>,
    ) -> Self {
        TableRoute { event_type: event_type.into(), entity: entity.into(), id_column: id_column.into() }
    }
}

/// 基于「表名 → 路由」登记的默认映射器。
///
/// 行内所有列原样成为意图字段——`DENY` 时的反例（如"申请额度 20 ≠ 合法 10"）
/// 因此直接可读，无需回查数据库。
#[derive(Debug, Clone, Default)]
pub struct TableIntentMapper {
    routes: HashMap<String, TableRoute>,
    /// 是否允许未登记表按 `(表名, "id")` 兜底纳管。默认关闭（fail-safe：不纳管即放行）。
    fallback_to_id: bool,
}

impl TableIntentMapper {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一张纳管表。
    pub fn register(
        mut self,
        table: impl Into<String>,
        event_type: impl Into<String>,
        entity: impl Into<String>,
        id_column: impl Into<String>,
    ) -> Self {
        self.routes
            .insert(table.into(), TableRoute::new(event_type, entity, id_column));
        self
    }

    /// 打开"未登记表按 `id` 列兜底纳管"。谨慎使用——会让 `DENY` 面扩展到全库。
    pub fn with_id_fallback(mut self) -> Self {
        self.fallback_to_id = true;
        self
    }

    pub fn route_of(&self, table: &str) -> Option<&TableRoute> {
        self.routes.get(table)
    }

    pub fn tables(&self) -> impl Iterator<Item = &str> {
        self.routes.keys().map(String::as_str)
    }
}

impl TxIntentMapper for TableIntentMapper {
    fn map(&self, m: &RowMutation) -> Option<Intent> {
        match self.routes.get(&m.table) {
            Some(route) => Some(build_intent(
                m,
                &route.event_type.clone(),
                &route.entity.clone(),
                &route.id_column.clone(),
                &m.table,
            )),
            None if self.fallback_to_id => {
                let table = m.table.clone();
                Some(build_intent(m, &table, "Row", "id", &m.table))
            }
            None => None,
        }
    }
}

fn build_intent(
    m: &RowMutation,
    event_type: &str,
    entity: &str,
    id_column: &str,
    table: &str,
) -> Intent {
    let entity_id = m.get(id_column).unwrap_or("").to_string();
    let mut i = Intent::database(event_type, table, m.op, entity, entity_id, m.at);
    for (k, v) in &m.row {
        i.fields.insert(k.clone(), v.clone());
    }
    i
}

// =====================================================================
// 事务闸门
// =====================================================================

/// `COMMIT` 前的统一送审结果。
#[derive(Debug, Clone, PartialEq)]
pub enum CommitOutcome {
    /// 全部通过，调用方应执行真正的 `COMMIT`。
    Committed {
        /// 送审行数（`DENY` 前已通过的行也算）。
        reviewed: usize,
        /// 未纳管因而未送审的行数。
        bypassed: usize,
    },
    /// 至少一行被拒，调用方**必须**执行 `ROLLBACK`。
    RolledBack {
        /// 人类可读原因。
        reason: String,
        /// 拒绝码。
        code: String,
        /// 触发拒绝的行序号（`pending` 中的下标）。
        denied_at: usize,
        /// 触发拒绝的规则名（极速域命中时为空）。
        rule: String,
    },
}

impl CommitOutcome {
    pub fn is_committed(&self) -> bool {
        matches!(self, CommitOutcome::Committed { .. })
    }
    pub fn is_rolled_back(&self) -> bool {
        matches!(self, CommitOutcome::RolledBack { .. })
    }
}

impl fmt::Display for CommitOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitOutcome::Committed { reviewed, bypassed } => {
                write!(f, "COMMIT (reviewed={reviewed}, bypassed={bypassed})")
            }
            CommitOutcome::RolledBack { code, reason, denied_at, rule } => write!(
                f,
                "ROLLBACK DENY:{code} (row={denied_at}, rule={}) — {reason}",
                if rule.is_empty() { "<shared-memory-latch>" } else { rule }
            ),
        }
    }
}

/// JDBC / MyBatis / MySQL Proxy 拦截插件的核心闸门。
///
/// 用法（对应 JDBC 生命周期）：
///
/// ```text
/// // PreparedStatement.execute() 之后
/// guard.stage(RowMutation::insert("coupon", row));
/// // Connection.commit() 之前
/// match guard.commit() {
///     CommitOutcome::Committed { .. }   => conn.commit(),
///     CommitOutcome::RolledBack { .. }  => conn.rollback(),   // 物理禁止落库
/// }
/// ```
pub struct TxGuard<D: DecisionPoint = RegulatoryRuntime> {
    core: PepCore<D>,
    mapper: Box<dyn TxIntentMapper>,
    pending: Vec<RowMutation>,
    /// 未纳管、未送审的行数（可观测性）。
    bypassed: usize,
}

impl<D: DecisionPoint> TxGuard<D> {
    pub fn new(core: PepCore<D>, mapper: Box<dyn TxIntentMapper>) -> Self {
        TxGuard { core, mapper, pending: Vec::new(), bypassed: 0 }
    }

    /// 用「表 → 路由」登记表构造。
    pub fn with_table_mapper(core: PepCore<D>, mapper: TableIntentMapper) -> Self {
        Self::new(core, Box::new(mapper))
    }

    pub fn core(&self) -> &PepCore<D> {
        &self.core
    }
    pub fn core_mut(&mut self) -> &mut PepCore<D> {
        &mut self.core
    }

    /// 拦截点：`execute()` 之后登记一行。
    ///
    /// 返回该行**单独**的送审结果——但**不要**据此提前回滚：事务的最终裁决
    /// 必须由 [`TxGuard::commit`] 统一给出（单行放行不代表整个事务合法）。
    pub fn stage(&mut self, m: RowMutation) -> Protocol {
        if self.mapper.map(&m).is_none() {
            self.bypassed += 1;
            self.pending.push(m);
            return Protocol::Allow;
        }
        self.pending.push(m);
        Protocol::Allow
    }

    /// `COMMIT` 前的统一送审。
    pub fn commit(&mut self) -> CommitOutcome {
        for (idx, m) in self.pending.iter().enumerate() {
            let Some(intent) = self.mapper.map(m) else {
                continue;
            };
            let out = self.core.admit(&intent);
            if out.is_denied() {
                let code = out.protocol.code().unwrap_or(crate::ERR_MALFORMED).to_string();
                let reason = format!(
                    "{} 被准入守卫拒绝（{}，拒绝码 {}）：{}",
                    m,
                    out.explain(),
                    code,
                    if out.fast_path { "共享内存租约命中" } else { "规则求值" }
                );
                let rule = out.rule().to_string();
                return CommitOutcome::RolledBack { reason, code, denied_at: idx, rule };
            }
        }
        CommitOutcome::Committed { reviewed: self.pending.len(), bypassed: self.bypassed }
    }

    /// 已登记但未提交的行。
    pub fn pending(&self) -> &[RowMutation] {
        &self.pending
    }

    /// 未纳管行数。
    pub fn bypassed(&self) -> usize {
        self.bypassed
    }

    /// 事务结束后清空（无论提交还是回滚都要调用）。
    pub fn clear(&mut self) {
        self.pending.clear();
        self.bypassed = 0;
    }
}

// =====================================================================
// Transactional Outbox
// =====================================================================

/// `outbox` 暂存表里的一行。
#[derive(Debug, Clone, PartialEq)]
pub struct OutboxEntry {
    /// 暂存表主键（`BIGINT UNSIGNED`，对齐 Rust `u64`）。
    pub id: u64,
    pub intent: Intent,
    /// 入队时的预审结论。
    pub protocol: Protocol,
    pub enqueued_at: u64,
    /// 已投递到业务表的时间（`None` = 尚未投递）。
    pub relayed_at: Option<u64>,
    /// 被丢弃的原因（`DENY` 时）。
    pub discard_reason: Option<String>,
}

impl OutboxEntry {
    pub fn is_pending(&self) -> bool {
        self.relayed_at.is_none() && self.discard_reason.is_none()
    }
    pub fn is_delivered(&self) -> bool {
        self.relayed_at.is_some()
    }
    pub fn is_discarded(&self) -> bool {
        self.discard_reason.is_some()
    }
}

/// 一次 relay 的结果。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RelayReport {
    /// 已投递到业务表的 outbox id。
    pub delivered: Vec<u64>,
    /// 已丢弃的 `(outbox id, 拒绝码)`。
    pub discarded: Vec<(u64, String)>,
    /// 送审后仍被拒但**改判**为放行的（时钟回退 / 规则热更新导致）；
    /// 保留字段是为了可观测性——正常应为空。
    pub still_pending: Vec<u64>,
}

impl RelayReport {
    pub fn is_empty(&self) -> bool {
        self.delivered.is_empty() && self.discarded.is_empty() && self.still_pending.is_empty()
    }
    pub fn total(&self) -> usize {
        self.delivered.len() + self.discarded.len() + self.still_pending.len()
    }
}

/// Transactional Outbox 中继器。
///
/// 业务侧零侵入：业务事务只写 `outbox` 表，本类型负责在事务提交后
/// 逐条送审并决定投递 / 丢弃。
pub struct Outbox<D: DecisionPoint = RegulatoryRuntime> {
    core: PepCore<D>,
    entries: Vec<OutboxEntry>,
    next_id: u64,
}

impl<D: DecisionPoint> Outbox<D> {
    pub fn new(core: PepCore<D>) -> Self {
        Outbox { core, entries: Vec::new(), next_id: 1 }
    }

    pub fn core(&self) -> &PepCore<D> {
        &self.core
    }
    pub fn core_mut(&mut self) -> &mut PepCore<D> {
        &mut self.core
    }

    /// 业务事务内：把意图写入暂存表，并做一次预审（写入 `protocol` 列）。
    ///
    /// 预审**不阻断业务事务**——Outbox 的价值恰恰在于业务事务不依赖引擎可用性。
    /// 真正的阻断发生在 [`Outbox::relay`]。
    pub fn enqueue(&mut self, intent: Intent) -> Protocol {
        let now = intent.timestamp.max(self.core.now());
        let adj = self.core.adjudicate(&intent).remove(0);
        let protocol = Protocol::from_adjudication(&adj);
        let id = self.next_id;
        self.next_id += 1;
        let out = protocol.clone();
        self.entries.push(OutboxEntry {
            id,
            intent,
            protocol,
            enqueued_at: now,
            relayed_at: None,
            discard_reason: None,
        });
        out
    }

    /// 暂存表全量。
    pub fn entries(&self) -> &[OutboxEntry] {
        &self.entries
    }

    /// 尚未处理的条目。
    pub fn pending(&self) -> impl Iterator<Item = &OutboxEntry> {
        self.entries.iter().filter(|e| e.is_pending())
    }

    /// 中继：逐条重新送审（**必须重新送审**——入队时的预审结论可能已过期），
    /// `ALLOW` 投递、`DENY` 丢弃。
    pub fn relay(&mut self, now: u64) -> RelayReport {
        let mut report = RelayReport::default();
        for e in self.entries.iter_mut() {
            if !e.is_pending() {
                continue;
            }
            let out = self.core.admit(&e.intent);
            if out.is_allowed() {
                e.relayed_at = Some(now);
                e.protocol = Protocol::Allow;
                report.delivered.push(e.id);
            } else {
                e.discard_reason = Some(out.explain().to_string());
                e.protocol = out.protocol.clone();
                report
                    .discarded
                    .push((e.id, out.protocol.code().unwrap_or(crate::ERR_MALFORMED).to_string()));
            }
        }
        report
    }

    /// 清理已终结（投递或丢弃）的条目，返回清理数。
    pub fn purge(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.is_pending());
        before - self.entries.len()
    }

    /// 已终结条目的计数。
    pub fn settled(&self) -> usize {
        self.entries.len() - self.pending().count()
    }
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecisionPoint, PepCore};
    use rules_runtime::Adjudication;

    /// 按 `fields["blocked"]` 决定放行 / 拒绝的假 PDP。
    struct FieldGate {
        now: u64,
    }

    impl DecisionPoint for FieldGate {
        fn now(&self) -> u64 {
            self.now
        }
        fn admit(&mut self, intent: &Intent) -> Adjudication {
            if intent.fields.get("blocked").map(String::as_str) == Some("1") {
                Adjudication {
                    verdict: rules_ast::Verdict::Deny {
                        code: "ERR_ROW_BLOCKED".into(),
                        reason: "row rejected".into(),
                    },
                    spec_name: "RowGate".into(),
                    entity_name: intent.entity.clone(),
                    entity_id: intent.entity_id.clone(),
                    event_type: intent.event_type.clone(),
                    explain: "该行命中禁区".into(),
                    effects: Vec::new(),
                    timestamp: intent.timestamp,
                    from_guard: false,
                }
            } else {
                Adjudication::allow(intent.event_type.clone(), intent.timestamp)
            }
        }
        fn frozen_until(&self, _e: &str, _i: &str) -> u64 {
            0
        }
    }

    fn row_coupon(user: &str, amount: &str, blocked: bool) -> RowMutation {
        let mut r = HashMap::new();
        r.insert("user_id".to_string(), user.to_string());
        r.insert("amount".to_string(), amount.to_string());
        if blocked {
            r.insert("blocked".to_string(), "1".to_string());
        }
        RowMutation::insert("coupon", r)
    }

    fn mapper() -> TableIntentMapper {
        TableIntentMapper::new().register("coupon", "CouponIssueRow", "User", "user_id")
    }

    fn guard() -> TxGuard<FieldGate> {
        TxGuard::with_table_mapper(PepCore::new(FieldGate { now: 100 }), mapper())
    }

    // ---------- 行与映射 ----------

    #[test]
    fn row_mutation_accessors_and_display() {
        let m = row_coupon("U1", "10", false);
        assert_eq!(m.get("amount"), Some("10"));
        assert_eq!(m.get("missing"), None);
        assert_eq!(m.to_string(), "INSERT coupon");
        assert_eq!(RowOp::Update.to_string(), "UPDATE");
        assert_eq!(RowOp::Delete.as_str(), "DELETE");
        assert_eq!(m.at, 0);
        assert_eq!(m.clone().at(1102).at, 1102);
    }

    #[test]
    fn row_business_timestamp_flows_into_intent() {
        // 模式 D 的日历口径依赖这个时间：`in [11-01 .. 11-03]` 必须知道是哪一天
        let m = mapper();
        let i = m.map(&row_coupon("U1", "10", false).at(1102)).unwrap();
        assert_eq!(i.timestamp, 1102);
    }

    #[test]
    fn unregistered_table_is_bypassed() {
        let m = TableIntentMapper::new().register("coupon", "E", "User", "user_id");
        let other = RowMutation::insert("audit_log", HashMap::new());
        assert!(m.map(&other).is_none(), "未登记表不得纳管");
        assert_eq!(m.tables().count(), 1);
        assert!(m.route_of("coupon").is_some());
    }

    #[test]
    fn id_fallback_can_be_opted_in() {
        let m = TableIntentMapper::new().with_id_fallback();
        let mut row = HashMap::new();
        row.insert("id".to_string(), "42".to_string());
        let i = m.map(&RowMutation::insert("anything", row)).unwrap();
        assert_eq!(i.entity, "Row");
        assert_eq!(i.entity_id, "42");
        assert_eq!(i.event_type, "anything");
    }

    #[test]
    fn mapped_intent_carries_all_columns_and_origin() {
        let m = mapper();
        let i = m.map(&row_coupon("U9", "20", false)).unwrap();
        assert_eq!(i.event_type, "CouponIssueRow");
        assert_eq!(i.entity, "User");
        assert_eq!(i.entity_id, "U9");
        assert_eq!(i.fields.get("amount").map(String::as_str), Some("20"));
        assert_eq!(i.latch_key, "User#U9");
        assert_eq!(i.origin.as_str(), "database");
        match i.origin {
            crate::Origin::Database { ref table, op } => {
                assert_eq!(table, "coupon");
                assert_eq!(op, RowOp::Insert);
            }
            ref other => panic!("期望 Database 来源，实际 {other:?}"),
        }
    }

    // ---------- TxGuard ----------

    #[test]
    fn clean_transaction_commits() {
        let mut g = guard();
        g.stage(row_coupon("U1", "10", false));
        g.stage(row_coupon("U2", "10", false));
        let out = g.commit();
        match out {
            CommitOutcome::Committed { reviewed, bypassed } => {
                assert_eq!(reviewed, 2);
                assert_eq!(bypassed, 0);
            }
            other => panic!("期望 Committed，实际 {other:?}"),
        }
        assert!(out.is_committed());
        assert!(out.to_string().contains("COMMIT"));
        assert_eq!(g.core().stats().allowed, 2);
    }

    #[test]
    fn one_bad_row_rolls_back_whole_transaction() {
        let mut g = guard();
        g.stage(row_coupon("U1", "10", false));
        g.stage(row_coupon("U2", "20", true));
        g.stage(row_coupon("U3", "10", false));
        let out = g.commit();
        match &out {
            CommitOutcome::RolledBack { code, denied_at, rule, reason } => {
                assert_eq!(code, "ERR_ROW_BLOCKED");
                assert_eq!(*denied_at, 1, "必须定位到具体行");
                assert_eq!(rule, "RowGate");
                assert!(reason.contains("INSERT coupon"));
                assert!(reason.contains("规则求值"));
            }
            other => panic!("期望 RolledBack，实际 {other:?}"),
        }
        assert!(out.is_rolled_back());
        assert!(out.to_string().contains("ROLLBACK DENY:ERR_ROW_BLOCKED"));
        // 整个事务中止：第 3 行不再送审
        assert_eq!(g.core().stats().reviewed, 2);
    }

    #[test]
    fn bypassed_rows_are_counted_not_sent() {
        let mut g = guard();
        g.stage(RowMutation::insert("audit_log", HashMap::new()));
        g.stage(row_coupon("U1", "10", false));
        match g.commit() {
            CommitOutcome::Committed { reviewed, bypassed } => {
                assert_eq!(reviewed, 2, "pending 包含全部登记行");
                assert_eq!(bypassed, 1);
            }
            other => panic!("期望 Committed，实际 {other:?}"),
        }
        assert_eq!(g.bypassed(), 1);
        assert_eq!(g.core().stats().reviewed, 1, "只有纳管行进入 PDP");
    }

    #[test]
    fn clear_resets_pending_between_transactions() {
        let mut g = guard();
        g.stage(row_coupon("U1", "10", false));
        assert_eq!(g.pending().len(), 1);
        g.clear();
        assert_eq!(g.pending().len(), 0);
        assert_eq!(g.bypassed(), 0);
        assert!(g.commit().is_committed());
    }

    #[test]
    fn stage_is_optimistic_and_commit_is_authoritative() {
        let mut g = guard();
        // stage 永远 Allow——单行放行不代表事务合法
        assert_eq!(g.stage(row_coupon("U1", "20", true)), Protocol::Allow);
        assert!(g.commit().is_rolled_back());
    }

    #[test]
    fn tx_guard_uses_fast_path_after_a_lease_is_broadcast() {
        // 让人为地往共享内存位图写一笔冻结，第二行应被极速域拦下
        let mut g = guard();
        g.core().latch().put("User#U1", 200);
        g.stage(row_coupon("U1", "10", false));
        match g.commit() {
            CommitOutcome::RolledBack { code, rule, reason, .. } => {
                assert_eq!(code, crate::ERR_FROZEN);
                assert!(rule.is_empty(), "极速域命中无规则名");
                assert!(reason.contains("共享内存租约命中"), "{reason}");
            }
            other => panic!("期望 RolledBack，实际 {other:?}"),
        }
    }

    // ---------- Outbox ----------

    fn outbox() -> Outbox<FieldGate> {
        Outbox::new(PepCore::new(FieldGate { now: 100 }))
    }

    fn intent(user: &str, blocked: bool) -> Intent {
        let mut i = Intent::database("CouponIssueRow", "coupon", RowOp::Insert, "User", user, 100);
        i.fields.insert("user_id".into(), user.into());
        if blocked {
            i.fields.insert("blocked".into(), "1".into());
        }
        i
    }

    #[test]
    fn outbox_enqueue_does_not_block_business_transaction() {
        let mut ob = outbox();
        let p = ob.enqueue(intent("U1", true));
        assert_eq!(p.to_wire(), "DENY:ERR_ROW_BLOCKED");
        assert_eq!(ob.entries().len(), 1);
        assert!(ob.entries()[0].is_pending(), "入队只是记录，业务事务照常提交");
    }

    #[test]
    fn relay_delivers_allowed_and_discards_denied() {
        let mut ob = outbox();
        ob.enqueue(intent("U1", false));
        ob.enqueue(intent("U2", true));
        ob.enqueue(intent("U3", false));

        let rep = ob.relay(200);
        assert_eq!(rep.delivered, vec![1, 3]);
        assert_eq!(rep.discarded, vec![(2, "ERR_ROW_BLOCKED".to_string())]);
        assert_eq!(rep.total(), 3);
        assert!(!rep.is_empty());

        assert!(ob.entries()[0].is_delivered());
        assert_eq!(ob.entries()[0].relayed_at, Some(200));
        assert!(ob.entries()[1].is_discarded());
        assert!(ob.entries()[1].discard_reason.as_deref().unwrap().contains("禁区"));
        assert_eq!(ob.settled(), 3);
        assert_eq!(ob.pending().count(), 0);
    }

    #[test]
    fn relay_is_idempotent_for_settled_entries() {
        let mut ob = outbox();
        ob.enqueue(intent("U1", false));
        let first = ob.relay(200);
        assert_eq!(first.total(), 1);
        let second = ob.relay(300);
        assert!(second.is_empty(), "已终结条目不得重复投递");
    }

    #[test]
    fn purge_compacts_settled_entries() {
        let mut ob = outbox();
        ob.enqueue(intent("U1", false));
        ob.enqueue(intent("U2", true));
        ob.relay(200);
        assert_eq!(ob.purge(), 2);
        assert_eq!(ob.entries().len(), 0);
        assert_eq!(ob.settled(), 0);
    }

    #[test]
    fn outbox_ids_are_monotonic_u64() {
        let mut ob = outbox();
        ob.enqueue(intent("A", false));
        ob.enqueue(intent("B", false));
        assert_eq!(ob.entries()[0].id, 1);
        assert_eq!(ob.entries()[1].id, 2);
        assert_eq!(ob.entries()[0].intent.entity_id, "A");
    }

    #[test]
    fn relay_report_empty_predicate() {
        let r = RelayReport::default();
        assert!(r.is_empty());
        assert_eq!(r.total(), 0);
    }
}
