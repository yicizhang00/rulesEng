//! v1.0 PEP 侧验收测试（PRD §8 · AC2 / AC4 + FR4 三个接入点）。
//!
//! 与 `rules-runtime/tests/acceptance_v1.rs` 的分工：
//!
//! | | 验收对象 |
//! |---|---|
//! | `rules-runtime` 侧 | **PDP**：规则语义对不对 |
//! | 本文件 | **PEP**：阻断发生在不在"物理边界"上 |
//!
//! 三个物理边界都要验：
//!
//! ```text
//!   AC2  报单网关  Gateway(C-ABI)  第 21 笔同线程阻断 + 60s 冻结 + 共享内存广播
//!   AC4  数据库    TxGuard         COMMIT 前送审，DENY 强制 ROLLBACK
//!   FR4  消息代理  Kafka           on_send 抛拦截异常，消息不进 Broker
//! ```
//!
//! 全部契约直接读 `examples/*.rules`——验收对象是交付给业务人员的那份 DSL。

use rules_dictionary::DataDictionary;
use rules_pep::db::{CommitOutcome, Outbox, RowMutation, RowOp, TableIntentMapper, TxGuard};
use rules_pep::kafka::{KafkaInterceptError, ProducerRecord, RuleKafkaProducerInterceptor};
use rules_pep::{DecisionPoint, FrozenLatch, Intent, PepCore, Protocol, ERR_FROZEN};
use rules_runtime::RegulatoryRuntime;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// =====================================================================
// 工具
// =====================================================================

fn example(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
}

/// 契约源码 → 挂共享内存位图的 PEP 核心。
fn core_from(name: &str) -> PepCore<RegulatoryRuntime> {
    let src = example(name);
    let spec = rules_parser::parse(&src).unwrap_or_else(|e| panic!("{name} 解析失败: {e}"));
    let rt = RegulatoryRuntime::new(spec, DataDictionary::default());
    // 位图容量故意开小一点：验证"逻辑删除 + 固定容量"在有界实体集下够用
    PepCore::with_latch(rt, Arc::new(FrozenLatch::new(256)))
}

/// Unix 秒（Howard Hinnant civil→days，与运行时决策表的日历口径一致）。
fn ts(y: i64, m: i64, d: i64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    ((era * 146_097 + doe - 719_468) * 86_400) as u64
}

fn order_intent(seat: &str, t: u64) -> Intent {
    Intent::gateway("OrderIntent", "SSE", "Seat", seat, t)
}

// =====================================================================
// AC2 —— 报单网关：同线程物理阻断 + 60s 冻结 + 共享内存广播
// =====================================================================

#[test]
fn ac2_gateway_blocks_21st_order_in_same_thread() {
    let mut pep = core_from("seat_flood_protection.rules");

    // 1.0 ~ 1.5 秒内 21 笔报单（同一秒粒度）：前 20 笔放行
    let mut blocked = None;
    for i in 1..=21u64 {
        let out = pep.admit(&order_intent("SEAT-A", 1000));
        if out.is_denied() {
            blocked = Some((i, out));
            break;
        }
    }

    let (n, out) = blocked.expect("第 21 笔报单必须被阻断");
    assert_eq!(n, 21, "阻断必须恰好发生在第 21 笔");
    assert_eq!(out.protocol.to_wire(), "DENY:ERR_SEAT_FLOOD");
    assert_eq!(out.rule(), "MaxFrequencyLimit");
    assert!(!out.fast_path, "首次阻断走的是规则求值路径");

    // 被拒事件不占用窗口配额（物理阻断 = 撤回）
    assert_eq!(pep.pdp().stream_len("SeatActions"), 20);

    // 租约已广播到共享内存位图：now() + 60s
    assert_eq!(pep.latch().frozen_until("Seat#SEAT-A"), 1060);
    assert_eq!(pep.active_leases(), 1);
    assert_eq!(pep.stats().leases_broadcast, 1);
}

#[test]
fn ac2_subsequent_orders_are_blocked_by_shared_memory_only() {
    let mut pep = core_from("seat_flood_protection.rules");
    for _ in 1..=21 {
        pep.admit(&order_intent("SEAT-A", 1000));
    }
    let reviews_before = pep.stats().reviewed;

    // 冻结期内 30 笔：全部走极速域，不求值任何规则
    for _ in 0..30 {
        let out = pep.admit(&order_intent("SEAT-A", 1010));
        assert!(out.is_denied());
        assert!(out.fast_path, "冻结期内必须命中共享内存位图");
        assert_eq!(out.protocol, Protocol::deny(ERR_FROZEN));
        assert!(out.adjudication.is_none(), "极速域不得产生裁决对象");
    }

    assert_eq!(pep.stats().latch_hits, 30);
    assert_eq!(pep.stats().reviewed, reviews_before + 30);
    // 窗口不被污染
    assert_eq!(pep.pdp().stream_len("SeatActions"), 20);
    // 租约保持单调（不得被后续小额违规刷掉）
    assert_eq!(pep.latch().frozen_until("Seat#SEAT-A"), 1060);
}

#[test]
fn ac2_lease_expires_without_any_background_timer() {
    let mut pep = core_from("seat_flood_protection.rules");
    for _ in 1..=21 {
        pep.admit(&order_intent("SEAT-A", 1000));
    }
    assert!(pep.fast_gate_at("Seat#SEAT-A", 1059).is_deny());
    assert!(pep.fast_gate_at("Seat#SEAT-A", 1060).is_allow(), "到期即放行");

    // 无后台定时器：时钟推进是唯一的回收时机
    assert_eq!(pep.tick(1060), 1);
    assert_eq!(pep.active_leases(), 0);
    assert_eq!(pep.latch().frozen_until("Seat#SEAT-A"), 0);

    // 放行后重新超频 → 重新施加租约（此刻窗口已淘汰旧事件）
    let mut again = None;
    for i in 1..=21u64 {
        let out = pep.admit(&order_intent("SEAT-A", 1060));
        if out.is_denied() {
            again = Some(i);
            break;
        }
    }
    assert_eq!(again, Some(21), "旧事件已滑出 5s 窗口，必须重新累积到 21 笔");
    assert_eq!(pep.latch().frozen_until("Seat#SEAT-A"), 1120, "租约重新生效且为 now()+60s");
}

#[test]
fn ac2_engine_process_and_gateway_process_share_one_latch() {
    // 引擎进程：持有一个 PepCore
    let mut engine = core_from("seat_flood_protection.rules");
    let bytes = engine.latch().byte_len();
    let ptr = engine.latch().as_ptr();

    // 网关进程：从同一块共享内存原位构造（真实部署是 shm_open + mmap）
    let gateway = unsafe { FrozenLatch::attach(ptr, bytes / 16) };
    assert_eq!(gateway.frozen_until("Seat#SEAT-A"), 0);

    // 引擎侧跑满 21 笔 → 广播冻结
    for _ in 1..=21 {
        engine.admit(&order_intent("SEAT-A", 1000));
    }

    // 网关侧**零 IPC** 立刻看到冻结
    assert!(gateway.is_frozen("Seat#SEAT-A", 1000));
    assert_eq!(gateway.frozen_until("Seat#SEAT-A"), 1060);

    // 到期后网关侧同样立刻看到放行
    assert_eq!(engine.release_expired_leases(1060), 1);
    assert!(!gateway.is_frozen("Seat#SEAT-A", 1060));
}

#[test]
fn ac2_gateway_view_is_independent_of_pdp_process() {
    // 网关侧只读位图、完全不加载规则——这正是"引擎独立部署"的形态：
    // 引擎进程算出超限后写共享内存，网关进程零 IPC 看到事实。
    let latch = FrozenLatch::new(256);
    let now = 1000u64;
    assert!(!latch.is_frozen("Seat#SEAT-A", now), "未冻结时放行");

    latch.put("Seat#SEAT-A", 1060);
    assert!(latch.is_frozen("Seat#SEAT-A", now));
    assert!(!latch.is_frozen("Seat#SEAT-B", now), "未登记的席位 fail-open");
    assert!(!latch.is_frozen("Seat#SEAT-A", 1060), "到期即放行");

    // 网关侧也能自行续期（本地快速路径），单调语义依旧成立
    assert_eq!(latch.put("Seat#SEAT-A", 900), Some(1060), "不得缩短冻结期");
    assert_eq!(latch.put("Seat#SEAT-A", 2000), Some(2000));
}

// =====================================================================
// AC4 —— 数据库事务拦截：COMMIT 前送审，DENY 强制回滚
// =====================================================================

fn coupon_guard() -> TxGuard<RegulatoryRuntime> {
    let core = core_from("ecommerce_coupon.rules");
    let mapper = TableIntentMapper::new().register("coupon", "IssueCouponIntent", "User", "user_id");
    TxGuard::with_table_mapper(core, mapper)
}

fn coupon_row(user: &str, amount: &str) -> RowMutation {
    let mut row = HashMap::new();
    row.insert("user_id".to_string(), user.to_string());
    row.insert("requested_amount".to_string(), amount.to_string());
    RowMutation::insert("coupon", row).at(ts(2026, 11, 2))
}

#[test]
fn ac4_fraudulent_coupon_row_forces_rollback() {
    let mut guard = coupon_guard();

    // 11-02 申请 20 元：决策表查出合法额度 10 元 → 该行被拒 → 整个事务回滚
    guard.stage(coupon_row("U1", "20"));
    let outcome = guard.commit();

    match &outcome {
        CommitOutcome::RolledBack { code, denied_at, rule, reason } => {
            assert_eq!(code, "ERR_COUPON_AMOUNT_FRAUD");
            assert_eq!(*denied_at, 0);
            assert_eq!(rule, "PreventFraud");
            assert!(reason.contains("INSERT coupon"), "{reason}");
        }
        other => panic!("篡改金额必须触发 ROLLBACK，实际 {other:?}"),
    }
    assert!(outcome.to_string().contains("ROLLBACK DENY:ERR_COUPON_AMOUNT_FRAUD"));
}

#[test]
fn ac4_legitimate_coupon_row_commits() {
    let mut guard = coupon_guard();
    guard.stage(coupon_row("U1", "10"));
    assert!(guard.commit().is_committed(), "11-02 的合法额度是 10 元");
}

#[test]
fn ac4_duplicate_phase_is_blocked_by_state_lattice_at_commit() {
    let mut guard = coupon_guard();

    // 第一次领券：放行
    guard.stage(coupon_row("U1", "10"));
    assert!(guard.commit().is_committed());
    guard.clear();

    // PEP 放行后业务侧推进状态格：PHASE_1 已领取（非侵入式，业务代码不写规则）
    guard.core_mut().pdp_mut().set_state_bits("User", "U1", &["PHASE_1"]);
    assert_eq!(guard.core().pdp().state_mask("User", "U1"), 0x01);

    // 同阶段二次领券（额度合法）→ 被状态格拦截
    guard.stage(coupon_row("U1", "10"));
    match guard.commit() {
        CommitOutcome::RolledBack { code, rule, .. } => {
            assert_eq!(code, "ERR_COUPON_AMOUNT_FRAUD");
            assert_eq!(rule, "PreventFraud");
        }
        other => panic!("同阶段二次领券必须被状态格拦截，实际 {other:?}"),
    }
}

#[test]
fn ac4_mixed_batch_rolls_back_whole_transaction() {
    let mut guard = coupon_guard();
    guard.stage(coupon_row("U1", "10")); // 合法
    guard.stage(coupon_row("U2", "20")); // 篡改金额
    guard.stage(coupon_row("U3", "10")); // 合法（但因前一行回滚而不落库）

    match guard.commit() {
        CommitOutcome::RolledBack { denied_at, .. } => assert_eq!(denied_at, 1, "必须定位到第 2 行"),
        other => panic!("整批必须回滚，实际 {other:?}"),
    }
    // 第 3 行不再送审（事务已中止）
    assert_eq!(guard.core().stats().reviewed, 2);
}

#[test]
fn ac4_unmanaged_tables_are_bypassed_not_blocked() {
    let mut guard = coupon_guard();
    guard.stage(RowMutation::insert("audit_log", HashMap::new()).at(ts(2026, 11, 2)));
    guard.stage(coupon_row("U1", "10"));
    match guard.commit() {
        CommitOutcome::Committed { reviewed, bypassed } => {
            assert_eq!(reviewed, 2);
            assert_eq!(bypassed, 1);
        }
        other => panic!("未纳管表不得阻断事务，实际 {other:?}"),
    }
}

#[test]
fn ac4_outbox_path_keeps_business_transaction_unblocked() {
    // Transactional Outbox：业务事务只写暂存表，不依赖引擎可用性
    let core = core_from("ecommerce_coupon.rules");
    let mut outbox = Outbox::new(core);

    let intent = |user: &str, amount: &str| {
        Intent::database("IssueCouponIntent", "coupon", RowOp::Insert, "User", user, ts(2026, 11, 2))
            .with_field("user_id", user)
            .with_field("requested_amount", amount)
    };

    // 入队即预审（写 protocol 列），但**不阻断业务事务**
    assert_eq!(outbox.enqueue(intent("U1", "10")).to_wire(), "ALLOW");
    assert_eq!(outbox.enqueue(intent("U2", "20")).to_wire(), "DENY:ERR_COUPON_AMOUNT_FRAUD");
    assert_eq!(outbox.enqueue(intent("U3", "10")).to_wire(), "ALLOW");

    // 事务已提交，relay 阶段才决定投递 / 丢弃
    let report = outbox.relay(ts(2026, 11, 2) + 1);
    assert_eq!(report.delivered, vec![1, 3]);
    assert_eq!(report.discarded, vec![(2, "ERR_COUPON_AMOUNT_FRAUD".to_string())]);
    assert_eq!(outbox.settled(), 3);
}

// =====================================================================
// FR4 —— Kafka 生产者拦截器
// =====================================================================

fn coupon_interceptor() -> RuleKafkaProducerInterceptor<RegulatoryRuntime> {
    RuleKafkaProducerInterceptor::with_header_mapper(core_from("ecommerce_coupon.rules"))
}

fn coupon_record(user: &str, amount: &str) -> ProducerRecord {
    ProducerRecord::new("coupon.issue", b"payload".to_vec())
        .with_key(user)
        .with_timestamp(ts(2026, 11, 2))
        .with_header("rules.event_type", "IssueCouponIntent")
        .with_header("rules.entity", "User")
        .with_header("rules.entity_id", user)
        .with_header("requested_amount", amount)
}

#[test]
fn kafka_denied_message_never_reaches_broker() {
    let mut ic = coupon_interceptor();
    let err = ic
        .on_send(&coupon_record("U1", "20"))
        .expect_err("篡改金额的消息必须被拦截");

    match &err {
        KafkaInterceptError::Denied(d) => {
            assert_eq!(d.protocol.to_wire(), "DENY:ERR_COUPON_AMOUNT_FRAUD");
            assert_eq!(d.rule, "PreventFraud");
            assert_eq!(d.topic, "coupon.issue");
            assert_eq!(d.entity_id, "U1");
            assert!(!d.fast_path);
        }
        other => panic!("期望 Denied，实际 {other:?}"),
    }
    assert_eq!(ic.denied_by_topic().get("coupon.issue"), Some(&1));
}

#[test]
fn kafka_allowed_message_is_returned_untouched() {
    let mut ic = coupon_interceptor();
    assert!(ic.on_send(&coupon_record("U1", "10")).is_ok());
    ic.on_acknowledgement(&coupon_record("U1", "10"));
    assert_eq!(ic.core().stats().allowed, 1);
    assert!(ic.denied_by_topic().is_empty());
}

#[test]
fn kafka_missing_routing_metadata_is_rejected_fail_closed() {
    let mut ic = coupon_interceptor();
    let bare = ProducerRecord::new("coupon.issue", b"payload".to_vec());
    let err = ic.on_send(&bare).expect_err("缺少路由元数据必须拒绝");
    assert!(matches!(err, KafkaInterceptError::MissingRouting { .. }));
}

// =====================================================================
// PEP ⇄ PDP 协议（PRD §3）
// =====================================================================

#[test]
fn protocol_is_exactly_allow_or_deny_code() {
    let mut pep = core_from("ecommerce_coupon.rules");
    let allow = pep.admit(
        &Intent::new("IssueCouponIntent", "User", "U1", ts(2026, 11, 2))
            .with_field("user_id", "U1")
            .with_field("requested_amount", "10"),
    );
    assert_eq!(allow.protocol.to_wire(), "ALLOW");

    let deny = pep.admit(
        &Intent::new("IssueCouponIntent", "User", "U1", ts(2026, 11, 2))
            .with_field("user_id", "U1")
            .with_field("requested_amount", "20"),
    );
    assert_eq!(deny.protocol.to_wire(), "DENY:ERR_COUPON_AMOUNT_FRAUD");

    // 协议串是 PEP 与 PDP 之间唯一的数据契约
    assert_eq!(Protocol::parse(&allow.protocol.to_wire()), Protocol::Allow);
    assert_eq!(Protocol::parse(&deny.protocol.to_wire()).code(), Some("ERR_COUPON_AMOUNT_FRAUD"));
}

#[test]
fn malformed_protocol_is_fail_closed() {
    assert!(Protocol::parse("ALLOWED").is_deny(), "近似但不是 ALLOW 的串必须拒绝");
    assert!(Protocol::parse("deny:").is_deny());
    assert_eq!(Protocol::parse("DENY:").code(), Some(rules_pep::ERR_MALFORMED));
}

#[test]
fn audit_view_does_not_short_circuit_on_latch() {
    let mut pep = core_from("seat_flood_protection.rules");
    for _ in 1..=21 {
        pep.admit(&order_intent("SEAT-A", 1000));
    }
    assert!(pep.latch().is_frozen("Seat#SEAT-A", 1010));

    // 审计路径不读位图：事件照常落地，用于回放 / 对账
    let res = pep.adjudicate(&order_intent("SEAT-A", 1010));
    assert_eq!(res.len(), 1);
    assert_eq!(pep.stats().latch_hits, 0, "审计路径不得计入极速域命中");
}

#[test]
fn real_engine_frozen_until_is_surfaced_through_pep() {
    let mut pep = core_from("seat_flood_protection.rules");
    for _ in 1..=21 {
        pep.admit(&order_intent("SEAT-A", 1000));
    }
    // 引擎账本与共享内存位图必须一致（两个真相源不允许漂移）
    assert_eq!(
        pep.pdp().frozen_until("Seat", "SEAT-A"),
        pep.latch().frozen_until("Seat#SEAT-A")
    );
}
