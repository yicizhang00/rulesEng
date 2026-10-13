//! v1.0 验收测试（PRD §8 · AC2 / AC3 / AC4 / AC5）。
//!
//! 四个用例直接读 `examples/*.rules`——**验收对象就是交付给业务人员的
//! 那份 DSL**，而不是测试里另写一份等价的 Rust 构造。这样任何一次
//! 文法/语义漂移都会在这里立刻暴露。
//!
//! ```text
//!   AC2  模式 C  21 笔报单 → 第 21 笔物理阻断 + 60s 冻结 + 60s 后放行
//!   AC3  模式 A  批文后 400 天启动发行 → DENY:ERR_APPROVAL_EXPIRED
//!   AC4  模式 D  11-02 领 20 元 → DENY；同阶段二次领券 → 被状态格拦截
//!   AC5  模式 B  多事实推导 + 循环依赖静态驳回 + 32 步熔断
//! ```

use rules_ast::*;
use rules_dictionary::DataDictionary;
use rules_runtime::{Adjudication, Event, Fact, RegulatoryRuntime, Value};
use std::collections::HashMap;
use std::path::PathBuf;

// =====================================================================
// 工具
// =====================================================================

fn example(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
}

fn load(name: &str) -> RegulatoryRuntime {
    let src = example(name);
    let spec = rules_parser::parse(&src).unwrap_or_else(|e| panic!("{name} 解析失败: {e}"));
    RegulatoryRuntime::new(spec, DataDictionary::default())
}

fn ev(ts: u64, ty: &str, fields: &[(&str, &str)]) -> Event {
    Event {
        event_type: ty.to_string(),
        fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        timestamp: ts,
    }
}

fn num_event(ts: u64, ty: &str, fields: &[(&str, &str)], nums: &[(&str, f64)]) -> Event {
    let mut e = ev(ts, ty, fields);
    for (k, v) in nums {
        e.fields.insert(k.to_string(), format!("{v}"));
    }
    e
}

// =====================================================================
// AC2 —— 模式 C：IPO 打新席位洪水防护
// =====================================================================

#[test]
fn ac2_seat_flood_21st_order_is_blocked_then_released() {
    let mut rt = load("seat_flood_protection.rules");

    // 用例 1 的 DSL 必须解析成模式 C
    assert_eq!(rt.mode_of("MaxFrequencyLimit"), Some(Mode::Stream));
    assert_eq!(rt.mode_of("IsNotFrozen"), Some(Mode::Stream));

    // 1.0 ~ 1.5 秒内连发 21 笔报单（逐笔间隔 20ms，同一秒粒度下等价）
    let mut blocked_at = None;
    for i in 1..=21u64 {
        let v = rt.admit(num_event(1, "OrderIntent", &[("seat_id", "SEAT-A")], &[("price", 10.0)]));
        if v.is_deny() {
            blocked_at = Some(i);
            break;
        }
    }

    // (a) 前 20 笔全部放行，第 21 笔被物理阻断
    assert_eq!(blocked_at, Some(21), "第 21 笔报单必须被拒绝");
    assert_eq!(rt.violations.last().map(|v| v.verdict.code()), Some(Some("ERR_SEAT_FLOOD")));

    // (b) 被拒事件不进窗口：窗口里仍是 20 笔
    assert_eq!(rt.stream_len("SeatActions"), 20, "物理阻断的事件不得占用窗口配额");

    // (c) 惩罚租约生效：frozen_until = now() + 60s
    assert_eq!(rt.entity_var("Seat", "SEAT-A", "frozen_until"), Some(Value::Num(61.0)));
    assert!(rt.is_frozen("Seat", "SEAT-A"));

    // (d) 冻结期内任意报单被 PEP 前置快筛直接拒绝（与窗口无关）
    let during = rt.admit(ev(30, "OrderIntent", &[("seat_id", "SEAT-A")]));
    assert!(during.is_deny());
    assert_eq!(during.code(), Some("ERR_SEAT_FROZEN"));
    assert!(during.from_guard, "冻结期拒绝必须走 PEP 前置快筛路径");

    // (e) 60s 后自动放行（无后台定时器：由 tick 的到期回收推进）
    rt.set_clock(62);
    rt.tick();
    assert!(!rt.is_frozen("Seat", "SEAT-A"), "60s 后租约必须被回收");

    let after = rt.admit(ev(62, "OrderIntent", &[("seat_id", "SEAT-A")]));
    assert!(!after.is_deny(), "60s 冻结到期后必须放行：{after:?}");
}

#[test]
fn ac2_lease_is_monotonic_and_survives_repeated_flooding() {
    let mut rt = load("seat_flood_protection.rules");
    for _ in 0..21 {
        rt.admit(ev(1, "OrderIntent", &[("seat_id", "S1")]));
    }
    assert_eq!(rt.entity_var("Seat", "S1", "frozen_until"), Some(Value::Num(61.0)));
    assert!(rt.is_frozen("Seat", "S1"));

    // 冻结期内继续灌 30 笔：一律走 PEP 前置快筛，既不进窗口也不刷新租约
    for _ in 0..30 {
        let v = rt.admit(ev(10, "OrderIntent", &[("seat_id", "S1")]));
        assert_eq!(v.code(), Some("ERR_SEAT_FROZEN"));
    }
    assert_eq!(rt.stream_len("SeatActions"), 20, "冻结期内的事件不得污染窗口");
    assert_eq!(rt.entity_var("Seat", "S1", "frozen_until"), Some(Value::Num(61.0)));

    // 回拨时钟不能让租约倒退（账本只增不减）
    rt.set_clock(5);
    assert!(rt.is_frozen("Seat", "S1"));

    // 到期回收后重新放行，再次超频则重新施加租约
    rt.set_clock(62);
    rt.tick();
    assert!(!rt.is_frozen("Seat", "S1"));
    for _ in 0..21 {
        rt.admit(ev(62, "OrderIntent", &[("seat_id", "S1")]));
    }
    assert_eq!(rt.entity_var("Seat", "S1", "frozen_until"), Some(Value::Num(122.0)));
}

// =====================================================================
// AC3 —— 模式 A：再融资批文有效期
// =====================================================================

#[test]
fn ac3_approval_expiry_blocks_issuance_on_day_400() {
    let mut rt = load("additional_issuance.rules");
    let t0: u64 = 1_800_000_000; // 批文下达时刻

    rt.ensure_entity("Company", "600000");
    rt.set_clock(t0);

    // 批文下达：单调置位 CSRC_APPROVED，并登记批文日期（非侵入式数据源绑定）
    let mask = rt.set_state_bits("Company", "600000", &["CSRC_APPROVED"]);
    assert_eq!(mask, 0x04);
    rt.set_entity_var("Company", "600000", "approval_date", Value::Num(t0 as f64));

    // (a) 停滞 10 天：零事件、零告警、零消耗
    rt.set_clock(t0 + 10 * 86_400);
    rt.tick();
    assert!(rt.violations.is_empty(), "批文后停滞 10 天不得产生任何违规");

    // (b) 第 400 天通过 PEP 启动发行 → 被拒
    rt.set_clock(t0 + 400 * 86_400);
    let v = rt.admit(ev(
        t0 + 400 * 86_400,
        "CommenceIssuanceIntent",
        &[("company_code", "600000")],
    ));
    assert!(v.is_deny(), "第 400 天启动发行必须被拒绝");
    assert_eq!(v.code(), Some("ERR_APPROVAL_EXPIRED"));
    assert_eq!(v.verdict.as_str(), "DENY:ERR_APPROVAL_EXPIRED");

    // (c) 已置位 ISSUING 后不再受批文有效期约束（单调格 + 互斥子句）
    rt.set_state_bits("Company", "600000", &["ISSUING"]);
    let v2 = rt.admit(ev(
        t0 + 400 * 86_400,
        "CommenceIssuanceIntent",
        &[("company_code", "600000")],
    ));
    assert!(!v2.is_deny(), "已进入 ISSUING 阶段后不再触发批文有效期不变量：{v2:?}");
}

#[test]
fn ac3_pure_mode_has_no_mutable_state_leak() {
    let mut rt = load("additional_issuance.rules");
    rt.ensure_entity("Company", "C1");
    rt.set_clock(1000);
    rt.set_state_bits("Company", "C1", &["BOARD_RESOLVED"]);
    let m = rt.set_state_mask("Company", "C1", 0x02);
    // 单调：位只增不减（0x01 | 0x02 = 0x03）
    assert_eq!(m, 0x03);
    assert_eq!(rt.state_mask("Company", "C1"), 0x03);
}

// =====================================================================
// AC4 —— 模式 D：大促领券
// =====================================================================

/// 2026-11-02 00:00:00 UTC 的 Unix 秒（Howard Hinnant days_from_civil）。
fn ts(y: i64, m: i64, d: i64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    ((era * 146_097 + doe - 719_468) * 86_400) as u64
}

#[test]
fn ac4_coupon_amount_and_phase_lattice_block_fraud() {
    let mut rt = load("ecommerce_coupon.rules");
    assert_eq!(rt.mode_of("PreventFraud"), Some(Mode::DecisionTable));
    assert!(rt.decision_table("DetermineAmount").is_some());

    let t = ts(2026, 11, 2);
    rt.ensure_entity("User", "U1");

    // (a) 11-02 申请 20 元：决策表查出合法额度是 10 元 → 拦截
    let over = rt.admit(num_event(
        t,
        "IssueCouponIntent",
        &[("user_id", "U1")],
        &[("requested_amount", 20.0)],
    ));
    assert!(over.is_deny(), "11-02 申请 20 元必须被拦截");
    assert_eq!(over.code(), Some("ERR_COUPON_AMOUNT_FRAUD"));

    // (b) 11-02 申请 10 元（合法额度）→ 放行
    let ok = rt.admit(num_event(
        t,
        "IssueCouponIntent",
        &[("user_id", "U1")],
        &[("requested_amount", 10.0)],
    ));
    assert!(!ok.is_deny(), "11-02 申请 10 元应当放行：{ok:?}");

    // PEP 放行后业务侧推进状态格：PHASE_1 已领取
    rt.set_state_bits("User", "U1", &["PHASE_1"]);
    assert_eq!(rt.state_mask("User", "U1"), 0x01);

    // (c) 同阶段二次刷券（额度合法）→ 被状态格拦截
    let dup = rt.admit(num_event(
        t,
        "IssueCouponIntent",
        &[("user_id", "U1")],
        &[("requested_amount", 10.0)],
    ));
    assert!(dup.is_deny(), "同阶段二次领券必须被状态格拦截");
    assert_eq!(dup.code(), Some("ERR_COUPON_AMOUNT_FRAUD"));

    // (d) 跨阶段（11-04，额度 20）不受 PHASE_1 影响
    let p2 = rt.admit(num_event(
        ts(2026, 11, 4),
        "IssueCouponIntent",
        &[("user_id", "U1")],
        &[("requested_amount", 20.0)],
    ));
    assert!(!p2.is_deny(), "跨阶段合法领券应当放行：{p2:?}");
}

#[test]
fn ac4_default_row_covers_non_promotion_period() {
    let dt = {
        let rt = load("ecommerce_coupon.rules");
        rt.decision_table("DetermineAmount").cloned().unwrap()
    };
    // 决策表结构：3 条促销期规则 + 1 条 default
    assert_eq!(dt.rows.len(), 4);
    assert_eq!(dt.hit_policy, HitPolicy::Unique);
    assert!(dt.default_row().is_some(), "default 行必须存在，保证完备性");
}

// =====================================================================
// AC5 —— 模式 B：受限工作内存
// =====================================================================

fn fact(ty: &str, fields: &[(&str, Value)]) -> Fact {
    let mut m = HashMap::new();
    for (k, v) in fields {
        m.insert(k.to_string(), v.clone());
    }
    Fact::new(ty, m)
}

#[test]
fn ac5_multi_fact_derivation_blocks_inflight_order() {
    let rt = load("suspicious_account.rules");
    assert_eq!(rt.mode_of("Derive_Suspicious_Account"), Some(Mode::Stateful));
    assert_eq!(rt.mode_of("Action_On_Suspicious"), Some(Mode::Stateful));

    // (a) 无环图 → 编译期 DAG 检验通过
    assert!(rt.check_rule_dag().is_ok(), "用例 4 的两条规则必须无环");

    // (b) 多事实推导：Account(高频) + InFlightOrder(大额) → SuspiciousTag → yield DENY
    let res = rt.run_stateful(vec![
        fact("Account", &[("id", Value::Text("A1".into())), ("trade_frequency_5s", Value::Num(20.0))]),
        fact(
            "InFlightOrder",
            &[("account_id", Value::Text("A1".into())), ("amount", Value::Num(900_000.0))],
        ),
    ]);

    assert!(!res.truncated, "本会话不应触发熔断");
    assert_eq!(res.steps, 1, "恰好推导出 1 条 SuspiciousTag");
    assert_eq!(
        res.verdict.as_ref().map(|(r, c, _)| (r.as_str(), c.as_str())),
        Some(("Action_On_Suspicious", "ERR_SUSPICIOUS_INFLIGHT_ORDER"))
    );
    assert_eq!(res.memory.of_type("SuspiciousTag").count(), 1);
    // 推导轨迹：Derive 规则 → SuspiciousTag
    assert_eq!(res.trace, vec![("Derive_Suspicious_Account".to_string(), "SuspiciousTag".to_string())]);
}

#[test]
fn ac5_low_frequency_account_is_not_derived() {
    let rt = load("suspicious_account.rules");
    // 频次 5 ≤ 10 → 不推导出 SuspiciousTag → 不放行 DENY
    let res = rt.run_stateful(vec![
        fact("Account", &[("id", Value::Text("A2".into())), ("trade_frequency_5s", Value::Num(5.0))]),
        fact(
            "InFlightOrder",
            &[("account_id", Value::Text("A2".into())), ("amount", Value::Num(900_000.0))],
        ),
    ]);
    assert!(res.verdict.is_none(), "低频账户不得被阻断");
    assert_eq!(res.memory.of_type("SuspiciousTag").count(), 0);
}

#[test]
fn ac5_cyclic_dependency_is_rejected_statically() {
    // 循环依赖必须在编译期被静态驳回（PRD §4.2 / AC5）
    let a = StatefulRuleDecl {
        name: "A".into(),
        patterns: vec![Pattern {
            binding: None,
            type_name: "X".into(),
            constraints: vec![],
            meta: NodeMeta::default(),
            span: Span::default(),
        }],
        negatives: vec![],
        actions: vec![RuleAction::Insert {
            type_name: "Y".into(),
            fields: vec![],
            span: Span::default(),
        }],
        meta: NodeMeta::default(),
        span: Span::default(),
    };
    let b = StatefulRuleDecl {
        name: "B".into(),
        patterns: vec![Pattern {
            binding: None,
            type_name: "Y".into(),
            constraints: vec![],
            meta: NodeMeta::default(),
            span: Span::default(),
        }],
        negatives: vec![],
        actions: vec![RuleAction::Insert {
            type_name: "X".into(),
            fields: vec![],
            span: Span::default(),
        }],
        meta: NodeMeta::default(),
        span: Span::default(),
    };
    let err = rules_runtime::check_dag(&[a, b]).unwrap_err();
    assert!(err.rules.contains(&"A".to_string()));
    assert!(err.message().contains("循环"), "诊断应当说明是循环依赖：{}", err.message());
}

#[test]
fn ac5_activation_budget_fuses_runaway_derivation() {
    // 每条 Seed 事实都插入一条**不同内容**的 Chained 事实 → 激活步数线性增长，
    // 超过 32 步必须被熔断（而不是无限激活）。
    let r = StatefulRuleDecl {
        name: "Grow".into(),
        patterns: vec![Pattern {
            binding: Some("$s".into()),
            type_name: "Seed".into(),
            constraints: vec![],
            meta: NodeMeta::default(),
            span: Span::default(),
        }],
        negatives: vec![],
        actions: vec![RuleAction::Insert {
            type_name: "Chained".into(),
            fields: vec![("n".into(), Expr::Ident("$s.n".into()))],
            span: Span::default(),
        }],
        meta: NodeMeta::default(),
        span: Span::default(),
    };

    let mut wm = rules_runtime::WorkingMemory::new();
    for i in 0..80 {
        wm.insert(fact("Seed", &[("n", Value::Num(i as f64))]));
    }

    // 每条 Seed 产生一条**内容不同**的 Chained（否则去重会立刻让规则停火）
    let mut n = 0.0f64;
    let res = rules_runtime::run_session(&[r], wm, move |_e, _p| {
        n += 1.0;
        Value::Num(n)
    });
    assert!(res.truncated, "超过 32 步必须熔断");
    assert!(res.steps > rules_runtime::MAX_ACTIVATION_STEPS);
    assert!(res.steps <= rules_runtime::MAX_ACTIVATION_STEPS + 1);
}

// =====================================================================
// 四模路由与协议一致性
// =====================================================================
#[test]
fn all_four_modes_are_routed_from_the_prd_examples() {
    let cases = [
        ("seat_flood_protection.rules", "MaxFrequencyLimit", Mode::Stream),
        ("additional_issuance.rules", "ApprovalValidity", Mode::Pure),
        ("ecommerce_coupon.rules", "PreventFraud", Mode::DecisionTable),
        ("suspicious_account.rules", "Derive_Suspicious_Account", Mode::Stateful),
    ];
    for (file, name, want) in cases {
        let rt = load(file);
        assert_eq!(rt.mode_of(name), Some(want), "{file} :: {name} 模式不符");
    }
}

#[test]
fn adjudication_protocol_is_allow_or_deny_code() {
    let mut rt = load("seat_flood_protection.rules");
    let ok = rt.admit(ev(1, "OrderIntent", &[("seat_id", "S9")]));
    assert_eq!(ok.as_protocol(), "ALLOW");
    assert!(!ok.is_deny());
    assert!(matches!(ok.verdict, Verdict::Allow));

    // 上面那一笔已经进了窗口，再补 19 笔凑满 20
    for _ in 0..19 {
        let v = rt.admit(ev(1, "OrderIntent", &[("seat_id", "S9")]));
        assert!(!v.is_deny(), "前 20 笔必须放行");
    }
    let denied: Adjudication = rt.admit(ev(1, "OrderIntent", &[("seat_id", "S9")]));
    assert!(denied.as_protocol().starts_with("DENY:"), "第 21 笔必须被拒绝");
    // 裁决必须携带可回放的反例参数
    assert!(!denied.explain.is_empty(), "裁决必须带违反解释");
    assert!(denied.lease_until(rt.now).is_some(), "超频裁决必须带 LeaseUpdate 副作用");
}

// =====================================================================
// FR5 —— 长周期双轨调度器（离散时间轮 HashedWheelTimer）
// =====================================================================

#[test]
fn fr5_state_bit_is_sourced_from_the_entity_declaration() {
    let rt = load("additional_issuance.rules");
    // §5 用例 2 显式声明了位向量常量
    assert_eq!(rt.state_bit("Company", "BOARD_RESOLVED"), Some(0x01));
    assert_eq!(rt.state_bit("Company", "SHAREHOLDER_APPROVED"), Some(0x02));
    assert_eq!(rt.state_bit("Company", "CSRC_APPROVED"), Some(0x04));
    assert_eq!(rt.state_bit("Company", "ISSUING"), Some(0x08));
    // 未声明的状态必须返回 None（调用方不得静默当成 0）
    assert_eq!(rt.state_bit("Company", "NO_SUCH_STATE"), None);
    assert_eq!(rt.state_bit("NoSuchEntity", "ISSUING"), None);
}

/// **AC3 的时间轮轨**：批文下达即注册 $T_0 + 365\text{d}$ 单次唤醒，
/// 中间 365 天**一格都不扫**（`evaluated_ticks == 0`），到期只读一次位图。
#[test]
fn ac3_double_track_wheel_sleeps_365_days_then_wakes_once() {
    let mut rt = load("additional_issuance.rules");
    let t0: u64 = 1_800_000_000;
    const DAY: u64 = rules_runtime::DAY_SECS;

    rt.ensure_entity("Company", "600000");
    rt.set_clock(t0);
    // 因果事件轨：批文下达 → 单调置位
    assert_eq!(rt.set_state_bits("Company", "600000", &["CSRC_APPROVED"]), 0x04);

    // 唤醒轨：注册 365 天后的单次复核
    let mut sched = rules_runtime::LongHorizonScheduler::new();
    sched.set_now(t0);
    let timer = rt
        .watch_state_expiry(&mut sched, "Company", "600000", "ISSUING", "批文 365 天有效期", t0 + 365 * DAY)
        .expect("ISSUING 已在 DSL 中声明为位向量状态");
    assert_eq!(sched.pending_len(), 1);
    assert_eq!(sched.sleep_span(), Some(365 * DAY), "调度器被告知可以睡满 365 天");

    // (a) 批文后停滞 10 天：零事件、零告警、零扫描
    let woken = rt.advance_schedule(&mut sched, t0 + 10 * DAY);
    assert!(woken.is_empty(), "休眠期不得有任何唤醒");
    assert_eq!(sched.stats().evaluated_ticks, 0, "休眠期不得扫描任何时间轮格子");
    assert!(rt.violations.is_empty(), "批文后停滞 10 天不得产生违规");

    // (b) 第 365 天到期唤醒：只读位图，判定批文失效
    let woken = rt.advance_schedule(&mut sched, t0 + 365 * DAY);
    assert_eq!(woken.len(), 1, "365 天到点必须恰好唤醒一次");
    let (wake, outcome) = &woken[0];
    assert_eq!(wake.state, "ISSUING");
    assert_eq!(wake.required_bit, 0x08);
    assert_eq!(wake.label, "批文 365 天有效期");
    assert!(outcome.is_lapsed(), "未进入 ISSUING → 批文在 365 天到期时失效");
    assert!(sched.stats().evaluated_ticks <= 2, "整个 365 天周期只允许极少数格被扫描");
    assert_eq!(sched.pending_len(), 0, "单次唤醒定时器触发后必须自动摘除");

    // (c) 换一条时间线：批文后第 300 天启动发行 → 到期时约束自然消解
    let mut rt2 = load("additional_issuance.rules");
    rt2.ensure_entity("Company", "600001");
    rt2.set_clock(t0);
    rt2.set_state_bits("Company", "600001", &["CSRC_APPROVED"]);
    let mut sched2 = rules_runtime::LongHorizonScheduler::new();
    sched2.set_now(t0);
    rt2.watch_state_expiry(&mut sched2, "Company", "600001", "ISSUING", "批文 365 天有效期", t0 + 365 * DAY)
        .expect("ISSUING 已声明");
    rt2.set_clock(t0 + 300 * DAY);
    rt2.set_state_bits("Company", "600001", &["ISSUING"]); // 因果轨推进
    let woken = rt2.advance_schedule(&mut sched2, t0 + 365 * DAY);
    assert_eq!(woken.len(), 1);
    assert_eq!(woken[0].1, rules_runtime::ExpiryOutcome::Satisfied, "已进入 ISSUING → 约束消解");

    // (d) 提前终止：$O(1)$ 取消后不再唤醒
    let mut sched3 = rules_runtime::LongHorizonScheduler::new();
    sched3.set_now(t0);
    let id = rt
        .watch_state_expiry(&mut sched3, "Company", "600000", "ISSUING", "批文 365 天有效期", t0 + 365 * DAY)
        .unwrap();
    assert!(sched3.cancel(id));
    assert!(sched3.advance_to(t0 + 400 * DAY).is_empty(), "取消后不得再唤醒");
    let _ = timer;
}

// =====================================================================
// FR6 —— 边缘跃迁算子（crosses_above / crosses_below）端到端
// =====================================================================

#[test]
fn fr6_crossing_edges_fire_exactly_once_per_crossing() {
    let mut rt = load("edge_crossing.rules");
    assert_eq!(rt.mode_of("UpEdge"), Some(Mode::Stream));
    assert_eq!(rt.mode_of("DownEdge"), Some(Mode::Stream));

    // (a) 第 1..9 笔：未达阈值，首拍不触发（EDGE_UNKNOWN 保护）
    for i in 1..=9u64 {
        let v = rt.admit(ev(1, "OrderIntent", &[("seat_id", "S1")]));
        assert!(!v.is_deny(), "第 {i} 笔不得触发边缘跃迁：{v:?}");
    }

    // (b) 第 10 笔：计数达到阈值 —— 唯一一次向上跃迁（阈值闭区间）
    let up = rt.admit(ev(1, "OrderIntent", &[("seat_id", "S1")]));
    assert!(up.is_deny(), "第 10 笔必须触发 crosses_above");
    assert_eq!(up.code(), Some("ERR_EDGE_UP"));

    // (c) 第 11..20 笔：高位保持，必须被抑制（这是本算子的全部价值）
    for i in 11..=20u64 {
        let v = rt.admit(ev(1, "OrderIntent", &[("seat_id", "S1")]));
        assert!(!v.is_deny(), "第 {i} 笔仍处阈值之上，crosses_above 不得重复告警：{v:?}");
    }
    // 20 笔里第 10 笔被物理阻断并撤回，窗口只留下 19 笔
    assert_eq!(rt.stream_len("SeatActions"), 19, "被拒事件不得占用窗口配额");

    // (d) 窗口滑出：计数回落到 10 以下 → 唯一一次向下跃迁
    let down = rt.admit(ev(8, "OrderIntent", &[("seat_id", "S1")]));
    assert!(down.is_deny(), "窗口滑出后必须触发 crosses_below：{down:?}");
    assert_eq!(down.code(), Some("ERR_EDGE_DOWN"));

    // (e) 再次保持低位：不得重复告警
    for _ in 0..3 {
        let v = rt.admit(ev(8, "OrderIntent", &[("seat_id", "S1")]));
        assert!(!v.is_deny(), "低位保持期间 crosses_below 不得重复告警：{v:?}");
    }
}

/// 回归：早期实现把 `side == 1` 提到公共位置，导致 `crosses_below` 退化成
/// "只要仍在阈值之上就每拍为真" —— 即它本该消除的告警风暴。此用例锁死该行为。
#[test]
fn fr6_crosses_below_does_not_degrade_into_an_alarm_storm() {
    let mut rt = load("edge_crossing.rules");
    for _ in 0..9 {
        rt.admit(ev(1, "OrderIntent", &[("seat_id", "S1")]));
    }
    // 第 10 笔向上跃迁并撤回，窗口停在 9
    assert_eq!(rt.admit(ev(1, "OrderIntent", &[("seat_id", "S1")])).code(), Some("ERR_EDGE_UP"));

    // 关键断言：之后每一拍都会把计数推回阈值之上，但 crosses_below **不得**为真
    for i in 0..5 {
        let v = rt.admit(ev(1, "OrderIntent", &[("seat_id", "S1")]));
        assert_ne!(
            v.code(),
            Some("ERR_EDGE_DOWN"),
            "第 {} 拍：计数从未真正回落到阈值之下，crosses_below 不得触发：{v:?}",
            i + 11
        );
    }
}

#[test]
fn fr6_edges_are_per_entity_isolated() {
    let mut rt = load("edge_crossing.rules");
    // S1 越过阈值
    for _ in 0..10 {
        rt.admit(ev(1, "OrderIntent", &[("seat_id", "S1")]));
    }
    // S2 的首拍必须因为"从未观测过"而不触发（每实体独立的 edge_side）
    let first = rt.admit(ev(1, "OrderIntent", &[("seat_id", "S2")]));
    assert!(!first.is_deny(), "S2 首拍不得受 S1 的跃迁状态影响：{first:?}");
}

